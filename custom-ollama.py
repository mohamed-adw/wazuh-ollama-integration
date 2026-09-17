#!/usr/bin/env python3
"""
custom-ollama.py

Worker exécuté en arrière-plan par le wrapper `custom-ollama`.
Pour UNE alerte Wazuh :
  1. Charge l'alerte JSON (copie temporaire faite par le wrapper).
  2. Appelle l'API Ollama (Mistral 7B) avec un prompt structuré.
  3. Écrit le résultat dans SQLite (table `alerts`), lue en parallèle par
     le dashboard Flask.
  4. Nettoie le fichier temporaire.



import contextlib
import fcntl
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error

# --- Configuration (surchageable via variables d'environnement) ----------
OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/api/generate"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "240"))   # cf. bug connu : décharge RAM -> premier appel lent
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")
DB_PATH = os.environ.get("WAZUH_AI_DB", "/var/ossec/integrations/data/alerts.db")
MAX_RETRIES = 1


LOCK_PATH = os.environ.get("WAZUH_AI_LOCK", "/var/ossec/integrations/data/custom-ollama.lock")
LOCK_WAIT_WARN_AFTER = 60  # log un avertissement si l'attente du verrou dépasse ce délai (secondes)


@contextlib.contextmanager
def serialize():
    """Bloque jusqu'à obtenir le verrou exclusif -> un seul worker actif à
    la fois (appel Ollama + écriture SQLite compris). Les autres workers
    lancés en parallèle par le wrapper attendent simplement leur tour ici,
    sans jamais bloquer wazuh-integratord lui-même (qui a déjà rendu la
    main depuis longtemps côté wrapper)."""
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    fd = open(LOCK_PATH, "w")
    start = time.monotonic()
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        waited = time.monotonic() - start
        if waited > LOCK_WAIT_WARN_AFTER:
            print(f"[custom-ollama] attente du verrou : {waited:.0f}s avant traitement "
                  f"(file d'attente longue -> envisager d'augmenter le seuil <level> "
                  f"dans ossec.conf pour réduire le volume d'alertes)")
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()

PROMPT_TEMPLATE = """Tu es un analyste SOC. Voici une alerte Wazuh brute (JSON) :

{alert_json}

IMPORTANT : réponds INTÉGRALEMENT en français, même si l'alerte ci-dessus
contient des champs en anglais. Ne recopie pas les termes anglais de
l'alerte, traduis-les dans ta réponse.

Réponds STRICTEMENT dans ce format (une ligne par champ, pas de markdown),
et rappelle-toi : tout doit être écrit en français.
SCORE: <note de criticité réelle sur 10>/10
CAUSE: <cause probable en une phrase, en français>
EXPLICATION: <explication claire en 2-3 phrases pour un humain, en français>
ACTIONS: <actions recommandées, courtes, séparées par ';', en français>
"""


def load_alert(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def call_ollama(alert):
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": PROMPT_TEMPLATE.format(alert_json=json.dumps(alert, ensure_ascii=False)),
        "stream": False,
        "keep_alive": OLLAMA_KEEP_ALIVE,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL, data=data, headers={"Content-Type": "application/json"}
    )
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("response", "")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2)
    raise RuntimeError(f"Ollama call failed after {MAX_RETRIES + 1} attempts: {last_err}")


def parse_ollama_response(text):
    """Extraction tolérante par regex (le modèle ne respecte pas toujours
    le format à 100%) — ne jamais faire planter le pipeline sur un format
    inattendu."""
    def grab(field, default=""):
        m = re.search(rf"{field}\s*:\s*(.+)", text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    score_raw = grab("SCORE", "?/10")
    score_match = re.search(r"(\d{1,2})\s*/\s*10", score_raw)
    score = int(score_match.group(1)) if score_match else None

    return {
        "score": score,
        "cause": grab("CAUSE"),
        "explication": grab("EXPLICATION"),
        "actions": grab("ACTIONS"),
        "raw_response": text,
    }


def ensure_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            timestamp TEXT,
            agent_name TEXT,
            rule_id TEXT,
            rule_level INTEGER,
            rule_description TEXT,
            ai_score INTEGER,
            ai_cause TEXT,
            ai_explication TEXT,
            ai_actions TEXT,
            ai_raw_response TEXT,
            raw_alert TEXT,
            status TEXT,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_processed_at ON alerts(processed_at)")
    conn.commit()


def save_result(alert, analysis, status="ok"):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")  # permet lectures concurrentes par Flask pendant l'écriture
    try:
        ensure_schema(conn)
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        conn.execute(
            """
            INSERT INTO alerts (
                alert_id, timestamp, agent_name, rule_id, rule_level,
                rule_description, ai_score, ai_cause, ai_explication,
                ai_actions, ai_raw_response, raw_alert, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("id"),
                alert.get("timestamp"),
                agent.get("name"),
                str(rule.get("id")),
                rule.get("level"),
                rule.get("description"),
                analysis.get("score") if analysis else None,
                analysis.get("cause") if analysis else None,
                analysis.get("explication") if analysis else None,
                analysis.get("actions") if analysis else None,
                analysis.get("raw_response") if analysis else None,
                json.dumps(alert, ensure_ascii=False),
                status,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_copy_path = sys.argv[1]

    try:
        alert = load_alert(alert_copy_path)
    except Exception as e:
        print(f"[custom-ollama] impossible de lire l'alerte {alert_copy_path}: {e}")
        return
    finally:
        # Le fichier était une copie temporaire créée par le wrapper -> on nettoie.
        try:
            os.remove(alert_copy_path)
        except OSError:
            pass

    try:
        with serialize():
            response_text = call_ollama(alert)
            analysis = parse_ollama_response(response_text)
            save_result(alert, analysis, status="ok")
        print(f"[custom-ollama] alerte {alert.get('id')} traitée, score={analysis.get('score')}")
    except Exception as e:
        print(f"[custom-ollama] échec traitement alerte {alert.get('id')}: {e}")
        with serialize():
            save_result(alert, None, status="error")


if __name__ == "__main__":
    main()
