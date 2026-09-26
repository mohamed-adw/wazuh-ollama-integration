#!/usr/bin/env python3
"""
Wazuh -> Ollama/Mistral 7B connector

Fonctionnement :
    1. Interroge le Wazuh Indexer
    2. Sélectionne les alertes du jour dont rule.level >= 7
    3. Limite le traitement à MAX_ALERTS_PER_RUN alertes
    4. Envoie chaque alerte à Ollama/Mistral 7B
    5. Extrait :
         - score de dangerosité
         - cause probable
         - explication
         - actions recommandées
    6. Enregistre le résultat dans SQLite
    7. Le dashboard Flask lit ensuite cette base SQLite

Le traitement est séquentiel afin de limiter la charge CPU
sur le serveur de démonstration.
"""

import os
import re
import json
import sqlite3
import logging
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
import urllib3


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

load_dotenv(
    os.path.join(BASE_DIR, ".env")
)


# Wazuh Indexer
WAZUH_INDEXER_HOST = os.getenv(
    "WAZUH_INDEXER_HOST",
    "https://localhost:9200"
)

WAZUH_INDEXER_USER = os.getenv(
    "WAZUH_INDEXER_USER",
    "admin"
)

WAZUH_INDEXER_PASSWORD = os.getenv(
    "WAZUH_INDEXER_PASSWORD",
    ""
)


# Ollama
OLLAMA_HOST = os.getenv(
    "OLLAMA_HOST",
    "http://127.0.0.1:11434"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "mistral"
)

OLLAMA_TIMEOUT = int(
    os.getenv(
        "OLLAMA_TIMEOUT",
        "240"
    )
)

OLLAMA_KEEP_ALIVE = os.getenv(
    "OLLAMA_KEEP_ALIVE",
    "30m"
)


# Filtrage des alertes
ALERT_LEVEL_THRESHOLD = int(
    os.getenv(
        "ALERT_LEVEL_THRESHOLD",
        "7"
    )
)

MAX_ALERTS_PER_RUN = int(
    os.getenv(
        "MAX_ALERTS_PER_RUN",
        "10"
    )
)


# SQLite
#
# IMPORTANT :
# Le dashboard Flask utilise cette même variable :
#
# WAZUH_AI_DB=/var/ossec/integrations/data/alerts.db
#
DB_PATH = os.getenv(
    "WAZUH_AI_DB",
    "/var/ossec/integrations/data/alerts.db"
)


# Désactivation des avertissements SSL
# car Wazuh Indexer peut utiliser un certificat interne.
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s "
        "[%(levelname)s] "
        "%(message)s"
    ),
)

logger = logging.getLogger(
    "wazuh-ollama-connector"
)


# ============================================================
# INITIALISATION SQLITE
# ============================================================

def init_database():
    """
    Initialise la base SQLite si elle n'existe pas.

    Le schéma est volontairement aligné sur app.py et
    dashboard.html.
    """

    db_directory = os.path.dirname(
        DB_PATH
    )

    if db_directory:
        os.makedirs(
            db_directory,
            exist_ok=True
        )

    conn = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    try:

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

                status TEXT,

                processed_at TEXT
            )
            """
        )

        conn.commit()

    finally:

        conn.close()


# ============================================================
# REQUÊTE WAZUH INDEXER
# ============================================================

def build_wazuh_query():
    """
    Construit la requête envoyée au Wazuh Indexer.

    Seules les alertes :
        - du jour courant
        - avec rule.level >= 7

    sont sélectionnées.

    Le nombre d'alertes est limité à MAX_ALERTS_PER_RUN.
    """

    return {
        "size": MAX_ALERTS_PER_RUN,

        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],

        "query": {
            "bool": {
                "filter": [

                    {
                        "range": {
                            "timestamp": {
                                "gte": "now/d",
                                "lt": "now+1d/d"
                            }
                        }
                    },

                    {
                        "range": {
                            "rule.level": {
                                "gte": ALERT_LEVEL_THRESHOLD
                            }
                        }
                    }

                ]
            }
        }
    }


# ============================================================
# RÉCUPÉRATION DES ALERTES WAZUH
# ============================================================

def fetch_wazuh_alerts():
    """
    Interroge l'API REST du Wazuh Indexer.
    """

    url = (
        WAZUH_INDEXER_HOST.rstrip("/")
        + "/wazuh-alerts-*/_search"
    )

    query = build_wazuh_query()

    logger.info(
        "Interrogation du Wazuh Indexer..."
    )

    logger.info(
        "Seuil : rule.level >= %s",
        ALERT_LEVEL_THRESHOLD
    )

    logger.info(
        "Maximum : %s alertes",
        MAX_ALERTS_PER_RUN
    )

    try:

        response = requests.post(
            url,

            auth=(
                WAZUH_INDEXER_USER,
                WAZUH_INDEXER_PASSWORD
            ),

            json=query,

            verify=False,

            timeout=30,

            headers={
                "Content-Type":
                    "application/json"
            }
        )

        response.raise_for_status()

        data = response.json()

        hits = (
            data
            .get("hits", {})
            .get("hits", [])
        )

        logger.info(
            "%d alerte(s) récupérée(s).",
            len(hits)
        )

        return hits

    except requests.exceptions.Timeout:

        logger.error(
            "Timeout lors de la connexion au Wazuh Indexer."
        )

    except requests.exceptions.ConnectionError:

        logger.error(
            "Impossible de joindre le Wazuh Indexer."
        )

    except requests.exceptions.HTTPError as error:

        logger.error(
            "Erreur HTTP Wazuh Indexer : %s",
            error
        )

    except requests.exceptions.RequestException as error:

        logger.error(
            "Erreur Wazuh Indexer : %s",
            error
        )

    except json.JSONDecodeError:

        logger.error(
            "Réponse Wazuh Indexer invalide."
        )

    except Exception as error:

        logger.exception(
            "Erreur inattendue : %s",
            error
        )

    return []


# ============================================================
# EXTRACTION DES INFORMATIONS D'UNE ALERTE
# ============================================================

def extract_alert(alert):
    """
    Transforme une alerte brute Wazuh en dictionnaire
    simplifié destiné au modèle.
    """

    source = alert.get(
        "_source",
        {}
    )

    rule = source.get(
        "rule",
        {}
    )

    agent = source.get(
        "agent",
        {}
    )

    alert_id = (
        source.get("id")
        or alert.get("_id")
        or ""
    )

    timestamp = source.get(
        "timestamp",
        ""
    )

    agent_name = (
        agent.get("name")
        or agent.get("id")
        or "Inconnu"
    )

    rule_id = rule.get(
        "id",
        ""
    )

    rule_level = rule.get(
        "level",
        0
    )

    rule_description = rule.get(
        "description",
        ""
    )

    # Plusieurs sources possibles pour le contenu
    # de l'événement.
    full_log = source.get(
        "full_log"
    )

    message = source.get(
        "message"
    )

    data = source.get(
        "data",
        {}
    )

    data_message = ""

    if isinstance(data, dict):

        data_message = data.get(
            "message",
            ""
        )

    description = (
        full_log
        or message
        or data_message
        or rule_description
        or ""
    )

    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "agent_name": agent_name,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "description": description
    }


# ============================================================
# CONSTRUCTION DU PROMPT
# ============================================================

def build_prompt(alert):
    """
    Construit le prompt destiné à Mistral 7B.
    """

    return f"""
Tu es un analyste spécialisé en cybersécurité.

Analyse l'alerte Wazuh suivante et réponds en français.

INFORMATIONS DE L'ALERTE
------------------------

Identifiant :
{alert["alert_id"]}

Horodatage :
{alert["timestamp"]}

Agent :
{alert["agent_name"]}

Identifiant de la règle :
{alert["rule_id"]}

Niveau Wazuh :
{alert["rule_level"]}

Description de la règle :
{alert["rule_description"]}

Événement :
{alert["description"]}


OBJECTIF
--------

Analyse cet événement et fournis :

1. Une explication claire de l'alerte.

2. Un score de dangerosité compris entre 1 et 10.
   Le score représente une estimation du risque associé
   à l'événement.
   Il est complémentaire au niveau rule.level fourni
   par Wazuh.

3. La cause probable de l'événement.

4. Les actions recommandées à l'analyste.


FORMAT OBLIGATOIRE
------------------

EXPLICATION:
<texte>

SCORE_DANGEROSITE:
<nombre entre 1 et 10>

CAUSE_PROBABLE:
<texte>

ACTIONS_RECOMMANDEES:
<texte>

Réponds uniquement avec ces quatre sections.
""".strip()


# ============================================================
# APPEL OLLAMA
# ============================================================

def call_ollama(prompt):
    """
    Envoie le prompt à Ollama.
    """

    url = (
        OLLAMA_HOST.rstrip("/")
        + "/api/generate"
    )

    payload = {
        "model": OLLAMA_MODEL,

        "prompt": prompt,

        "stream": False,

        "keep_alive": OLLAMA_KEEP_ALIVE
    }

    logger.info(
        "Envoi vers Ollama (%s)...",
        OLLAMA_MODEL
    )

    try:

        response = requests.post(
            url,

            json=payload,

            timeout=OLLAMA_TIMEOUT,

            headers={
                "Content-Type":
                    "application/json"
            }
        )

        response.raise_for_status()

        data = response.json()

        text = data.get(
            "response",
            ""
        )

        if not text.strip():

            logger.warning(
                "Ollama a retourné une réponse vide."
            )

            return None

        return text.strip()

    except requests.exceptions.Timeout:

        logger.error(
            "Timeout Ollama après %d secondes.",
            OLLAMA_TIMEOUT
        )

    except requests.exceptions.ConnectionError:

        logger.error(
            "Impossible de contacter Ollama."
        )

    except requests.exceptions.HTTPError as error:

        logger.error(
            "Erreur HTTP Ollama : %s",
            error
        )

    except requests.exceptions.RequestException as error:

        logger.error(
            "Erreur Ollama : %s",
            error
        )

    except Exception as error:

        logger.exception(
            "Erreur inattendue Ollama : %s",
            error
        )

    return None


# ============================================================
# EXTRACTION DU SCORE
# ============================================================

def extract_score(text):
    """
    Extrait un score compris entre 1 et 10.
    """

    if not text:
        return None

    patterns = [

        r"SCORE_DANGEROSITE\s*:\s*(10|[1-9])",

        r"score de dangerosité\s*[:\-]?\s*(10|[1-9])",

        r"\b(10|[1-9])\s*/\s*10\b",

        r"\b(10|[1-9])\s+sur\s+10\b"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:

            try:

                score = int(
                    match.group(1)
                )

                if 1 <= score <= 10:

                    return score

            except ValueError:

                pass

    return None


# ============================================================
# EXTRACTION D'UNE SECTION DU TEXTE
# ============================================================

def extract_section(
    text,
    start_marker,
    end_markers
):
    """
    Extrait une section du résultat de Mistral.
    """

    if not text:
        return ""

    upper_text = text.upper()

    start = upper_text.find(
        start_marker.upper()
    )

    if start == -1:
        return ""

    start += len(
        start_marker
    )

    end = len(text)

    for marker in end_markers:

        position = upper_text.find(
            marker.upper(),
            start
        )

        if (
            position != -1
            and position < end
        ):

            end = position

    return text[
        start:end
    ].strip()


# ============================================================
# PARSING DE LA RÉPONSE DE MISTRAL
# ============================================================

def parse_response(response):
    """
    Transforme la réponse de Mistral en données
    compatibles avec le dashboard.
    """

    if not response:

        return {
            "ai_score": None,
            "ai_cause": "",
            "ai_explication": "",
            "ai_actions": ""
        }

    explanation = extract_section(
        response,

        "EXPLICATION:",

        [
            "SCORE_DANGEROSITE:",
            "CAUSE_PROBABLE:",
            "ACTIONS_RECOMMANDEES:"
        ]
    )

    cause = extract_section(
        response,

        "CAUSE_PROBABLE:",

        [
            "ACTIONS_RECOMMANDEES:"
        ]
    )

    actions = extract_section(
        response,

        "ACTIONS_RECOMMANDEES:",

        []
    )

    score = extract_score(
        response
    )

    return {
        "ai_score": score,
        "ai_cause": cause,
        "ai_explication": explanation,
        "ai_actions": actions
    }


# ============================================================
# ENREGISTREMENT SQLITE
# ============================================================

def save_result(alert, analysis):
    """
    Enregistre le résultat dans alerts.db.

    Les noms de colonnes correspondent exactement à ceux
    utilisés par app.py :
        ai_score
        ai_cause
        ai_explication
        ai_actions
        status
    """

    processed_at = datetime.now(
        timezone.utc
    ).isoformat()

    conn = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    try:

        conn.execute(
            """
            INSERT INTO alerts (
                alert_id,
                timestamp,
                agent_name,
                rule_id,
                rule_level,
                rule_description,
                ai_score,
                ai_cause,
                ai_explication,
                ai_actions,
                status,
                processed_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                alert["alert_id"],

                alert["timestamp"],

                alert["agent_name"],

                alert["rule_id"],

                alert["rule_level"],

                alert["rule_description"],

                analysis["ai_score"],

                analysis["ai_cause"],

                analysis["ai_explication"],

                analysis["ai_actions"],

                "analyzed",

                processed_at
            )
        )

        conn.commit()

    finally:

        conn.close()


# ============================================================
# TRAITEMENT D'UNE ALERTE
# ============================================================

def process_alert(raw_alert):
    """
    Analyse une alerte complète.
    """

    alert = extract_alert(
        raw_alert
    )

    logger.info(
        "--------------------------------------------"
    )

    logger.info(
        "Alerte : %s",
        alert["alert_id"]
    )

    logger.info(
        "Règle : %s",
        alert["rule_id"]
    )

    logger.info(
        "Niveau : %s",
        alert["rule_level"]
    )

    logger.info(
        "Agent : %s",
        alert["agent_name"]
    )

    prompt = build_prompt(
        alert
    )

    response = call_ollama(
        prompt
    )

    # En cas d'échec d'Ollama :
    # aucune donnée IA n'est enregistrée.
    if not response:

        logger.warning(
            "Analyse IA impossible pour %s.",
            alert["alert_id"]
        )

        return False

    analysis = parse_response(
        response
    )

    # Vérification du résultat
    if analysis["ai_score"] is None:

        logger.warning(
            "Score de dangerosité absent pour %s.",
            alert["alert_id"]
        )

        return False

    if not (
        1 <= analysis["ai_score"] <= 10
    ):

        logger.warning(
            "Score invalide : %s",
            analysis["ai_score"]
        )

        return False

    try:

        save_result(
            alert,
            analysis
        )

        logger.info(
            "Résultat enregistré dans SQLite."
        )

        logger.info(
            "Score de dangerosité : %s/10",
            analysis["ai_score"]
        )

        return True

    except sqlite3.Error as error:

        logger.error(
            "Erreur SQLite : %s",
            error
        )

        return False


# ============================================================
# MAIN
# ============================================================

def main():

    logger.info(
        "============================================"
    )

    logger.info(
        "Wazuh - Ollama/Mistral 7B Connector"
    )

    logger.info(
        "============================================"
    )

    logger.info(
        "Wazuh Indexer : %s",
        WAZUH_INDEXER_HOST
    )

    logger.info(
        "Modèle Ollama : %s",
        OLLAMA_MODEL
    )

    logger.info(
        "Seuil : rule.level >= %d",
        ALERT_LEVEL_THRESHOLD
    )

    logger.info(
        "Maximum par exécution : %d",
        MAX_ALERTS_PER_RUN
    )

    logger.info(
        "Base SQLite : %s",
        DB_PATH
    )

    # Création de la base si nécessaire
    init_database()

    # Récupération des alertes
    alerts = fetch_wazuh_alerts()

    if not alerts:

        logger.info(
            "Aucune alerte à traiter."
        )

        return

    success = 0

    # Traitement volontairement séquentiel
    for index, alert in enumerate(
        alerts,
        start=1
    ):

        logger.info(
            "Traitement %d/%d",
            index,
            len(alerts)
        )

        try:

            if process_alert(alert):

                success += 1

        except Exception as error:

            logger.exception(
                "Erreur pendant le traitement "
                "de l'alerte %d : %s",
                index,
                error
            )

    logger.info(
        "============================================"
    )

    logger.info(
        "Traitement terminé."
    )

    logger.info(
        "Alertes récupérées : %d",
        len(alerts)
    )

    logger.info(
        "Alertes analysées : %d",
        success
    )

    logger.info(
        "============================================"
    )


# ============================================================
# POINT D'ENTRÉE
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        logger.info(
            "Arrêt demandé."
        )

    except Exception as error:

        logger.exception(
            "Erreur fatale : %s",
            error
        )
