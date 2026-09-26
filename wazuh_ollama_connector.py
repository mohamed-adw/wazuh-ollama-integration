#!/usr/bin/env python3
"""
Connecteur Wazuh → Ollama/Mistral 7B
=====================================

Ce script récupère les alertes de sécurité depuis le Wazuh Indexer,
sélectionne les alertes dont le niveau de sévérité est supérieur ou
égal au seuil configuré, puis les soumet au modèle Mistral 7B exécuté
localement avec Ollama.

Les résultats de l'analyse sont enregistrés dans une base SQLite
utilisée ensuite par le dashboard Flask.

Pré-requis :
    - Fichier .env rempli (voir .env.example)
    - Ollama démarré avec le modèle configuré déjà téléchargé
      (ollama pull mistral)
    - Wazuh Indexer accessible
    - Python avec les dépendances nécessaires :
        requests
        python-dotenv

Architecture :
    Wazuh Indexer
          |
          v
    wazuh_ollama_connector.py
          |
          v
    Ollama / Mistral 7B
          |
          v
    SQLite alerts.db
          |
          v
    Flask / Dashboard
"""

import os
import sys
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Configuration générale
# ---------------------------------------------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("wazuh_ollama_connector")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    """Centralise et valide la configuration issue des variables d'environnement."""

    WAZUH_INDEXER_HOST = os.getenv(
        "WAZUH_INDEXER_HOST",
        "https://127.0.0.1:9200",
    )

    WAZUH_INDEXER_USER = os.getenv(
        "WAZUH_INDEXER_USER",
        "admin",
    )

    WAZUH_INDEXER_PASSWORD = os.getenv(
        "WAZUH_INDEXER_PASSWORD",
        "",
    )

    OLLAMA_HOST = os.getenv(
        "OLLAMA_HOST",
        "http://127.0.0.1:11434",
    )

    OLLAMA_MODEL = os.getenv(
        "OLLAMA_MODEL",
        "mistral:7b",
    )

    OLLAMA_TIMEOUT = int(
        os.getenv(
            "OLLAMA_TIMEOUT",
            "240",
        )
    )

    OLLAMA_KEEP_ALIVE = os.getenv(
        "OLLAMA_KEEP_ALIVE",
        "30m",
    )

    ALERT_LEVEL_THRESHOLD = int(
        os.getenv(
            "ALERT_LEVEL_THRESHOLD",
            "7",
        )
    )

    MAX_ALERTS_PER_RUN = int(
        os.getenv(
            "MAX_ALERTS_PER_RUN",
            "10",
        )
    )

    DB_PATH = Path(
        os.getenv(
            "WAZUH_AI_DB",
            "/var/ossec/integrations/data/alerts.db",
        )
    )

    @classmethod
    def validate(cls):
        """Vérifie les paramètres indispensables avant l'exécution."""

        if not cls.WAZUH_INDEXER_HOST:
            raise ValueError(
                "WAZUH_INDEXER_HOST n'est pas configuré."
            )

        if not cls.WAZUH_INDEXER_USER:
            raise ValueError(
                "WAZUH_INDEXER_USER n'est pas configuré."
            )

        if not cls.WAZUH_INDEXER_PASSWORD:
            raise ValueError(
                "WAZUH_INDEXER_PASSWORD n'est pas configuré."
            )

        if not cls.OLLAMA_HOST:
            raise ValueError(
                "OLLAMA_HOST n'est pas configuré."
            )

        if not cls.OLLAMA_MODEL:
            raise ValueError(
                "OLLAMA_MODEL n'est pas configuré."
            )

        if cls.ALERT_LEVEL_THRESHOLD < 0:
            raise ValueError(
                "ALERT_LEVEL_THRESHOLD doit être positif ou nul."
            )

        if cls.MAX_ALERTS_PER_RUN <= 0:
            raise ValueError(
                "MAX_ALERTS_PER_RUN doit être supérieur à zéro."
            )

        if cls.OLLAMA_TIMEOUT <= 0:
            raise ValueError(
                "OLLAMA_TIMEOUT doit être supérieur à zéro."
            )


# ---------------------------------------------------------------------------
# Base SQLite
# ---------------------------------------------------------------------------

def init_database():
    """
    Initialise la base SQLite et crée la table alerts si elle n'existe pas.
    """

    try:
        Config.DB_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        import sqlite3

        connection = sqlite3.connect(
            Config.DB_PATH,
            timeout=10,
        )

        try:
            connection.execute(
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

            connection.commit()

        finally:
            connection.close()

        logger.info(
            "Base SQLite initialisée : %s",
            Config.DB_PATH,
        )

    except Exception as exc:
        logger.error(
            "Erreur lors de l'initialisation de la base SQLite : %s",
            exc,
        )
        raise


# ---------------------------------------------------------------------------
# Wazuh Indexer
# ---------------------------------------------------------------------------

def get_today_alerts():
    """
    Récupère les alertes du jour courant depuis le Wazuh Indexer.

    Seules les alertes dont le niveau de règle est supérieur ou égal
    à ALERT_LEVEL_THRESHOLD sont sélectionnées.

    Le nombre d'alertes est limité à MAX_ALERTS_PER_RUN.
    """

    now = datetime.now(timezone.utc)

    start_of_day = now.strftime(
        "%Y-%m-%dT00:00:00.000Z"
    )

    end_of_day = now.strftime(
        "%Y-%m-%dT23:59:59.999Z"
    )

    index_pattern = "wazuh-alerts-*"

    url = (
        f"{Config.WAZUH_INDEXER_HOST}/"
        f"{index_pattern}/_search"
    )

    query = {
        "size": Config.MAX_ALERTS_PER_RUN,
        "sort": [
            {
                "timestamp": {
                    "order": "desc",
                }
            }
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_of_day,
                                "lte": end_of_day,
                            }
                        }
                    },
                    {
                        "range": {
                            "rule.level": {
                                "gte": Config.ALERT_LEVEL_THRESHOLD,
                            }
                        }
                    },
                ]
            }
        },
    }

    logger.info(
        "Interrogation du Wazuh Indexer..."
    )

    logger.info(
        "Seuil de sévérité : >= %s",
        Config.ALERT_LEVEL_THRESHOLD,
    )

    logger.info(
        "Nombre maximal d'alertes : %s",
        Config.MAX_ALERTS_PER_RUN,
    )

    try:
        response = requests.post(
            url,
            auth=(
                Config.WAZUH_INDEXER_USER,
                Config.WAZUH_INDEXER_PASSWORD,
            ),
            json=query,
            verify=False,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        hits = data.get(
            "hits",
            {},
        ).get(
            "hits",
            [],
        )

        logger.info(
            "%s alerte(s) récupérée(s).",
            len(hits),
        )

        return hits

    except requests.RequestException as exc:
        logger.error(
            "Erreur de communication avec Wazuh Indexer : %s",
            exc,
        )
        return []

    except json.JSONDecodeError as exc:
        logger.error(
            "Réponse JSON invalide du Wazuh Indexer : %s",
            exc,
        )
        return []

    except Exception as exc:
        logger.error(
            "Erreur inattendue lors de la récupération des alertes : %s",
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# Préparation des données Wazuh
# ---------------------------------------------------------------------------

def extract_alert_data(hit):
    """
    Extrait les informations utiles d'une alerte Wazuh.
    """

    source = hit.get(
        "_source",
        {},
    )

    rule = source.get(
        "rule",
        {},
    )

    agent = source.get(
        "agent",
        {},
    )

    alert_id = (
        source.get("id")
        or hit.get("_id")
        or ""
    )

    timestamp = source.get(
        "timestamp",
        "",
    )

    agent_name = agent.get(
        "name",
        "N/A",
    )

    rule_id = str(
        rule.get(
            "id",
            "",
        )
    )

    rule_level = int(
        rule.get(
            "level",
            0,
        )
        or 0
    )

    rule_description = rule.get(
        "description",
        "Aucune description disponible.",
    )

    return {
        "alert_id": str(alert_id),
        "timestamp": timestamp,
        "agent_name": agent_name,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "raw_alert": source,
    }


# ---------------------------------------------------------------------------
# Construction du prompt
# ---------------------------------------------------------------------------

def build_prompt(alert):
    """
    Construit le prompt envoyé à Mistral 7B.

    Le modèle doit produire quatre informations :
        - SCORE_DANGEROSITE
        - CAUSE_PROBABLE
        - EXPLICATION
        - ACTIONS_RECOMMANDEES
    """

    raw_alert = alert.get(
        "raw_alert",
        {},
    )

    prompt = f"""
Tu es un analyste en cybersécurité chargé d'analyser une alerte
provenant de Wazuh.

Analyse l'alerte suivante et réponds en français.

Informations principales :

Agent :
{alert["agent_name"]}

ID de la règle :
{alert["rule_id"]}

Niveau de la règle Wazuh :
{alert["rule_level"]}

Description de la règle :
{alert["rule_description"]}

Événement complet :
{json.dumps(raw_alert, ensure_ascii=False, indent=2)}

Ta réponse doit respecter exactement le format suivant :

EXPLICATION:
<explication claire et concise de l'événement>

SCORE_DANGEROSITE:
<nombre entier entre 1 et 10>

CAUSE_PROBABLE:
<cause ou causes probables>

ACTIONS_RECOMMANDEES:
<actions recommandées à l'analyste>

Le score de dangerosité est une estimation complémentaire au niveau
de sévérité fourni par Wazuh.

Ne modifie pas le niveau de règle Wazuh.
Ne donne pas de score inférieur à 1 ou supérieur à 10.
Ne mets aucun texte avant EXPLICATION.
"""

    return prompt.strip()


# ---------------------------------------------------------------------------
# Communication avec Ollama
# ---------------------------------------------------------------------------

def analyze_with_ollama(prompt):
    """
    Envoie le prompt à Ollama et récupère l'analyse de Mistral 7B.
    """

    url = (
        f"{Config.OLLAMA_HOST.rstrip('/')}"
        "/api/generate"
    )

    payload = {
        "model": Config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": Config.OLLAMA_KEEP_ALIVE,
    }

    logger.info(
        "Envoi de l'alerte à Ollama avec le modèle %s...",
        Config.OLLAMA_MODEL,
    )

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=Config.OLLAMA_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()

        result = data.get(
            "response",
            "",
        )

        if not result:
            logger.warning(
                "Ollama a retourné une réponse vide."
            )
            return None

        return result.strip()

    except requests.Timeout:
        logger.error(
            "Délai d'attente dépassé lors de la communication avec Ollama."
        )
        return None

    except requests.RequestException as exc:
        logger.error(
            "Erreur de communication avec Ollama : %s",
            exc,
        )
        return None

    except json.JSONDecodeError as exc:
        logger.error(
            "Réponse JSON invalide d'Ollama : %s",
            exc,
        )
        return None

    except Exception as exc:
        logger.error(
            "Erreur inattendue lors de l'analyse Ollama : %s",
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Analyse de la réponse du modèle
# ---------------------------------------------------------------------------

def parse_ai_response(response):
    """
    Analyse la réponse textuelle de Mistral 7B.

    Retourne :
        score
        cause
        explication
        actions
    """

    if not response:
        return None

    score = None
    cause = ""
    explication = ""
    actions = ""

    lines = response.splitlines()

    current_section = None

    explanation_lines = []
    cause_lines = []
    actions_lines = []

    for line in lines:
        stripped = line.strip()

        if not stripped:
            continue

        upper = stripped.upper()

        if upper.startswith("EXPLICATION:"):
            current_section = "explication"

            value = stripped.split(
                ":",
                1,
            )[1].strip()

            if value:
                explanation_lines.append(value)

            continue

        if upper.startswith("SCORE_DANGEROSITE:"):
            current_section = "score"

            value = stripped.split(
                ":",
                1,
            )[1].strip()

            try:
                digits = "".join(
                    character
                    for character in value
                    if character.isdigit()
                )

                if digits:
                    score = int(digits)

            except ValueError:
                score = None

            continue

        if upper.startswith("CAUSE_PROBABLE:"):
            current_section = "cause"

            value = stripped.split(
                ":",
                1,
            )[1].strip()

            if value:
                cause_lines.append(value)

            continue

        if upper.startswith("ACTIONS_RECOMMANDEES:"):
            current_section = "actions"

            value = stripped.split(
                ":",
                1,
            )[1].strip()

            if value:
                actions_lines.append(value)

            continue

        if current_section == "explication":
            explanation_lines.append(stripped)

        elif current_section == "cause":
            cause_lines.append(stripped)

        elif current_section == "actions":
            actions_lines.append(stripped)

    explication = "\n".join(
        explanation_lines
    ).strip()

    cause = "\n".join(
        cause_lines
    ).strip()

    actions = "\n".join(
        actions_lines
    ).strip()

    if score is not None:
        score = max(
            1,
            min(
                score,
                10,
            ),
        )

    return {
        "ai_score": score,
        "ai_cause": cause,
        "ai_explication": explication,
        "ai_actions": actions,
    }


# ---------------------------------------------------------------------------
# Enregistrement SQLite
# ---------------------------------------------------------------------------

def save_analysis(alert, analysis):
    """
    Enregistre l'alerte et son analyse dans la base SQLite.
    """

    import sqlite3

    processed_at = datetime.now(
        timezone.utc
    ).isoformat()

    connection = sqlite3.connect(
        Config.DB_PATH,
        timeout=10,
    )

    try:
        connection.execute(
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
                analysis.get("ai_score"),
                analysis.get("ai_cause", ""),
                analysis.get("ai_explication", ""),
                analysis.get("ai_actions", ""),
                "analyzed",
                processed_at,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    logger.info(
        "Analyse enregistrée pour l'alerte %s.",
        alert["alert_id"],
    )


# ---------------------------------------------------------------------------
# Traitement d'une alerte
# ---------------------------------------------------------------------------

def process_alert(hit):
    """
    Traite une alerte Wazuh de bout en bout.
    """

    alert = extract_alert_data(
        hit
    )

    logger.info(
        "Traitement de l'alerte %s | règle=%s | niveau=%s | agent=%s",
        alert["alert_id"],
        alert["rule_id"],
        alert["rule_level"],
        alert["agent_name"],
    )

    if (
        alert["rule_level"]
        < Config.ALERT_LEVEL_THRESHOLD
    ):
        logger.info(
            "Alerte ignorée : niveau %s inférieur au seuil %s.",
            alert["rule_level"],
            Config.ALERT_LEVEL_THRESHOLD,
        )
        return False

    prompt = build_prompt(
        alert
    )

    ai_response = analyze_with_ollama(
        prompt
    )

    if not ai_response:
        logger.warning(
            "Analyse IA non réalisée pour l'alerte %s.",
            alert["alert_id"],
        )
        return False

    analysis = parse_ai_response(
        ai_response
    )

    if not analysis:
        logger.warning(
            "Impossible d'analyser la réponse IA pour l'alerte %s.",
            alert["alert_id"],
        )
        return False

    if analysis.get("ai_score") is None:
        logger.warning(
            "Score de dangerosité absent pour l'alerte %s.",
            alert["alert_id"],
        )

    save_analysis(
        alert,
        analysis,
    )

    return True


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

def main():
    """
    Point d'entrée principal du connecteur.
    """

    logger.info(
        "============================================================"
    )

    logger.info(
        "Démarrage du connecteur Wazuh → Ollama"
    )

    logger.info(
        "============================================================"
    )

    try:
        Config.validate()

    except ValueError as exc:
        logger.error(
            "Configuration invalide : %s",
            exc,
        )
        return 1

    logger.info(
        "Wazuh Indexer : %s",
        Config.WAZUH_INDEXER_HOST,
    )

    logger.info(
        "Ollama : %s",
        Config.OLLAMA_HOST,
    )

    logger.info(
        "Modèle : %s",
        Config.OLLAMA_MODEL,
    )

    logger.info(
        "Seuil d'alerte : >= %s",
        Config.ALERT_LEVEL_THRESHOLD,
    )

    logger.info(
        "Maximum d'alertes par exécution : %s",
        Config.MAX_ALERTS_PER_RUN,
    )

    logger.info(
        "Base SQLite : %s",
        Config.DB_PATH,
    )

    try:
        init_database()

    except Exception as exc:
        logger.error(
            "Impossible d'initialiser la base SQLite : %s",
            exc,
        )
        return 1

    alerts = get_today_alerts()

    if not alerts:
        logger.info(
            "Aucune alerte à traiter."
        )
        return 0

    processed = 0
    failed = 0

    for hit in alerts:

        try:
            success = process_alert(
                hit
            )

            if success:
                processed += 1
            else:
                failed += 1

        except Exception as exc:
            failed += 1

            logger.exception(
                "Erreur lors du traitement d'une alerte : %s",
                exc,
            )

    logger.info(
        "============================================================"
    )

    logger.info(
        "Traitement terminé : %s réussie(s), %s échec(s).",
        processed,
        failed,
    )

    logger.info(
        "============================================================"
    )

    return 0


# ---------------------------------------------------------------------------
# Exécution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(
        main()
    )
