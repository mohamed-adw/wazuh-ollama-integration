#!/usr/bin/env python3
"""
Mini serveur Flask (dashboard temps réel) — lit la base SQLite alimentée
par le worker `custom-ollama.py` et sert :
  - GET /            -> page HTML (dashboard.html)
  - GET /api/alerts  -> JSON des N dernières alertes (utilisé par le JS
                         d'auto-refresh, pas besoin de recharger la page)


"""

import os
import sqlite3

from flask import Flask, jsonify, render_template

DB_PATH = os.environ.get("WAZUH_AI_DB", "/var/ossec/integrations/data/alerts.db")
DEFAULT_LIMIT = 50

app = Flask(__name__)


def get_alerts(limit=DEFAULT_LIMIT):
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, alert_id, timestamp, agent_name, rule_id, rule_level,
                   rule_description, ai_score, ai_cause, ai_explication,
                   ai_actions, status, processed_at
            FROM alerts
            ORDER BY processed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_alerts())


if __name__ == "__main__":
    # host=0.0.0.0 pour rester accessible depuis le réseau interne comme
    # l'ancien serveur reports (port pensé pour être ouvert uniquement au
    # réseau interne via ufw, cf. règles déjà en place)
    app.run(host="0.0.0.0", port=8080)
