# Connecteur Wazuh ↔ Ollama

Script Python qui relie **Wazuh (SIEM)** à un **LLM local (Ollama/Mistral 7B)** afin de générer une analyse en langage naturel des alertes de sécurité.

Le projet permet de compléter les alertes Wazuh avec :

- une explication de l'événement ;
- un score de dangerosité ;
- une cause probable ;
- des actions recommandées.

Le modèle **Mistral 7B** est exécuté localement avec **Ollama**. Les données utilisées pour l'analyse restent ainsi dans l'infrastructure étudiée.

---

## Fonctionnement

Le connecteur fonctionne selon les étapes suivantes :

1. Interroge le **Wazuh Indexer** (OpenSearch, port 9200) pour récupérer les alertes du jour correspondant au seuil configuré. Par défaut, seules les alertes dont le niveau est **supérieur ou égal à 7** sont sélectionnées.
2. Pour chaque alerte sélectionnée, construit un prompt structuré et l'envoie à **Ollama** (modèle Mistral 7B, en local, port 11434).
3. Récupère l'analyse produite par le modèle :
   - explication ;
   - score de dangerosité ;
   - cause probable ;
   - actions recommandées.
4. Enregistre les résultats dans une base **SQLite** utilisée par le dashboard Flask.
5. Le dashboard récupère les résultats depuis SQLite et les affiche automatiquement.

Le traitement est effectué localement et ne nécessite aucune API d'inférence distante.

---

## Architecture

```text
                         Wazuh
                           │
                           ▼
                    Wazuh Indexer
                    (OpenSearch)
                           │
                           ▼
             wazuh_ollama_connector.py
                           │
                           ▼
                    Ollama API
                localhost:11434
                           │
                           ▼
                      Mistral 7B
                           │
                           ▼
                    Analyse IA
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
          SQLite                    Rapport JSON
        alerts.db                  si configuré
              │
              ▼
           app.py
        Flask Dashboard
              │
              ▼
       dashboard.html
              │
              ▼
     Auto-refresh JavaScript
             5 s
```

Le modèle Ollama est exécuté localement sur le serveur :

```text
http://localhost:11434
```

Aucun appel à une API d'inférence distante n'est nécessaire.

---

# Structure du projet

```text
wazuh-ollama-integration/
│
├── app.py
├── custom-ollama
├── custom-ollama.py
├── wazuh_ollama_connector.py
├── dashboard.html
├── requirements.txt
├── wazuh-ai-dashboard.service
├── .env.example
└── README.md
```

---

## Rôle des principaux fichiers

| Fichier | Rôle |
|---|---|
| `custom-ollama` | Wrapper d'intégration utilisé par Wazuh |
| `custom-ollama.py` | Élément d'intégration permettant le déclenchement du traitement depuis Wazuh |
| `wazuh_ollama_connector.py` | Connecteur principal chargé de récupérer les alertes Wazuh, de sélectionner les alertes selon le seuil configuré, de construire le prompt, de communiquer avec Ollama/Mistral 7B et d'enregistrer les résultats |
| `app.py` | Application web Flask utilisée pour servir le dashboard |
| `dashboard.html` | Interface web d'affichage des alertes enrichies |
| `requirements.txt` | Dépendances Python du projet |
| `wazuh-ai-dashboard.service` | Service systemd permettant d'exécuter automatiquement le dashboard |
| `.env.example` | Exemple de configuration des variables d'environnement |
| `README.md` | Documentation du projet |

---

# 1. Prérequis

Le projet nécessite :

- Wazuh ;
- Wazuh Indexer / OpenSearch ;
- Python 3 ;
- Ollama ;
- Mistral 7B ;
- SQLite ;
- Flask ;
- les dépendances Python présentes dans `requirements.txt`.

Dans l'environnement de démonstration, Mistral 7B est exécuté sur **CPU**.

---

# 2. Installation

## 2.1 Installation des dépendances Python

Installer les dépendances :

```bash
pip3 install -r requirements.txt --break-system-packages
```

Les principales bibliothèques utilisées sont notamment :

```text
requests
python-dotenv
Flask
```

---

## 2.2 Configuration de l'environnement

Copier le fichier d'exemple :

```bash
cp .env.example .env
```

Modifier ensuite le fichier :

```bash
nano .env
```

Exemple :

```env
# --- Wazuh Indexer (OpenSearch) ---
WAZUH_INDEXER_HOST=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=CHANGE_ME

# --- Ollama (LLM local) ---
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mistral:7b

# --- Filtre des alertes ---
# Niveau de sévérité minimum à analyser par l'IA (Wazuh : 0-15)
ALERT_LEVEL_THRESHOLD=7

# --- Nombre max d'alertes à traiter par exécution ---
MAX_ALERTS_PER_RUN=10

# --- Paramètres Ollama ---
OLLAMA_TIMEOUT=240
OLLAMA_KEEP_ALIVE=30m

# --- Base de données SQLite ---
WAZUH_AI_DB=/var/ossec/integrations/data/alerts.db
```

---

# 3. Configuration des variables

| Variable | Valeur par défaut | Description |
|---|---:|---|
| `WAZUH_INDEXER_HOST` | `https://localhost:9200` | Adresse du Wazuh Indexer |
| `WAZUH_INDEXER_USER` | `admin` | Utilisateur du Wazuh Indexer |
| `WAZUH_INDEXER_PASSWORD` | `CHANGE_ME` | Mot de passe du Wazuh Indexer |
| `OLLAMA_HOST` | `http://localhost:11434` | Adresse de l'API Ollama |
| `OLLAMA_MODEL` | `mistral:7b` | Modèle de langage utilisé |
| `ALERT_LEVEL_THRESHOLD` | `7` | Niveau minimal des alertes à analyser |
| `MAX_ALERTS_PER_RUN` | `10` | Nombre maximal d'alertes traitées par exécution |
| `OLLAMA_TIMEOUT` | `240` | Délai d'attente maximal en secondes |
| `OLLAMA_KEEP_ALIVE` | `30m` | Durée pendant laquelle le modèle reste chargé |
| `WAZUH_AI_DB` | `/var/ossec/integrations/data/alerts.db` | Emplacement de la base SQLite |

Le seuil utilisé par le connecteur est :

```text
rule.level >= ALERT_LEVEL_THRESHOLD
```

Avec la configuration par défaut :

```text
rule.level >= 7
```

Le nombre d'alertes est limité par :

```text
MAX_ALERTS_PER_RUN=10
```

Cette limitation permet de maîtriser la charge du serveur lorsque l'inférence est réalisée sur CPU.

---

# 4. Installation d'Ollama et de Mistral 7B

Installer Ollama :

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Vérifier son fonctionnement :

```bash
systemctl status ollama
```

Télécharger Mistral 7B :

```bash
ollama pull mistral:7b
```

Tester le modèle :

```bash
ollama run mistral:7b
```

Vérifier l'API locale :

```bash
curl http://localhost:11434/api/tags
```

Le connecteur utilise ensuite cette API pour transmettre les alertes au modèle.

---

# 5. Installation du connecteur

Le fichier principal du traitement est :

```text
wazuh_ollama_connector.py
```

Copier le connecteur dans le répertoire approprié :

```bash
sudo cp wazuh_ollama_connector.py /var/ossec/integrations/
```

Appliquer les permissions :

```bash
sudo chown root:wazuh /var/ossec/integrations/wazuh_ollama_connector.py
sudo chmod 750 /var/ossec/integrations/wazuh_ollama_connector.py
```

Le connecteur peut ensuite être exécuté directement :

```bash
python3 wazuh_ollama_connector.py
```

---

# 6. Fonctionnement de `wazuh_ollama_connector.py`

Le connecteur assure le traitement complet des alertes.

## Étape 1 — Interrogation du Wazuh Indexer

Le connecteur interroge l'API REST du Wazuh Indexer afin de récupérer les alertes du jour.

Les alertes sont filtrées selon :

```text
rule.level >= ALERT_LEVEL_THRESHOLD
```

La valeur utilisée par défaut est :

```text
ALERT_LEVEL_THRESHOLD>=7
```

Le nombre d'alertes récupérées est limité par :

```text
MAX_ALERTS_PER_RUN=10
```

---

## Étape 2 — Préparation de l'alerte

Pour chaque événement sélectionné, le connecteur récupère notamment :

- l'identifiant de l'alerte ;
- la date de l'événement ;
- le nom de l'agent ;
- l'identifiant de la règle ;
- le niveau de la règle ;
- la description de la règle ;
- les informations de l'événement.

Ces informations sont ensuite intégrées dans un prompt destiné au modèle.

---

## Étape 3 — Analyse avec Ollama

Le prompt est transmis à l'API locale :

```text
http://localhost:11434/api/generate
```

Le modèle utilisé par défaut est :

```text
mistral:7b
```

Le modèle produit notamment :

```text
EXPLICATION:
...

SCORE_DANGEROSITE:
...

CAUSE_PROBABLE:
...

ACTIONS_RECOMMANDEES:
...
```

---

## Étape 4 — Enregistrement des résultats

Les résultats sont enregistrés dans la base :

```text
/var/ossec/integrations/data/alerts.db
```

Les informations enregistrées comprennent notamment :

- `ai_score` ;
- `ai_cause` ;
- `ai_explication` ;
- `ai_actions`.

Ces données sont ensuite utilisées par le dashboard Flask.

---

# 7. Base SQLite

Créer le répertoire :

```bash
sudo mkdir -p /var/ossec/integrations/data
```

Appliquer les permissions :

```bash
sudo chown wazuh:wazuh /var/ossec/integrations/data
sudo chmod 770 /var/ossec/integrations/data
```

La base utilisée est :

```text
/var/ossec/integrations/data/alerts.db
```

Le connecteur crée la table `alerts` si elle n'existe pas.

## Structure principale

| Colonne | Description |
|---|---|
| `id` | Identifiant interne |
| `alert_id` | Identifiant de l'alerte Wazuh |
| `timestamp` | Date de l'événement |
| `agent_name` | Nom de l'agent |
| `rule_id` | Identifiant de la règle |
| `rule_level` | Niveau de sévérité Wazuh |
| `rule_description` | Description de la règle |
| `ai_score` | Score de dangerosité généré par Mistral 7B |
| `ai_cause` | Cause probable |
| `ai_explication` | Explication générée par le modèle |
| `ai_actions` | Actions recommandées |
| `status` | État du traitement |
| `processed_at` | Date du traitement |

---

# 8. Vérification de la base

Après une analyse, il est possible de vérifier les résultats :

```bash
sqlite3 /var/ossec/integrations/data/alerts.db \
    "SELECT id, rule_level, ai_score, ai_cause FROM alerts ORDER BY id DESC LIMIT 5;"
```

---

# 9. Intégration Wazuh

Les fichiers d'intégration Wazuh sont :

```text
custom-ollama
custom-ollama.py
```

Copier les fichiers :

```bash
sudo cp custom-ollama /var/ossec/integrations/
sudo cp custom-ollama.py /var/ossec/integrations/
```

Appliquer les permissions :

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-ollama*
sudo chmod 750 /var/ossec/integrations/custom-ollama*
```

La configuration de l'intégration est réalisée dans :

```text
/var/ossec/etc/ossec.conf
```

Exemple :

```xml
<integration>
    <name>custom-ollama</name>
    ...
</integration>
```

Après modification :

```bash
sudo systemctl restart wazuh-manager
```

---

# 10. Dashboard Flask

Le dashboard est développé avec **Flask**.

Il utilise :

```text
app.py
```

pour fournir l'application web et :

```text
dashboard.html
```

pour afficher l'interface.

Le dashboard lit les données enregistrées dans SQLite.

---

## 10.1 Lancement manuel

Lancer :

```bash
python3 app.py
```

Le dashboard écoute sur le port :

```text
8080
```

Il peut être consulté avec :

```text
http://localhost:8080
```

ou :

```text
http://ADRESSE_IP_DU_SERVEUR:8080
```

---

## 10.2 API du dashboard

Le dashboard expose :

```text
GET /
```

pour l'interface principale.

Il expose également :

```text
GET /api/alerts
```

pour récupérer les alertes au format JSON.

L'interface JavaScript actualise automatiquement les données toutes les :

```text
5 secondes
```

---

# 11. Déploiement du dashboard avec systemd

Copier le service :

```bash
sudo cp wazuh-ai-dashboard.service /etc/systemd/system/
```

Recharger systemd :

```bash
sudo systemctl daemon-reload
```

Activer et démarrer :

```bash
sudo systemctl enable --now wazuh-ai-dashboard
```

Vérifier :

```bash
sudo systemctl status wazuh-ai-dashboard
```

---

# 12. Test manuel

Avant de dépendre du déclenchement automatique, il est possible de tester directement le connecteur :

```bash
python3 wazuh_ollama_connector.py
```

Vérifier ensuite les logs affichés dans le terminal.

Vérifier également la base :

```bash
sqlite3 /var/ossec/integrations/data/alerts.db \
    "SELECT id, alert_id, rule_level, ai_score, status FROM alerts ORDER BY id DESC LIMIT 5;"
```

Puis lancer le dashboard :

```bash
python3 app.py
```

---

# 13. Gestion des erreurs

Le connecteur gère notamment :

- l'indisponibilité du Wazuh Indexer ;
- une réponse invalide du Wazuh Indexer ;
- l'indisponibilité d'Ollama ;
- le dépassement du délai d'attente ;
- une réponse vide du modèle ;
- une réponse JSON invalide ;
- l'absence du score de dangerosité.

En cas d'indisponibilité d'Ollama, de dépassement du délai d'attente ou de réponse invalide, l'analyse par IA n'est pas réalisée.

Le fonctionnement de Wazuh et la collecte des alertes restent indépendants du traitement IA.

Le traitement IA constitue ainsi une couche complémentaire et non bloquante pour la supervision.

---

# 14. Performances

Dans l'environnement de démonstration fonctionnant en CPU-only :

- le chargement initial de Mistral 7B peut prendre environ 140 secondes ;
- le traitement d'une alerte prend de l'ordre de 10 secondes une fois le modèle chargé ;
- le traitement dépend directement du nombre d'alertes et des ressources disponibles ;
- le traitement est limité à 10 alertes par exécution.

Les paramètres suivants permettent de contrôler le comportement :

```env
MAX_ALERTS_PER_RUN=10
OLLAMA_TIMEOUT=240
OLLAMA_KEEP_ALIVE=30m
```

Ces mesures correspondent à l'environnement de démonstration et ne constituent pas un benchmark de production.

---

# 15. Rapport JSON

Lorsque la génération de rapports JSON est utilisée par la version du connecteur déployée, les résultats peuvent être enregistrés dans un répertoire de rapports sous la forme :

```text
reports/rapport-YYYYMMDD-HHMMSS.json
```

Exemple :

```text
reports/rapport-20260926-143000.json
```

Le fichier permet de conserver une représentation structurée des analyses produites.

La base SQLite reste la source utilisée par le dashboard Flask.

---

# 16. Ancienne approche basée sur le polling

Une première approche du projet reposait sur une exécution périodique via cron.

Exemple :

```text
*/10 * * * *
```

Cette approche a été remplacée par une architecture permettant de traiter les alertes dans le cadre de l'intégration Wazuh.

L'ancien mécanisme de polling n'est donc plus nécessaire lorsque l'intégration actuelle est correctement déployée.

---

# 17. Décommissionnement de l'ancien système

Si une ancienne tâche cron est encore configurée :

```bash
crontab -e
```

Supprimer l'ancienne tâche liée au traitement du connecteur après validation de la nouvelle architecture.

Si un ancien service de rapports n'est plus utilisé :

```bash
sudo systemctl disable --now wazuh-reports
```

Les anciens rapports peuvent être conservés comme archives si nécessaire.

---

# 18. Points de vigilance

## Charge CPU

Mistral 7B est exécuté sur CPU dans l'environnement de démonstration.

Plusieurs traitements simultanés peuvent augmenter fortement la charge du serveur.

Il est donc nécessaire de surveiller :

- CPU ;
- RAM ;
- temps d'inférence ;
- nombre d'alertes ;
- disponibilité d'Ollama.

## Seuil d'alerte

Le seuil actuel est :

```text
ALERT_LEVEL_THRESHOLD=7
```

Un seuil trop faible peut entraîner un volume important d'analyses IA.

## Nombre d'alertes

Le nombre maximal d'alertes est :

```text
MAX_ALERTS_PER_RUN=10
```

Cette limitation permet de contrôler la charge.

## Base SQLite

La base peut augmenter progressivement.

Pour une utilisation prolongée, une politique de rétention ou de rotation peut être ajoutée.

---

# 19. Sécurité

Aucune donnée sensible ne doit être publiée dans le dépôt.

Ne jamais versionner :

- les mots de passe ;
- les clés privées ;
- les tokens d'accès ;
- le fichier `.env` contenant les secrets ;
- les bases SQLite contenant des données sensibles ;
- les informations internes de l'infrastructure.

Le fichier :

```text
.env.example
```

doit uniquement contenir des valeurs d'exemple.

Exemple :

```env
WAZUH_INDEXER_PASSWORD=CHANGE_ME
```

Le véritable mot de passe doit uniquement être présent dans le fichier local :

```text
.env
```

Le fichier `.env` doit être ajouté au `.gitignore`.

Exemple :

```gitignore
.env
__pycache__/
*.pyc
reports/
*.db
```

---

# 20. Technologies utilisées

| Technologie | Utilisation |
|---|---|
| Wazuh | SIEM et génération des alertes |
| Wazuh Indexer / OpenSearch | Stockage et interrogation des alertes |
| Ollama | Serveur d'inférence local |
| Mistral 7B | Modèle de langage utilisé pour l'analyse |
| Python | Développement du connecteur et du dashboard |
| Requests | Communication avec Wazuh Indexer et Ollama |
| python-dotenv | Gestion des variables d'environnement |
| Flask | Framework web du dashboard |
| SQLite | Stockage des résultats |
| JavaScript | Actualisation automatique du dashboard |
| systemd | Gestion du service Flask |

---

# 21. Limites connues

- L'inférence de Mistral 7B est réalisée sur CPU dans l'environnement de test.
- Le temps de traitement peut être élevé lors de l'analyse d'une alerte.
- Les performances dépendent des ressources matérielles disponibles.
- Le nombre d'alertes traitées est limité par exécution.
- La base SQLite nécessite une politique de rétention pour une utilisation prolongée.
- Les résultats produits par le modèle doivent être vérifiés par un analyste de sécurité.
- Le projet correspond à un environnement de démonstration et de validation technique.

---

# 22. Évolutions possibles

Plusieurs évolutions peuvent être envisagées :

- utilisation d'un serveur disposant d'un GPU afin de réduire le temps d'inférence ;
- mise en place d'une file d'attente pour les alertes ;
- amélioration de la gestion de la concurrence ;
- déduplication des alertes ;
- mise en place d'une politique automatique de rétention SQLite ;
- amélioration de l'interface du dashboard ;
- ajout d'autres modèles de langage locaux ;
- amélioration de la journalisation ;
- extension de l'intégration à d'autres composants de supervision.

Ces évolutions restent des perspectives et n'ont pas nécessairement été déployées dans l'environnement de démonstration.

---

# 23. Contexte du projet

Ce projet a été réalisé dans le cadre d'un **Projet de Fin d'Études (PFE)** portant sur le renforcement d'une architecture SIEM par l'intelligence artificielle.

L'objectif est d'étudier l'intégration d'un modèle de langage local avec Wazuh afin d'enrichir l'interprétation des alertes de sécurité tout en conservant les données et l'inférence dans l'infrastructure locale.

Le projet porte notamment sur :

- l'enrichissement des alertes Wazuh par l'intelligence artificielle ;
- l'exécution locale d'un modèle Mistral 7B avec Ollama ;
- l'enregistrement des résultats dans SQLite ;
- la présentation des analyses dans un dashboard Flask ;
- l'étude des contraintes matérielles liées à l'exécution d'un LLM sur CPU.

---

# 24. Auteur

**Mohamed Adw**

Projet réalisé dans le cadre du cursus :

**Génie Informatique – Ingénierie de la Cybersécurité**

Année universitaire :

**2025–2026**
