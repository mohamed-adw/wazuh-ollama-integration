# Intégration Wazuh → Ollama → Dashboard

Ce projet met en œuvre une intégration entre **Wazuh**, **Ollama**, **Mistral 7B** et un **dashboard Flask** afin d'enrichir les alertes de sécurité à l'aide d'un modèle de langage exécuté localement.

L'objectif est de fournir aux analystes une analyse complémentaire des alertes Wazuh comprenant notamment :

- une explication de l'événement ;
- un score de dangerosité ;
- une cause probable ;
- des actions recommandées.

Le modèle **Mistral 7B** est exécuté localement avec **Ollama**. Aucune API d'inférence distante n'est nécessaire.

---

## Architecture

L'architecture du projet est organisée autour de Wazuh, du connecteur Python, d'Ollama/Mistral 7B, d'une base SQLite et d'un dashboard Flask.

```text
                         Wazuh
                           │
                           ▼
                  Wazuh Indexer
                           │
                           ▼
             wazuh_ollama_connector.py
                           │
                           ▼
                    Ollama API
                           │
                           ▼
                      Mistral 7B
                           │
                           ▼
                    Analyse IA
                           │
                           ▼
                     SQLite
                    alerts.db
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
                         (5 s)
```

Le modèle Ollama est exécuté localement sur le serveur.

L'API utilisée par le connecteur est :

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

## Rôle des principaux fichiers

| Fichier | Rôle |
|---|---|
| `custom-ollama` | Wrapper d'intégration appelé par Wazuh |
| `custom-ollama.py` | Gestion du déclenchement de l'intégration et transmission du traitement au connecteur |
| `wazuh_ollama_connector.py` | Connecteur principal chargé de récupérer les alertes Wazuh, de sélectionner les alertes selon le seuil configuré, de transmettre les événements à Ollama/Mistral 7B et d'enregistrer les résultats dans SQLite |
| `app.py` | Application web Flask du dashboard |
| `dashboard.html` | Interface d'affichage des alertes enrichies |
| `requirements.txt` | Dépendances Python nécessaires au projet |
| `wazuh-ai-dashboard.service` | Service systemd permettant d'exécuter le dashboard Flask |
| `.env.example` | Exemple de configuration des variables d'environnement utilisées par le connecteur |
| `README.md` | Documentation et procédure d'installation du projet |

---

# 1. Prérequis

Le projet nécessite :

- Wazuh ;
- Wazuh Indexer ;
- Python 3 ;
- Ollama ;
- Mistral 7B ;
- SQLite ;
- Flask ;
- les dépendances Python indiquées dans `requirements.txt`.

Le serveur utilisé pour la démonstration fonctionne avec une exécution du modèle sur **CPU**.

---

# 2. Installation du connecteur

Le fichier principal du traitement IA est :

```text
wazuh_ollama_connector.py
```

Il est chargé de :

1. charger la configuration ;
2. interroger le Wazuh Indexer ;
3. sélectionner les alertes à analyser ;
4. construire le prompt ;
5. transmettre l'événement à Ollama ;
6. récupérer la réponse de Mistral 7B ;
7. extraire les informations produites par le modèle ;
8. enregistrer les résultats dans SQLite.

---

## 2.1 Installation des dépendances Python

Installer les dépendances du projet :

```bash
pip3 install -r requirements.txt --break-system-packages
```

Les principales bibliothèques utilisées par le connecteur sont :

- `requests`
- `python-dotenv`

Le dashboard utilise notamment :

- `Flask`

---

# 3. Configuration avec `.env`

Le dépôt contient un fichier :

```text
.env.example
```

Ce fichier sert uniquement de modèle de configuration.

Créer le fichier local `.env` :

```bash
cp .env.example .env
```

Puis modifier les valeurs nécessaires.

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

## Paramètres principaux

| Variable | Valeur par défaut | Fonction |
|---|---:|---|
| `WAZUH_INDEXER_HOST` | `https://localhost:9200` | Adresse du Wazuh Indexer |
| `WAZUH_INDEXER_USER` | `admin` | Utilisateur du Wazuh Indexer |
| `WAZUH_INDEXER_PASSWORD` | `CHANGE_ME` | Mot de passe du Wazuh Indexer |
| `OLLAMA_HOST` | `http://localhost:11434` | Adresse de l'API Ollama |
| `OLLAMA_MODEL` | `mistral:7b` | Modèle utilisé pour l'analyse |
| `ALERT_LEVEL_THRESHOLD` | `7` | Niveau minimal des alertes analysées |
| `MAX_ALERTS_PER_RUN` | `10` | Nombre maximal d'alertes traitées |
| `OLLAMA_TIMEOUT` | `240` | Délai maximal d'attente en secondes |
| `OLLAMA_KEEP_ALIVE` | `30m` | Durée de maintien du modèle en mémoire |
| `WAZUH_AI_DB` | `/var/ossec/integrations/data/alerts.db` | Chemin de la base SQLite |

### Seuil de sélection

Le connecteur sélectionne les alertes dont le niveau de règle Wazuh est :

```text
rule.level >= 7
```

Le paramètre :

```env
ALERT_LEVEL_THRESHOLD=7
```

permet de modifier ce seuil.

Le nombre d'alertes traitées par exécution est limité par :

```env
MAX_ALERTS_PER_RUN=10
```

Cette limitation permet de maîtriser la charge du serveur lorsque le traitement du modèle est réalisé sur CPU.

---

# 4. Sécurité de la configuration

Le fichier `.env` peut contenir des informations sensibles, notamment le mot de passe du Wazuh Indexer.

Il ne doit donc pas être publié dans le dépôt Git.

Ne jamais versionner :

```text
.env
```

Le fichier suivant peut être versionné :

```text
.env.example
```

car il ne contient pas de mot de passe réel.

Ne jamais publier :

- les mots de passe ;
- les clés privées ;
- les tokens d'accès ;
- les fichiers `.env` contenant des secrets ;
- les bases SQLite contenant des données sensibles ;
- les informations d'infrastructure interne non nécessaires au fonctionnement du projet.

---

# 5. Installation d'Ollama et de Mistral 7B

Installer Ollama sur le serveur :

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Vérifier son fonctionnement :

```bash
systemctl status ollama
```

Télécharger le modèle Mistral 7B :

```bash
ollama pull mistral:7b
```

Tester le modèle :

```bash
ollama run mistral:7b
```

Vérifier que l'API Ollama est accessible :

```bash
curl http://localhost:11434/api/tags
```

Le connecteur utilise cette API locale pour transmettre les événements au modèle.

---

# 6. Fonctionnement de `wazuh_ollama_connector.py`

Le connecteur fonctionne selon les étapes suivantes :

```text
Wazuh Indexer
      │
      ▼
Récupération des alertes
      │
      ▼
Filtre rule.level >= 7
      │
      ▼
Maximum 10 alertes
      │
      ▼
Construction du prompt
      │
      ▼
Ollama
      │
      ▼
Mistral 7B
      │
      ▼
Analyse de l'alerte
      │
      ├── Score de dangerosité
      ├── Cause probable
      ├── Explication
      └── Actions recommandées
      │
      ▼
SQLite
```

Le traitement est effectué localement.

Les données de l'alerte sont transmises à l'instance Ollama présente sur le serveur :

```text
http://localhost:11434
```

---

## 6.1 Analyse produite par Mistral 7B

Le modèle reçoit les informations pertinentes de l'alerte Wazuh et produit une réponse structurée contenant :

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

Le connecteur extrait ensuite ces différents éléments afin de les enregistrer dans SQLite.

Le score de dangerosité est compris entre :

```text
1 et 10
```

Il constitue une estimation complémentaire au niveau `rule.level` fourni par Wazuh.

---

# 7. Base de données SQLite

Les résultats sont enregistrés dans :

```text
/var/ossec/integrations/data/alerts.db
```

Le connecteur crée automatiquement la table `alerts` si elle n'existe pas.

La structure utilisée contient notamment :

| Colonne | Description |
|---|---|
| `id` | Identifiant interne |
| `alert_id` | Identifiant de l'alerte Wazuh |
| `timestamp` | Date de l'événement |
| `agent_name` | Nom de l'agent Wazuh |
| `rule_id` | Identifiant de la règle |
| `rule_level` | Niveau de la règle Wazuh |
| `rule_description` | Description de la règle |
| `ai_score` | Score de dangerosité produit par l'IA |
| `ai_cause` | Cause probable |
| `ai_explication` | Explication de l'événement |
| `ai_actions` | Actions recommandées |
| `status` | État du traitement |
| `processed_at` | Date du traitement IA |

---

## 7.1 Création du répertoire SQLite

Créer le répertoire :

```bash
sudo mkdir -p /var/ossec/integrations/data
```

Appliquer les permissions :

```bash
sudo chown wazuh:wazuh /var/ossec/integrations/data
sudo chmod 770 /var/ossec/integrations/data
```

Si nécessaire, ajouter l'utilisateur du dashboard au groupe `wazuh` :

```bash
sudo usermod -aG wazuh sysadmin
```

Une reconnexion peut être nécessaire pour que la modification du groupe soit prise en compte.

---

# 8. Installation de l'intégration Wazuh

Les fichiers utilisés par l'intégration Wazuh sont :

```text
custom-ollama
custom-ollama.py
```

Les copier dans le répertoire officiel des intégrations :

```bash
sudo cp custom-ollama /var/ossec/integrations/
sudo cp custom-ollama.py /var/ossec/integrations/
```

Appliquer les permissions :

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-ollama*
sudo chmod 750 /var/ossec/integrations/custom-ollama*
```

Le connecteur Python peut également être placé dans le même répertoire lorsqu'il est utilisé directement par l'intégration :

```bash
sudo cp wazuh_ollama_connector.py /var/ossec/integrations/
```

Puis appliquer les permissions :

```bash
sudo chown root:wazuh /var/ossec/integrations/wazuh_ollama_connector.py
sudo chmod 750 /var/ossec/integrations/wazuh_ollama_connector.py
```

---

# 9. Configuration de Wazuh

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

Le seuil de déclenchement configuré dans Wazuh peut être adapté aux besoins de supervision.

Exemple pour les tests :

```xml
<level>3</level>
```

Le connecteur applique ensuite son propre seuil d'analyse défini par :

```env
ALERT_LEVEL_THRESHOLD=7
```

---

# 10. Test du connecteur

Le connecteur peut être testé directement :

```bash
python3 wazuh_ollama_connector.py
```

Avant le lancement, vérifier que :

- Ollama fonctionne ;
- Mistral 7B est installé ;
- Wazuh Indexer est accessible ;
- le fichier `.env` est correctement configuré.

Vérifier Ollama :

```bash
systemctl status ollama
```

Vérifier le modèle :

```bash
ollama list
```

Vérifier l'API :

```bash
curl http://localhost:11434/api/tags
```

---

# 11. Vérification de la base SQLite

Après une analyse, vérifier les résultats :

```bash
sqlite3 /var/ossec/integrations/data/alerts.db \
    "SELECT id, rule_level, ai_score, ai_cause FROM alerts ORDER BY id DESC LIMIT 5;"
```

Une ligne peut notamment contenir :

```text
id
rule_level
ai_score
ai_cause
```

Les autres informations sont disponibles dans les différentes colonnes de la table `alerts`.

---

# 12. Gestion des erreurs

Le connecteur gère notamment les situations suivantes :

- indisponibilité du Wazuh Indexer ;
- réponse invalide du Wazuh Indexer ;
- indisponibilité d'Ollama ;
- dépassement du délai d'attente ;
- réponse vide du modèle ;
- réponse JSON invalide ;
- absence du score de dangerosité.

En cas d'échec de l'analyse IA, le traitement de l'alerte n'empêche pas le fonctionnement général de Wazuh.

Le traitement IA constitue donc une couche complémentaire à la supervision.

---

# 13. Performances

Le serveur de démonstration utilisé pour le projet fonctionne en **CPU-only**.

Les performances dépendent notamment :

- des ressources CPU ;
- de la mémoire disponible ;
- du nombre d'alertes à traiter ;
- du temps d'inférence de Mistral 7B ;
- du chargement initial du modèle.

La configuration limite le nombre d'alertes traitées par exécution :

```env
MAX_ALERTS_PER_RUN=10
```

Le délai d'attente d'Ollama est configuré à :

```env
OLLAMA_TIMEOUT=240
```

Le modèle peut rester chargé pendant :

```env
OLLAMA_KEEP_ALIVE=30m
```

Ces paramètres sont adaptés à l'environnement de démonstration et peuvent être ajustés selon les ressources disponibles.

---

# 14. Dashboard Flask

Le dashboard est développé avec **Flask**.

Il récupère les résultats enregistrés dans SQLite et les affiche dans une interface web.

Le fichier principal est :

```text
app.py
```

L'interface est définie dans :

```text
dashboard.html
```

---

## 14.1 Lancement du dashboard

Lancer le dashboard manuellement :

```bash
python3 app.py
```

Le serveur Flask écoute sur :

```text
8080
```

Le dashboard peut alors être consulté depuis :

```text
http://localhost:8080
```

ou depuis l'adresse IP du serveur :

```text
http://ADRESSE_IP_DU_SERVEUR:8080
```

---

# 15. API du dashboard

Le dashboard fournit notamment :

```text
GET /
```

pour afficher l'interface web.

Il fournit également :

```text
GET /api/alerts
```

pour récupérer les alertes enregistrées au format JSON.

L'interface JavaScript interroge automatiquement cette API afin d'actualiser les données.

L'actualisation est réalisée toutes les :

```text
5 secondes
```

---

# 16. Déploiement avec systemd

Pour exécuter le dashboard de manière persistante, copier le service systemd :

```bash
sudo cp wazuh-ai-dashboard.service /etc/systemd/system/
```

Recharger systemd :

```bash
sudo systemctl daemon-reload
```

Activer et démarrer le service :

```bash
sudo systemctl enable --now wazuh-ai-dashboard
```

Vérifier son état :

```bash
sudo systemctl status wazuh-ai-dashboard
```

Le service permet au dashboard de démarrer automatiquement avec le serveur et de redémarrer en cas d'arrêt du processus.

---

# 17. Fonctionnement global

Lorsqu'une alerte correspondant aux critères configurés est disponible dans Wazuh :

```text
1. Wazuh génère et enregistre l'alerte
              │
              ▼
2. Wazuh Indexer stocke l'événement
              │
              ▼
3. Le connecteur récupère les alertes sélectionnées
              │
              ▼
4. rule.level >= ALERT_LEVEL_THRESHOLD
              │
              ▼
5. Construction du prompt
              │
              ▼
6. Ollama reçoit l'événement
              │
              ▼
7. Mistral 7B analyse l'alerte
              │
              ▼
8. Le connecteur extrait les résultats
              │
              ▼
9. SQLite enregistre l'analyse
              │
              ▼
10. Flask récupère les données
              │
              ▼
11. Dashboard affiche l'alerte enrichie
```

Cette architecture permet d'ajouter une couche d'analyse IA aux alertes Wazuh tout en conservant l'exécution du modèle dans l'infrastructure locale.

---

# 18. Traitement de l'intelligence artificielle

Le traitement du modèle est effectué localement avec Ollama.

Le connecteur transmet au modèle les informations nécessaires à l'analyse de l'événement.

Mistral 7B produit ensuite :

```text
Score de dangerosité
        +
Explication
        +
Cause probable
        +
Actions recommandées
```

Les résultats sont ensuite stockés dans SQLite et affichés dans le dashboard.

L'analyse produite par le modèle doit être considérée comme une aide à l'analyse et doit être vérifiée par un analyste de sécurité avant toute action.

---

# 19. Ancienne approche basée sur le polling

Une première approche du projet reposait sur une exécution périodique du traitement, notamment via cron.

Exemple :

```text
*/10 * * * *
```

Cette approche permettait de lancer périodiquement le traitement des alertes.

La configuration actuelle s'appuie sur les composants d'intégration Wazuh et sur le connecteur Python pour assurer le traitement des événements sélectionnés.

Les anciennes tâches cron utilisées uniquement pour l'ancien système peuvent être supprimées après validation de la nouvelle architecture.

---

# 20. Décommissionnement de l'ancien système

Si une ancienne tâche cron est encore configurée :

```bash
crontab -e
```

Supprimer l'ancienne tâche liée au traitement des alertes lorsque la nouvelle architecture a été validée.

Si un ancien service de rapports était utilisé et n'est plus nécessaire :

```bash
sudo systemctl disable --now wazuh-reports
```

Les anciens rapports JSON ou HTML peuvent être conservés comme archives si nécessaire.

---

# 21. Points de vigilance

## Charge du serveur

L'exécution de Mistral 7B sur CPU peut entraîner un temps d'inférence important.

Il est donc nécessaire de surveiller :

- l'utilisation CPU ;
- la mémoire RAM ;
- le nombre d'alertes ;
- le temps de traitement ;
- la disponibilité d'Ollama.

## Nombre d'alertes

Le nombre d'alertes traitées est limité par :

```env
MAX_ALERTS_PER_RUN=10
```

Cette limitation permet de réduire la charge lors des traitements.

## Seuil de sélection

Le seuil par défaut est :

```env
ALERT_LEVEL_THRESHOLD=7
```

Une valeur trop faible peut entraîner un volume important d'analyses IA.

## Base SQLite

La base peut augmenter progressivement avec le nombre d'alertes analysées.

Pour une utilisation prolongée, une politique de rétention ou de rotation peut être mise en place.

---

# 22. Technologies utilisées

| Technologie | Utilisation |
|---|---|
| Wazuh | SIEM et génération des alertes de sécurité |
| Wazuh Indexer | Stockage et interrogation des alertes |
| Ollama | Serveur d'inférence locale |
| Mistral 7B | Modèle de langage utilisé pour l'analyse |
| Python | Développement du connecteur et du dashboard |
| Requests | Communication avec Wazuh Indexer et Ollama |
| python-dotenv | Chargement des variables d'environnement |
| Flask | Framework web du dashboard |
| SQLite | Stockage des résultats d'analyse |
| systemd | Gestion du service du dashboard |
| JavaScript | Actualisation automatique de l'interface |

---

# 23. Limites connues

- L'inférence de Mistral 7B est réalisée sur CPU dans l'environnement de test.
- Le temps de traitement peut être élevé lors de l'analyse d'une alerte.
- Les performances dépendent directement des ressources matérielles disponibles.
- Le nombre d'alertes traitées est volontairement limité par exécution.
- La base SQLite nécessite une politique de rétention pour une utilisation prolongée.
- Le traitement IA dépend de la disponibilité d'Ollama.
- Les résultats générés par le modèle doivent être vérifiés par un analyste.
- Le projet correspond à un environnement de démonstration et de validation technique.

---

# 24. Sécurité

Aucune donnée sensible ne doit être publiée dans ce dépôt.

Ne jamais versionner :

- les mots de passe ;
- les clés privées ;
- les tokens d'accès ;
- les fichiers `.env` contenant des secrets ;
- les bases de données contenant des données sensibles ;
- les informations d'infrastructure interne non nécessaires au fonctionnement du projet.

Les paramètres sensibles doivent être configurés directement sur le serveur ou fournis via des variables d'environnement.

Le fichier :

```text
.env.example
```

sert uniquement de modèle et ne doit pas contenir de véritables identifiants ou mots de passe.

---

# 25. Évolutions possibles

Plusieurs évolutions peuvent être envisagées :

- utilisation d'un serveur disposant d'un GPU afin de réduire le temps d'inférence ;
- mise en place d'une véritable file d'attente pour les alertes ;
- amélioration de la gestion de la concurrence ;
- mise en place d'une politique automatique de rétention SQLite ;
- amélioration de l'interface du dashboard ;
- ajout d'autres modèles de langage locaux ;
- amélioration de la journalisation ;
- ajout de mécanismes de déduplication des alertes ;
- extension de l'intégration à d'autres composants de supervision.

Ces évolutions restent des perspectives et ne constituent pas nécessairement des fonctionnalités déployées dans l'environnement de démonstration.

---

# 26. Contexte du projet

Ce projet a été réalisé dans le cadre d'un **Projet de Fin d'Études (PFE)** portant sur le renforcement d'une architecture SIEM par l'intelligence artificielle.

L'objectif est d'étudier l'intégration d'un modèle de langage local avec Wazuh afin d'enrichir l'interprétation des alertes de sécurité tout en conservant les données et l'inférence dans l'infrastructure locale.

Le projet porte notamment sur :

- l'intégration de Wazuh avec un modèle de langage local ;
- l'analyse automatisée des alertes ;
- l'affichage des résultats dans un dashboard ;
- la conservation des données dans une base locale ;
- l'étude des contraintes matérielles liées à l'exécution d'un LLM sur CPU.

---

# 27. Auteur

**Mohamed Adw**

Projet réalisé dans le cadre du cursus :

**Génie Informatique – Ingénierie de la Cybersécurité**

Année universitaire :

**2025–2026**
