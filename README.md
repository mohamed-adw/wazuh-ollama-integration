# Intégration native Wazuh → Ollama → Dashboard

Ce projet met en œuvre une intégration native entre **Wazuh**, **Ollama** et un **dashboard Flask** afin d'enrichir automatiquement les alertes de sécurité à l'aide du modèle de langage **Mistral 7B**.

L'architecture utilise le mécanisme officiel `<integration>` de Wazuh. Contrairement à une approche basée sur un polling périodique par cron, le connecteur est déclenché lorsqu'une alerte correspondant aux critères configurés est générée par Wazuh.

## Architecture

```text
Wazuh (analysisd / integratord)
        │
        ▼
/var/ossec/integrations/custom-ollama
        │
        │ Wrapper synchrone
        │
        ▼
custom-ollama.py
        │
        │ Traitement asynchrone
        ▼
Ollama
        │
        ▼
Mistral 7B
        │
        ▼
SQLite (WAL)
        │
        ▼
Dashboard Flask (app.py)
        │
        ▼
dashboard.html
        │
        └── Auto-refresh JavaScript (5 s)
```

Le modèle Ollama est exécuté localement sur le serveur. L'API utilisée par le connecteur est donc :

```text
http://localhost:11434
```

Aucun appel à une API d'inférence distante n'est nécessaire.

## Structure du projet

```text
wazuh-ollama-integration/
│
├── app.py
├── custom-ollama
├── custom-ollama.py
├── dashboard.html
├── requirements.txt
├── wazuh-ai-dashboard.service
└── README.md
└── wazuh_ollama_connector.py
└── .env.example
```

### Rôle des principaux fichiers

| Fichier | Rôle |
|---|---|
| `custom-ollama` | Wrapper d'intégration appelé par Wazuh |
| `custom-ollama.py` | Traitement des alertes et communication avec Ollama |
| `app.py` | Application web Flask du dashboard |
| `dashboard.html` | Interface d'affichage des alertes enrichies |
| `requirements.txt` | Dépendances Python |
| `wazuh-ai-dashboard.service` | Service systemd du dashboard |
| `README.md` | Documentation du projet |

## 1. Installation du script d'intégration

Copier les scripts dans le répertoire officiel des intégrations Wazuh :

```bash
sudo cp custom-ollama /var/ossec/integrations/
sudo cp custom-ollama.py /var/ossec/integrations/
```

Appliquer les permissions nécessaires :

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-ollama*
sudo chmod 750 /var/ossec/integrations/custom-ollama*
```

Créer le répertoire utilisé pour la base SQLite :

```bash
sudo mkdir -p /var/ossec/integrations/data
sudo chown wazuh:wazuh /var/ossec/integrations/data
sudo chmod 770 /var/ossec/integrations/data
```

Si nécessaire, ajouter l'utilisateur utilisé pour le dashboard au groupe `wazuh` :

```bash
sudo usermod -aG wazuh sysadmin
```

Une reconnexion de l'utilisateur peut être nécessaire pour que la modification du groupe soit prise en compte.

## 2. Configuration de Wazuh

La configuration de l'intégration est ajoutée dans :

```text
/var/ossec/etc/ossec.conf
```

Exemple de configuration :

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

Pour les tests initiaux, il est possible d'utiliser un seuil de niveau de règle faible, par exemple :

```xml
<level>3</level>
```

Une fois l'intégration validée, le seuil peut être adapté aux besoins de supervision afin d'éviter de générer un volume excessif d'analyses IA.

## 3. Installation d'Ollama et de Mistral 7B

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

Vérifier également que l'API Ollama est accessible localement :

```bash
curl http://localhost:11434/api/tags
```

Le connecteur utilise l'API locale d'Ollama pour transmettre les informations des alertes au modèle.

## 4. Test manuel de l'intégration

Avant d'attendre une nouvelle alerte Wazuh, il est possible de tester manuellement le connecteur :

```bash
sudo /var/ossec/integrations/custom-ollama \
    /var/ossec/logs/alerts/alerts.json \
    "" \
    "http://localhost:11434"
```

Suivre ensuite le journal du connecteur :

```bash
tail -f /var/ossec/logs/integrations/custom-ollama.log
```

La base SQLite peut être vérifiée avec :

```bash
sqlite3 /var/ossec/integrations/data/alerts.db \
    "SELECT id, rule_level, ai_score, ai_cause FROM alerts ORDER BY id DESC LIMIT 5;"
```

## 5. Dashboard Flask

Le dashboard est développé avec **Flask** et permet d'afficher les alertes Wazuh enrichies par l'analyse du modèle Mistral 7B.

Installer les dépendances :

```bash
pip3 install -r requirements.txt --break-system-packages
```

Lancer le dashboard manuellement pour effectuer un test :

```bash
python3 app.py
```

Le dashboard est alors accessible sur le port :

```text
8080
```

L'interface récupère les données enregistrées dans SQLite et actualise automatiquement l'affichage.

## 6. Déploiement avec systemd

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

## 7. Fonctionnement de l'intégration

Lorsqu'une alerte correspondant aux critères configurés est générée par Wazuh :

1. `wazuh-analysisd` analyse l'événement.
2. `wazuh-integratord` déclenche l'intégration configurée.
3. Le wrapper `custom-ollama` est exécuté.
4. Le traitement de l'alerte est transmis à `custom-ollama.py`.
5. Le script communique avec l'API locale d'Ollama.
6. Le modèle **Mistral 7B** analyse les informations de l'alerte.
7. Le résultat de l'analyse est enregistré dans SQLite.
8. Le dashboard Flask récupère les données.
9. L'interface présente l'alerte enrichie à l'utilisateur.

Cette architecture permet de traiter les alertes sans dépendre d'un mécanisme de polling périodique.

## 8. Gestion du traitement IA

Le traitement du modèle est effectué de manière asynchrone afin de ne pas bloquer durablement le mécanisme de déclenchement de l'intégration Wazuh.

Le temps de traitement dépend notamment :

- de la charge du serveur ;
- du nombre d'alertes à traiter ;
- des ressources CPU et RAM disponibles ;
- du temps d'inférence de Mistral 7B.

Dans l'environnement de test utilisé pour ce projet, l'inférence est réalisée sur CPU.

## 9. Base de données SQLite

Les résultats d'analyse sont enregistrés dans une base SQLite située dans :

```text
/var/ossec/integrations/data/alerts.db
```

Le mode **WAL (Write-Ahead Logging)** est utilisé afin de faciliter les opérations de lecture et d'écriture concurrentes.

Le dashboard Flask peut ainsi consulter les résultats pendant que de nouvelles analyses sont enregistrées.

## 10. Ancienne architecture basée sur le polling

Une première approche du projet reposait sur une exécution périodique via cron, par exemple :

```text
*/10 * * * *
```

Cette approche a été remplacée par le mécanisme natif `<integration>` de Wazuh.

L'architecture actuelle permet ainsi un déclenchement directement lié à la génération des alertes correspondant aux critères définis dans Wazuh, sans dépendre d'une interrogation périodique des fichiers d'alertes.

## 11. Décommissionnement de l'ancien système

Une fois la nouvelle intégration validée, l'ancien mécanisme de polling peut être désactivé :

```bash
crontab -e
```

Supprimer l'ancienne tâche cron liée au connecteur.

Si un ancien serveur de rapports était utilisé, son service peut également être arrêté après validation :

```bash
sudo systemctl disable --now wazuh-reports
```

Les anciens rapports JSON/HTML peuvent être conservés à titre d'archive pour permettre une comparaison avec la nouvelle architecture.

## Points de vigilance

### Charge simultanée

Lorsque plusieurs alertes sont générées simultanément, plusieurs traitements peuvent être lancés.

Sur une infrastructure fonctionnant uniquement sur CPU, plusieurs appels concurrents à Ollama peuvent augmenter le temps de traitement.

Il est donc nécessaire de surveiller la charge du serveur et le temps d'inférence.

Une évolution possible consiste à mettre en place une véritable file d'attente afin de contrôler le nombre de traitements IA simultanés.

### Nettoyage de la base

Aucune purge automatique des anciennes alertes n'est actuellement imposée par le projet.

Pour une utilisation à long terme, une politique de rétention ou de rotation de la base SQLite peut être mise en place afin de limiter sa croissance.

### Seuil de déclenchement

Le niveau de règle utilisé pendant les tests doit être adapté à l'environnement de production.

Un seuil trop faible peut entraîner un nombre important d'analyses IA et augmenter inutilement la charge du serveur.

## Technologies utilisées

| Technologie | Utilisation |
|---|---|
| Wazuh | SIEM et génération des alertes de sécurité |
| Ollama | Serveur d'inférence locale |
| Mistral 7B | Modèle de langage utilisé pour l'analyse |
| Python | Développement du connecteur et du dashboard |
| Flask | Framework web du dashboard |
| SQLite | Stockage des résultats d'analyse |
| systemd | Gestion du service du dashboard |
| JavaScript | Actualisation automatique de l'interface |

## Limites connues

- L'inférence de Mistral 7B est réalisée sur CPU dans l'environnement de test.
- Le temps de traitement peut être élevé lors de l'analyse d'une alerte.
- Plusieurs alertes simultanées peuvent entraîner plusieurs traitements concurrents.
- La base SQLite nécessite une politique de rétention pour une utilisation prolongée.
- Le projet est destiné à un environnement de démonstration et de validation technique.

## Sécurité

Aucune donnée sensible ne doit être publiée dans ce dépôt.

Ne jamais versionner :

- les mots de passe ;
- les clés privées ;
- les tokens d'accès ;
- les fichiers `.env` contenant des secrets ;
- les bases de données contenant des données sensibles ;
- les informations d'infrastructure interne non nécessaires au fonctionnement du projet.

Les paramètres sensibles doivent être configurés directement sur le serveur ou fournis via des variables d'environnement.

## Évolution possible

Plusieurs évolutions peuvent être envisagées :

- utilisation d'un serveur disposant d'un GPU pour réduire le temps d'inférence ;
- mise en place d'une véritable file d'attente pour les alertes ;
- amélioration de la gestion de la concurrence ;
- mise en place d'une politique automatique de rétention SQLite ;
- amélioration de l'interface du dashboard ;
- ajout d'autres modèles de langage locaux ;
- intégration de mécanismes supplémentaires de supervision et de journalisation.

## Contexte du projet

Ce projet a été réalisé dans le cadre d'un **Projet de Fin d'Études (PFE)** portant sur le renforcement d'une architecture SIEM par l'intelligence artificielle.

L'objectif est d'étudier l'intégration d'un modèle de langage local avec Wazuh afin d'enrichir l'interprétation des alertes de sécurité tout en conservant les données et l'inférence dans l'infrastructure locale.

## Auteur

**Mohamed Adw**

Projet réalisé dans le cadre du cursus **Génie Informatique – Ingénierie de la Cybersécurité**.

Année universitaire **2025–2026**.
