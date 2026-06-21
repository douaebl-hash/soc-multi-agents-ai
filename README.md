# 🛡️ SOC Multi-Agents IA — Guide d'Installation et d'Utilisation

Système multi-agents basé sur LangChain et Mistral 7B pour l'automatisation des tâches d'un analyste SOC.

---

## 📋 Prérequis

- **Python** 3.10 ou supérieur
- **Ollama** installé et en cours d'exécution
- **Git**
- RAM : minimum 8 Go (16 Go recommandés pour Mistral 7B)

---

## ⚙️ Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-org/soc-multi-agents.git
cd soc-multi-agents
```

### 2. Créer un environnement virtuel

```bash
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
```

### 3. Installer les dépendances Python

```bash
pip install -r requirements.txt
```

**Dépendances principales :**

```
langchain>=0.2.0
langchain-ollama>=0.1.0
langchain-core>=0.2.0
streamlit>=1.35.0
```

### 4. Installer et démarrer Ollama

```bash
# Installation Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Télécharger le modèle Mistral
ollama pull mistral

# Vérifier qu'Ollama tourne
ollama serve
```

### 5. Initialiser la structure de données

```bash
mkdir -p data/processed data/reports data/logs data/raw data/shared
```

---

## 🚀 Lancement du Système

Ouvrir **4 terminaux** distincts (un par agent) depuis la racine du projet.

### Terminal 1 — Agent Extracteur

```bash
python agents/extracteur/extracteur_agent.py
```

### Terminal 2 — Agent Analyseur

```bash
python agents/analyseur/analyseur_agent.py --model mistral --poll-interval 2.0
```

Options disponibles :
| Option | Défaut | Description |
|--------|--------|-------------|
| `--model` | `mistral` | Nom du modèle Ollama |
| `--poll-interval` | `2.0` | Intervalle de polling en secondes |

### Terminal 3 — Agent Rapporteur

```bash
python agents/rapporteur/rapporteur_agent.py --mode poll --poll-interval 5.0
```

Options disponibles :
| Option | Défaut | Description |
|--------|--------|-------------|
| `--mode` | `poll` | `poll` (continu) ou `once` (one-shot) |
| `--poll-interval` | `5.0` | Intervalle de polling |

### Terminal 4 — Agent Exécuteur

```bash
python agents/executeur/executeur_agent.py --model mistral --severity CRITICAL HIGH
```

Options disponibles :
| Option | Défaut | Description |
|--------|--------|-------------|
| `--model` | `mistral` | Nom du modèle Ollama |
| `--poll-interval` | `3.0` | Intervalle de polling |
| `--dry-run` | `False` | Simuler les actions sans les exécuter |
| `--severity` | `CRITICAL HIGH` | Seuils déclenchant les actions |

> **💡 Conseil :** Toujours démarrer avec `--dry-run` lors des premiers tests.

---

## 🔍 Mode Test Rapide

Pour tester sans lancer tous les agents :

```bash
# Lecture one-shot de la SharedMemory par le Rapporteur
python agents/rapporteur/rapporteur_agent.py --mode once

# Exécuteur en mode simulation
python agents/executeur/executeur_agent.py --dry-run
```

---

## 📊 Dashboard Streamlit

```bash
streamlit run dashboard/app.py
```

Accéder à : `http://localhost:8501`

Le dashboard affiche :
- Statistiques globales des incidents (CRITICAL, HIGH, MEDIUM, LOW)
- Timeline des événements détectés
- Derniers rapports générés
- Journal des actions d'exécution

---

## 📁 Structure du Projet

```
soc-multi-agents/
├── shared_memory.py              # Bus de communication central
├── agents/
│   ├── extracteur/
│   │   └── extracteur_agent.py
│   ├── analyseur/
│   │   ├── analyseur_agent.py
│   │   ├── rules_engine.py       # Heuristiques de classification
│   │   └── correlator.py         # Moteur de corrélation temporelle
│   ├── rapporteur/
│   │   ├── rapporteur_agent.py
│   │   ├── report_generator.py   # Génération de rapports LLM
│   │   ├── dashboard_data.py     # Persistance pour Streamlit
│   │   └── analyser_adapter.py   # Conversion résultats → incidents
│   └── executeur/
│       ├── executeur_agent.py
│       ├── response_engine.py    # Exécution des actions
│       └── action_logger.py      # Journalisation des actions
├── data/
│   ├── processed/                # Canaux SharedMemory (JSON)
│   ├── reports/                  # Rapports d'incidents générés
│   ├── logs/                     # Logs d'audit
│   ├── raw/                      # Logs bruts sources
│   └── shared/
│       ├── memory.json           # Métadonnées inter-agents
│       └── incidents_history.json
├── dashboard/
│   └── app.py                    # Interface Streamlit
└── requirements.txt
```

---

## 🔧 Configuration Avancée

### Changer de modèle LLM

Le système supporte tout modèle compatible Ollama :

```bash
ollama pull llama3        # Alternative à Mistral
ollama pull phi3          # Modèle très léger (< 4 Go RAM)
ollama pull gemma2        # Alternative Google

# Lancer avec un autre modèle
python agents/analyseur/analyseur_agent.py --model llama3
```

### Ajuster les seuils de sévérité

Modifier dans `agents/analyseur/rules_engine.py` les règles heuristiques, ou dans `executeur_agent.py` le seuil de déclenchement des actions :

```python
# Inclure MEDIUM dans les actions automatiques
python agents/executeur/executeur_agent.py --severity CRITICAL HIGH MEDIUM
```

---

## 🗂️ Canaux de Communication (SharedMemory)

| Canal | Producteur | Consommateur | Contenu |
|-------|-----------|--------------|---------|
| `pending_analysis` | Extracteur | Analyseur | Événements prioritaires |
| `events_structured` | Extracteur | Analyseur | Tous les événements |
| `analysis_results` | Analyseur | Rapporteur, Exécuteur | Résultats d'analyse |
| `correlation_alerts` | Analyseur | Rapporteur | Alertes de corrélation |
| `actions_a_executer` | Rapporteur | Exécuteur | Actions planifiées |
| `execution_log` | Exécuteur | Audit | Traçabilité des actions |

---

## ⚠️ Dépannage

**Ollama ne répond pas**
```bash
# Vérifier l'état du service
ollama ps
# Redémarrer
ollama serve
```

**Erreur de parsing JSON du LLM**  
Normal — le système dispose d'un fallback déterministe. Si trop fréquent, vérifier que le modèle est bien chargé : `ollama list`

**SharedMemory corrompue**  
```bash
# Réinitialiser les canaux
rm data/processed/*.json
```

**Agents retraitent les mêmes événements**  
Les `_seen_ids` sont en mémoire vive uniquement. Un redémarrage de l'agent vide ce cache. Solution : les agents ignorent les événements déjà publiés dans les canaux de sortie.

---

## 📄 Licence

Projet académique — Usage éducatif uniquement.