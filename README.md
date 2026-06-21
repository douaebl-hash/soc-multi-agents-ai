# 🛡️ SOC Multi-Agents IA — Guide d'Installation et d'Utilisation

Système multi-agents basé sur LangChain et Mistral pour l'automatisation des tâches d'un analyste SOC.

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
git clone https://github.com/votre-org/soc-multi-agents-ai.git
cd soc-multi-agents-ai
```

### 2. Installer les dépendances Python

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

### 3. Installer et démarrer Ollama

```bash
# Installation Ollama (Windows)
irm https://ollama.com/install.ps1 | iex

# Télécharger le modèle Mistral
ollama pull mistral

# Vérifier qu'Ollama tourne
ollama serve
```


---

## 🚀 Lancement du Système

Ouvrir **4 terminaux** distincts (un par agent) depuis la racine du projet.

### Terminal 1 — Agent Extracteur

```bash
python agents/extracteur/extracteur_agent.py --daemon
```

### Terminal 2 — Agent Analyseur

```bash
python agents/analyseur/analyseur_agent.py --model mistral 
```

### Terminal 3 — Agent Rapporteur

```bash
python agents/rapporteur/rapporteur_agent.py --mode poll 
```


### Terminal 4 — Agent Exécuteur

```bash
python agents/executeur/executeur_agent.py --model mistral 
```
---
## 📊 Dashboard Streamlit

```bash
streamlit run dashboard_app.py
```
Accéder à : `http://localhost:8501`

Le dashboard affiche :
- Statistiques globales des incidents (CRITICAL, HIGH, MEDIUM, LOW)
- Timeline des événements détectés
- Derniers rapports générés

---

## 📁 Structure du Projet

```
soc-multi-agents/
├── shared_memory.py              # Bus de communication central
├── agents/
│   ├── extracteur/
│   │   └── extractor.py
│   ├── analyseur/
│   │   ├── analyseur_agent.py
│   │   ├── rules_engine.py       # Heuristiques de classification
│   │   └── correlator.py         # Moteur de corrélation temporelle
│   ├── rapporteur/
│   │   ├── rapporteur_agent.py
│   │   ├── report_generator.py   # Génération de rapports LLM
│   │   ├── dashboard_app.py      # Interface Streamlit
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
│                  
```

---

