# Agent Extracteur — SOC AI Agent System

Premier agent du pipeline multi-agents (Extracteur → Analyseur → Rapporteur → Exécuteur).

## Rôle

- **Collecte** depuis trois sources : logs systèmes (`syslog.log`), trafic réseau / IDS-IPS
  (format proche de Suricata `eve.json`), alertes SIEM (format générique type Wazuh/Elastic/Splunk).
- **Nettoie et structure** : déduplication, normalisation des horodatages, normalisation de la
  sévérité (échelles hétérogènes → score 0-1 commun) dans un schéma `Event` unique.
- **Détecte les événements pertinents** via un moteur de règles (mots-clés FR/EN + seuil de
  sévérité), avec un point d'extension optionnel pour un Small LLM local (Ollama) via LangChain.
- **Publie** les événements pertinents dans la mémoire partagée (`data/processed/pending_analysis.json`)
  pour l'Agent Analyseur, et journalise chaque étape dans `data/processed/audit_extractor.log`.

## Fichiers

```
src/utils/parsers.py        Parsing des 3 formats sources -> dicts normalisés
src/utils/shared_memory.py  Mémoire partagée fichier-JSON inter-agents (pattern pub/sub simple)
src/agents/extractor.py     Classe ExtractorAgent : pipeline complet
tests/test_extractor.py     9 tests unitaires (parsing, nettoyage, règles, pipeline)
data/raw/                   Sources simulées (syslog.log, network_traffic.json, siem_alerts.json)
data/processed/             Sorties : events_structured.json, events_relevant.json, audit log
requirements-extractor.txt  Dépendances additionnelles (vide en mode sans LLM)
```

## Utilisation

```python
from src.agents.extractor import ExtractorAgent

agent = ExtractorAgent()                 # mode règles uniquement
summary = agent.run()                    # collecte -> nettoyage -> détection -> publication
print(summary)
```

Ou directement : `python3 -m src.agents.extractor`

Lancer les tests : `pytest tests/test_extractor.py -v`

## Activer le Small LLM (optionnel)

```python
agent = ExtractorAgent(use_llm=True, llm_model="llama3.2:1b")
```

Nécessite un serveur [Ollama](https://ollama.com) local (`ollama pull llama3.2:1b`) et les
dépendances de `requirements-extractor.txt`. Le LLM n'est interrogé qu'en complément, sur les
messages que les règles jugent *non* pertinents, pour rattraper les cas ambigus — si Ollama est
indisponible, l'agent retombe silencieusement sur les règles seules (aucun crash).

## Brancher de vraies sources plus tard

Le contrat de sortie (`list[Event]`) ne change pas si vous remplacez la lecture de fichier par :
- un `tail -f` sur `eve.json` de Suricata pour le réseau,
- l'API REST de Wazuh ou un export Elastic pour le SIEM,
- `journalctl`/syslog distant (rsyslog) pour les logs systèmes.

Il suffit d'adapter `collect_network()` / `collect_siem()` / `collect_syslog()` dans `extractor.py`
pour qu'ils alimentent la même liste d'`Event`, le reste du pipeline (nettoyage, détection,
publication) ne change pas.

## Pour l'orchestration LangChain (agents suivants)

`ExtractorAgent.run()` est une fonction Python normale : elle peut être enveloppée dans un
`Tool` LangChain (`langchain.tools.Tool`) pour être appelée par un `AgentExecutor` ou un graphe
LangGraph orchestrant les 4 agents. La mémoire partagée (`SharedMemory`) joue le rôle de bus de
communication minimal entre agents ; elle peut être remplacée plus tard par
`ConversationBufferMemory`, Redis, ou une vraie file de messages sans changer l'interface de
`ExtractorAgent`.
