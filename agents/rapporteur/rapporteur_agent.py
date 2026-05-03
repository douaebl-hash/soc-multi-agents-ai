# Agent 3 — Rapporteur : génère rapports, résumés et tableaux de bord SOC

import json
import os
from datetime import datetime
from typing import Any

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools   import Tool
from langchain_ollama  import OllamaLLM
from langchain.prompts import PromptTemplate
from langchain.memory  import ConversationBufferMemory

from report_generator import (
    generate_incident_report,
    generate_summary_report,
    generate_dashboard,
)

# ─── Configuration ─────────────────────────────────────────────────────────────
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "mistral")
SHARED_MEMORY = os.getenv("SHARED_MEMORY_PATH", "data/shared/memory.json")
os.makedirs(os.path.dirname(SHARED_MEMORY), exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# OUTILS (Tools) exposés à l'agent LangChain
# ═══════════════════════════════════════════════════════════════════════════════

def tool_generate_incident_report(input_str: str) -> str:
    """
    Outil : génère un rapport détaillé pour un incident.
    Attend un JSON sérialisé en string représentant l'incident.
    """
    try:
        incident_data = json.loads(input_str)
        result = generate_incident_report(incident_data)
        _write_to_shared_memory("last_incident_report", result)
        return f"✅ Rapport généré et sauvegardé : {result['filepath']}\n\n{result['content'][:500]}..."
    except json.JSONDecodeError as e:
        return f"❌ Erreur : input invalide (JSON attendu). Détail : {e}"
    except Exception as e:
        return f"❌ Erreur lors de la génération : {e}"


def tool_generate_summary(input_str: str) -> str:
    """
    Outil : génère un rapport de synthèse sur plusieurs incidents.
    Attend une liste JSON d'incidents.
    """
    try:
        incidents = json.loads(input_str)
        if not isinstance(incidents, list):
            incidents = [incidents]
        result = generate_summary_report(incidents)
        _write_to_shared_memory("last_summary_report", result)
        return f"✅ Synthèse générée ({result['incident_count']} incidents) : {result['filepath']}\n\n{result['content'][:500]}..."
    except Exception as e:
        return f"❌ Erreur lors de la synthèse : {e}"


def tool_generate_dashboard(input_str: str) -> str:
    """
    Outil : génère un tableau de bord statistique SOC.
    Attend une liste JSON d'incidents pour le calcul des stats.
    """
    try:
        incidents = json.loads(input_str)
        if not isinstance(incidents, list):
            incidents = [incidents]
        result = generate_dashboard(incidents)
        _write_to_shared_memory("last_dashboard", result)
        return (
            f"✅ Dashboard généré : {result['filepath']}\n"
            f"Statistiques : {json.dumps(result['stats'], indent=2)}\n\n"
            f"{result['content'][:500]}..."
        )
    except Exception as e:
        return f"❌ Erreur lors du dashboard : {e}"


def tool_read_analyser_output(input_str: str = "") -> str:
    """
    Outil : lit les données produites par l'Agent Analyseur depuis la mémoire partagée.
    """
    try:
        memory = _read_shared_memory()
        analyser_data = memory.get("analyser_output", None)
        if not analyser_data:
            return "⚠️ Aucune donnée de l'Agent Analyseur trouvée en mémoire partagée."
        return f"✅ Données de l'analyseur récupérées :\n{json.dumps(analyser_data, indent=2)}"
    except Exception as e:
        return f"❌ Erreur lecture mémoire partagée : {e}"


# ─── Liste des outils ─────────────────────────────────────────────────────────
TOOLS = [
    Tool(
        name        = "GenerateIncidentReport",
        func        = tool_generate_incident_report,
        description = (
            "Génère un rapport d'incident détaillé pour UN incident. "
            "Input : JSON string avec les champs de l'incident "
            "(incident_id, severity, attack_type, source_ip, dest_ip, anomalies, etc.)"
        ),
    ),
    Tool(
        name        = "GenerateSummaryReport",
        func        = tool_generate_summary,
        description = (
            "Génère un rapport de synthèse pour une LISTE d'incidents. "
            "Input : JSON string représentant une liste d'incidents."
        ),
    ),
    Tool(
        name        = "GenerateDashboard",
        func        = tool_generate_dashboard,
        description = (
            "Génère un tableau de bord synthétique avec statistiques SOC. "
            "Input : JSON string d'une liste d'incidents pour calculer les stats."
        ),
    ),
    Tool(
        name        = "ReadAnalyserOutput",
        func        = tool_read_analyser_output,
        description = (
            "Lit les résultats produits par l'Agent Analyseur depuis "
            "la mémoire partagée. Aucun input requis."
        ),
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

class RapporteurAgent:
    """
    Agent 3 — Rapporteur SOC
    Reçoit les incidents analysés et génère : rapports détaillés,
    synthèses et tableaux de bord.
    """

    def __init__(self):
        self.llm    = OllamaLLM(model=OLLAMA_MODEL, temperature=0.3)
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        self.agent_executor = self._build_agent()
        print(f"[RapporteurAgent] ✅ Initialisé avec le modèle : {OLLAMA_MODEL}")

    def _build_agent(self) -> AgentExecutor:
        """Construit l'agent ReAct avec ses outils."""
        prompt = PromptTemplate.from_template("""
Tu es l'Agent Rapporteur d'un SOC (Security Operations Center).
Ta mission est de transformer les données d'incidents de sécurité
en rapports professionnels, synthèses et tableaux de bord.

Tu as accès aux outils suivants :
{tools}

Noms des outils disponibles : {tool_names}

Utilise le format suivant :
Question: la tâche que tu dois accomplir
Thought: réfléchis à ce que tu dois faire
Action: le nom de l'outil à utiliser
Action Input: l'input de l'outil (JSON valide)
Observation: le résultat de l'outil
... (répète Thought/Action/Observation si nécessaire)
Thought: j'ai maintenant toutes les informations
Final Answer: ton rapport final ou résumé de ce qui a été généré

Historique de conversation :
{chat_history}

Question: {input}
{agent_scratchpad}
""")
        agent = create_react_agent(self.llm, TOOLS, prompt)
        return AgentExecutor(
            agent=agent,
            tools=TOOLS,
            memory=self.memory,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=5,
        )

    # ── Méthodes publiques ──────────────────────────────────────────────────

    def process_incident(self, incident_data: dict) -> dict:
        """
        Traite un seul incident : génère son rapport.
        Point d'entrée principal appelé par l'orchestrateur.
        """
        print(f"\n[RapporteurAgent] 🔔 Traitement incident : {incident_data.get('incident_id', '?')}")

        task = (
            f"Génère un rapport d'incident complet pour cet incident : "
            f"{json.dumps(incident_data)}"
        )
        result = self.agent_executor.invoke({"input": task})
        return {"status": "success", "output": result["output"]}

    def process_batch(self, incidents_list: list) -> dict:
        """
        Traite une liste d'incidents :
        - génère un rapport par incident critique/élevé
        - génère une synthèse globale
        - génère un tableau de bord
        """
        print(f"\n[RapporteurAgent] 📦 Traitement batch : {len(incidents_list)} incidents")

        reports = []

        # 1. Rapports individuels pour les incidents HIGH et CRITICAL
        for incident in incidents_list:
            if incident.get("severity", "").upper() in ("CRITICAL", "HIGH"):
                report = self.process_incident(incident)
                reports.append(report)

        # 2. Synthèse globale
        task_summary = (
            f"Génère un rapport de synthèse pour cette liste d'incidents : "
            f"{json.dumps(incidents_list)}"
        )
        summary = self.agent_executor.invoke({"input": task_summary})

        # 3. Tableau de bord
        task_dashboard = (
            f"Génère un tableau de bord statistique pour : "
            f"{json.dumps(incidents_list)}"
        )
        dashboard = self.agent_executor.invoke({"input": task_dashboard})

        return {
            "status"          : "success",
            "individual_reports": reports,
            "summary"         : summary["output"],
            "dashboard"       : dashboard["output"],
            "processed_at"    : datetime.now().isoformat(),
        }

    def run_from_shared_memory(self) -> dict:
        """
        Lit automatiquement les données de l'Agent Analyseur
        depuis la mémoire partagée et lance le traitement.
        """
        print("[RapporteurAgent] 🔗 Lecture depuis la mémoire partagée...")
        task = (
            "Lis les données de l'Agent Analyseur depuis la mémoire partagée, "
            "puis génère les rapports appropriés (rapport d'incident, synthèse et dashboard)."
        )
        result = self.agent_executor.invoke({"input": task})
        return {"status": "success", "output": result["output"]}


# ═══════════════════════════════════════════════════════════════════════════════
# MÉMOIRE PARTAGÉE (communication inter-agents)
# ═══════════════════════════════════════════════════════════════════════════════

def _read_shared_memory() -> dict:
    """Lit le fichier de mémoire partagée JSON."""
    if not os.path.exists(SHARED_MEMORY):
        return {}
    with open(SHARED_MEMORY, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_to_shared_memory(key: str, value: Any):
    """Écrit une valeur dans la mémoire partagée."""
    memory = _read_shared_memory()
    memory[key] = value
    memory["last_updated_by"] = "rapporteur_agent"
    memory["last_updated_at"] = datetime.now().isoformat()
    with open(SHARED_MEMORY, "w", encoding="utf-8") as f:
        json.dump(memory, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE DIRECT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    agent = RapporteurAgent()

    # Exemple d'incident simulé (normalement fourni par l'Agent Analyseur)
    sample_incident = {
        "incident_id"      : "INC-2024-001",
        "timestamp"        : "2024-01-15T14:32:00",
        "source_ip"        : "192.168.1.105",
        "dest_ip"          : "10.0.0.50",
        "attack_type"      : "Brute Force SSH",
        "severity"         : "HIGH",
        "anomalies"        : ["500 tentatives de connexion en 2 minutes", "IP inconnue"],
        "correlated_events": ["INC-2024-000", "INC-2024-002"],
        "affected_system"  : "Serveur SSH Production",
        "risk_score"       : 8.5,
        "false_positive"   : False,
    }

    result = agent.process_incident(sample_incident)
    print("\n=== RÉSULTAT FINAL ===")
    print(result["output"])
