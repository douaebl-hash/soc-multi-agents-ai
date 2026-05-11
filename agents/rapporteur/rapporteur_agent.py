# agents/rapporteur/rapporteur_agent.py
# Agent 3 — Rapporteur SOC
# Approche directe (sans ReAct) — compatible avec les SLMs comme Mistral

import json
import os
from datetime import datetime

from report_generator import (
    generate_incident_report,
    generate_summary_report,
    generate_dashboard,
)

# ─── Mémoire partagée ─────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHARED_MEMORY = os.getenv("SHARED_MEMORY_PATH", os.path.join(BASE_DIR, "data", "shared", "memory.json"))
os.makedirs(os.path.dirname(SHARED_MEMORY), exist_ok=True)


def _read_shared_memory() -> dict:
    if not os.path.exists(SHARED_MEMORY):
        return {}
    with open(SHARED_MEMORY, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_to_shared_memory(key: str, value):
    memory = _read_shared_memory()
    memory[key] = value
    memory["last_updated_by"] = "rapporteur_agent"
    memory["last_updated_at"] = datetime.now().isoformat()
    with open(SHARED_MEMORY, "w", encoding="utf-8") as f:
        json.dump(memory, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT RAPPORTEUR — Logique directe
# ═══════════════════════════════════════════════════════════════════════════════

class RapporteurAgent:
    """
    Agent 3 — Rapporteur SOC
    Appelle directement les fonctions de génération sans passer
    par un agent ReAct (plus fiable avec les SLMs).
    """

    def __init__(self):
        print("[RapporteurAgent] ✅ Initialisé")

    def process_incident(self, incident_data: dict) -> dict:
        """Génère un rapport détaillé pour un seul incident."""
        print(f"\n[RapporteurAgent] 🔔 Traitement incident : {incident_data.get('incident_id', '?')}")

        result = generate_incident_report(incident_data)
        _write_to_shared_memory("last_incident_report", {
            "incident_id" : result["incident_id"],
            "filepath"    : result["filepath"],
            "generated_at": result["generated_at"],
        })

        print(f"[RapporteurAgent] ✅ Rapport généré : {result['filepath']}")
        return result

    def process_batch(self, incidents_list: list) -> dict:
        """Rapport individuel (HIGH/CRITICAL) + synthèse + dashboard."""
        print(f"\n[RapporteurAgent] 📦 Batch : {len(incidents_list)} incidents")

        individual_reports = []
        for incident in incidents_list:
            if incident.get("severity", "").upper() in ("CRITICAL", "HIGH"):
                r = self.process_incident(incident)
                individual_reports.append({"incident_id": r["incident_id"], "filepath": r["filepath"]})

        print("\n[RapporteurAgent] 📋 Génération de la synthèse...")
        summary = generate_summary_report(incidents_list)
        _write_to_shared_memory("last_summary_report", {"filepath": summary["filepath"], "generated_at": summary["generated_at"]})

        print("\n[RapporteurAgent] 📊 Génération du dashboard...")
        dashboard = generate_dashboard(incidents_list)
        _write_to_shared_memory("last_dashboard", {"filepath": dashboard["filepath"], "stats": dashboard["stats"], "generated_at": dashboard["generated_at"]})

        result = {
            "status"            : "success",
            "individual_reports": individual_reports,
            "summary_filepath"  : summary["filepath"],
            "dashboard_filepath": dashboard["filepath"],
            "stats"             : dashboard["stats"],
            "processed_at"      : datetime.now().isoformat(),
        }

        print(f"\n[RapporteurAgent] ✅ Batch terminé — {len(individual_reports)} rapport(s) individuel(s)")
        return result

    def run_from_shared_memory(self) -> dict:
        """Lit les incidents de l'Agent Analyseur et lance le traitement."""
        print("[RapporteurAgent] 🔗 Lecture mémoire partagée...")
        memory = _read_shared_memory()
        analyser_output = memory.get("analyser_output")
        if not analyser_output:
            print("[RapporteurAgent] ⚠️  Aucune donnée de l'Agent Analyseur trouvée.")
            return {"status": "no_data"}
        incidents = analyser_output if isinstance(analyser_output, list) else [analyser_output]
        return self.process_batch(incidents)


# ═══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    agent = RapporteurAgent()

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

    print("\n" + "=" * 60)
    print("RAPPORT GÉNÉRÉ :")
    print("=" * 60)
    print(result["content"])