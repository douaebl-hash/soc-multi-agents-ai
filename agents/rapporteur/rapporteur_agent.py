# agents/rapporteur/rapporteur_agent.py
# Agent 3 — Rapporteur SOC
# Approche directe (sans ReAct) — compatible avec les SLMs comme Mistral

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime

# ── Chemins pour importer la SharedMemory de l'Extracteur ─────────────────────
PROJECT_ROOT   = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EXTRACTEUR_DIR = os.path.join(PROJECT_ROOT, "agents", "extracteur")
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, EXTRACTEUR_DIR)

from shared_memory import SharedMemory

from report_generator import (
    generate_incident_report,
    generate_summary_report,
    generate_dashboard,
)
from dashboard_data import record_incident, record_incidents
from analyser_adapter import analyseur_result_to_incident_batch

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("RapporteurAgent")

# ─── Config chemins ───────────────────────────────────────────────────────────
# Même chemin que l'Analyseur (upstream direct) : PROJECT_ROOT/data/processed
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
SHARED_JSON   = os.getenv(
    "SHARED_MEMORY_PATH",
    os.path.join(PROJECT_ROOT, "data", "shared", "memory.json"),
)
os.makedirs(os.path.dirname(SHARED_JSON), exist_ok=True)

# ─── Canaux SharedMemory (écrits par l'Analyseur) ─────────────────────────────
CHANNEL_RESULTS      = "analysis_results"     # résultats analysés event par event
CHANNEL_CORRELATIONS = "correlation_alerts"   # alertes de corrélation croisée


# ─── Mémoire JSON simple (pour garder les métadonnées des rapports) ───────────

def _read_meta() -> dict:
    if not os.path.exists(SHARED_JSON):
        return {}
    try:
        with open(SHARED_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_meta(key: str, value):
    meta = _read_meta()
    meta[key] = value
    meta["last_updated_by"] = "rapporteur_agent"
    meta["last_updated_at"] = datetime.now().isoformat()
    with open(SHARED_JSON, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT RAPPORTEUR
# ═══════════════════════════════════════════════════════════════════════════════

class RapporteurAgent:
    """
    Agent 3 — Rapporteur SOC.

    Deux modes de fonctionnement :
    • Mode batch  : process_batch(incidents_list) — appelé manuellement avec des
                    incidents déjà au format Rapporteur.
    • Mode polling : run() — poll en continu la SharedMemory de l'Analyseur,
                    convertit les résultats via analyser_adapter, génère les
                    rapports et enregistre dans l'historique du dashboard.
    """

    def __init__(self, poll_interval: float = 5.0):
        self.shared_memory  = SharedMemory(base_dir=PROCESSED_DIR)
        self.poll_interval  = poll_interval
        self._running       = True
        # Garde les event_ids déjà traités pour éviter les doublons
        self._seen_ids: set = set()

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)
        log.info("✅ RapporteurAgent initialisé (base: %s)", PROCESSED_DIR)

    def _shutdown(self, *_):
        log.warning("⏹  Signal reçu — arrêt après le cycle courant...")
        self._running = False

    # ─── Mode polling ──────────────────────────────────────────────────────────

    def run(self):
        """
        Boucle principale : poll analysis_results, convertit via l'adaptateur,
        génère les rapports et alimente le dashboard.
        """
        log.info("▶  Mode polling démarré (intervalle: %.1fs)", self.poll_interval)
        while self._running:
            try:
                self._poll_cycle()
            except Exception as e:
                log.error("Erreur dans le cycle de polling : %s", e, exc_info=True)
            time.sleep(self.poll_interval)
        log.info("⏹  RapporteurAgent arrêté proprement.")

    def _poll_cycle(self):
        """Un cycle : lit les nouveaux résultats de l'Analyseur et les traite."""
        raw_results = self.shared_memory.read(CHANNEL_RESULTS)
        if not raw_results:
            return

        # Filtrer les event_ids déjà vus
        new_results = [
            r for r in raw_results
            if isinstance(r, dict) and r.get("event_id") not in self._seen_ids
        ]
        if not new_results:
            return

        log.info("🔔 %d nouveau(x) résultat(s) de l'Analyseur", len(new_results))

        # Adapter le format Analyseur → format Rapporteur
        incidents = analyseur_result_to_incident_batch(new_results)

        # Traiter le batch
        self.process_batch(incidents)

        # Marquer comme vus
        for r in new_results:
            self._seen_ids.add(r["event_id"])

    # ─── Traitement d'un incident unique ──────────────────────────────────────

    def process_incident(self, incident_data: dict) -> dict:
        """Génère un rapport détaillé pour un seul incident."""
        log.info("🔔 Traitement incident : %s", incident_data.get("incident_id", "?"))

        result = generate_incident_report(incident_data)
        record_incident(incident_data)
        _write_meta("last_incident_report", {
            "incident_id" : result["incident_id"],
            "filepath"    : result["filepath"],
            "generated_at": result["generated_at"],
        })

        log.info("✅ Rapport généré : %s", result["filepath"])
        return result

    # ─── Traitement d'un batch ─────────────────────────────────────────────────

    def process_batch(self, incidents_list: list) -> dict:
        """
        Rapport individuel pour chaque incident CRITICAL/HIGH,
        + synthèse globale + dashboard texte LLM.
        """
        if not incidents_list:
            return {"status": "empty"}

        log.info("📦 Batch : %d incident(s)", len(incidents_list))

        # Persistance dans l'historique dashboard
        record_incidents(incidents_list)

        # Rapports individuels (tous les incidents)
        individual_reports = []
        for incident in incidents_list:
            r = self.process_incident(incident)
            individual_reports.append({
                "incident_id": r["incident_id"],
                "filepath"   : r["filepath"],
            })

        # Synthèse globale
        log.info("📋 Génération de la synthèse...")
        summary = generate_summary_report(incidents_list)
        _write_meta("last_summary_report", {
            "filepath"    : summary["filepath"],
            "generated_at": summary["generated_at"],
        })

        # Dashboard textuel (généré par le LLM)
        log.info("📊 Génération du dashboard LLM...")
        dashboard = generate_dashboard(incidents_list)
        _write_meta("last_dashboard", {
            "filepath"    : dashboard["filepath"],
            "stats"       : dashboard["stats"],
            "generated_at": dashboard["generated_at"],
        })

        result = {
            "status"            : "success",
            "individual_reports": individual_reports,
            "summary_filepath"  : summary["filepath"],
            "dashboard_filepath": dashboard["filepath"],
            "stats"             : dashboard["stats"],
            "processed_at"      : datetime.now().isoformat(),
        }

        log.info(
            "✅ Batch terminé — %d rapport(s) individuel(s), synthèse : %s",
            len(individual_reports), summary["filepath"],
        )
        return result

    # ─── Lecture one-shot depuis la SharedMemory (ancien mode) ────────────────

    def run_from_shared_memory(self) -> dict:
        """
        Lecture one-shot : lit tous les résultats disponibles dans
        'analysis_results', les convertit et génère les rapports.
        Utile pour les tests ou un lancement manuel sans boucle.
        """
        log.info("🔗 Lecture one-shot de la SharedMemory (canal: %s)...", CHANNEL_RESULTS)
        raw_results = self.shared_memory.read(CHANNEL_RESULTS)

        if not raw_results:
            log.warning("⚠️  Aucune donnée dans '%s'.", CHANNEL_RESULTS)
            return {"status": "no_data"}

        log.info("📥 %d résultat(s) récupéré(s)", len(raw_results))
        incidents = analyseur_result_to_incident_batch(raw_results)
        return self.process_batch(incidents)


# ═══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Agent Rapporteur SOC")
    parser.add_argument(
        "--mode",
        choices=["poll", "once"],
        default="poll",
        help="poll = boucle continue | once = lecture one-shot",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Intervalle de polling en secondes (mode poll)",
    )
    args = parser.parse_args()

    agent = RapporteurAgent(poll_interval=args.poll_interval)

    if args.mode == "once":
        result = agent.run_from_shared_memory()
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        agent.run()