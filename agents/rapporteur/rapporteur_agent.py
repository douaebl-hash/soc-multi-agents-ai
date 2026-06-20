# agents/rapporteur/rapporteur_agent.py
# Agent 3 — Rapporteur SOC

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime

PROJECT_ROOT   = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EXTRACTEUR_DIR = os.path.join(PROJECT_ROOT, "agents", "extracteur")
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, EXTRACTEUR_DIR)

from shared_memory import SharedMemory

# Modification : On retire generate_dashboard qui n'est plus nécessaire
from report_generator import (
    generate_incident_report,
    generate_summary_report,
)
from dashboard_data import record_incidents
from analyser_adapter import analyseur_result_to_incident_batch

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("RapporteurAgent")

BASE_DIR = PROJECT_ROOT
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")
CHANNEL_RESULTS = "analysis_results"
MEMORY_JSON_PATH = os.path.join(BASE_DIR, "data", "shared", "memory.json")


class RapporteurAgent:
    def __init__(self, base_dir: str = None, poll_interval: float = 5.0):
        target_dir = base_dir or os.path.join(PROJECT_ROOT, "data", "processed")
        self.shared_memory = SharedMemory(base_dir=target_dir)
        self.poll_interval = poll_interval
        self._running = True
        self._seen_incident_ids = set()

        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, *_):
        log.warning("[SHUTDOWN] Signal reçu - Arrêt de l'Agent Rapporteur...")
        self._running = False

    def run(self, mode: str = "poll"):
        if mode == "once":
            self.run_once()
            return

        log.info("[START] Agent Rapporteur en écoute continue (canal: %s)...", CHANNEL_RESULTS)
        while self._running:
            try:
                raw_results = self.shared_memory.read(CHANNEL_RESULTS)
                if raw_results:
                    incidents = analyseur_result_to_incident_batch(raw_results)
                    new_incidents = [
                        inc for inc in incidents
                        if inc.get("incident_id") and inc["incident_id"] not in self._seen_incident_ids
                    ]

                    if new_incidents:
                        log.info("📥 %d nouvel/nouveaux incident(s) détecté(s)", len(new_incidents))
                        self.process_batch(new_incidents)
                        
                        for inc in new_incidents:
                            self._seen_incident_ids.add(inc["incident_id"])

            except Exception as e:
                log.error("[ERROR] Erreur dans la boucle de polling : %s", e, exc_info=True)

            time.sleep(self.poll_interval)

        log.info("[STOP] Agent Rapporteur arrêté proprement.")

    def process_batch(self, incidents: list) -> dict:
        log.info("🚀 Traitement d'un lot de %d incident(s)...", len(incidents))

        # 1. Enregistrement persistant pour le Dashboard graphique
        record_incidents(incidents)

        # 2. Génération des rapports d'incidents individuels (LLM)
        incident_reports = []
        for inc in incidents:
            log.info("✍️ Génération du rapport individuel pour : %s", inc.get("incident_id"))
            rep = generate_incident_report(inc)
            incident_reports.append(rep)

        # 3. Génération de la synthèse globale / Summary (LLM)
        log.info("📊 Génération de la synthèse globale (Summary Report)...")
        summary_rep = generate_summary_report(incidents)

        # 4. Mise à jour des métadonnées pour Streamlit (Sans le dashboard LLM textuel)
        self._update_shared_metadata(summary_rep)

        log.info("✅ Lot traité avec succès !")
        return {
            "status": "success",
            "incidents_count": len(incidents),
            "summary_filepath": summary_rep.get("filepath"),
        }

    def _update_shared_metadata(self, summary_rep: dict):
        """Met à jour le fichier d'index mémoire pour l'application Streamlit."""
        os.makedirs(os.path.dirname(MEMORY_JSON_PATH), exist_ok=True)
        meta = {}
        if os.path.exists(MEMORY_JSON_PATH):
            try:
                with open(MEMORY_JSON_PATH, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                meta = {}

        meta["last_summary_report"] = {
            "filepath": summary_rep.get("filepath"),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        # Nettoyage de l'ancienne clé du dashboard textuel pour éviter les conflits
        if "last_dashboard_report" in meta:
            del meta["last_dashboard_report"]

        try:
            with open(MEMORY_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=4, ensure_ascii=False)
        except Exception as e:
            log.error("❌ Impossible d'écrire les métadonnées partagées : %s", e)

    def run_once(self):
        log.info("🔗 Lecture one-shot de la SharedMemory (canal: %s)...", CHANNEL_RESULTS)
        raw_results = self.shared_memory.read(CHANNEL_RESULTS)

        if not raw_results:
            log.warning("⚠️  Aucune donnée dans '%s'.", CHANNEL_RESULTS)
            return {"status": "no_data"}

        log.info("📥 %d résultat(s) récupéré(s)", len(raw_results))
        incidents = analyseur_result_to_incident_batch(raw_results)
        return self.process_batch(incidents)


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
    agent.run(mode=args.mode)