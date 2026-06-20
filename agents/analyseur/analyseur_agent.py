"""
analyseur_agent.py
Agent Analyseur - Multi-Agent SOC System

Pipeline:
  SharedMemory (events_structured / pending_analysis)
    -> rules_engine   (fast heuristic enrichment, no LLM)
    -> correlator     (temporal cross-source correlation)
    -> LangChain + Mistral (deep analysis, only for severity >= 0.7)
    -> SharedMemory (analysis_results / correlation_alerts -> read by Rapporteur)

IMPORTANT - matches the real SharedMemory API written by the Extracteur team:
  - SharedMemory.write(channel, items) OVERWRITES the channel with the full list
  - SharedMemory.read(channel) just returns the list, it does NOT clear it
  -> So this agent keeps an in-memory set of event_ids it has already processed,
     to avoid re-analyzing the same events on every poll.
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from typing import Optional

# ── shared_memory.py now lives at the repo root ──
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

from shared_memory import SharedMemory

from agents.analyseur.rules_engine import analyze_event
from agents.analyseur.correlator import CorrelationEngine

# ── LangChain + Ollama ────────────────────────────────────────────────────────
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("AnalyseurAgent")

# ─── LLM Prompt ──────────────────────────────────────────────────────────────
ANALYSIS_PROMPT = PromptTemplate(
    input_variables=["event_json", "entities_json", "event_type"],
    template="""You are a SOC (Security Operations Center) analyst AI.
Analyze the following security event and respond ONLY in JSON, no extra text, no markdown fences.

EVENT TYPE: {event_type}
EXTRACTED ENTITIES: {entities_json}
FULL EVENT: {event_json}

Respond with this EXACT JSON structure:
{{
  "attack_summary": "<one sentence describing what is happening>",
  "attack_technique": "<MITRE ATT&CK technique name if applicable, else UNKNOWN>",
  "affected_assets": ["<ip or hostname>"],
  "recommended_action": "<immediate action the SOC should take>",
  "confidence": <float 0.0 to 1.0>,
  "needs_escalation": <true or false>
}}"""
)


class AnalyseurAgent:
    def __init__(self, model_name: str = "mistral", poll_interval: float = 2.0):
        processed_dir = os.path.join(PROJECT_ROOT, "data", "processed")
        self.memory = SharedMemory(base_dir=processed_dir)
        self.correlator = CorrelationEngine()
        self.poll_interval = poll_interval
        self._running = True

        # Track which event_ids have already been processed, per channel,
        # since SharedMemory.read() does not clear the channel.
        self._seen_ids = {
            "pending_analysis": set(),
            "events_structured": set(),
        }

        log.info(f"[INIT] Loading Ollama model: {model_name}")
        self.llm = OllamaLLM(model=model_name, temperature=0.0)
        log.info("[INIT] LLM ready.")

        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, *_):
        log.warning("[SHUTDOWN] Signal received - stopping after current loop...")
        self._running = False

    # ─── Main loop ────────────────────────────────────────────────────────────
    def run(self):
        log.info("[START] Agent Analyseur running. Polling shared memory channels...")
        while self._running:
            try:
                self._process_channel("pending_analysis", priority=True)
                self._process_channel("events_structured", priority=False)
            except Exception as e:
                log.error(f"[ERROR] Polling loop error: {e}", exc_info=True)
            time.sleep(self.poll_interval)
        log.info("[STOP] Agent Analyseur stopped cleanly.")

    def _process_channel(self, channel: str, priority: bool):
        events = self.memory.read(channel)
        if not events:
            return

        new_events = [
            e for e in events
            if e.get("event_id") and e["event_id"] not in self._seen_ids[channel]
        ]
        if not new_events:
            return

        label = "PRIORITY" if priority else "STANDARD"
        log.info(f"[{label}] {len(new_events)} new event(s) on [{channel}]")

        for event in new_events:
            try:
                self._handle_event(event)
            except Exception as e:
                log.error(f"[ERROR] Failed on event {event.get('event_id', '?')}: {e}", exc_info=True)
            finally:
                self._seen_ids[channel].add(event.get("event_id"))

    # ─── Per-event pipeline ───────────────────────────────────────────────────
    def _handle_event(self, event: dict):
        event_id = event.get("event_id", "UNKNOWN")
        log.info(f"[ANALYZE] {event_id} (source: {event.get('source')})")

        enriched = analyze_event(event)
        log.info(
            f"[HEURISTIC] {event_id} -> type={enriched['event_type']} "
            f"severity={enriched['heuristic_severity']} needs_llm={enriched['needs_llm_analysis']}"
        )

        correlation_alert = self.correlator.add_event(enriched)
        if correlation_alert:
            log.warning(
                f"[CORRELATION] Pattern: {correlation_alert['pattern']} "
                f"IP: {correlation_alert['attacker_ip']} "
                f"Severity: {correlation_alert['severity_label']}"
            )
            self._append_to_channel("correlation_alerts", correlation_alert)

        llm_result = None
        if enriched["needs_llm_analysis"]:
            llm_result = self._llm_analyze(enriched)

        result = self._build_result(enriched, llm_result, correlation_alert)
        self._append_to_channel("analysis_results", result)
        log.info(f"[PUBLISHED] {event_id} -> [analysis_results]")

    # ─── LLM analysis ─────────────────────────────────────────────────────────
    def _llm_analyze(self, enriched: dict) -> Optional[dict]:
        event_id = enriched.get("event_id", "?")
        log.info(f"[LLM] Sending {event_id} to Mistral...")

        prompt_text = ANALYSIS_PROMPT.format(
            event_json=json.dumps({
                "event_id": enriched.get("event_id"),
                "timestamp": enriched.get("timestamp"),
                "source": enriched.get("source"),
                "severity": enriched.get("heuristic_severity"),
                "message": enriched.get("message"),
            }, indent=2),
            entities_json=json.dumps(enriched.get("entities", {}), indent=2),
            event_type=enriched.get("event_type", "UNKNOWN"),
        )

        raw_output = ""
        try:
            raw_output = self.llm.invoke(prompt_text)
            clean = raw_output.strip()
            if clean.startswith("```"):
                clean = clean.strip("`")
                if clean.startswith("json"):
                    clean = clean[4:]
            parsed = json.loads(clean.strip())
            log.info(f"[LLM] OK for {event_id}: {parsed.get('attack_summary', '')[:80]}")
            return parsed
        except json.JSONDecodeError as e:
            log.warning(f"[LLM] JSON parse error for {event_id}: {e}. Raw (first 200 chars): {raw_output[:200]}")
            return None
        except Exception as e:
            log.error(f"[LLM] Call failed for {event_id}: {e}")
            return None

    # ─── Output builders ──────────────────────────────────────────────────────
    def _build_result(self, enriched: dict, llm_result: Optional[dict],
                       correlation_alert: Optional[dict]) -> dict:
        final_severity = enriched["heuristic_severity"]

        if correlation_alert and correlation_alert["correlation_severity"] >= 1.0:
            final_severity = 1.0

        if llm_result and isinstance(llm_result.get("confidence"), (int, float)):
            final_severity = round(0.7 * final_severity + 0.3 * float(llm_result["confidence"]), 2)
            final_severity = min(final_severity, 1.0)

        return {
            "event_id": enriched.get("event_id"),
            "timestamp": enriched.get("timestamp"),
            "analyzed_at": datetime.utcnow().isoformat(),
            "source": enriched.get("source"),
            "event_type": enriched.get("event_type"),
            "final_severity": final_severity,
            "severity_label": _label(final_severity),
            "entities": enriched.get("entities"),
            "llm_analysis": llm_result,
            "correlation_alert": correlation_alert,
            "original_message": enriched.get("message"),
        }

    def _append_to_channel(self, channel: str, item: dict):
        """
        Mirrors the real SharedMemory semantics: write() overwrites the whole
        channel, so we read-modify-write to append safely.
        """
        existing = self.memory.read(channel)
        existing.append(item)
        self.memory.write(channel, existing)


def _label(score: float) -> str:
    if score >= 1.0: return "CRITICAL"
    if score >= 0.85: return "HIGH"
    if score >= 0.7: return "MEDIUM"
    if score >= 0.4: return "LOW"
    return "INFO"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Agent Analyseur")
    parser.add_argument("--model", default="mistral", help="Ollama model name")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()

    agent = AnalyseurAgent(model_name=args.model, poll_interval=args.poll_interval)
    agent.run()