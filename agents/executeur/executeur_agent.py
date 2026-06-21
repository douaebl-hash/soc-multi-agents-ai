"""
executeur_agent.py
AI-Driven Agent Exécuteur — Based on the ORIGINAL working approach.
Uses simple LangChain invoke + asks Mistral for clean JSON.
"""

import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

from shared_memory import SharedMemory
from agents.executeur.response_engine import ResponseEngine
from agents.executeur.action_logger import ActionLogger

from langchain_ollama import OllamaLLM

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ExecuteurAgent")


class ExecuteurAgent:
    def __init__(
        self,
        model_name: str = "mistral",
        poll_interval: float = 3.0,
        dry_run: bool = False,
        severity_threshold: List[str] = None,
    ):
        processed_dir = os.path.join(PROJECT_ROOT, "data", "processed")
        reports_dir = os.path.join(PROJECT_ROOT, "data", "reports")
        self.memory = SharedMemory(base_dir=processed_dir)
        self.engine = ResponseEngine(dry_run=dry_run)
        self.logger = ActionLogger()
        self.poll_interval = poll_interval
        self.dry_run = dry_run
        self._running = True
        self._seen_ids: set = set()
        self.severity_threshold = set(severity_threshold or ["CRITICAL", "HIGH"])
        self.reports_dir = reports_dir

        log.info(f"[INIT] Loading Ollama model: {model_name}")
        self.llm = OllamaLLM(model=model_name, temperature=0.0)
        log.info("[INIT] LLM ready.")

        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, *_):
        log.warning("[SHUTDOWN] Signal received — stopping after current loop...")
        self._running = False

    def run(self):
        log.info("[START] Agent Exécuteur running. Polling for incidents...")
        while self._running:
            try:
                self._poll_cycle()
            except Exception as e:
                log.error(f"[ERROR] Polling loop error: {e}", exc_info=True)
            time.sleep(self.poll_interval)
        log.info("[STOP] Agent Exécuteur stopped cleanly.")

    def _poll_cycle(self):
        actions_queue = self.memory.read("actions_a_executer")
        history_incidents = self._read_history_incidents()

        candidates = []
        for inc in (actions_queue or []) + history_incidents:
            if not isinstance(inc, dict):
                continue
            inc_id = inc.get("incident_id") or inc.get("event_id")
            if inc_id and inc_id not in self._seen_ids:
                candidates.append(inc)

        if not candidates:
            return

        log.info(f"[POLL] {len(candidates)} new incident(s) to process")
        for incident in candidates:
            try:
                self._handle_incident(incident)
            except Exception as e:
                log.error(f"[ERROR] Failed on incident {incident.get('incident_id', '?')}: {e}", exc_info=True)
            finally:
                self._seen_ids.add(incident.get("incident_id") or incident.get("event_id"))

    def _handle_incident(self, incident: dict):
        inc_id = incident.get("incident_id") or incident.get("event_id", "UNKNOWN")
        severity = (incident.get("severity", "") or "").upper()
        needs_escalation = incident.get("needs_escalation", False)

        log.info(f"[HANDLE] {inc_id} | severity={severity} | escalation={needs_escalation}")

        if severity not in self.severity_threshold and not needs_escalation:
            log.info(f"[SKIP] {inc_id} — below threshold and no escalation flag")
            self._log_skip(inc_id, severity)
            return

        # Fetch rapporteur report
        report_content = self._fetch_rapporteur_report(inc_id)
        log.info(f"[REPORT] {inc_id} — rapporteur report {'found' if report_content else 'not found'}")

        # LLM generates the response plan
        response_plan = self._generate_response_plan(incident, report_content)
        if not response_plan:
            log.error(f"[FAIL] {inc_id} — could not generate response plan")
            return

        reasoning = response_plan.get("reasoning", "No reasoning provided")
        actions = response_plan.get("actions", [])
        log.info(f"[PLAN] {inc_id} — {len(actions)} action(s) | Reason: {reasoning[:100]}...")

        # Execute each action
        action_results = []
        for action_def in actions:
            result = self.engine.execute(action_def, incident)
            action_results.append(result)
            time.sleep(0.1)

        # Build execution record
        execution_record = {
            "execution_id": f"exec_{inc_id}_{int(time.time())}",
            "incident_id": inc_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions_taken": action_results,
            "ai_reasoning": reasoning,
            "playbook_used": "ai_generated",
            "executed_by": "executeur_agent",
            "requires_human_review": severity == "CRITICAL",
        }

        self.logger.log(execution_record)
        self._append_to_channel("execution_log", execution_record)
        log.info(f"[DONE] {inc_id} — {len(action_results)} action(s) executed")

    def _generate_response_plan(self, incident: dict, report_content: str) -> Optional[dict]:
        """Ask Mistral to generate a structured response plan."""
        try:
            incident_json = json.dumps(incident, indent=2, default=str, ensure_ascii=False)

            # SIMPLE prompt — just like the original working version
            prompt = f"""You are a SOC response orchestrator AI.

Analyze this security incident and decide which actions to execute.

Available actions: BLOCK_IP, UNBLOCK_IP, BLOCK_PORT, KILL_PROCESS, DISABLE_USER, FLUSH_DNS, NOTIFY_ADMIN, LOG_ONLY.

Rules:
- CRITICAL: block IP + notify
- HIGH: block IP + notify
- MEDIUM/LOW: notify or log
- NEVER block internal IPs (10.x, 172.16-31.x, 192.168.x)

Incident:
{incident_json}

Report:
{report_content or "No report available."}

Respond with ONLY this JSON (no other text):
{{"reasoning": "brief justification", "actions": [{{"action": "BLOCK_IP", "parameters": {{"ip": "203.0.113.50", "duration_minutes": 60}}, "reasoning": "blocking attacker"}}]}}"""

            log.info(f"[LLM] Sending incident {incident.get('incident_id', '?')} to Mistral...")
            raw = self.llm.invoke(prompt)

            log.info(f"[LLM] Raw response: {raw[:200]}...")

            # Extract JSON — multiple strategies
            parsed = self._extract_json(raw)

            if parsed and "actions" in parsed:
                log.info(f"[LLM] SUCCESS — {len(parsed['actions'])} action(s) suggested")
                return parsed
            else:
                log.warning("[LLM] Response missing 'actions' field")
                return self._fallback_response_plan(incident)

        except Exception as e:
            log.error(f"[LLM] Call failed: {e}")
            return self._fallback_response_plan(incident)

    def _extract_json(self, text: str) -> Optional[dict]:
        """Extract JSON from Mistral response."""
        text = text.strip()

        # Strategy 1: Find JSON between ``` and ```
        match = re.search(r'```(?:json)?\s*\n(.*?)\n```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except:
                pass

        # Strategy 2: Find first { to last }
        try:
            start = text.index('{')
            end = text.rindex('}') + 1
            return json.loads(text[start:end])
        except:
            pass

        # Strategy 3: Try entire text
        try:
            return json.loads(text)
        except:
            pass

        return None

    def _fallback_response_plan(self, incident: dict) -> dict:
        """Deterministic fallback when LLM fails."""
        severity = (incident.get("severity", "") or "").upper()
        source_ip = incident.get("source_ip", "")
        inc_id = incident.get("incident_id", "UNKNOWN")

        is_public = (source_ip and 
                     not self.engine._is_internal_ip(source_ip) and 
                     self.engine._is_valid_ip(source_ip))

        actions = []
        if severity == "CRITICAL":
            if is_public:
                actions.append({"action": "BLOCK_IP", "parameters": {"ip": source_ip, "duration_minutes": 120}, "reasoning": "Critical: blocking attacker"})
            actions.append({"action": "NOTIFY_ADMIN", "parameters": {"message": f"CRITICAL incident {inc_id}", "severity": "CRITICAL"}, "reasoning": "Critical: notify team"})
        elif severity == "HIGH":
            if is_public:
                actions.append({"action": "BLOCK_IP", "parameters": {"ip": source_ip, "duration_minutes": 60}, "reasoning": "High: blocking attacker"})
            actions.append({"action": "NOTIFY_ADMIN", "parameters": {"message": f"HIGH incident {inc_id}", "severity": "HIGH"}, "reasoning": "High: notify team"})
        else:
            actions.append({"action": "LOG_ONLY", "parameters": {"reason": f"Severity {severity} below threshold"}, "reasoning": "Low severity, log only"})

        return {"reasoning": f"Fallback (severity={severity})", "actions": actions}

    def _fetch_rapporteur_report(self, incident_id: str) -> str:
        if not os.path.exists(self.reports_dir):
            return ""
        for fname in os.listdir(self.reports_dir):
            if fname.startswith(f"incident_report_{incident_id}") and fname.endswith(".txt"):
                try:
                    with open(os.path.join(self.reports_dir, fname), "r", encoding="utf-8") as f:
                        return f.read()
                except OSError:
                    continue
        for fname in os.listdir(self.reports_dir):
            if fname.startswith("summary_report_") and fname.endswith(".txt"):
                try:
                    with open(os.path.join(self.reports_dir, fname), "r", encoding="utf-8") as f:
                        return f.read()
                except OSError:
                    continue
        return ""

    def _read_history_incidents(self) -> List[dict]:
        history_path = os.path.join(PROJECT_ROOT, "data", "shared", "incidents_history.json")
        if not os.path.exists(history_path):
            return []
        try:
            with open(history_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return list(data.values())
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _append_to_channel(self, channel: str, item: dict):
        existing = self.memory.read(channel)
        existing.append(item)
        self.memory.write(channel, existing)

    def _log_skip(self, inc_id: str, severity: str):
        skip_record = {
            "execution_id": f"skip_{inc_id}",
            "incident_id": inc_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions_taken": [],
            "ai_reasoning": "Incident below severity threshold",
            "playbook_used": "none",
            "executed_by": "executeur_agent",
            "requires_human_review": False,
        }
        self.logger.log(skip_record)
        self._append_to_channel("execution_log", skip_record)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Agent Exécuteur SOC")
    parser.add_argument("--model", default="mistral")
    parser.add_argument("--poll-interval", type=float, default=3.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--severity", nargs="+", default=["CRITICAL", "HIGH"])
    args = parser.parse_args()

    agent = ExecuteurAgent(
        model_name=args.model,
        poll_interval=args.poll_interval,
        dry_run=args.dry_run,
        severity_threshold=args.severity,
    )
    agent.run()