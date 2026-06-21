"""
executeur_agent.py
Agent Exécuteur — Per-Incident Email with Action Tracking.

Sends ONE email per incident showing:
  - What the Rapporteur suggested
  - What was actually executed (automated)
  - What requires manual intervention
  - Summary at the end
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
        log.info("[START] Agent Exécuteur (Per-Incident Email) running...")
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

        # Step 1: Fetch Rapporteur report
        report_content = self._fetch_rapporteur_report(inc_id)
        has_report = bool(report_content)

        if not has_report:
            log.warning(f"[REPORT] {inc_id} — NO Rapporteur report found!")
        else:
            log.info(f"[REPORT] {inc_id} — Rapporteur report FOUND ({len(report_content)} chars)")

        # Extract Rapporteur suggested actions BEFORE translation
        suggested_actions = self._extract_suggested_actions(report_content)

        # Step 2: Mistral translates to commands
        response_plan = self._translate_to_commands(incident, report_content)

        if not response_plan:
            log.error(f"[FAIL] {inc_id} — Could not translate Rapporteur recommendations")
            return

        reasoning = response_plan.get("reasoning", "No reasoning provided")
        actions = response_plan.get("actions", [])
        log.info(f"[PLAN] {inc_id} — {len(actions)} command(s) from Mistral")

        # Step 3: Execute all commands and collect results
        automated_results = []
        manual_tasks = []

        for action_def in actions:
            result = self.engine.execute(action_def, incident)

            # Categorize: automated vs manual
            if result["status"] in ["success", "simulated"]:
                automated_results.append(result)
            elif result["status"] == "blocked_by_policy":
                manual_tasks.append({
                    "task": f"Manual review required: {result['action']} on {result.get('target', 'N/A')}",
                    "reason": result["details"],
                    "original_action": result["action"]
                })
            elif result["status"] in ["pending_confirmation", "failed"]:
                manual_tasks.append({
                    "task": f"Action failed/needs confirmation: {result['action']}",
                    "reason": result["details"],
                    "original_action": result["action"]
                })

            log.info(f"[EXECUTE] {result['action']} -> {result['status']} | {result['details'][:60]}...")
            time.sleep(0.1)

        # Step 4: Build per-incident email with action tracking
        self._send_incident_email(incident, suggested_actions, automated_results, manual_tasks, report_content)

        # Step 5: Log everything
        execution_record = {
            "execution_id": f"exec_{inc_id}_{int(time.time())}",
            "incident_id": inc_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions_taken": automated_results + [{"task": t["task"], "status": "manual"} for t in manual_tasks],
            "ai_reasoning": reasoning,
            "rapporteur_report_used": has_report,
            "playbook_used": "command_translator",
            "executed_by": "executeur_agent",
            "requires_human_review": len(manual_tasks) > 0 or severity == "CRITICAL",
        }

        self.logger.log(execution_record)
        self._append_to_channel("execution_log", execution_record)
        log.info(f"[DONE] {inc_id} — {len(automated_results)} automated, {len(manual_tasks)} manual tasks")

    def _extract_suggested_actions(self, report_content: str) -> List[str]:
        """Extract the 'Actions Suggérées pour l\'Agent Exécuteur' section from report."""
        if not report_content:
            return []

        lines = report_content.split('\n')
        suggested = []
        in_actions_section = False

        for line in lines:
            stripped = line.strip()
            # Detect start of Actions Suggérées section
            if any(keyword in stripped.lower() for keyword in [
                "actions suggérées", "actions suggerees", 
                "actions suggérées pour l'agent", "actions suggerees pour l'agent",
                "actions for executeur", "suggested actions"
            ]):
                in_actions_section = True
                continue
            # Detect end of section (next ## header)
            if in_actions_section and stripped.startswith('##'):
                break
            # Collect bullet points in the section
            if in_actions_section and stripped:
                # Skip empty lines and section headers
                if stripped.startswith('#') or not stripped:
                    continue
                # Clean up bullet markers
                clean = re.sub(r'^[\s\-•\*\d\.]+', '', stripped).strip()
                if clean:
                    suggested.append(clean)

        return suggested

    def _send_incident_email(self, incident: dict, suggested_actions: List[str], 
                             automated_results: list, manual_tasks: list, report_content: str):
        """Send ONE email per incident tracking Rapporteur suggestions vs execution."""
        inc_id = incident.get("incident_id", "UNKNOWN")
        severity = incident.get("severity", "UNKNOWN")
        attack_type = incident.get("attack_type", "Unknown")
        source_ip = incident.get("source_ip", "N/A")

        executed_count = len(automated_results)
        manual_count = len(manual_tasks)
        total_suggested = len(suggested_actions)

        # Build email content
        email_lines = []

        # ═══════════════════════════════════════════════════════════════
        # HEADER
        # ═══════════════════════════════════════════════════════════════
        email_lines.append(f"""🛡️ SOC SECURITY ALERT — INCIDENT RESPONSE REPORT
{'='*65}
📌 Incident ID: {inc_id}
🔴 Severity: {severity}
🎯 Attack Type: {attack_type}
🌐 Source IP: {source_ip}
⏰ Time: {datetime.now(timezone.utc).isoformat()}
🤖 Mode: {"REAL EXECUTION" if not self.dry_run else "SIMULATION MODE"}
{'='*65}
""")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 1: RAPPORTEUR SUGGESTED ACTIONS
        # ═══════════════════════════════════════════════════════════════
        email_lines.append("""
📋 ACTIONS SUGGÉRÉES PAR LE RAPPORTEUR
────────────────────────────────────────
""")
        if suggested_actions:
            for i, action in enumerate(suggested_actions, 1):
                email_lines.append(f"   {i}. 📌 {action}")
        else:
            email_lines.append("   ⚠️ Aucune action spécifique suggérée dans le rapport.")
        email_lines.append("")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 2: EXECUTED ACTIONS (Automated)
        # ═══════════════════════════════════════════════════════════════
        email_lines.append("""
✅ ACTIONS EXÉCUTÉES AUTOMATIQUEMENT
────────────────────────────────────
""")
        if automated_results:
            for i, result in enumerate(automated_results, 1):
                status_icon = "✅" if result["status"] == "success" else "🧪"
                email_lines.append(f"""
   {i}. {status_icon} {result['action']}
      ├─ Target: {result.get('target', 'N/A')}
      ├─ Status: {result['status'].upper()}
      ├─ Details: {result['details']}
      └─ Duration: {result['duration_ms']}ms
""")
        else:
            email_lines.append("   ❌ Aucune action n\'a été exécutée automatiquement.")
        email_lines.append("")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 3: MANUAL INTERVENTION REQUIRED
        # ═══════════════════════════════════════════════════════════════
        email_lines.append("""
🔧 INTERVENTION MANUELLE REQUISE
─────────────────────────────────
""")
        if manual_tasks:
            for i, task in enumerate(manual_tasks, 1):
                email_lines.append(f"""
   {i}. ⚠️ {task['task']}
      ├─ Raison: {task['reason']}
      └─ 🔴 Action requise: Veuillez examiner et exécuter manuellement si approprié.
""")
        else:
            email_lines.append("   ✅ Aucune intervention manuelle requise.")
        email_lines.append("")

        # ═══════════════════════════════════════════════════════════════
        # SECTION 4: SUMMARY
        # ═══════════════════════════════════════════════════════════════
        email_lines.append(f"""
{'='*65}
📊 RÉSUMÉ DE L'INCIDENT
{'='*65}

   📋 Actions suggérées par le Rapporteur : {total_suggested}
   ✅ Actions exécutées automatiquement   : {executed_count}
   🔧 Actions nécessitant intervention manuelle : {manual_count}
   📈 Taux d\'automatisation              : {self._calc_automation_rate(executed_count, manual_count, total_suggested)}%

""")

        # Status summary
        if executed_count > 0 and manual_count == 0:
            email_lines.append("   🟢 STATUT: Toutes les actions ont été exécutées automatiquement.")
        elif executed_count > 0 and manual_count > 0:
            email_lines.append("   🟡 STATUT: Actions partiellement automatisées — intervention requise.")
        elif executed_count == 0 and manual_count > 0:
            email_lines.append("   🔴 STATUT: Aucune action automatisée — intervention manuelle totale requise.")
        else:
            email_lines.append("   ⚪ STATUT: Aucune action à exécuter pour cet incident.")

        email_lines.append(f"""

   💡 Recommandation:
   {"Veuillez procéder aux actions manuelles listées ci-dessus." if manual_count > 0 else "Aucune action supplémentaire requise."}

{'='*65}
Generated by SOC Multi-Agent System
Agent: Exécuteur | Mode: {"REAL" if not self.dry_run else "SIMULATION"}
{'='*65}
""")

        # Combine and send
        unified_message = "\n".join(email_lines)

        email_result = self.engine.notify_admin(
            message=unified_message,
            severity=severity,
            incident_id=inc_id
        )

        log.info(f"[EMAIL] Incident email sent: {email_result['status']}")
        if email_result['status'] == 'success':
            log.info(f"[EMAIL] ✅ Email sent for incident {inc_id}")

        return email_result

    def _calc_automation_rate(self, executed: int, manual: int, suggested: int) -> int:
        """Calculate automation rate percentage."""
        total = executed + manual
        if total == 0:
            return 0 if suggested == 0 else 0
        return round((executed / total) * 100)

    def _translate_to_commands(self, incident: dict, report_content: str) -> Optional[dict]:
        """Ask Mistral to translate Rapporteur recommendations into specific commands."""
        try:
            incident_json = json.dumps(incident, indent=2, default=str, ensure_ascii=False)

            prompt = f"""You are a SOC command translator AI.

The Rapporteur has decided what to do. Your job is to translate into specific commands.

AVAILABLE COMMANDS:
- BLOCK_IP: Block an IP. Parameters: ip, duration_minutes
- UNBLOCK_IP: Remove IP block. Parameters: ip
- BLOCK_PORT: Block a port. Parameters: port
- KILL_PROCESS: Terminate process. Parameters: process
- DISABLE_USER: Disable account. Parameters: user
- FLUSH_DNS: Clear DNS cache. Parameters: none
- NOTIFY_ADMIN: Send alert. Parameters: message, severity
- LOG_ONLY: Log incident. Parameters: reason

RULES:
- Follow Rapporteur recommendations EXACTLY
- If Rapporteur says "block IP", use BLOCK_IP
- If Rapporteur says "notify", use NOTIFY_ADMIN
- If Rapporteur says "isolate host", use BLOCK_PORT or LOG_ONLY
- NEVER block internal IPs (10.x, 172.16-31.x, 192.168.x)
- For internal IPs, use LOG_ONLY instead of BLOCK_IP

=== INCIDENT ===
{incident_json}

=== RAPPORTEUR REPORT (FOLLOW THIS) ===
{report_content or "No report available."}

Respond with ONLY this JSON:
{{"reasoning": "Translating Rapporteur recommendations", "actions": [{{"action": "BLOCK_IP", "parameters": {{"ip": "203.0.113.50", "duration_minutes": 60}}, "reasoning": "Rapporteur said block"}}]}}"""

            log.info(f"[LLM] Translating recommendations for {incident.get('incident_id', '?')}...")
            raw = self.llm.invoke(prompt)

            parsed = self._extract_json(raw)

            if parsed and "actions" in parsed:
                log.info(f"[LLM] SUCCESS — {len(parsed['actions'])} command(s)")
                return parsed
            else:
                log.warning("[LLM] Invalid response, using fallback")
                return self._fallback_translate(incident, report_content)

        except Exception as e:
            log.error(f"[LLM] Failed: {e}")
            return self._fallback_translate(incident, report_content)

    def _extract_json(self, text: str) -> Optional[dict]:
        """Extract JSON from text."""
        text = text.strip()

        # Strategy 1: Fences
        match = re.search(r'```(?:json)?\s*\n(.*?)\n```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except:
                pass

        # Strategy 2: First { to last }
        try:
            start = text.index('{')
            end = text.rindex('}') + 1
            return json.loads(text[start:end])
        except:
            pass

        # Strategy 3: Entire text
        try:
            return json.loads(text)
        except:
            pass

        return None

    def _fallback_translate(self, incident: dict, report_content: str) -> dict:
        """Parse Rapporteur report manually and create commands."""
        severity = (incident.get("severity", "") or "").upper()
        source_ip = incident.get("source_ip", "")
        inc_id = incident.get("incident_id", "UNKNOWN")

        is_public = (source_ip and 
                     not self.engine._is_internal_ip(source_ip) and 
                     self.engine._is_valid_ip(source_ip))

        actions = []

        if report_content:
            report_lower = report_content.lower()

            if "bloquer" in report_lower or "block" in report_lower:
                if is_public:
                    actions.append({
                        "action": "BLOCK_IP",
                        "parameters": {"ip": source_ip, "duration_minutes": 120 if severity == "CRITICAL" else 60},
                        "reasoning": "Rapporteur recommended blocking IP"
                    })
                else:
                    actions.append({
                        "action": "LOG_ONLY",
                        "parameters": {"reason": f"Rapporteur recommended blocking internal IP {source_ip} — blocked by policy"},
                        "reasoning": "Internal IP blocking prohibited"
                    })

            if "isoler" in report_lower or "isolate" in report_lower:
                actions.append({
                    "action": "LOG_ONLY",
                    "parameters": {"reason": "Rapporteur recommended isolation — requires manual network configuration"},
                    "reasoning": "Host isolation requires manual intervention"
                })

            if "notifier" in report_lower or "notify" in report_lower:
                if not any(a["action"] == "NOTIFY_ADMIN" for a in actions):
                    actions.append({
                        "action": "NOTIFY_ADMIN",
                        "parameters": {
                            "message": f"Incident {inc_id}: {incident.get('attack_type', 'Unknown')} — Rapporteur recommends immediate attention",
                            "severity": severity
                        },
                        "reasoning": "Rapporteur recommended notification"
                    })

        if not actions:
            if severity == "CRITICAL":
                if is_public:
                    actions.append({"action": "BLOCK_IP", "parameters": {"ip": source_ip, "duration_minutes": 120}, "reasoning": "Critical: blocking attacker"})
                actions.append({"action": "NOTIFY_ADMIN", "parameters": {"message": f"CRITICAL incident {inc_id}", "severity": "CRITICAL"}, "reasoning": "Critical: notify team"})
            elif severity == "HIGH":
                if is_public:
                    actions.append({"action": "BLOCK_IP", "parameters": {"ip": source_ip, "duration_minutes": 60}, "reasoning": "High: blocking attacker"})
                actions.append({"action": "NOTIFY_ADMIN", "parameters": {"message": f"HIGH incident {inc_id}", "severity": "HIGH"}, "reasoning": "High: notify team"})
            else:
                actions.append({"action": "LOG_ONLY", "parameters": {"reason": f"Severity {severity}"}, "reasoning": "Low severity"})

        return {"reasoning": f"Fallback translation (severity={severity})", "actions": actions}

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
            "rapporteur_report_used": False,
            "playbook_used": "none",
            "executed_by": "executeur_agent",
            "requires_human_review": False,
        }
        self.logger.log(skip_record)
        self._append_to_channel("execution_log", skip_record)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Agent Exécuteur SOC (Per-Incident Email)")
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