"""
response_engine.py
AI-Driven Execution Engine with REAL email notifications.

Sends actual emails to: adamoulehiane2@gmail.com
"""

import json
import os
import subprocess
import time
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION EMAIL
# ═══════════════════════════════════════════════════════════════════════════════
DEFAULT_ALERT_EMAIL = "adamoulehiane2@gmail.com"

# ── Pour Gmail ────────────────────────────────────────────────────────────────
# Option 1: Mot de passe d'application Gmail (recommandé)
#   1. Va sur https://myaccount.google.com/apppasswords
#   2. Genere un mot de passe pour "Mail"
#   3. Definis la variable d'environnement: $env:SOC_SMTP_PASS = "xxxx xxxx xxxx xxxx"
#
# Option 2: Mot de passe normal (moins securise, peut necessiter "Acces moins securise")
#
# Option 3: Serveur SMTP de ton ecole/entreprise
#   $env:SOC_SMTP_SERVER = "smtp.votre-ecole.fr"
#   $env:SOC_SMTP_PORT = "587"
#   $env:SOC_SMTP_USER = "votre-login"
#   $env:SOC_SMTP_PASS = "votre-mot-de-passe"

SMTP_CONFIG = {
    "server": "smtp.gmail.com",
    "port": 587,
    "user": "adamoulehiane2@gmail.com",
    "password": "hoeh mfwn cgtz uhrl", 
    "to_email": "adamoulehiane2@gmail.com",
    "use_tls": True,
}

ALLOWED_COMMAND_PATTERNS = {
    "BLOCK_IP": {
        "description": "Block an IP address via Windows Firewall",
        "validation": "ip_must_be_public",
        "requires_confirmation": False,
    },
    "UNBLOCK_IP": {
        "description": "Remove a firewall block",
        "validation": "none",
        "requires_confirmation": False,
    },
    "BLOCK_PORT": {
        "description": "Block a specific port",
        "validation": "port_must_be_valid",
        "requires_confirmation": False,
    },
    "KILL_PROCESS": {
        "description": "Terminate a suspicious process",
        "validation": "process_must_exist",
        "requires_confirmation": True,
    },
    "DISABLE_USER": {
        "description": "Disable a compromised user account",
        "validation": "user_must_exist",
        "requires_confirmation": True,
    },
    "FLUSH_DNS": {
        "description": "Clear DNS cache",
        "validation": "none",
        "requires_confirmation": False,
    },
    "NOTIFY_ADMIN": {
        "description": "Send alert to SOC team",
        "validation": "none",
        "requires_confirmation": False,
    },
    "LOG_ONLY": {
        "description": "Log the incident without action",
        "validation": "none",
        "requires_confirmation": False,
    },
}

FORBIDDEN_PATTERNS = [
    "format", "diskpart", "del /f", "rmdir /s", "rd /s", "erase",
    "shutdown", "restart-computer", "stop-computer",
    "remove-item -recurse -force", "rm -rf",
    "invoke-expression", "iex", "downloadstring",
    "new-object net.webclient", "start-bitstransfer",
    "reg delete", "reg add", "bcdedit", "bootrec",
    "takeown", "icacls", "cipher /w", "vssadmin delete",
]


class ResponseEngine:
    def notify_admin(self, message: str, severity: str = "HIGH", incident_id: str = "") -> dict:
        """Public wrapper for unified email notifications from executeur_agent."""
        start = time.perf_counter()
        params = {
            "message": message,
            "severity": severity,
            "incident_id": incident_id,
        }
        return self._real_notify_admin(params, start)
    

    
    def __init__(self, dry_run: bool = False, require_confirmation: bool = False):
        self.dry_run = dry_run
        self.require_confirmation = require_confirmation
        self.blocklist_path = os.path.join(PROJECT_ROOT, "data", "config", "blocklist.json")
        self.isolated_path = os.path.join(PROJECT_ROOT, "data", "config", "isolated_hosts.json")
        self.alerts_dir = os.path.join(PROJECT_ROOT, "data", "reports", "alerts")
        self.rollback_log_path = os.path.join(PROJECT_ROOT, "data", "config", "rollback_log.json")
        os.makedirs(os.path.dirname(self.blocklist_path), exist_ok=True)
        os.makedirs(self.alerts_dir, exist_ok=True)

    # ═══════════════════════════════════════════════════════════════════════
    # MAIN ENTRY
    # ═══════════════════════════════════════════════════════════════════════
    def execute(self, action_def: Dict[str, Any], incident: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()
        action_name = action_def.get("action", "").upper()
        params = action_def.get("parameters", {})
        reasoning = action_def.get("reasoning", "No reasoning provided")

        if not self._is_action_allowed(action_name):
            return self._make_result(action_name, params, "blocked_by_policy",
                f"Action '{action_name}' not in whitelist. Allowed: {list(ALLOWED_COMMAND_PATTERNS.keys())}", start)

        if self._contains_forbidden(params):
            return self._make_result(action_name, params, "blocked_by_policy",
                "Action contains forbidden patterns.", start)

        validation_error = self._validate_parameters(action_name, params)
        if validation_error:
            return self._make_result(action_name, params, "validation_failed", validation_error, start)

        action_info = ALLOWED_COMMAND_PATTERNS[action_name]
        if action_info.get("requires_confirmation") and self.require_confirmation:
            return self._make_result(action_name, params, "pending_confirmation",
                f"Action '{action_name}' requires manual confirmation. Reasoning: {reasoning}", start)

        if self.dry_run:
            return self._execute_simulated(action_name, params, reasoning, start)

        return self._execute_real(action_name, params, reasoning, start)

    # ═══════════════════════════════════════════════════════════════════════
    # REAL EXECUTION
    # ═══════════════════════════════════════════════════════════════════════
    def _execute_real(self, action_name: str, params: dict, reasoning: str, start: float) -> dict:
        try:
            if action_name == "BLOCK_IP":
                return self._real_block_ip(params, reasoning, start)
            elif action_name == "UNBLOCK_IP":
                return self._real_unblock_ip(params, start)
            elif action_name == "BLOCK_PORT":
                return self._real_block_port(params, reasoning, start)
            elif action_name == "KILL_PROCESS":
                return self._real_kill_process(params, reasoning, start)
            elif action_name == "DISABLE_USER":
                return self._real_disable_user(params, reasoning, start)
            elif action_name == "FLUSH_DNS":
                return self._real_flush_dns(start)
            elif action_name == "NOTIFY_ADMIN":
                return self._real_notify_admin(params, start)
            elif action_name == "LOG_ONLY":
                return self._make_result(action_name, params, "success",
                    f"Logged only. Reasoning: {reasoning}", start)
            else:
                return self._make_result(action_name, params, "not_implemented",
                    f"Action '{action_name}' whitelisted but not implemented.", start)
        except Exception as e:
            return self._make_result(action_name, params, "failed",
                f"Execution error: {str(e)}", start)

    def _real_block_ip(self, params, reasoning, start):
        ip = params.get("ip", "")
        duration = params.get("duration_minutes", 60)
        ip_safe = ip.replace(".", "_")

        ps_cmd = (
            f'New-NetFirewallRule '
            f'-DisplayName "SOC_BLOCK_{ip_safe}" '
            f'-Direction Inbound '
            f'-RemoteAddress "{ip}" '
            f'-Action Block '
            f'-Enabled True '
            f'-Description "SOC: {reasoning}"'
        )
        result = self._run_powershell(ps_cmd)

        # Also create outbound block
        ps_cmd_out = (
            f'New-NetFirewallRule '
            f'-DisplayName "SOC_BLOCK_{ip_safe}_OUT" '
            f'-Direction Outbound '
            f'-RemoteAddress "{ip}" '
            f'-Action Block '
            f'-Enabled True'
        )
        self._run_powershell(ps_cmd_out)

        if result["success"]:
            self._save_rollback("BLOCK_IP", {"ip": ip, "ip_safe": ip_safe})
            self._update_blocklist(ip, duration, reasoning, True)
            return self._make_result("BLOCK_IP", params, "success",
                f"IP {ip} BLOCKED (inbound + outbound). Duration: {duration}min. {reasoning}", start)
        else:
            return self._make_result("BLOCK_IP", params, "failed",
                f"Firewall error: {result['stderr']}", start)

    def _real_unblock_ip(self, params, start):
        ip = params.get("ip", "")
        ip_safe = ip.replace(".", "_")
        self._run_powershell(f'Remove-NetFirewallRule -DisplayName "SOC_BLOCK_{ip_safe}" -ErrorAction SilentlyContinue')
        self._run_powershell(f'Remove-NetFirewallRule -DisplayName "SOC_BLOCK_{ip_safe}_OUT" -ErrorAction SilentlyContinue')
        self._update_blocklist(ip, 0, "", False)
        return self._make_result("UNBLOCK_IP", params, "success", f"IP {ip} unblocked.", start)

    def _real_block_port(self, params, reasoning, start):
        port = params.get("port", 0)
        ps_cmd = (
            f'New-NetFirewallRule '
            f'-DisplayName "SOC_BLOCK_PORT_{port}" '
            f'-Direction Inbound '
            f'-LocalPort {port} '
            f'-Protocol TCP '
            f'-Action Block '
            f'-Description "SOC: {reasoning}"'
        )
        result = self._run_powershell(ps_cmd)
        if result["success"]:
            self._save_rollback("BLOCK_PORT", {"port": port})
        return self._make_result("BLOCK_PORT", params,
            "success" if result["success"] else "failed",
            f"Port {port} blocked." if result["success"] else result["stderr"], start)

    def _real_kill_process(self, params, reasoning, start):
        process = params.get("process", "")
        ps_cmd = f'Stop-Process -Name "{process}" -Force -ErrorAction SilentlyContinue'
        result = self._run_powershell(ps_cmd)
        return self._make_result("KILL_PROCESS", params,
            "success" if result["success"] else "failed",
            f"Process {process} terminated." if result["success"] else result["stderr"], start)

    def _real_disable_user(self, params, reasoning, start):
        user = params.get("user", "")
        ps_cmd = f'Disable-LocalUser -Name "{user}" -ErrorAction SilentlyContinue'
        result = self._run_powershell(ps_cmd)
        if result["success"]:
            self._save_rollback("DISABLE_USER", {"user": user})
        return self._make_result("DISABLE_USER", params,
            "success" if result["success"] else "failed",
            f"User {user} disabled." if result["success"] else result["stderr"], start)

    def _real_flush_dns(self, start):
        result = self._run_powershell("Clear-DnsClientCache")
        return self._make_result("FLUSH_DNS", {}, "success" if result["success"] else "failed",
            "DNS cache cleared." if result["success"] else result["stderr"], start)

    # ═══════════════════════════════════════════════════════════════════════
    # REAL EMAIL NOTIFICATION
    # ═══════════════════════════════════════════════════════════════════════
    def _real_notify_admin(self, params, start):
        message = params.get("message", "SOC Alert")
        severity = params.get("severity", "HIGH")
        incident_id = params.get("incident_id", "")

        # 1. Always save to file (backup)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"alert_{incident_id or 'general'}_{timestamp}.txt"
        filepath = os.path.join(self.alerts_dir, filename)

        file_content = f"""=== SOC ALERT ===
Time: {datetime.now(timezone.utc).isoformat()}
Severity: {severity}
Incident: {incident_id}

{message}

---
Generated by Agent Exécuteur (REAL MODE)
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(file_content)

        # 2. Try to send REAL email
        email_status = self._send_real_email(message, severity, incident_id)

        return self._make_result("NOTIFY_ADMIN", params, "success",
            f"Alert saved to {filepath}. Email: {email_status}", start)

    def _send_real_email(self, message: str, severity: str, incident_id: str) -> str:
        """Send actual email via SMTP."""
        cfg = SMTP_CONFIG

        if not cfg["user"] or not cfg["password"]:
            return (
                "EMAIL NOT SENT - SMTP credentials not configured.\n"
                "  Set environment variables:\n"
                "    $env:SOC_SMTP_USER = 'votre-email@gmail.com'\n"
                "    $env:SOC_SMTP_PASS = 'votre-mot-de-passe-app'\n"
                "  Or use another SMTP server:\n"
                "    $env:SOC_SMTP_SERVER = 'smtp.votre-ecole.fr'\n"
                "    $env:SOC_SMTP_PORT = '587'\n"
                f"  Alert email target: {cfg['to_email']}"
            )

        try:
            # Build professional email
            subject = f"[SOC ALERT - {severity}] Incident {incident_id} detected"

            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <div style="background: {'#d32f2f' if severity == 'CRITICAL' else '#f57c00' if severity == 'HIGH' else '#fbc02d'}; color: white; padding: 20px;">
                        <h2 style="margin: 0;">🛡️ SOC Security Alert</h2>
                        <p style="margin: 5px 0 0 0; opacity: 0.9;">Severity: <strong>{severity}</strong></p>
                    </div>
                    <div style="padding: 20px;">
                        <p><strong>Incident ID:</strong> {incident_id}</p>
                        <p><strong>Time:</strong> {datetime.now(timezone.utc).isoformat()}</p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 15px 0;">
                        <pre style="background: #f8f8f8; padding: 15px; border-radius: 4px; overflow-x: auto;">{message}</pre>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 15px 0;">
                        <p style="color: #666; font-size: 12px;">
                            Generated automatically by SOC Multi-Agent System<br>
                            Agent: Exécuteur | Mode: REAL
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = cfg["user"]
            msg["To"] = cfg["to_email"]
            msg.attach(MIMEText(message, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(cfg["server"], cfg["port"]) as server:
                if cfg["use_tls"]:
                    server.starttls()
                server.login(cfg["user"], cfg["password"])
                server.send_message(msg)

            return f"✅ EMAIL SENT SUCCESSFULLY to {cfg['to_email']} via {cfg['server']}"

        except smtplib.SMTPAuthenticationError:
            return (
                "❌ EMAIL FAILED - Authentication error.\n"
                "  For Gmail: Use an 'App Password' not your normal password.\n"
                "  Go to: https://myaccount.google.com/apppasswords"
            )
        except smtplib.SMTPConnectError:
            return (
                f"❌ EMAIL FAILED - Cannot connect to {cfg['server']}:{cfg['port']}.\n"
                "  Check your internet connection and SMTP settings."
            )
        except Exception as e:
            return f"❌ EMAIL FAILED - {type(e).__name__}: {str(e)}"

    # ═══════════════════════════════════════════════════════════════════════
    # SIMULATION MODE
    # ═══════════════════════════════════════════════════════════════════════
    def _execute_simulated(self, action_name, params, reasoning, start):
        if action_name == "BLOCK_IP":
            ip = params.get("ip", "")
            duration = params.get("duration_minutes", 60)
            self._update_blocklist(ip, duration, reasoning, True)
            return self._make_result(action_name, params, "simulated",
                f"[SIMULATION] IP {ip} would be blocked for {duration}min. {reasoning}", start)

        elif action_name == "NOTIFY_ADMIN":
            # Even in dry-run, try to send email if configured
            email_status = self._send_real_email(
                params.get("message", ""),
                params.get("severity", "HIGH"),
                params.get("incident_id", "")
            )
            return self._make_result(action_name, params, "simulated",
                f"[SIMULATION] Alert file saved. Email: {email_status}", start)

        elif action_name == "LOG_ONLY":
            return self._make_result(action_name, params, "simulated",
                f"[SIMULATION] Logged only. {reasoning}", start)

        else:
            return self._make_result(action_name, params, "simulated",
                f"[SIMULATION] Action '{action_name}' would execute with: {params}. {reasoning}", start)

    # ═══════════════════════════════════════════════════════════════════════
    # SAFETY VALIDATION
    # ═══════════════════════════════════════════════════════════════════════
    def _is_action_allowed(self, action_name: str) -> bool:
        return action_name in ALLOWED_COMMAND_PATTERNS

    def _contains_forbidden(self, params: dict) -> bool:
        param_str = json.dumps(params).lower()
        return any(forbidden in param_str for forbidden in FORBIDDEN_PATTERNS)

    def _validate_parameters(self, action_name: str, params: dict) -> Optional[str]:
        if action_name == "BLOCK_IP":
            ip = params.get("ip", "")
            if not ip:
                return "IP address required"
            if self._is_internal_ip(ip):
                return f"Cannot block internal IP: {ip}"
            if not self._is_valid_ip(ip):
                return f"Invalid IP: {ip}"

        elif action_name == "BLOCK_PORT":
            port = params.get("port", 0)
            if not (1 <= port <= 65535):
                return f"Invalid port: {port}"

        elif action_name == "KILL_PROCESS":
            process = params.get("process", "")
            if not process:
                return "Process name required"
            critical = ["csrss", "wininit", "services", "lsass", "smss", "system", "explorer"]
            if process.lower() in critical:
                return f"Cannot kill critical process: {process}"

        elif action_name == "DISABLE_USER":
            user = params.get("user", "")
            if not user:
                return "Username required"
            import getpass
            if user.lower() == getpass.getuser().lower():
                return f"Cannot disable current user: {user}"

        return None

    def _is_internal_ip(self, ip: str) -> bool:
        if not ip or ip in ("", "Inconnue", "unknown"):
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
            return (first == 10 or
                   (first == 172 and 16 <= second <= 31) or
                   (first == 192 and second == 168))
        except ValueError:
            return False

    def _is_valid_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    # ═══════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════
    def _run_powershell(self, command: str) -> dict:
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True, text=True, timeout=15, shell=False
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stderr": "Timeout", "stdout": ""}
        except Exception as e:
            return {"success": False, "stderr": str(e), "stdout": ""}

    def _update_blocklist(self, ip: str, duration: int, reason: str, active: bool):
        blocklist = self._load_json(self.blocklist_path)
        blocklist[ip] = {
            "ip": ip,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": self._add_minutes(datetime.now(timezone.utc), duration).isoformat() if duration > 0 else "",
            "reason": reason,
            "active": active,
        }
        self._save_json(self.blocklist_path, blocklist)

    def _save_rollback(self, action: str, params: dict):
        rollback = self._load_json(self.rollback_log_path)
        rollback.setdefault("history", []).append({
            "action": action,
            "parameters": params,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._save_json(self.rollback_log_path, rollback)

    def _make_result(self, action: str, params: dict, status: str, details: str, start_time: float) -> dict:
        return {
            "action": action,
            "parameters": params,
            "status": status,
            "details": details,
            "duration_ms": round((time.perf_counter() - start_time) * 1000, 1),
        }

    def _load_json(self, path: str) -> dict:
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_json(self, path: str, data: dict):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    @staticmethod
    def _add_minutes(dt, minutes: int):
        from datetime import timedelta
        return dt + timedelta(minutes=minutes)