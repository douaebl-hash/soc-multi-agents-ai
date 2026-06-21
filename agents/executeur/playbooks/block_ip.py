"""
playbooks/block_ip.py
Manual playbook — kept for direct invocation or testing.
The AI-driven agent prefers generating actions dynamically.
"""

from typing import Any, Dict, List


def run(engine, incident: dict) -> List[Dict[str, Any]]:
    source_ip = incident.get("source_ip", "")
    if not source_ip or source_ip in ("Inconnue", "unknown", ""):
        return [{
            "action": "BLOCK_IP",
            "target": "N/A",
            "status": "skipped",
            "details": "No source IP available to block",
            "duration_ms": 0,
        }]

    reason = f"Incident {incident.get('incident_id', '?')}: {incident.get('attack_type', 'unknown attack')}"
    duration = 120 if incident.get("severity", "").upper() == "CRITICAL" else 60
    result = engine.block_ip(ip=source_ip, duration_minutes=duration, reason=reason)
    return [result]
