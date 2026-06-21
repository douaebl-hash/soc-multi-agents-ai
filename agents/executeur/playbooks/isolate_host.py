"""
playbooks/isolate_host.py
Manual playbook — kept for direct invocation or testing.
"""

from typing import Any, Dict, List


def run(engine, incident: dict) -> List[Dict[str, Any]]:
    target = incident.get("dest_ip", "") or incident.get("source_ip", "")
    if not target or target in ("Inconnue", "unknown", ""):
        return [{
            "action": "ISOLATE_HOST",
            "target": "N/A",
            "status": "skipped",
            "details": "No target host available to isolate",
            "duration_ms": 0,
        }]

    reason = f"Incident {incident.get('incident_id', '?')}: {incident.get('attack_type', 'unknown attack')}"
    result = engine.isolate_host(host_id=target, reason=reason)
    return [result]
