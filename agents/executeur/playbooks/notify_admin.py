"""
playbooks/notify_admin.py
Manual playbook — kept for direct invocation or testing.
"""

from typing import Any, Dict, List


def run(engine, incident: dict) -> List[Dict[str, Any]]:
    inc_id = incident.get("incident_id", "UNKNOWN")
    severity = incident.get("severity", "HIGH")
    attack_type = incident.get("attack_type", "Unknown")
    source_ip = incident.get("source_ip", "N/A")
    dest_ip = incident.get("dest_ip", "N/A")
    risk_score = incident.get("risk_score", "N/A")

    message = f"""ALERT: New security incident requires attention.

Incident ID: {inc_id}
Severity: {severity}
Attack Type: {attack_type}
Source IP: {source_ip}
Destination IP: {dest_ip}
Risk Score: {risk_score}/10

Anomalies detected:
{chr(10).join(f"  - {a}" for a in incident.get("anomalies", []))}

Recommended action: {incident.get("recommended_action", "Review and respond manually")}
"""

    result = engine.notify_admin(message=message, severity=severity, incident_id=inc_id)
    return [result]
