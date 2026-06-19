"""
rules_engine.py
Heuristic detection rules for Agent Analyseur.
No LLM involved here - fast, deterministic, zero-cost first pass.
"""

import re
from datetime import datetime

# ─── Severity thresholds ────────────────────────────────────────────────────
SEVERITY_SUSPICIOUS = 0.7   # Flag for deeper LLM analysis

# ─── Keywords that raise severity ───────────────────────────────────────────
ATTACK_KEYWORDS = [
    "failed password", "authentication failure", "invalid user",
    "brute force", "port scan", "syn flood", "exploit",
    "malware", "ransomware", "unauthorized", "privilege escalation",
    "root login", "reverse shell", "payload",
    "injection", "xss", "sqli", "rce", "lfi", "rfi",
    "ddos", "denied",
]

CRITICAL_KEYWORDS = [
    "root", "admin", "administrator", "/etc/passwd", "/etc/shadow",
    "nc -e", "bash -i", "/bin/sh", "wget http", "curl http",
    "chmod 777",
]

# ─── Regex patterns ─────────────────────────────────────────────────────────
IP_PATTERN      = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PORT_PATTERN    = re.compile(r'\bport\s+(\d{1,5})\b', re.IGNORECASE)
USER_PATTERN    = re.compile(r'(?:for|user|invalid user)\s+(\w+)', re.IGNORECASE)
FAILED_AUTH_PAT = re.compile(r'failed (password|login|authentication)', re.IGNORECASE)


def extract_entities(event: dict) -> dict:
    """Extract IPs, ports, users, failed-auth flag from an event."""
    message = (event.get("message", "") or "") + " " + (event.get("raw", "") or "")

    ips   = list(set(IP_PATTERN.findall(message)))
    ports = list(set(PORT_PATTERN.findall(message)))
    users = list(set(USER_PATTERN.findall(message)))
    is_failed_auth = bool(FAILED_AUTH_PAT.search(message))

    return {
        "ips": ips,
        "ports": ports,
        "users": users,
        "is_failed_auth": is_failed_auth,
    }


def compute_heuristic_severity(event: dict, entities: dict) -> float:
    """Re-score severity 0.0-1.0 based on heuristic rules."""
    score = float(event.get("severity", 0.0) or 0.0)
    message = (event.get("message", "") or "").lower()

    for kw in ATTACK_KEYWORDS:
        if kw in message:
            score = max(score, 0.6)
            break

    for kw in CRITICAL_KEYWORDS:
        if kw in message:
            score = max(score, 0.85)
            break

    if entities.get("is_failed_auth"):
        score = max(score, 0.7)

    if "root" in entities.get("users", []) and entities.get("is_failed_auth"):
        score = max(score, 0.9)

    return min(round(score, 2), 1.0)


def classify_event_type(event: dict, entities: dict) -> str:
    """Returns a human-readable category for the event."""
    message = (event.get("message", "") or "").lower()
    source = event.get("source", "")

    if entities.get("is_failed_auth"):
        return "BRUTE_FORCE_ATTEMPT"
    if source == "network" and any(p in message for p in ["scan", "syn", "probe"]):
        return "PORT_SCAN"
    if any(kw in message for kw in ["exploit", "payload", "shellcode"]):
        return "EXPLOIT_ATTEMPT"
    if any(kw in message for kw in ["malware", "ransomware", "trojan"]):
        return "MALWARE_ACTIVITY"
    if entities.get("ips") and source == "network":
        return "SUSPICIOUS_TRAFFIC"
    return "UNKNOWN"


def analyze_event(event: dict) -> dict:
    """Full heuristic pipeline for one event. Returns enriched copy."""
    entities = extract_entities(event)
    new_severity = compute_heuristic_severity(event, entities)
    event_type = classify_event_type(event, entities)
    needs_llm = new_severity >= SEVERITY_SUSPICIOUS

    return {
        **event,
        "heuristic_severity": new_severity,
        "event_type": event_type,
        "entities": entities,
        "needs_llm_analysis": needs_llm,
        "analyzed_at": datetime.utcnow().isoformat(),
    }