# agents/rapporteur/analyser_adapter.py
#
# Adaptateur de format entre l'Agent Analyseur et l'Agent Rapporteur.
#
# L'Analyseur écrit dans SharedMemory (canal "analysis_results") des objets
# au format _build_result() :
#   {
#     "event_id", "timestamp", "analyzed_at", "source",
#     "event_type", "final_severity", "severity_label",
#     "entities": {"ips", "ports", "users", "is_failed_auth"},
#     "llm_analysis": {...} | None,
#     "correlation_alert": {...} | None,
#     "original_message",
#   }
#
# Le Rapporteur (templates + report_generator) attend des "incidents" :
#   {
#     "incident_id", "timestamp", "source_ip", "dest_ip",
#     "attack_type", "severity", "anomalies",
#     "correlated_events", "affected_system",
#     "risk_score", "false_positive",
#   }
#
# Ce module assure la conversion sans modifier les deux autres agents.

from typing import Optional


# ─── Mapping severity_label Analyseur → labels attendus par le Rapporteur ────
# L'Analyseur produit : CRITICAL / HIGH / MEDIUM / LOW / INFO
# Le Rapporteur (templates, process_batch) utilise : CRITICAL / HIGH / MEDIUM / LOW
_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH"    : "HIGH",
    "MEDIUM"  : "MEDIUM",
    "LOW"     : "LOW",
    "INFO"    : "LOW",   # INFO → LOW pour ne pas le perdre
}


def analyseur_result_to_incident(result: dict) -> dict:
    """
    Convertit un élément de 'analysis_results' (format Analyseur)
    en incident (format Rapporteur).
    """
    entities         = result.get("entities") or {}
    ips              = entities.get("ips") or []
    llm              = result.get("llm_analysis") or {}
    correlation      = result.get("correlation_alert") or {}

    # ── Champs de base ──────────────────────────────────────────────────────
    incident_id      = result.get("event_id", "UNKNOWN")
    timestamp        = result.get("timestamp") or result.get("analyzed_at", "")
    source_ip        = ips[0] if ips else "Inconnue"
    dest_ip          = ips[1] if len(ips) > 1 else "Inconnue"
    attack_type      = _resolve_attack_type(result, llm, correlation)
    severity_label   = _SEVERITY_MAP.get(
        (result.get("severity_label") or "").upper(), "MEDIUM"
    )
    risk_score       = round(float(result.get("final_severity", 0.5)) * 10, 1)
    affected_system  = result.get("source", "Inconnu")

    # ── Anomalies : message original + résumé LLM si dispo ─────────────────
    anomalies = []
    msg = result.get("original_message", "")
    if msg:
        anomalies.append(msg[:200])

    llm_summary = llm.get("attack_summary", "")
    if llm_summary and llm_summary != msg:
        anomalies.append(f"[LLM] {llm_summary}")

    corr_desc = correlation.get("description", "")
    if corr_desc:
        anomalies.append(f"[CORRÉLATION] {corr_desc}")

    if not anomalies:
        anomalies = ["Aucun détail disponible"]

    # ── Événements corrélés ─────────────────────────────────────────────────
    correlated_events = correlation.get("involved_event_ids", [])

    # ── Champs enrichis (extras gardés pour le dashboard/historique) ─────────
    incident = {
        # Champs standard Rapporteur
        "incident_id"      : incident_id,
        "timestamp"        : timestamp,
        "source_ip"        : source_ip,
        "dest_ip"          : dest_ip,
        "attack_type"      : attack_type,
        "severity"         : severity_label,
        "anomalies"        : anomalies,
        "correlated_events": correlated_events,
        "affected_system"  : affected_system,
        "risk_score"       : risk_score,
        "false_positive"   : False,

        # Extras utiles pour le dashboard
        "event_type"       : result.get("event_type", "UNKNOWN"),
        "analyzed_at"      : result.get("analyzed_at", ""),
        "mitre_technique"  : llm.get("attack_technique", ""),
        "recommended_action": llm.get("recommended_action", ""),
        "needs_escalation" : llm.get("needs_escalation", False),
        "correlation_pattern": correlation.get("pattern", ""),
        "llm_confidence"   : llm.get("confidence"),
        "affected_assets"  : llm.get("affected_assets", []),
    }
    return incident


def analyseur_result_to_incident_batch(results: list) -> list:
    """Convertit une liste complète de résultats Analyseur en incidents."""
    return [analyseur_result_to_incident(r) for r in results if isinstance(r, dict)]


def _resolve_attack_type(result: dict, llm: dict, correlation: dict) -> str:
    """
    Détermine le type d'attaque le plus précis disponible.
    Priorité : corrélation > technique MITRE (LLM) > event_type heuristique.
    """
    # 1. Pattern de corrélation (ex: BRUTE_FORCE_CONFIRMED, INTRUSION_ATTEMPT)
    pattern = correlation.get("pattern", "")
    if pattern:
        return _humanize_pattern(pattern)

    # 2. Technique MITRE fournie par le LLM
    mitre = llm.get("attack_technique", "")
    if mitre and mitre.upper() != "UNKNOWN":
        return mitre

    # 3. Event type heuristique de la rules_engine
    event_type = result.get("event_type", "")
    if event_type and event_type != "UNKNOWN":
        return _humanize_event_type(event_type)

    return "Non classifié"


def _humanize_pattern(pattern: str) -> str:
    mapping = {
        "BRUTE_FORCE_CONFIRMED" : "Brute Force Confirmé",
        "PORT_SCAN_CONFIRMED"   : "Scan de Ports Confirmé",
        "INTRUSION_ATTEMPT"     : "Tentative d'Intrusion",
    }
    return mapping.get(pattern, pattern.replace("_", " ").title())


def _humanize_event_type(event_type: str) -> str:
    mapping = {
        "BRUTE_FORCE_ATTEMPT": "Tentative Brute Force",
        "PORT_SCAN"          : "Scan de Ports",
        "EXPLOIT_ATTEMPT"    : "Tentative d'Exploit",
        "MALWARE_ACTIVITY"   : "Activité Malware",
        "SUSPICIOUS_TRAFFIC" : "Trafic Suspect",
    }
    return mapping.get(event_type, event_type.replace("_", " ").title())
