# agents/rapporteur/dashboard_data.py
# Historique persistant des incidents, utilisé par le dashboard Streamlit.


import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HISTORY_PATH = os.getenv(
    "INCIDENTS_HISTORY_PATH",
    os.path.join(BASE_DIR, "data", "shared", "incidents_history.json"),
)
os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)


def _read_history() -> dict:
    if not os.path.exists(HISTORY_PATH):
        return {}
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def record_incidents(incidents_list: list) -> None:
    """Ajoute ou met à jour une liste d'incidents dans l'historique persistant."""
    if not incidents_list:
        return
    history = _read_history()
    for inc in incidents_list:
        inc_id = inc.get("incident_id") or f"AUTO-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        record = dict(inc)
        record["incident_id"] = inc_id
        record.setdefault("recorded_at", datetime.now().isoformat())
        history[inc_id] = record
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


def record_incident(incident: dict) -> None:
    """Raccourci pour enregistrer un seul incident."""
    record_incidents([incident])


def load_all_incidents() -> list:
    """Retourne tous les incidents connus, triés du plus récent au plus ancien."""
    history = _read_history()
    incidents = list(history.values())
    incidents.sort(key=lambda i: i.get("timestamp") or i.get("recorded_at") or "", reverse=True)
    return incidents


def clear_history() -> None:
    """Réinitialise l'historique (utile pour les démos / tests)."""
    if os.path.exists(HISTORY_PATH):
        os.remove(HISTORY_PATH)


def compute_stats(incidents_list: list) -> dict:
    """
    Calcule les statistiques agrégées sur une liste d'incidents.
    Copie indépendante de report_generator._compute_stats : le dashboard
    n'a ainsi PAS besoin d'importer LangChain/Ollama pour s'afficher.
    """
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    attack_types, suspicious_ips = {}, []
    for inc in incidents_list:
        sev = inc.get("severity", "MEDIUM").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        attack = inc.get("attack_type", "Unknown")
        attack_types[attack] = attack_types.get(attack, 0) + 1
        src = inc.get("source_ip")
        if src and src not in suspicious_ips:
            suspicious_ips.append(src)
    total = len(incidents_list)
    fp_count = sum(1 for i in incidents_list if i.get("false_positive", False))
    return {
        "period": "Historique complet",
        "total_alerts": total,
        "confirmed_incidents": total - fp_count,
        "false_positives": fp_count,
        "detection_rate": round((total - fp_count) / total * 100, 1) if total > 0 else 0,
        "severity_counts": severity_counts,
        "attack_types": attack_types,
        "top_suspicious_ips": suspicious_ips[:5],
    }
