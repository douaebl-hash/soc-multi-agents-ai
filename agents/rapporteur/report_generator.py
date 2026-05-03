# Moteur de génération de rapports via LLM (Ollama / LangChain)

import json
import os
from datetime import datetime
from langchain_ollama import OllamaLLM
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

from templates import (
    get_incident_report_template,
    get_summary_template,
    get_dashboard_template,
)

# ─── Configuration ────────────────────────────────────────────────────────────
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")   # ou "phi3", "llama3", etc.
REPORTS_DIR  = os.getenv("REPORTS_DIR", "data/reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _get_llm():
    """Instancie le modèle LLM local via Ollama."""
    return OllamaLLM(model=OLLAMA_MODEL, temperature=0.3)


def _save_report(content: str, report_type: str, incident_id: str = "") -> str:
    """Sauvegarde le rapport dans un fichier texte et retourne le chemin."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix    = f"_{incident_id}" if incident_id else ""
    filename  = f"{report_type}{suffix}_{timestamp}.txt"
    filepath  = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== RAPPORT SOC — {datetime.now().isoformat()} ===\n\n")
        f.write(content)

    print(f"[ReportGenerator] ✅ Rapport sauvegardé : {filepath}")
    return filepath


# ─── Génération de rapport d'incident ─────────────────────────────────────────

def generate_incident_report(incident_data: dict) -> dict:
    """
    Génère un rapport détaillé pour un seul incident.

    Args:
        incident_data: dict avec les champs analysés (severity, attack_type, etc.)

    Returns:
        dict avec le rapport texte et le chemin du fichier sauvegardé
    """
    print(f"[ReportGenerator] 📝 Génération rapport pour incident {incident_data.get('incident_id', '?')}")

    prompt_text = get_incident_report_template(incident_data)

    # Construction du prompt LangChain
    prompt = PromptTemplate(
        input_variables=["context"],
        template="{context}"
    )
    chain = LLMChain(llm=_get_llm(), prompt=prompt)

    report_content = chain.run(context=prompt_text)

    filepath = _save_report(
        report_content,
        report_type="incident_report",
        incident_id=incident_data.get("incident_id", "unknown")
    )

    return {
        "incident_id" : incident_data.get("incident_id"),
        "report_type" : "incident_report",
        "content"     : report_content,
        "filepath"    : filepath,
        "generated_at": datetime.now().isoformat(),
    }


# ─── Génération de synthèse ────────────────────────────────────────────────────

def generate_summary_report(incidents_list: list) -> dict:
    """
    Génère un rapport de synthèse sur une liste d'incidents.

    Args:
        incidents_list: liste de dicts d'incidents analysés

    Returns:
        dict avec le rapport de synthèse et le chemin du fichier
    """
    print(f"[ReportGenerator] 📋 Génération synthèse pour {len(incidents_list)} incidents")

    prompt_text = get_summary_template(incidents_list)

    prompt = PromptTemplate(input_variables=["context"], template="{context}")
    chain  = LLMChain(llm=_get_llm(), prompt=prompt)

    report_content = chain.run(context=prompt_text)

    filepath = _save_report(report_content, report_type="summary_report")

    return {
        "report_type"    : "summary_report",
        "incident_count" : len(incidents_list),
        "content"        : report_content,
        "filepath"       : filepath,
        "generated_at"   : datetime.now().isoformat(),
    }


# ─── Génération du tableau de bord ────────────────────────────────────────────

def generate_dashboard(incidents_list: list) -> dict:
    """
    Calcule les stats et génère un tableau de bord synthétique.

    Args:
        incidents_list: liste d'incidents analysés

    Returns:
        dict avec le dashboard et les statistiques calculées
    """
    print("[ReportGenerator] 📊 Génération du tableau de bord")

    # ── Calcul des statistiques ──
    stats = _compute_stats(incidents_list)

    prompt_text = get_dashboard_template(stats)

    prompt = PromptTemplate(input_variables=["context"], template="{context}")
    chain  = LLMChain(llm=_get_llm(), prompt=prompt)

    dashboard_content = chain.run(context=prompt_text)

    filepath = _save_report(dashboard_content, report_type="dashboard")

    return {
        "report_type" : "dashboard",
        "stats"       : stats,
        "content"     : dashboard_content,
        "filepath"    : filepath,
        "generated_at": datetime.now().isoformat(),
    }


def _compute_stats(incidents_list: list) -> dict:
    """Calcule les statistiques à partir d'une liste d'incidents."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    attack_types    = {}
    suspicious_ips  = []

    for inc in incidents_list:
        sev = inc.get("severity", "MEDIUM").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

        attack = inc.get("attack_type", "Unknown")
        attack_types[attack] = attack_types.get(attack, 0) + 1

        src_ip = inc.get("source_ip")
        if src_ip and src_ip not in suspicious_ips:
            suspicious_ips.append(src_ip)

    total    = len(incidents_list)
    fp_count = sum(1 for i in incidents_list if i.get("false_positive", False))

    return {
        "period"              : "Dernières 24h",
        "total_alerts"        : total,
        "confirmed_incidents" : total - fp_count,
        "false_positives"     : fp_count,
        "detection_rate"      : round(((total - fp_count) / total * 100), 1) if total > 0 else 0,
        "severity_counts"     : severity_counts,
        "attack_types"        : attack_types,
        "top_suspicious_ips"  : suspicious_ips[:5],
        "executed_actions"    : [],   # sera rempli par l'Agent Exécuteur
    }
