# agents/rapporteur/report_generator.py
# Moteur de génération de rapports via LLM (Ollama / LangChain)

import json
import os
from datetime import datetime
from langchain_ollama import OllamaLLM
from langchain.prompts import PromptTemplate

from templates import (
    get_incident_report_template,
    get_summary_template,
    get_dashboard_template,
)

# ─── Configuration ─────────────────────────────────────────────────────────────
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORTS_DIR = os.getenv("REPORTS_DIR", os.path.join(BASE_DIR, "data", "reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)


def _get_chain(prompt_template: str) -> any:
    """Crée une chain LangChain moderne (prompt | llm)."""
    llm    = OllamaLLM(model=OLLAMA_MODEL, temperature=0.3)
    prompt = PromptTemplate(input_variables=["context"], template="{context}")
    return prompt | llm          # nouvelle syntaxe LCEL — remplace LLMChain


def _run_chain(prompt_text: str) -> str:
    """Exécute la chain et retourne le texte généré."""
    chain = _get_chain(prompt_text)
    return chain.invoke({"context": prompt_text})  # .invoke() au lieu de .run()


def _save_report(content: str, report_type: str, incident_id: str = "") -> str:
    """Sauvegarde le rapport et retourne le chemin."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix    = f"_{incident_id}" if incident_id else ""
    filename  = f"{report_type}{suffix}_{timestamp}.txt"
    filepath  = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== RAPPORT SOC — {datetime.now().isoformat()} ===\n\n")
        f.write(content)
    print(f"[ReportGenerator] ✅ Rapport sauvegardé : {filepath}")
    return filepath


# ─── Rapport d'incident ────────────────────────────────────────────────────────

def generate_incident_report(incident_data: dict) -> dict:
    print(f"[ReportGenerator] 📝 Génération rapport incident {incident_data.get('incident_id', '?')}")
    prompt_text    = get_incident_report_template(incident_data)
    report_content = _run_chain(prompt_text)
    filepath       = _save_report(report_content, "incident_report", incident_data.get("incident_id", "unknown"))
    return {
        "incident_id" : incident_data.get("incident_id"),
        "report_type" : "incident_report",
        "content"     : report_content,
        "filepath"    : filepath,
        "generated_at": datetime.now().isoformat(),
    }


# ─── Synthèse ─────────────────────────────────────────────────────────────────

def generate_summary_report(incidents_list: list) -> dict:
    print(f"[ReportGenerator] 📋 Génération synthèse pour {len(incidents_list)} incidents")
    prompt_text    = get_summary_template(incidents_list)
    report_content = _run_chain(prompt_text)
    filepath       = _save_report(report_content, "summary_report")
    return {
        "report_type"    : "summary_report",
        "incident_count" : len(incidents_list),
        "content"        : report_content,
        "filepath"       : filepath,
        "generated_at"   : datetime.now().isoformat(),
    }


# ─── Dashboard ────────────────────────────────────────────────────────────────

def generate_dashboard(incidents_list: list) -> dict:
    print("[ReportGenerator] 📊 Génération du dashboard")
    stats          = _compute_stats(incidents_list)
    prompt_text    = get_dashboard_template(stats)
    report_content = _run_chain(prompt_text)
    filepath       = _save_report(report_content, "dashboard")
    return {
        "report_type" : "dashboard",
        "stats"       : stats,
        "content"     : report_content,
        "filepath"    : filepath,
        "generated_at": datetime.now().isoformat(),
    }


def _compute_stats(incidents_list: list) -> dict:
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
    total    = len(incidents_list)
    fp_count = sum(1 for i in incidents_list if i.get("false_positive", False))
    return {
        "period"              : "Dernières 24h",
        "total_alerts"        : total,
        "confirmed_incidents" : total - fp_count,
        "false_positives"     : fp_count,
        "detection_rate"      : round((total - fp_count) / total * 100, 1) if total > 0 else 0,
        "severity_counts"     : severity_counts,
        "attack_types"        : attack_types,
        "top_suspicious_ips"  : suspicious_ips[:5],
        "executed_actions"    : [],
    }