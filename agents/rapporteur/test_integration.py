# agents/rapporteur/test_integration.py
#
# Script de test d'intégration pour l'Agent Rapporteur.
#
# USAGE :
#   # Cas 1 — L'Analyseur a déjà tourné, lire ce qui est dans la SharedMemory :
#   python test_integration.py --mode read
#
#   # Cas 2 — L'Analyseur n'a pas tourné, injecter des données réalistes puis traiter :
#   python test_integration.py --mode inject
#
#   # Voir ce qui est dans la SharedMemory sans rien traiter :
#   python test_integration.py --mode inspect

import argparse
import json
import os
import sys

PROJECT_ROOT   = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EXTRACTEUR_DIR = os.path.join(PROJECT_ROOT, "agents", "extracteur")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, EXTRACTEUR_DIR)

from src.utils.shared_memory import SharedMemory

PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)

# ─── Données réalistes au format exact de l'Analyseur ─────────────────────────
# Ces données reproduisent exactement ce que _build_result() dans analyseur_agent.py
# écrit dans le canal "analysis_results".

SAMPLE_ANALYSIS_RESULTS = [
    {
        "event_id"       : "EVT-20240115-001",
        "timestamp"      : "2024-01-15T14:32:00",
        "analyzed_at"    : "2024-01-15T14:32:05.123456",
        "source"         : "syslog",
        "event_type"     : "BRUTE_FORCE_ATTEMPT",
        "final_severity" : 0.9,
        "severity_label" : "HIGH",
        "entities": {
            "ips"           : ["192.168.1.105"],
            "ports"         : ["22"],
            "users"         : ["root"],
            "is_failed_auth": True,
        },
        "llm_analysis": {
            "attack_summary"    : "Tentative de brute force SSH répétée depuis une IP externe ciblant le compte root.",
            "attack_technique"  : "T1110.001 - Password Guessing",
            "affected_assets"   : ["192.168.1.1", "10.0.0.50"],
            "recommended_action": "Bloquer immédiatement l'IP 192.168.1.105 au niveau du firewall et activer le fail2ban.",
            "confidence"        : 0.93,
            "needs_escalation"  : True,
        },
        "correlation_alert": {
            "alert_type"         : "CORRELATION_ALERT",
            "pattern"            : "BRUTE_FORCE_CONFIRMED",
            "attacker_ip"        : "192.168.1.105",
            "description"        : "IP 192.168.1.105 a effectué 6 tentatives d'authentification échouées en 5 minutes.",
            "correlation_severity": 0.85,
            "severity_label"     : "HIGH",
            "involved_event_ids" : ["EVT-20240115-000", "EVT-20240115-001"],
            "detected_at"        : "2024-01-15T14:32:05.000000",
        },
        "original_message": "Failed password for root from 192.168.1.105 port 22 ssh2",
    },
    {
        "event_id"       : "EVT-20240115-002",
        "timestamp"      : "2024-01-15T15:00:00",
        "analyzed_at"    : "2024-01-15T15:00:02.654321",
        "source"         : "network",
        "event_type"     : "PORT_SCAN",
        "final_severity" : 0.75,
        "severity_label" : "MEDIUM",
        "entities": {
            "ips"           : ["10.10.10.10"],
            "ports"         : ["80", "443", "8080", "3306", "22"],
            "users"         : [],
            "is_failed_auth": False,
        },
        "llm_analysis"    : None,
        "correlation_alert": None,
        "original_message": "network 10.10.10.10 -> 10.0.0.1 syn probe port 80",
    },
    {
        "event_id"       : "EVT-20240115-003",
        "timestamp"      : "2024-01-15T15:30:00",
        "analyzed_at"    : "2024-01-15T15:30:01.987654",
        "source"         : "syslog",
        "event_type"     : "EXPLOIT_ATTEMPT",
        "final_severity" : 1.0,
        "severity_label" : "CRITICAL",
        "entities": {
            "ips"           : ["172.16.0.5"],
            "ports"         : ["3306"],
            "users"         : ["admin"],
            "is_failed_auth": False,
        },
        "llm_analysis": {
            "attack_summary"    : "Tentative d'injection SQL détectée sur le serveur de base de données.",
            "attack_technique"  : "T1190 - Exploit Public-Facing Application",
            "affected_assets"   : ["10.0.0.50"],
            "recommended_action": "Isoler le serveur DB, analyser les logs MySQL et appliquer les patches.",
            "confidence"        : 0.97,
            "needs_escalation"  : True,
        },
        "correlation_alert": {
            "alert_type"         : "CORRELATION_ALERT",
            "pattern"            : "INTRUSION_ATTEMPT",
            "attacker_ip"        : "172.16.0.5",
            "description"        : "IP 172.16.0.5 a combiné un scan réseau ET des tentatives d'authentification — attaque coordonnée.",
            "correlation_severity": 1.0,
            "severity_label"     : "CRITICAL",
            "involved_event_ids" : ["EVT-20240115-002", "EVT-20240115-003"],
            "detected_at"        : "2024-01-15T15:30:01.000000",
        },
        "original_message": "SQL injection payload detected in POST /api/users: SELECT * FROM users WHERE 1=1--",
    },
    {
        "event_id"       : "EVT-20240115-004",
        "timestamp"      : "2024-01-15T16:00:00",
        "analyzed_at"    : "2024-01-15T16:00:01.111111",
        "source"         : "network",
        "event_type"     : "SUSPICIOUS_TRAFFIC",
        "final_severity" : 0.45,
        "severity_label" : "LOW",
        "entities": {
            "ips"           : ["10.0.0.99"],
            "ports"         : ["53"],
            "users"         : [],
            "is_failed_auth": False,
        },
        "llm_analysis"    : None,
        "correlation_alert": None,
        "original_message": "Unusual DNS query volume from 10.0.0.99 (internal host)",
    },
]


def inspect_shared_memory(memory: SharedMemory):
    """Affiche le contenu actuel des canaux de la SharedMemory."""
    print("\n" + "=" * 60)
    print("📂 CONTENU ACTUEL DE LA SHARED MEMORY")
    print("=" * 60)

    for channel in ["analysis_results", "correlation_alerts", "events_structured", "pending_analysis"]:
        data = memory.read(channel)
        count = len(data) if data else 0
        print(f"\n  [{channel}] — {count} élément(s)")
        if count > 0:
            # Afficher un résumé des 2 premiers
            for item in data[:2]:
                eid   = item.get("event_id", item.get("alert_type", "?"))
                sev   = item.get("severity_label", item.get("final_severity", "?"))
                etype = item.get("event_type", item.get("pattern", "?"))
                print(f"    • {eid} | sev={sev} | type={etype}")
            if count > 2:
                print(f"    ... et {count - 2} autre(s)")
    print()


def inject_and_process(memory: SharedMemory):
    """Injecte des données réalistes dans la SharedMemory puis lance le Rapporteur."""
    print("\n" + "=" * 60)
    print("💉 INJECTION DE DONNÉES DE TEST DANS LA SHARED MEMORY")
    print("=" * 60)

    # Lire ce qui existe déjà et ajouter les nouvelles données (sans écraser)
    existing = memory.read("analysis_results") or []
    existing_ids = {e.get("event_id") for e in existing}

    to_add = [r for r in SAMPLE_ANALYSIS_RESULTS if r["event_id"] not in existing_ids]
    if not to_add:
        print("  ℹ️  Ces event_ids sont déjà dans la SharedMemory, pas de doublon.")
    else:
        memory.write("analysis_results", existing + to_add)
        print(f"  ✅ {len(to_add)} résultat(s) injecté(s) dans 'analysis_results'")

    _run_rapporteur(memory)


def read_and_process(memory: SharedMemory):
    """Lit ce qui est dans la SharedMemory et lance le Rapporteur."""
    print("\n" + "=" * 60)
    print("📥 LECTURE DEPUIS LA SHARED MEMORY (données réelles de l'Analyseur)")
    print("=" * 60)

    data = memory.read("analysis_results") or []
    if not data:
        print("  ⚠️  Aucune donnée dans 'analysis_results'.")
        print("  → Lance d'abord l'Analyseur, ou utilise --mode inject pour tester.")
        return

    print(f"  ✅ {len(data)} résultat(s) trouvé(s) dans 'analysis_results'")
    _run_rapporteur(memory)


def _run_rapporteur(memory: SharedMemory):
    """Importe et lance le Rapporteur sur les données présentes dans la SharedMemory."""
    from rapporteur_agent import RapporteurAgent
    from analyser_adapter import analyseur_result_to_incident_batch

    print("\n" + "=" * 60)
    print("🚀 LANCEMENT DU RAPPORTEUR")
    print("=" * 60)

    raw_results = memory.read("analysis_results") or []
    incidents   = analyseur_result_to_incident_batch(raw_results)

    print(f"\n  Incidents convertis ({len(incidents)}) :")
    for inc in incidents:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(inc["severity"], "⚪")
        print(f"    {icon} [{inc['severity']}] {inc['incident_id']} | {inc['attack_type']} | IP={inc['source_ip']} | score={inc['risk_score']}")

    print()
    agent  = RapporteurAgent()
    result = agent.process_batch(incidents)

    print("\n" + "=" * 60)
    print("✅ RÉSULTAT DU RAPPORTEUR")
    print("=" * 60)
    print(f"  Rapports individuels : {len(result.get('individual_reports', []))}")
    for r in result.get("individual_reports", []):
        print(f"    • {r['incident_id']} → {r['filepath']}")
    print(f"  Synthèse   : {result.get('summary_filepath', 'N/A')}")
    print(f"  Dashboard  : {result.get('dashboard_filepath', 'N/A')}")
    print(f"\n  Stats      : {json.dumps(result.get('stats', {}), ensure_ascii=False, indent=4)}")
    print()
    print("  💡 Lance le dashboard pour visualiser :")
    print("     streamlit run dashboard_app.py")


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test d'intégration — Agent Rapporteur SOC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes disponibles :
  inspect  Affiche le contenu actuel de la SharedMemory (sans rien modifier)
  inject   Injecte des données réalistes au format Analyseur, puis traite
  read     Lit les vraies données de l'Analyseur dans la SharedMemory, puis traite
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["inspect", "inject", "read"],
        default="inspect",
        help="Mode de test (défaut: inspect)",
    )
    args = parser.parse_args()

    memory = SharedMemory(base_dir=PROCESSED_DIR)
    print(f"📁 SharedMemory base_dir : {PROCESSED_DIR}")

    if args.mode == "inspect":
        inspect_shared_memory(memory)
    elif args.mode == "inject":
        inspect_shared_memory(memory)
        inject_and_process(memory)
    elif args.mode == "read":
        inspect_shared_memory(memory)
        read_and_process(memory)
