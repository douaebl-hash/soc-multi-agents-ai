# Tests unitaires et d'intégration pour l'Agent Rapporteur

import json
import os
import unittest
from unittest.mock import patch, MagicMock

# ── permet d'importer les modules depuis le dossier rapporteur ──
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from templates import (
    get_incident_report_template,
    get_summary_template,
    get_dashboard_template,
)
from report_generator import _compute_stats


# ─── Données de test ──────────────────────────────────────────────────────────

SAMPLE_INCIDENT = {
    "incident_id"      : "INC-TEST-001",
    "timestamp"        : "2024-01-15T14:32:00",
    "source_ip"        : "192.168.1.105",
    "dest_ip"          : "10.0.0.50",
    "attack_type"      : "Brute Force SSH",
    "severity"         : "HIGH",
    "anomalies"        : ["500 tentatives en 2 min", "IP inconnue"],
    "correlated_events": ["INC-TEST-000"],
    "affected_system"  : "Serveur SSH Production",
    "risk_score"       : 8.5,
    "false_positive"   : False,
}

SAMPLE_INCIDENTS_LIST = [
    SAMPLE_INCIDENT,
    {
        "incident_id" : "INC-TEST-002",
        "timestamp"   : "2024-01-15T15:00:00",
        "source_ip"   : "10.10.10.10",
        "attack_type" : "Port Scan",
        "severity"    : "MEDIUM",
        "anomalies"   : ["Scan de 1000 ports en 30s"],
        "false_positive": False,
    },
    {
        "incident_id" : "INC-TEST-003",
        "timestamp"   : "2024-01-15T15:30:00",
        "source_ip"   : "172.16.0.5",
        "attack_type" : "SQL Injection",
        "severity"    : "CRITICAL",
        "anomalies"   : ["Payload SQL détecté", "Tentative d'exfiltration"],
        "false_positive": False,
    },
    {
        "incident_id"  : "INC-TEST-004",
        "attack_type"  : "Faux positif - scan interne",
        "severity"     : "LOW",
        "false_positive": True,
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS DES TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

class TestTemplates(unittest.TestCase):

    def test_incident_template_contains_required_fields(self):
        """Le gabarit d'incident doit contenir les infos clés de l'incident."""
        template = get_incident_report_template(SAMPLE_INCIDENT)
        self.assertIn("INC-TEST-001", template)
        self.assertIn("Brute Force SSH", template)
        self.assertIn("HIGH", template)
        self.assertIn("192.168.1.105", template)
        print("✅ test_incident_template_contains_required_fields : OK")

    def test_incident_template_has_report_sections(self):
        """Le gabarit doit demander toutes les sections du rapport."""
        template = get_incident_report_template(SAMPLE_INCIDENT)
        self.assertIn("Résumé Exécutif", template)
        self.assertIn("Recommandations", template)
        self.assertIn("Impact", template)
        print("✅ test_incident_template_has_report_sections : OK")

    def test_summary_template_lists_all_incidents(self):
        """Le gabarit de synthèse doit lister tous les incidents."""
        template = get_summary_template(SAMPLE_INCIDENTS_LIST)
        self.assertIn(str(len(SAMPLE_INCIDENTS_LIST)), template)
        self.assertIn("Brute Force SSH", template)
        self.assertIn("SQL Injection", template)
        print("✅ test_summary_template_lists_all_incidents : OK")

    def test_dashboard_template_contains_stats(self):
        """Le gabarit du dashboard doit contenir les stats clés."""
        stats = {
            "period"        : "Dernières 24h",
            "total_alerts"  : 10,
            "detection_rate": 90,
        }
        template = get_dashboard_template(stats)
        self.assertIn("10", template)
        self.assertIn("90", template)
        print("✅ test_dashboard_template_contains_stats : OK")


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS DES STATISTIQUES
# ═══════════════════════════════════════════════════════════════════════════════

class TestComputeStats(unittest.TestCase):

    def test_total_alerts_count(self):
        stats = _compute_stats(SAMPLE_INCIDENTS_LIST)
        self.assertEqual(stats["total_alerts"], 4)
        print("✅ test_total_alerts_count : OK")

    def test_false_positive_count(self):
        stats = _compute_stats(SAMPLE_INCIDENTS_LIST)
        self.assertEqual(stats["false_positives"], 1)
        print("✅ test_false_positive_count : OK")

    def test_confirmed_incidents(self):
        stats = _compute_stats(SAMPLE_INCIDENTS_LIST)
        self.assertEqual(stats["confirmed_incidents"], 3)
        print("✅ test_confirmed_incidents : OK")

    def test_detection_rate(self):
        stats = _compute_stats(SAMPLE_INCIDENTS_LIST)
        self.assertEqual(stats["detection_rate"], 75.0)
        print("✅ test_detection_rate : OK")

    def test_attack_types_counted(self):
        stats = _compute_stats(SAMPLE_INCIDENTS_LIST)
        self.assertIn("Brute Force SSH", stats["attack_types"])
        self.assertIn("SQL Injection",   stats["attack_types"])
        print("✅ test_attack_types_counted : OK")

    def test_top_ips_max_5(self):
        stats = _compute_stats(SAMPLE_INCIDENTS_LIST)
        self.assertLessEqual(len(stats["top_suspicious_ips"]), 5)
        print("✅ test_top_ips_max_5 : OK")

    def test_empty_list(self):
        stats = _compute_stats([])
        self.assertEqual(stats["total_alerts"], 0)
        self.assertEqual(stats["detection_rate"], 0)
        print("✅ test_empty_list : OK")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST D'INTÉGRATION (mock du LLM pour ne pas appeler Ollama)
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportGeneratorIntegration(unittest.TestCase):

    @patch("report_generator._run_chain")
    def test_generate_incident_report_creates_file(self, mock_run_chain):
        """Vérifie que generate_incident_report crée bien un fichier."""
        # Mock : simule la réponse du LLM sans appeler Ollama
        mock_run_chain.return_value = "## Rapport de test\nContenu simulé du rapport."

        from report_generator import generate_incident_report
        result = generate_incident_report(SAMPLE_INCIDENT)

        self.assertEqual(result["incident_id"], "INC-TEST-001")
        self.assertIn("filepath", result)
        self.assertTrue(os.path.exists(result["filepath"]))

        # Nettoyage
        os.remove(result["filepath"])
        print("✅ test_generate_incident_report_creates_file : OK")

    @patch("report_generator._run_chain")
    def test_generate_summary_report(self, mock_run_chain):
        """Vérifie que generate_summary_report fonctionne avec plusieurs incidents."""
        mock_run_chain.return_value = "## Synthèse simulée\nVue d'ensemble des incidents."

        from report_generator import generate_summary_report
        result = generate_summary_report(SAMPLE_INCIDENTS_LIST)

        self.assertEqual(result["incident_count"], 4)
        self.assertIn("filepath", result)
        self.assertTrue(os.path.exists(result["filepath"]))

        os.remove(result["filepath"])
        print("✅ test_generate_summary_report : OK")


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("🧪 TESTS — Agent Rapporteur SOC")
    print("=" * 60)
    unittest.main(verbosity=2)