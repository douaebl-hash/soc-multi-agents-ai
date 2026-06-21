"""
test_agent.py
Unit and integration tests for the AI-Driven Agent Exécuteur.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

from agents.executeur.response_engine import ResponseEngine
from agents.executeur.action_logger import ActionLogger
from agents.executeur.playbooks import block_ip, isolate_host, notify_admin


class TestResponseEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.engine = ResponseEngine(dry_run=True)
        self.engine.blocklist_path = os.path.join(self.tmpdir, "blocklist.json")
        self.engine.isolated_path = os.path.join(self.tmpdir, "isolated.json")
        self.engine.alerts_dir = os.path.join(self.tmpdir, "alerts")
        os.makedirs(self.engine.alerts_dir, exist_ok=True)

    def test_block_ip(self):
        result = self.engine.block_ip("192.168.1.100", 30, "Test")
        self.assertEqual(result["action"], "BLOCK_IP")
        self.assertEqual(result["status"], "simulated")
        with open(self.engine.blocklist_path) as f:
            self.assertIn("192.168.1.100", json.load(f))

    def test_isolate_host(self):
        result = self.engine.isolate_host("10.0.0.5", "Malware")
        self.assertEqual(result["action"], "ISOLATE_HOST")

    def test_notify_admin(self):
        result = self.engine.notify_admin("Test", "CRITICAL", "INC-001")
        self.assertEqual(result["action"], "NOTIFY_ADMIN")
        self.assertTrue(os.path.exists(result["details"].split("File: ")[-1]))


class TestActionLogger(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = ActionLogger()
        self.logger.jsonl_path = os.path.join(self.tmpdir, "audit.jsonl")
        self.logger.json_path = os.path.join(self.tmpdir, "audit.json")

    def test_log_and_history(self):
        self.logger.log({"execution_id": "e1", "incident_id": "INC-A"})
        self.logger.log({"execution_id": "e2", "incident_id": "INC-B"})
        self.logger.log({"execution_id": "e3", "incident_id": "INC-A"})
        self.assertEqual(len(self.logger.get_history("INC-A")), 2)


class TestSafetyPolicies(unittest.TestCase):
    def test_internal_ip_blocking(self):
        from agents.executeur.executeur_agent import ExecuteurAgent
        agent = ExecuteurAgent(dry_run=True)
        self.assertTrue(agent._is_internal_ip("10.0.0.1"))
        self.assertTrue(agent._is_internal_ip("172.16.5.1"))
        self.assertTrue(agent._is_internal_ip("192.168.1.1"))
        self.assertFalse(agent._is_internal_ip("8.8.8.8"))
        self.assertFalse(agent._is_internal_ip("1.2.3.4"))


class TestFallbackPlan(unittest.TestCase):
    def test_critical_fallback(self):
        from agents.executeur.executeur_agent import ExecuteurAgent
        agent = ExecuteurAgent(dry_run=True)
        plan = agent._fallback_response_plan({
            "incident_id": "TEST-001",
            "severity": "CRITICAL",
            "source_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
        })
        actions = [a["action"] for a in plan["actions"]]
        self.assertIn("BLOCK_IP", actions)
        self.assertIn("ISOLATE_HOST", actions)
        self.assertIn("NOTIFY_ADMIN", actions)

    def test_high_fallback(self):
        from agents.executeur.executeur_agent import ExecuteurAgent
        agent = ExecuteurAgent(dry_run=True)
        plan = agent._fallback_response_plan({
            "incident_id": "TEST-002",
            "severity": "HIGH",
            "source_ip": "1.2.3.4",
        })
        actions = [a["action"] for a in plan["actions"]]
        self.assertIn("BLOCK_IP", actions)
        self.assertIn("NOTIFY_ADMIN", actions)
        self.assertNotIn("ISOLATE_HOST", actions)

    def test_low_fallback(self):
        from agents.executeur.executeur_agent import ExecuteurAgent
        agent = ExecuteurAgent(dry_run=True)
        plan = agent._fallback_response_plan({
            "incident_id": "TEST-003",
            "severity": "LOW",
        })
        actions = [a["action"] for a in plan["actions"]]
        self.assertEqual(actions, ["NOTIFY_ADMIN"])


class TestPlaybooks(unittest.TestCase):
    def setUp(self):
        self.engine = ResponseEngine(dry_run=True)
        self.tmpdir = tempfile.mkdtemp()
        self.engine.blocklist_path = os.path.join(self.tmpdir, "bl.json")
        self.engine.isolated_path = os.path.join(self.tmpdir, "iso.json")
        self.engine.alerts_dir = os.path.join(self.tmpdir, "alerts")
        os.makedirs(self.engine.alerts_dir, exist_ok=True)

    def test_block_ip_playbook(self):
        results = block_ip.run(self.engine, {
            "incident_id": "T1", "source_ip": "192.168.1.50",
            "attack_type": "Brute Force", "severity": "HIGH"
        })
        self.assertEqual(results[0]["action"], "BLOCK_IP")

    def test_block_ip_no_ip(self):
        results = block_ip.run(self.engine, {"incident_id": "T2", "source_ip": ""})
        self.assertEqual(results[0]["status"], "skipped")

    def test_isolate_host_playbook(self):
        results = isolate_host.run(self.engine, {
            "incident_id": "T3", "dest_ip": "10.0.0.5",
            "attack_type": "Malware", "severity": "CRITICAL"
        })
        self.assertEqual(results[0]["action"], "ISOLATE_HOST")

    def test_notify_admin_playbook(self):
        results = notify_admin.run(self.engine, {
            "incident_id": "T4", "severity": "MEDIUM",
            "attack_type": "Port Scan", "source_ip": "172.16.0.1",
            "anomalies": ["SYN flood"], "recommended_action": "Monitor"
        })
        self.assertEqual(results[0]["action"], "NOTIFY_ADMIN")


class TestIntegration(unittest.TestCase):
    def test_full_pipeline(self):
        engine = ResponseEngine(dry_run=True)
        tmpdir = tempfile.mkdtemp()
        engine.blocklist_path = os.path.join(tmpdir, "bl.json")
        engine.isolated_path = os.path.join(tmpdir, "iso.json")
        engine.alerts_dir = os.path.join(tmpdir, "alerts")
        os.makedirs(engine.alerts_dir, exist_ok=True)

        incident = {
            "incident_id": "E2E-001",
            "source_ip": "10.0.0.99",
            "dest_ip": "192.168.1.10",
            "attack_type": "Intrusion Attempt",
            "severity": "CRITICAL",
            "needs_escalation": True,
            "anomalies": ["Failed auth + port scan correlation"],
            "recommended_action": "Block and isolate",
        }

        results = []
        results.extend(block_ip.run(engine, incident))
        results.extend(isolate_host.run(engine, incident))
        results.extend(notify_admin.run(engine, incident))

        self.assertEqual(len(results), 3)
        actions = [r["action"] for r in results]
        self.assertIn("BLOCK_IP", actions)
        self.assertIn("ISOLATE_HOST", actions)
        self.assertIn("NOTIFY_ADMIN", actions)

        with open(engine.blocklist_path) as f:
            self.assertIn("10.0.0.99", json.load(f))
        with open(engine.isolated_path) as f:
            self.assertIn("192.168.1.10", json.load(f))
        self.assertEqual(len(os.listdir(engine.alerts_dir)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
