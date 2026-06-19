"""
test_agent.py
Test suite for Agent Analyseur.
Tests rules_engine + correlator directly (no LLM, no Ollama needed).
Also includes an optional end-to-end test that writes fake events into
SharedMemory the same way the real Extracteur does.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EXTRACTEUR_DIR = os.path.join(PROJECT_ROOT, "agents", "extracteur")
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, EXTRACTEUR_DIR)

from agents.analyseur.rules_engine import analyze_event, extract_entities
from agents.analyseur.correlator import CorrelationEngine
from src.utils.shared_memory import SharedMemory

# ─── Sample events (same shape as real Extracteur output) ─────────────────────
FAILED_SSH = {
    "event_id": "test_001",
    "timestamp": "2026-06-17T19:09:29",
    "source": "syslog",
    "severity": 0.5,
    "message": "Failed password for root from 192.168.1.105 port 22 ssh2",
    "raw": "<13>Jun 17 19:09:29 sshd[123]: Failed password for root from 192.168.1.105 port 22 ssh2",
}

PORT_SCAN_EVENT = {
    "event_id": "test_002",
    "timestamp": "2026-06-17T19:09:35",
    "source": "network",
    "severity": 0.6,
    "message": "SYN probe from 192.168.1.105 to multiple ports scan detected",
    "raw": "",
}

LOW_SEVERITY = {
    "event_id": "test_003",
    "timestamp": "2026-06-17T19:10:00",
    "source": "syslog",
    "severity": 0.1,
    "message": "User john logged in successfully",
    "raw": "",
}


def test_entity_extraction():
    print("\n[TEST 1] Entity extraction from syslog event")
    entities = extract_entities(FAILED_SSH)
    print(f"  IPs: {entities['ips']}  Users: {entities['users']}  Failed auth: {entities['is_failed_auth']}")
    assert "192.168.1.105" in entities["ips"]
    assert entities["is_failed_auth"]
    assert "root" in entities["users"]
    print("  PASSED")


def test_severity_scoring():
    print("\n[TEST 2] Heuristic severity scoring")
    enriched = analyze_event(FAILED_SSH)
    print(f"  severity={enriched['heuristic_severity']} type={enriched['event_type']} needs_llm={enriched['needs_llm_analysis']}")
    assert enriched["heuristic_severity"] >= 0.7
    assert enriched["needs_llm_analysis"]
    assert enriched["event_type"] == "BRUTE_FORCE_ATTEMPT"
    print("  PASSED")


def test_low_severity_no_llm():
    print("\n[TEST 3] Low severity event should NOT trigger LLM")
    enriched = analyze_event(LOW_SEVERITY)
    print(f"  severity={enriched['heuristic_severity']} needs_llm={enriched['needs_llm_analysis']}")
    assert not enriched["needs_llm_analysis"]
    print("  PASSED")


def test_brute_force_correlation():
    print("\n[TEST 4] Brute-force correlation (5 failed auths, same IP)")
    engine = CorrelationEngine()
    alert = None
    for i in range(5):
        event = {**FAILED_SSH, "event_id": f"bf_{i}"}
        enriched = analyze_event(event)
        alert = engine.add_event(enriched)
    print(f"  Final alert: {alert}")
    assert alert is not None
    assert alert["pattern"] == "BRUTE_FORCE_CONFIRMED"
    print("  PASSED")


def test_intrusion_correlation():
    print("\n[TEST 5] Port scan + auth failure = INTRUSION_ATTEMPT (CRITICAL)")
    engine = CorrelationEngine()
    enriched_scan = analyze_event(PORT_SCAN_EVENT)
    engine.add_event(enriched_scan)
    enriched_ssh = analyze_event(FAILED_SSH)
    alert = engine.add_event(enriched_ssh)
    print(f"  Final alert: {alert}")
    assert alert is not None
    assert alert["pattern"] == "INTRUSION_ATTEMPT"
    assert alert["severity_label"] == "CRITICAL"
    print("  PASSED")


def test_shared_memory_roundtrip():
    """
    Sanity check that we write/read SharedMemory exactly like the real
    Extracteur and Analyseur will - using a throwaway test channel so we
    don't touch real data.
    """
    print("\n[TEST 6] SharedMemory roundtrip (write -> read)")
    test_dir = os.path.join(PROJECT_ROOT, "data", "processed")
    mem = SharedMemory(base_dir=test_dir)

    mem.write("test_channel", [{"event_id": "x1", "message": "hello"}])
    result = mem.read("test_channel")
    print(f"  Read back: {result}")
    assert len(result) == 1
    assert result[0]["event_id"] == "x1"

    # cleanup
    path = os.path.join(test_dir, "test_channel.json")
    if os.path.exists(path):
        os.remove(path)
    print("  PASSED")


if __name__ == "__main__":
    print("=" * 60)
    print("  Agent Analyseur - Test Suite")
    print("=" * 60)

    tests = [
        test_entity_extraction,
        test_severity_scoring,
        test_low_severity_no_llm,
        test_brute_force_correlation,
        test_intrusion_correlation,
        test_shared_memory_roundtrip,
    ]

    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}")
        except Exception as e:
            print(f"  EXCEPTION: {e}")

    print(f"\n{'=' * 60}")
    print(f"  Results: {passed}/{len(tests)} tests passed")
    print("=" * 60)