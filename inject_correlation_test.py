"""
inject_correlation_test.py
Manually injects 5 failed-auth events from the same IP into pending_analysis,
to trigger a live BRUTE_FORCE_CONFIRMED correlation alert in the running agent.

Run this while analyseur_agent.py is running in another terminal.
"""

import sys
import os
import time
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "agents", "extracteur"))

from src.utils.shared_memory import SharedMemory

memory = SharedMemory(base_dir=os.path.join(PROJECT_ROOT, "data", "processed"))

ATTACKER_IP = "192.168.50.66"

events = []
for i in range(5):
    events.append({
        "event_id": f"corrtest_{i}_{int(time.time())}",
        "timestamp": datetime.utcnow().isoformat(),
        "source": "syslog",
        "severity": 0.5,
        "message": f"Failed password for root from {ATTACKER_IP} port 22 ssh2",
        "raw": f"<13>sshd[999]: Failed password for root from {ATTACKER_IP} port 22 ssh2",
    })

print(f"Injecting {len(events)} brute-force events from {ATTACKER_IP} into pending_analysis...")
memory.write("pending_analysis", events)
print("Done. Check the running agent's terminal within ~2-4 seconds.")
print("Then run: type data\\processed\\correlation_alerts.json")