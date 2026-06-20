import os
import sys
import json
from datetime import datetime, timezone

# Configuration des chemins
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROCESSED_DIR = os.path.join(CURRENT_DIR, "data", "processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)

print("⏳ Génération des données de test dans data/processed...")

# Simulation d'événements structurés
events = [
    {
        "event_id": "e1b2c3d4",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "network",
        "severity": 0.5,
        "message": "Network Traffic observed: TCP 192.168.1.50 -> 10.0.0.5:80"
    },
    {
        "event_id": "f5g6h7i8",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "network",
        "severity": 0.8,
        "message": "Network Traffic observed: TCP 172.16.0.99 -> 192.168.1.200:22 | Potential SSH brute force"
    }
]

# Écriture de events_structured.json
structured_path = os.path.join(PROCESSED_DIR, "events_structured.json")
with open(structured_path, "w", encoding="utf-8") as f:
    json.dump(events, f, indent=4)

# Écriture de pending_analysis.json (uniquement l'événement critique)
pending_path = os.path.join(PROCESSED_DIR, "pending_analysis.json")
with open(pending_path, "w", encoding="utf-8") as f:
    json.dump([events[1]], f, indent=4)

print("[✅ SUCCESS] Les fichiers suivants ont été créés :")
print(f" -> {structured_path}")
print(f" -> {pending_path}")