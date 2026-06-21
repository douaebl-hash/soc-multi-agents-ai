"""
action_logger.py
Immutable audit trail for the Agent Exécuteur.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class ActionLogger:
    def __init__(self):
        self.audit_dir = os.path.join(PROJECT_ROOT, "data", "shared")
        self.jsonl_path = os.path.join(self.audit_dir, "execution_audit.jsonl")
        self.json_path = os.path.join(self.audit_dir, "execution_audit.json")
        os.makedirs(self.audit_dir, exist_ok=True)

    def log(self, record: Dict[str, Any]) -> None:
        record["logged_at"] = datetime.now(timezone.utc).isoformat()

        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

        summary = self._load_summary()
        summary.append(record)
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)

    def _load_summary(self) -> list:
        if not os.path.exists(self.json_path):
            return []
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def get_history(self, incident_id: str = "") -> list:
        summary = self._load_summary()
        if incident_id:
            return [r for r in summary if r.get("incident_id") == incident_id]
        return summary
