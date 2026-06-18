"""
shared_memory.py
Mémoire partagée simple, basée sur des fichiers JSON, permettant aux agents
du système multi-agents (Extracteur, Analyseur, Rapporteur, Exécuteur) de
communiquer entre eux sans dépendre d'un broker externe (pattern adapté à
un projet académique / prototype).

Chaque agent lit/écrit dans des "canaux" identifiés par un nom, par exemple :
  - "pending_analysis"   : événements pertinents en attente d'analyse
  - "incidents"           : incidents qualifiés par l'Agent Analyseur
  - "actions_a_executer"  : actions de remédiation pour l'Agent Exécuteur
"""

import json
import os
from datetime import datetime, timezone
from threading import Lock
from typing import Any, List


class SharedMemory:
    def __init__(self, base_dir: str = "data/processed"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self._lock = Lock()

    def _path(self, channel: str) -> str:
        return os.path.join(self.base_dir, f"{channel}.json")

    def read(self, channel: str) -> List[Any]:
        path = self._path(channel)
        if not os.path.exists(path):
            return []
        with self._lock, open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return json.loads(content) if content else []

    def write(self, channel: str, items: List[Any]) -> None:
        path = self._path(channel)
        with self._lock, open(path, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2, default=str)

    def append(self, channel: str, item: Any) -> None:
        items = self.read(channel)
        items.append(item)
        self.write(channel, items)

    def publish_message(self, channel: str, sender: str, payload: Any) -> None:
        """Publie un message structuré et horodaté, utilisé pour la
        communication inter-agents (ex: Extracteur -> Analyseur)."""
        message = {
            "sender": sender,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        self.append(channel, message)
