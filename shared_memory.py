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
        """
        Atomic write: writes to a temp file then renames it onto the real
        file. os.replace() is atomic on both Windows and Linux, so a
        concurrent reader never sees a partial/truncated file mid-write.

        On Windows, os.replace() can transiently fail with WinError 5
        (Access is denied) if another process briefly holds a read handle
        on the destination file (common with antivirus/indexing, or another
        agent process reading the file at that exact moment). This is
        retried with a short backoff rather than failing immediately.
        """
        import time as _time

        path = self._path(channel)
        tmp_path = path + ".tmp"
        with self._lock, open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2, default=str)

        last_error = None
        for attempt in range(5):
            try:
                os.replace(tmp_path, path)
                return
            except PermissionError as e:
                last_error = e
                _time.sleep(0.05 * (attempt + 1))  # 50ms, 100ms, 150ms, 200ms, 250ms

        # All retries exhausted - clean up the temp file and surface the error
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise last_error

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