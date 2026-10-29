"""Append-only audit logging with query support for UI inspection."""
from __future__ import annotations

import json
import os
import sys
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List


class AuditLog:
    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._path = os.path.join(data_dir, "audit.log")
        self._memory_buffer: deque[Dict[str, Any]] = deque(maxlen=500)
        try:
            os.makedirs(data_dir, exist_ok=True)
        except OSError:
            pass

    def record(self, event: str, **fields: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        entry.update(fields)
        self._memory_buffer.appendleft(entry)
        try:
            os.makedirs(self._data_dir, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            print(f"[audit] failed to write entry: {entry}", file=sys.stderr)
        return entry

    def read_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
                for line in reversed(lines[-limit:]):
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                if entries:
                    return entries[:limit]
            except OSError:
                pass
        return list(self._memory_buffer)[:limit]
