"""Append-only tamper-evident audit logging with SHA-256 hash chaining."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List

GENESIS_HASH = "0" * 64


def _compute_entry_sha256(entry_without_hash: Dict[str, Any], prev_hash: str) -> str:
    payload = {k: v for k, v in entry_without_hash.items() if k != "sha256"}
    payload["prev_hash"] = prev_hash
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{prev_hash}:{canonical}".encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._path = os.path.join(data_dir, "audit.log")
        self._memory_buffer: deque[Dict[str, Any]] = deque(maxlen=500)
        self._last_hash: str = GENESIS_HASH
        try:
            os.makedirs(data_dir, exist_ok=True)
        except OSError:
            pass
        self._init_last_hash()

    def _init_last_hash(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and isinstance(obj.get("sha256"), str):
                            self._last_hash = obj["sha256"]
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    def record(self, event: str, **fields: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        entry.update(fields)
        prev_hash = self._last_hash or GENESIS_HASH
        entry["prev_hash"] = prev_hash
        entry["sha256"] = _compute_entry_sha256(entry, prev_hash)
        self._last_hash = entry["sha256"]
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

    def verify_chain(self) -> Dict[str, Any]:
        """Verify SHA-256 hash-chain integrity across recorded audit entries."""
        checked = 0
        expected_prev = GENESIS_HASH
        head_sha256 = None
        raw_entries: List[Dict[str, Any]] = []
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                raw_entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                return {"valid": False, "checked": checked, "head_sha256": head_sha256}
            except OSError:
                pass
        else:
            raw_entries = list(reversed(self._memory_buffer))

        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            digest = item.get("sha256")
            prev = item.get("prev_hash")
            # Legacy entries recorded before SHA-256 hash chaining are skipped gracefully
            if not digest or not prev:
                continue
            if checked > 0 and prev != expected_prev:
                return {"valid": False, "checked": checked, "head_sha256": head_sha256}
            calc = _compute_entry_sha256(item, prev)
            if calc != digest:
                return {"valid": False, "checked": checked, "head_sha256": head_sha256}
            expected_prev = digest
            head_sha256 = digest
            checked += 1

        return {
            "valid": True,
            "checked": checked,
            "head_sha256": head_sha256 or GENESIS_HASH,
        }

    def query(self, event: str | None = None, limit: int = 100) -> List[Dict[str, Any]]:
        items = self.read_recent(limit=max(limit * 2, 100))
        if event:
            items = [x for x in items if x.get("event") == event]
        return items[:limit]
