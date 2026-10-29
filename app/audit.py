"""Append-only audit logging.

Every scan is recorded with who/what/when so the operating team has an
accountable trail — important for authorized security work against government
infrastructure.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict


class AuditLog:
    def __init__(self, data_dir: str) -> None:
        self._path = os.path.join(data_dir, "audit.log")
        os.makedirs(data_dir, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        entry: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        entry.update(fields)
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            # Never let audit I/O crash a scan; stderr is captured by Docker.
            import sys
            print(f"[audit] failed to write entry: {entry}", file=sys.stderr)
