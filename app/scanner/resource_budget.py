"""Memory-aware, bounded concurrency planning for active RCE verification."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

MAX_RCE_WORKERS = 8


def _read_number(path: str) -> Optional[int]:
    try:
        value = Path(path).read_text(encoding="ascii").strip()
        if value == "max":
            return None
        number = int(value)
        return number if number > 0 else None
    except (OSError, ValueError):
        return None


def available_memory_bytes() -> Optional[int]:
    """Return available memory, respecting a tighter Linux cgroup limit when present."""
    available: Optional[int] = None
    try:
        import psutil
        available = int(psutil.virtual_memory().available)
    except (ImportError, AttributeError, OSError, ValueError):
        pass

    # cgroup v2
    limit = _read_number("/sys/fs/cgroup/memory.max")
    current = _read_number("/sys/fs/cgroup/memory.current")
    # cgroup v1 fallback
    if limit is None:
        limit = _read_number("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        current = _read_number("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    if limit is not None and current is not None:
        remaining = max(0, limit - current)
        available = remaining if available is None else min(available, remaining)
    return available


def choose_batch_size(
    pending: int,
    *,
    available_bytes: Optional[int],
    max_workers: int,
    reserve_mb: int,
    worker_memory_mb: int,
) -> int:
    """Choose a wave size; unknown telemetry falls back to sequential execution."""
    if pending <= 0:
        return 0
    workers = max(1, min(int(max_workers), MAX_RCE_WORKERS))
    reserve = max(0, int(reserve_mb)) * 1024 * 1024
    per_worker = max(128, int(worker_memory_mb)) * 1024 * 1024
    if available_bytes is None:
        return 1
    if available_bytes <= reserve:
        return 0
    budget_workers = (available_bytes - reserve) // per_worker
    return min(pending, workers, max(0, int(budget_workers)))
