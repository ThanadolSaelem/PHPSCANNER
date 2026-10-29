"""Thin validation helper used by the API layer."""
from __future__ import annotations

from typing import List, Tuple

from .scanner.ip_utils import TargetError, expand_targets


def validate_targets(targets: List[str], max_targets: int) -> Tuple[bool, int, str]:
    """Return ``(ok, total, message)`` for a target list.

    Validation fully expands the ranges (cheap for the capped sizes we allow)
    so malformed specs and over-large scopes are rejected before a job starts.
    """
    try:
        _, total = expand_targets(targets, max_targets)
    except TargetError as exc:
        return False, 0, str(exc)
    return True, total, "ok"
