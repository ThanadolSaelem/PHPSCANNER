"""RCE Verify adapter — wraps CybersRMUTL security-audit-toolkit
``run_rce_verify`` for the thscan FastAPI surface.

The toolkit's ``run_rce_verify`` is blocking I/O (``requests`` + ``time.sleep``)
so it is executed inside ``asyncio.to_thread`` and never blocks the event loop.

There is **no interactive confirmation** here: the operator has already
acknowledged the active-check consent in the UI before this endpoint is called,
and scope is enforced by the caller (``main.py``) together with this adapter.

Chain-of-custody evidence produced by the toolkit
(transcript.log, metadata.json, summary.json, rce_proof.txt, rce_response.html)
is written under ``evidence_dir`` and returned as a file list so the API can
expose downloads.
"""
from __future__ import annotations

import asyncio
import importlib
import os
from typing import Any, Dict, List, Optional


def _module():
    return importlib.import_module("security_audit_toolkit")


def available() -> bool:
    """True when the bundled toolkit exposes run_rce_verify."""
    try:
        sat = _module()
    except ImportError:
        return False
    return hasattr(sat, "run_rce_verify")


async def run(target: str,
              *,
              evidence_dir: Optional[str] = None,
              timeout: float = 90.0,
              operator: Optional[str] = None,
              i_own_this_target: bool = False) -> Dict[str, Any]:
    """Run RCE verify against one target.

    Returns a JSON-serialisable dict::

        {
            "ran": True,
            "target": "http://10.0.0.5/",
            "verdict": "RCE_CONFIRMED",          # | CANARY_CONFIRMED | NOT_CONFIRMED | REJECTED | ERROR
            "summary": {"verdict": "...", ...},
            "evidence_dir": "data/chain/<job>/rce-verify/10_0_0_5",
            "evidence_files": ["transcript.log", "metadata.json", "summary.json", "rce_proof.txt"],
            "error": None,
        }
    """
    sat = _module()
    fn = getattr(sat, "run_rce_verify", None)
    if fn is None:
        return {"ran": False, "target": target,
                "verdict": "ERROR", "summary": {},
                "evidence_dir": None, "evidence_files": [],
                "error": "run_rce_verify not found in security_audit_toolkit"}

    # Scope: private hosts only unless the operator explicitly claimed ownership.
    scope_ok = sat.is_private_host(target) or i_own_this_target
    if not scope_ok:
        return {"ran": False, "target": target,
                "verdict": "REJECTED", "summary": {},
                "evidence_dir": None, "evidence_files": [],
                "error": "target is not a private host and --i-own-this-target was not set"}

    try:
        # Signature: run_rce_verify(target, lfi_url, session_endpoint,
        #                          evidence_dir, timeout, no_verify_ssl, operator,
        #                          confirm, i_own_this_target)
        verdict, summary, ev_dir = await asyncio.to_thread(
            fn, target,
            None, None,                       # lfi_url / session_endpoint: auto-detect
            evidence_dir,
            float(timeout),
            False,                            # no_verify_ssl
            operator,
            False,                            # confirm: no blocking input() via API
            i_own_this_target,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ran": False, "target": target,
                "verdict": "ERROR", "summary": {},
                "evidence_dir": evidence_dir, "evidence_files": [],
                "error": f"{type(exc).__name__}: {exc}"}

    evidence_files: List[str] = []
    if ev_dir and os.path.isdir(ev_dir):
        try:
            for name in sorted(os.listdir(ev_dir)):
                p = os.path.join(ev_dir, name)
                if os.path.isfile(p):
                    evidence_files.append(name)
        except OSError:
            pass

    return {
        "ran": True,
        "target": target,
        "verdict": verdict,
        "summary": summary or {},
        "evidence_dir": ev_dir,
        "evidence_files": evidence_files,
    }
