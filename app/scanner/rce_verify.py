"""Bounded async adapter for security_audit_toolkit.run_rce_verify.

It invokes the toolkit's original verifier in a child process so a wall-clock
limit can terminate a hung run. The API layer owns access control and requires
its feature flag, Bearer token, and explicit per-run confirmation.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

_RESULT_MARKER = "__THSCAN_RCE_VERIFY_RESULT__"
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_RUN_SEMAPHORE = asyncio.Semaphore(1)

_CHILD_RUNNER = r'''
import json, sys
import security_audit_toolkit as toolkit
payload = json.load(sys.stdin)
try:
    verdict, summary, evidence_dir = toolkit.run_rce_verify(
        payload["target"],
        lfi_url=payload.get("lfi_url"),
        session_endpoint=payload.get("session_endpoint"),
        evidence_dir=payload.get("evidence_dir"),
        timeout=payload["timeout"],
        no_verify_ssl=payload["no_verify_ssl"],
        operator=payload.get("operator"),
        confirm=False,
        i_own_this_target=True,
    )
    data = {"verdict": verdict, "summary": summary, "evidence_dir": evidence_dir}
except BaseException as exc:
    data = {"verdict": "ERROR", "summary": {}, "evidence_dir": payload.get("evidence_dir"),
            "error": type(exc).__name__ + ": " + str(exc)}
print("__THSCAN_RCE_VERIFY_RESULT__" + json.dumps(data, ensure_ascii=False, default=str))
'''


def _toolkit():
    try:
        return importlib.import_module("security_audit_toolkit")
    except (ImportError, SystemExit):
        return None


def available() -> bool:
    """Return True only when the bundled toolkit exposes the verifier."""
    toolkit = _toolkit()
    return bool(toolkit and callable(getattr(toolkit, "run_rce_verify", None)))


def _valid_http_url(value: Optional[str]) -> bool:
    if value is None:
        return True
    try:
        parsed = urlsplit(value)
        _ = parsed.port
        return (parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None and not parsed.fragment)
    except (TypeError, ValueError):
        return False


async def run(
    target: str,
    *,
    evidence_dir: Optional[str] = None,
    lfi_url: Optional[str] = None,
    session_endpoint: Optional[str] = None,
    timeout: float = 10.0,
    total_timeout: float = 180.0,
    no_verify_ssl: bool = False,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the upstream verifier with its full target and discovery options.

    ``timeout`` keeps the toolkit's per-request meaning. ``total_timeout`` is an
    additional app-level deadline enforced by terminating the child process.
    Authenticated API callers may target public hosts; the standalone toolkit's
    ownership override is set after the API has required explicit confirmation.
    """
    toolkit = _toolkit()
    fn = getattr(toolkit, "run_rce_verify", None) if toolkit else None
    if not callable(fn):
        return {
            "ran": False, "target": target, "verdict": "ERROR", "summary": {},
            "evidence_dir": None, "evidence_files": [],
            "error": "run_rce_verify is unavailable in security_audit_toolkit",
        }
    if not _valid_http_url(target):
        return {
            "ran": False, "target": target, "verdict": "REJECTED", "summary": {},
            "evidence_dir": None, "evidence_files": [],
            "error": "target_url must be a valid HTTP(S) URL",
        }
    for value, name in ((lfi_url, "lfi_url"), (session_endpoint, "session_endpoint")):
        if not _valid_http_url(value):
            return {
                "ran": False, "target": target, "verdict": "REJECTED", "summary": {},
                "evidence_dir": None, "evidence_files": [],
                "error": f"{name} must be a valid HTTP(S) URL",
            }
    if lfi_url and "FUZZ" not in lfi_url:
        return {
            "ran": False, "target": target, "verdict": "REJECTED", "summary": {},
            "evidence_dir": None, "evidence_files": [],
            "error": "lfi_url must contain the FUZZ placeholder",
        }

    try:
        request_timeout = max(1.0, min(float(timeout), 60.0))
        wall_timeout = max(5.0, min(float(total_timeout), 900.0))
    except (TypeError, ValueError):
        request_timeout, wall_timeout = 10.0, 180.0
    payload = {
        "target": target,
        "lfi_url": lfi_url,
        "session_endpoint": session_endpoint,
        "evidence_dir": evidence_dir,
        "timeout": request_timeout,
        "no_verify_ssl": bool(no_verify_ssl),
        "operator": operator,
    }

    try:
        await asyncio.wait_for(_RUN_SEMAPHORE.acquire(), timeout=0.01)
    except asyncio.TimeoutError:
        return {
            "ran": False, "target": target, "verdict": "BUSY", "summary": {},
            "evidence_dir": None, "evidence_files": [],
            "error": "another active RCE Verify is already running",
        }

    process = None
    result = None
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", _CHILD_RUNNER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(_PROJECT_ROOT),
        )
        communicate_task = asyncio.create_task(
            process.communicate(json.dumps(payload).encode("utf-8"))
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                asyncio.shield(communicate_task), timeout=wall_timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await communicate_task
            result = {
                "ran": True, "target": target, "verdict": "TIMEOUT", "summary": {},
                "evidence_dir": evidence_dir,
                "error": f"overall timeout exceeded ({wall_timeout:g}s)",
            }
        except asyncio.CancelledError:
            process.kill()
            try:
                await asyncio.shield(communicate_task)
            except (asyncio.CancelledError, Exception):
                pass
            raise

        if result is None:
            output = stdout.decode("utf-8", errors="replace")
            position = output.rfind(_RESULT_MARKER)
            if position < 0:
                err = stderr.decode("utf-8", errors="replace")[-1000:]
                result = {
                    "ran": True, "target": target, "verdict": "ERROR", "summary": {},
                    "evidence_dir": evidence_dir,
                    "error": "toolkit subprocess did not return a result" + (f": {err}" if err else ""),
                }
            else:
                try:
                    result = json.loads(output[position + len(_RESULT_MARKER):].splitlines()[0])
                    result["ran"] = True
                    result["target"] = target
                except (IndexError, json.JSONDecodeError) as exc:
                    result = {
                        "ran": True, "target": target, "verdict": "ERROR", "summary": {},
                        "evidence_dir": evidence_dir,
                        "error": f"invalid toolkit result: {type(exc).__name__}",
                    }
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - return adapter errors to the API
        result = {
            "ran": False, "target": target, "verdict": "ERROR", "summary": {},
            "evidence_dir": evidence_dir,
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        _RUN_SEMAPHORE.release()

    if result is None:
        result = {
            "ran": False, "target": target, "verdict": "ERROR", "summary": {},
            "evidence_dir": evidence_dir, "error": "toolkit subprocess returned no result",
        }
    returned_dir = result.get("evidence_dir")
    if evidence_dir and returned_dir:
        try:
            expected = Path(evidence_dir).resolve()
            actual = Path(returned_dir).resolve()
            if actual != expected:
                result["evidence_dir"] = None
                result["error"] = "toolkit returned an unexpected evidence directory"
                result["verdict"] = "ERROR"
        except (OSError, TypeError, ValueError):
            result["evidence_dir"] = None
            result["verdict"] = "ERROR"
            result["error"] = "invalid evidence directory returned by toolkit"

    evidence_files: List[str] = []
    safe_dir = result.get("evidence_dir")
    if safe_dir and os.path.isdir(safe_dir):
        try:
            root = Path(safe_dir).resolve()
            evidence_files = sorted(
                item.name for item in root.iterdir()
                if item.is_file() and item.resolve().parent == root
            )
        except OSError:
            pass
    result["evidence_files"] = evidence_files
    return result
