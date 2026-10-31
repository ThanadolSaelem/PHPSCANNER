"""Bounded runner for the opt-in Security Audit Toolkit pipeline."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

from ..config import Settings


_RISK_STATUSES = {
    "vulnerable", "high-risk", "likely-vulnerable", "unpatched",
    "medium-risk", "vulnerable-version", "vulnerable-conditions",
}
_SAFE_STATUSES = {"patched", "not-exploitable", "n/a", "mitigated", "safe"}


def available() -> bool:
    return shutil.which("security-audit") is not None


def _text(value: Any, limit: int = 1200) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return str(value)[:limit]


def _severity(status: str, cvss: float | None) -> str:
    if status in _SAFE_STATUSES or status == "unknown":
        return "safe"
    if cvss is not None and cvss >= 9.0:
        return "critical"
    if cvss is not None and cvss >= 7.0:
        return "high"
    if status in {"vulnerable", "high-risk", "likely-vulnerable", "unpatched"}:
        return "high"
    return "low"


def _compact_findings(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    groups = []
    for key in ("nginx_cves", "php_cves", "nodejs_cves", "gitlab_cves"):
        value = scan.get(key)
        if isinstance(value, dict):
            groups.extend(value.items())
        elif isinstance(value, list):
            groups.extend((str(i), item) for i, item in enumerate(value))
    cve_115560 = scan.get("cve_115560")
    if isinstance(cve_115560, dict):
        groups.append((cve_115560.get("cve", "CVE-2026-115560"), cve_115560))

    findings = []
    seen = set()
    for key, raw in groups:
        if not isinstance(raw, dict):
            continue
        cve = _text(raw.get("cve") or key, 100)
        if cve in seen:
            continue
        seen.add(cve)
        status = _text(raw.get("status") or "unknown", 80).lower()
        try:
            cvss = float(raw["cvss"]) if raw.get("cvss") is not None else None
        except (TypeError, ValueError):
            cvss = None
        confidence = _text(raw.get("confidence") or "low", 40).lower()
        if confidence not in {"confirmed", "high", "medium", "low"}:
            confidence = "low"
        findings.append({
            "cve": cve,
            "title": _text(raw.get("title") or cve, 240),
            "status": status,
            "severity": _severity(status, cvss),
            "confidence": confidence,
            "description": _text(raw.get("reason") or raw.get("description") or raw.get("detail")),
            "evidence": _text(raw.get("evidence") or raw.get("proof")),
            "recommendation": _text(raw.get("recommendation") or raw.get("remediation")),
            "cvss": cvss,
            "risk": status in _RISK_STATUSES,
        })
        if len(findings) >= 40:
            break
    return findings


def _artifacts(root: Path) -> List[Dict[str, str]]:
    allowed_suffixes = {".pdf", ".csv", ".html", ".json", ".txt", ".log", ".xlsx", ".png"}
    root_resolved = root.resolve()
    found = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in allowed_suffixes:
            continue
        rel = path.relative_to(root)
        if not (
            rel.parts[0] in {"reports", "evidence"}
            or (len(rel.parts) == 1 and path.name.startswith("pipeline_"))
        ):
            continue
        try:
            path.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        kind = "รายงาน" if rel.parts[0] == "reports" else "หลักฐาน"
        if path.name.startswith("pipeline_"):
            kind = "ข้อมูลผลตรวจ"
        found.append({"path": rel.as_posix(), "name": path.name, "kind": kind})
    return sorted(found, key=lambda item: (item["kind"], item["path"]))


def _guard_source(host: str, ip: str) -> str:
    return f'''"""Restrict toolkit traffic to the configured lab host and pinned address."""
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

_ALLOWED_HOST = {host!r}.lower().rstrip(".")
_PINNED_IP = {ip!r}
_original_getaddrinfo = socket.getaddrinfo

def _guarded_getaddrinfo(host, port, *args, **kwargs):
    name = host.decode("ascii", "ignore") if isinstance(host, bytes) else str(host)
    normalized = name.rstrip(".").lower()
    try:
        address = str(ipaddress.ip_address(normalized))
    except ValueError:
        address = None
    if normalized != _ALLOWED_HOST and address != _PINNED_IP:
        raise socket.gaierror("Security Audit Toolkit is restricted to the authorized lab host")
    return _original_getaddrinfo(_PINNED_IP, port, *args, **kwargs)

socket.getaddrinfo = _guarded_getaddrinfo

try:
    import requests
    _original_redirect_target = requests.Session.get_redirect_target

    def _guarded_redirect_target(session, response):
        location = _original_redirect_target(session, response)
        if location:
            next_url = urlsplit(urljoin(response.url, location))
            if (next_url.scheme.lower() not in ("http", "https")
                    or (next_url.hostname or "").rstrip(".").lower() != _ALLOWED_HOST):
                raise requests.TooManyRedirects(
                    "Redirect refused outside the authorized lab host", response=response)
        return location

    requests.Session.get_redirect_target = _guarded_redirect_target
except ImportError:
    pass
'''


async def _stop_process(proc: asyncio.subprocess.Process, communicate_task: asyncio.Task) -> None:
    if proc.returncode is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    if not communicate_task.done():
        try:
            await asyncio.wait_for(communicate_task, timeout=2.0)
        except asyncio.TimeoutError:
            communicate_task.cancel()


async def run_chain(
    settings: Settings,
    job_id: str,
    target: str,
    target_ip: str,
    cancel: asyncio.Event,
) -> Dict[str, Any]:
    executable = shutil.which("security-audit")
    if not executable:
        return {"status": "unavailable", "target": target, "error": "Toolkit CLI is not installed"}

    try:
        ipaddress.ip_address(target_ip)
        parts = urlsplit(target)
        if parts.scheme.lower() not in ("http", "https") or (parts.hostname or "").lower() not in settings.rce_chain_allowed_hosts:
            return {"status": "rejected", "target": target, "error": "Target is outside the configured allowlist"}
    except ValueError:
        return {"status": "rejected", "target": target, "error": "Invalid pinned target address"}

    root = Path(settings.data_dir) / "chain" / job_id
    runtime_dir = root / ".runtime"
    root.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    (runtime_dir / "sitecustomize.py").write_text(
        _guard_source(parts.hostname or "", target_ip), encoding="utf-8"
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = str(runtime_dir)
    # Avoid sending the authorized lab scan through a machine-wide proxy.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)

    argv = [
        sys.executable, executable, "--pipeline", target,
        "--i-own-this-target", "--no-interactive",
        "--depth", "2", "--max-pages", "20", "--timeout", "8",
        "--output-dir", "reports",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(root),
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        return {"status": "error", "target": target, "error": "Unable to start Security Audit Toolkit"}

    communicate_task = asyncio.create_task(proc.communicate(input=b"n\ny\n"))
    deadline = asyncio.get_running_loop().time() + max(10, settings.rce_chain_timeout_s)
    outcome = "completed"
    while not communicate_task.done():
        if cancel.is_set():
            outcome = "cancelled"
            await _stop_process(proc, communicate_task)
            break
        if asyncio.get_running_loop().time() >= deadline:
            outcome = "timeout"
            await _stop_process(proc, communicate_task)
            break
        await asyncio.wait({communicate_task}, timeout=0.2)

    stdout = b""
    if communicate_task.done() and not communicate_task.cancelled():
        try:
            stdout, _stderr = communicate_task.result()
        except Exception:
            pass

    pipeline_files = sorted(root.glob("pipeline_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    scan: Dict[str, Any] = {}
    if pipeline_files:
        try:
            payload = json.loads(pipeline_files[0].read_text(encoding="utf-8"))
            results = payload.get("results") or []
            if results and isinstance(results[0], dict):
                scan = results[0]
        except (OSError, json.JSONDecodeError, AttributeError):
            scan = {}

    summary = scan.get("summary") if isinstance(scan.get("summary"), dict) else {}
    evidence_summary: Dict[str, Any] = {}
    evidence_dir = root / "evidence"
    evidence_files = sorted(evidence_dir.glob("*/summary.json")) if evidence_dir.exists() else []
    for evidence_file in evidence_files:
        try:
            evidence_summary = json.loads(evidence_file.read_text(encoding="utf-8"))
            break
        except (OSError, json.JSONDecodeError):
            continue
    if not evidence_summary:
        match = re.search(rb"Verdict:\s*([A-Z_]+)", stdout)
        if match:
            evidence_summary = {"verdict": match.group(1).decode("ascii", "ignore")}

    returncode = proc.returncode
    if outcome == "completed" and returncode != 0:
        outcome = "error"
    if outcome == "completed" and not scan:
        outcome = "error"

    reachable = bool(scan.get("reachable"))
    verdict = _text(evidence_summary.get("verdict") or "NOT_REQUIRED", 80)
    if outcome != "completed":
        verdict = outcome.upper()

    fingerprint = scan.get("fingerprint") if isinstance(scan.get("fingerprint"), dict) else {}
    php_versions = fingerprint.get("php_versions") or []
    artifacts = _artifacts(root)
    result: Dict[str, Any] = {
        "status": outcome if outcome != "completed" else ("completed" if reachable else "unreachable"),
        "target": target,
        "target_ip": target_ip,
        "tool_version": "6.3.0",
        "reachable": reachable,
        "summary": {
            key: summary.get(key, 0)
            for key in ("total_cves", "detected", "vulnerable", "warning", "critical", "safe", "unknown")
        },
        "findings": _compact_findings(scan),
        "lfi_count": len(scan.get("lfi_findings") or []),
        "rce_verdict": verdict,
        "server": _text(
            " ".join(str(x) for x in (fingerprint.get("server_family"), fingerprint.get("server_version")) if x), 160
        ),
        "php_version": _text(", ".join(str(x) for x in php_versions), 120),
        "artifacts": artifacts,
    }
    if outcome == "error":
        result["error"] = "Security Audit Toolkit did not finish successfully"
    elif outcome == "timeout":
        result["error"] = "หมดเวลาตามที่ผู้ดูแลกำหนด; หยุด toolkit แล้ว"
    elif outcome == "cancelled":
        result["error"] = "ผู้ใช้หยุดการตรวจ chain แล้ว"
    elif not scan:
        result["error"] = "Toolkit did not produce a pipeline result"
    return result
