"""Runner for CybersRMUTL/security-audit-toolkit integrated into Fast Mode.

Supports:
1. Direct Python module invocation (`security_audit_toolkit.scan_single_target`) extracting all 16 CVE dictionary buckets:
   nginx_cves, php_cves, cve_115560, nodejs_cves, gitlab_cves, app_cves, device_cves,
   component_cves, exposure_cves, framework_cves, header_cves, tls_cves, online_cves,
   oskernel_cves, win_php_cves, container_cves + lfi_findings + preconditions.
2. CLI fallback (`security-audit --pipeline ...`).
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Settings
from ..models import Confidence, Finding, Severity

_RISK_STATUSES = {
    "vulnerable", "high-risk", "likely-vulnerable", "unpatched",
    "medium-risk", "vulnerable-version", "vulnerable-conditions", "open", "risk",
}
_SAFE_STATUSES = {"patched", "not-exploitable", "n/a", "mitigated", "safe", "ok", "unknown"}

_LAST_META: Dict[str, Dict[str, Any]] = {}


def get_target_meta(ip_or_host: str) -> Dict[str, Any]:
    return _LAST_META.get(ip_or_host, {})


_TOOLKIT_DICT_KEYS = (
    "nginx_cves",
    "php_cves",
    "nodejs_cves",
    "gitlab_cves",
    "app_cves",
    "device_cves",
    "component_cves",
    "exposure_cves",
    "framework_cves",
    "header_cves",
    "tls_cves",
    "online_cves",
    "oskernel_cves",
    "win_php_cves",
    "container_cves",
)


def _cli_path() -> Optional[str]:
    return shutil.which("security-audit")


def _module_available() -> bool:
    try:
        return importlib.util.find_spec("security_audit_toolkit") is not None
    except (ImportError, ValueError):
        return False


def available() -> bool:
    """Return True if CybersRMUTL security-audit-toolkit is installed as CLI or module."""
    return _cli_path() is not None or _module_available()


def _map_severity(status: str, cvss: Optional[float], raw_sev: str = "") -> Severity:
    s = raw_sev.strip().lower()
    if s in ("critical", "วิกฤต"):
        return Severity.critical
    if s.startswith(("high", "medium-high")) or s == "สูง":
        return Severity.high
    if s in ("medium", "low", "ปานกลาง", "ต่ำ"):
        return Severity.low
    st = status.strip().lower()
    if st in _SAFE_STATUSES:
        return Severity.safe
    if cvss is not None:
        if cvss >= 9.0:
            return Severity.critical
        if cvss >= 7.0:
            return Severity.high
        if cvss > 0:
            return Severity.low
    if st in {"vulnerable", "high-risk", "likely-vulnerable", "unpatched"}:
        return Severity.high
    return Severity.low


def _flatten_toolkit_result(raw: Any) -> List[Dict[str, Any]]:
    """Extract all finding dicts from a `scan_single_target` return dict or a list of dicts."""
    items: List[Dict[str, Any]] = []
    if isinstance(raw, list):
        for el in raw:
            items.extend(_flatten_toolkit_result(el))
        return items
    if not isinstance(raw, dict):
        return items

    # 1. Check the 15 category dicts from scan_single_target
    found_buckets = False
    for k in _TOOLKIT_DICT_KEYS:
        bucket = raw.get(k)
        if isinstance(bucket, dict):
            found_buckets = True
            for v in bucket.values():
                if isinstance(v, dict):
                    items.append(v)
        elif isinstance(bucket, list):
            found_buckets = True
            items.extend(x for x in bucket if isinstance(x, dict))

    # 2. Check cve_115560 single dict
    c115 = raw.get("cve_115560")
    if isinstance(c115, dict):
        found_buckets = True
        items.append(c115)

    # 3. Check lfi_findings list
    lfi_list = raw.get("lfi_findings")
    if isinstance(lfi_list, list):
        found_buckets = True
        for lfi in lfi_list:
            if isinstance(lfi, dict):
                items.append({
                    "cve": "LFI-CANDIDATE",
                    "name": f"พบจุดเสี่ยง Local File Inclusion (LFI) ที่ {lfi.get('path', '')}?{lfi.get('param', '')}",
                    "severity": "Critical" if lfi.get("confidence") == "high" else "High",
                    "status": "vulnerable",
                    "reason": f"หลักฐาน: {lfi.get('best_evidence', '')} ({lfi.get('url', '')})",
                    "host_check": "ตรวจสอบและกรองพารามิเตอร์ที่นำไปเปิดไฟล์ใน include/require/file_get_contents",
                })

    if found_buckets:
        return items

    # 4. Generic fallback for {"findings": [...]} or single finding dict
    for k in ("findings", "vulnerabilities", "results", "items"):
        if isinstance(raw.get(k), list):
            return [x for x in raw[k] if isinstance(x, dict)]
    if "cve" in raw or "title" in raw or "status" in raw:
        return [raw]
    return items


def parse_toolkit_findings(raw_items: Any) -> List[Finding]:
    """Convert raw output from security-audit-toolkit into thscan Finding objects."""
    flat = _flatten_toolkit_result(raw_items)
    out: List[Finding] = []
    seen: set[str] = set()
    for idx, item in enumerate(flat):
        raw_status = str(item.get("status") or item.get("result") or item.get("state") or "").strip().lower()
        if raw_status in _SAFE_STATUSES:
            continue
        cvss_val = item.get("cvss")
        try:
            cvss = float(cvss_val) if cvss_val is not None else None
        except (TypeError, ValueError):
            cvss = None

        cve_raw = item.get("cve") or item.get("id") or ""
        cves = [
            c.strip()
            for c in (cve_raw if isinstance(cve_raw, list) else str(cve_raw).split(","))
            if c.strip().startswith("CVE-")
        ]
        name_str = str(item.get("title") or item.get("name") or (cves[0] if cves else f"Finding #{idx + 1}")).strip()
        desc = str(item.get("reason") or item.get("details") or item.get("description") or item.get("summary") or name_str).strip()
        evidence = str(item.get("trigger") or item.get("evidence") or item.get("component") or item.get("url") or "").strip()
        rec = str(item.get("host_check") or item.get("recommendation") or item.get("mitigation") or "ตรวจสอบและอัปเดตแพตช์ตามคำแนะนำ").strip()
        sev = _map_severity(raw_status or "vulnerable", cvss, str(item.get("severity") or ""))
        if sev == Severity.safe:
            continue
        slug = (str(cve_raw) or name_str).lower().replace(" ", "_")[:40]
        rule_id = f"cybers_rmutl_{slug}"
        if rule_id in seen:
            continue
        seen.add(rule_id)
        conf = Confidence.confirmed if raw_status in ("vulnerable", "high-risk") else Confidence.high
        out.append(
            Finding(
                rule_id=rule_id,
                title=name_str,
                severity=sev,
                confidence=conf,
                description=desc[:1200],
                evidence=evidence[:600],
                recommendation=rec[:600],
                cve=cves,
                cvss=cvss,
            )
        )
    return out


def _run_module_target_sync(target: str, timeout: float) -> Optional[Dict[str, Any]]:
    """Directly invoke `security_audit_toolkit.scan_single_target` in Python if available."""
    try:
        sat = importlib.import_module("security_audit_toolkit")
        if not hasattr(sat, "scan_single_target"):
            return None
        opts = {
            "timeout": min(timeout, 6.0),
            "depth": 1,
            "max_pages": 10,
            "crawl_budget": 10,
            "rate": 0,
            "lfi_threads": 4,
            "skip_lfi": False,
            "no_verify_ssl": True,
            "verbose": False,
            "scan_mode": "auto",
            "mptcp_probe": True,
            "online_cve": True,
        }
        return sat.scan_single_target(target, opts, idx=1, total=1)
    except Exception:
        return None


def _run_sync(argv: List[str], timeout: float) -> Optional[str]:
    import subprocess
    try:
        res = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return res.stdout.decode("utf-8", errors="replace")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


async def _exec(argv: List[str], timeout: float) -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except NotImplementedError:
        return await asyncio.to_thread(_run_sync, argv, timeout)
    except (OSError, ValueError):
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return None
    return out.decode("utf-8", errors="replace")


async def run_target_audit(
    target: str,
    settings: Settings,
    cancel: Optional[asyncio.Event] = None,
) -> Dict[str, Any]:
    """Run CybersRMUTL security-audit-toolkit against a target IP or hostname."""
    if cancel and cancel.is_set():
        return {"ran": False, "findings": [], "summary": "cancelled"}
    if not available():
        return {"ran": False, "findings": [], "summary": "security-audit-toolkit not installed"}

    timeout = float(getattr(settings, "rce_chain_timeout_s", 45))

    # 1. Prefer direct Python module call (`scan_single_target`) so all 16 CVE buckets are captured losslessly
    if _module_available():
        raw_dict = await asyncio.to_thread(_run_module_target_sync, target, timeout)
        if isinstance(raw_dict, dict):
            fp = raw_dict.get("fingerprint") or {}
            cms_info = raw_dict.get("cms") or {}
            php_vers = fp.get("php_versions") or []
            srv_fam = fp.get("server_family") or ""
            srv_ver = fp.get("server_version") or ""
            srv_str = f"{srv_fam}/{srv_ver}".strip("/") if srv_fam and srv_fam != "unknown" else None
            meta = {
                "php_version": sorted(php_vers)[0] if php_vers else None,
                "cms": cms_info.get("cms") if isinstance(cms_info, dict) else None,
                "server": srv_str,
                "mac": fp.get("mac"),
                "os": fp.get("os"),
                "waf": fp.get("waf"),
                "stack_layers": fp.get("stack_layers") or [],
            }
            _LAST_META[target] = meta
            findings = parse_toolkit_findings(raw_dict)
            return {
                "ran": True,
                "target": target,
                "findings": findings,
                "vulnerability_count": len(findings),
                "summary": f"ตรวจพบความเสี่ยง {len(findings)} รายการ",
            }

    # 2. Fallback to CLI execution
    cli = _cli_path()
    with tempfile.TemporaryDirectory(prefix="thscan_rmutl_") as tmp_dir:
        root = Path(tmp_dir)
        ev_dir = root / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        base_cmd = [cli] if cli else [sys.executable, "-m", "security_audit_toolkit"]
        argv = [
            *base_cmd,
            "--pipeline", target,
            "--i-own-this-target",
            "--no-interactive",
            "--output-dir", str(root),
            "--evidence-dir", str(ev_dir),
        ]
        raw_out = await _exec(argv, timeout=timeout)
        parsed_items: List[Any] = []
        for jf in sorted(root.rglob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                parsed_items.append(data)
            except (OSError, json.JSONDecodeError):
                continue
        if raw_out and not parsed_items:
            m = re.search(r"(\[.*\]|\{.*\})", raw_out, re.DOTALL)
            if m:
                try:
                    parsed_items.append(json.loads(m.group(1)))
                except json.JSONDecodeError:
                    pass
        findings = parse_toolkit_findings(parsed_items)
        return {
            "ran": True,
            "target": target,
            "findings": findings,
            "vulnerability_count": len(findings),
            "summary": f"ตรวจพบความเสี่ยง {len(findings)} รายการ",
        }


async def run_for_targets(
    targets: List[str],
    site_hosts: Dict[str, str],
    settings: Settings,
    cancel: Optional[asyncio.Event] = None,
) -> Dict[str, List[Finding]]:
    """Run CybersRMUTL toolkit across scan targets in Fast Mode."""
    if not available() or not targets:
        return {}
    out: Dict[str, List[Finding]] = {}
    batch = targets[:16]
    sem = asyncio.Semaphore(4)

    async def _one(t: str) -> None:
        if cancel and cancel.is_set():
            return
        target_arg = site_hosts.get(t, t)
        async with sem:
            res = await run_target_audit(target_arg, settings, cancel)
        if target_arg in _LAST_META:
            _LAST_META[t] = _LAST_META[target_arg]
        if res.get("findings"):
            out[t] = res["findings"]

    await asyncio.gather(*(_one(t) for t in batch))
    return out



def rce_verify_available() -> bool:
    """Return True only when the toolkit module exposes its active verifier."""
    try:
        from . import rce_verify
        return rce_verify.available()
    except Exception:  # pragma: no cover - optional toolkit/package failure
        return False


async def run_rce_verify_target(
    target_url: str,
    settings: Settings,
    *,
    evidence_dir: Optional[str] = None,
    operator: Optional[str] = None,
    lfi_url: Optional[str] = None,
    session_endpoint: Optional[str] = None,
    timeout: float = 10.0,
    no_verify_ssl: bool = False,
    pinned_ip: Optional[str] = None,
    max_concurrency: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the bounded verifier, optionally pinned to a scan-confirmed address."""
    try:
        from . import rce_verify
    except Exception:  # pragma: no cover - optional toolkit/package failure
        return {
            "ran": False, "target": target_url, "verdict": "ERROR", "summary": {},
            "evidence_dir": None, "evidence_files": [],
            "error": "rce_verify adapter is unavailable",
        }
    return await rce_verify.run(
        target_url,
        evidence_dir=evidence_dir,
        lfi_url=lfi_url,
        session_endpoint=session_endpoint,
        timeout=timeout,
        total_timeout=float(getattr(settings, "rce_verify_total_timeout_s", 180)),
        no_verify_ssl=no_verify_ssl,
        operator=operator,
        pinned_ip=pinned_ip,
        max_concurrency=max_concurrency or int(getattr(settings, "rce_verify_max_workers", 2)),
    )
