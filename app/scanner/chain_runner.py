"""Runner for CybersRMUTL/security-audit-toolkit (v6.3.0) integrated into Deep Mode.

Execution order in Deep Mode:
  1. CybersRMUTL security-audit-toolkit (--pipeline / module scan)
  2. nmap (-sT -sV service & version detection)
  3. traceroute (network path mapping)
"""
from __future__ import annotations

import asyncio
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
_SAFE_STATUSES = {"patched", "not-exploitable", "n/a", "mitigated", "safe", "ok"}


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
    if s in ("high", "สูง"):
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


def parse_toolkit_findings(raw_items: Any) -> List[Finding]:
    """Convert raw JSON items from security-audit-toolkit into thscan Finding objects."""
    if isinstance(raw_items, dict):
        for k in ("findings", "vulnerabilities", "results", "items"):
            if isinstance(raw_items.get(k), list):
                raw_items = raw_items[k]
                break
    if not isinstance(raw_items, list):
        return []

    out: List[Finding] = []
    seen: set[str] = set()
    for idx, item in enumerate(raw_items):
        if not isinstance(item, dict):
            continue
        raw_status = str(item.get("status") or item.get("result") or item.get("state") or "").strip().lower()
        if raw_status in _SAFE_STATUSES:
            continue
        cvss_val = item.get("cvss")
        try:
            cvss = float(cvss_val) if cvss_val is not None else None
        except (TypeError, ValueError):
            cvss = None

        cve_raw = item.get("cve") or item.get("id") or ""
        cves = [c.strip() for c in (cve_raw if isinstance(cve_raw, list) else str(cve_raw).split(",")) if c.strip().startswith("CVE-")]
        title = str(item.get("title") or item.get("name") or (cves[0] if cves else f"CybersRMUTL Finding #{idx + 1}")).strip()
        desc = str(item.get("details") or item.get("description") or item.get("summary") or "ตรวจพบจาก CybersRMUTL Security Audit Toolkit").strip()
        evidence = str(item.get("evidence") or item.get("component") or item.get("url") or item.get("target") or "").strip()
        rec = str(item.get("recommendation") or item.get("remediation") or "ตรวจสอบและอัปเดตแพตช์ตามคำแนะนำของ CybersRMUTL / ThaiCERT").strip()
        sev = _map_severity(raw_status or "vulnerable", cvss, str(item.get("severity") or ""))
        if sev == Severity.safe:
            continue
        rule_id = f"cybers_rmutl_{(cves[0] if cves else title).lower().replace(' ', '_')[:32]}"
        if rule_id in seen:
            continue
        seen.add(rule_id)
        out.append(Finding(
            rule_id=rule_id,
            title=f"[CybersRMUTL] {title}",
            severity=sev,
            confidence=Confidence.high,
            description=desc[:1200],
            evidence=evidence[:600],
            recommendation=rec[:600],
            cve=cves,
            cvss=cvss,
        ))
    return out


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
    except asyncio.TimeoutError:
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
    """Run CybersRMUTL security-audit-toolkit against a target IP, CIDR, or URL."""
    if cancel and cancel.is_set():
        return {"ran": False, "findings": [], "summary": "cancelled"}
    if not available():
        return {"ran": False, "findings": [], "summary": "security-audit-toolkit not installed"}

    timeout = float(getattr(settings, "rce_chain_timeout_s", 90))
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
        # 1. Check any JSON files written into output_dir or evidence_dir
        for jf in sorted(root.rglob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, list):
                    parsed_items.extend(data)
                elif isinstance(data, dict):
                    for k in ("findings", "vulnerabilities", "results", "items"):
                        if isinstance(data.get(k), list):
                            parsed_items.extend(data[k])
            except (OSError, json.JSONDecodeError):
                continue

        # 2. Also parse JSON blocks or CVE lines from stdout if present
        if raw_out and not parsed_items:
            m = re.search(r"(\[.*\]|\{.*\})", raw_out, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(1))
                    if isinstance(data, list):
                        parsed_items.extend(data)
                    elif isinstance(data, dict):
                        parsed_items.append(data)
                except json.JSONDecodeError:
                    pass
            # Extract CVE mentions from text output if CLI printed human-readable report
            if not parsed_items:
                for line in raw_out.splitlines():
                    if any(w in line.upper() for w in ("VULNERABLE", "HIGH-RISK", "UNPATCHED")):
                        cves = re.findall(r"CVE-\d{4}-\d{4,7}", line.upper())
                        parsed_items.append({
                            "cve": ",".join(cves),
                            "title": cves[0] if cves else "ช่องโหว่จากการตรวจเชิงลึก CybersRMUTL",
                            "status": "vulnerable",
                            "details": line.strip(),
                            "target": target,
                        })

        findings = parse_toolkit_findings(parsed_items)
        return {
            "ran": True,
            "target": target,
            "findings": findings,
            "vulnerability_count": len(findings),
            "summary": (
                f"CybersRMUTL ตรวจพบความเสี่ยง {len(findings)} รายการ"
                if findings else "CybersRMUTL ตรวจสอบเสร็จสิ้น ไม่พบช่องโหว่เพิ่มเติม"
            ),
        }


async def run_for_targets(
    targets: List[str],
    site_hosts: Dict[str, str],
    settings: Settings,
    cancel: Optional[asyncio.Event] = None,
) -> Dict[str, List[Finding]]:
    """Run CybersRMUTL toolkit across scan targets FIRST before nmap & traceroute.
    Returns {ip_or_target: [Finding, ...]}."""
    if not available() or not targets:
        return {}
    out: Dict[str, List[Finding]] = {}
    # Limit to first 16 targets per batch so large /24 scans stay responsive
    batch = targets[:16]
    sem = asyncio.Semaphore(4)

    async def _one(t: str) -> None:
        if cancel and cancel.is_set():
            return
        target_arg = site_hosts.get(t, t)
        async with sem:
            res = await run_target_audit(target_arg, settings, cancel)
        if res.get("findings"):
            out[t] = res["findings"]

    await asyncio.gather(*(_one(t) for t in batch))
    return out
