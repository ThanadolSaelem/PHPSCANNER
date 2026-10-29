"""Scan orchestration: liveness -> MAC/ports -> web probe -> assessment.

Pipeline per authorized target range:
  1. expand targets (capped by max_targets)
  2. TCP-connect liveness sweep to find online hosts + latency
  3. read the ARP table (now populated by the sweep) for MAC addresses
  4. for each live host: port-scan web ports, probe PHP on any that answer,
     assess php2shell, label the device, write a ThaiCERT assessment line
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List

from ..config import Settings
from ..models import Device, JobState, ScanJob, Severity
from . import discovery, http_probe, port_scanner, vuln_rules
from .ip_utils import expand_targets, label_targets


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScanEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run(self, job: ScanJob, cancel: asyncio.Event) -> None:
        job.state = JobState.running
        job.started_at = _now()
        try:
            await self._run(job, cancel)
            job.state = JobState.cancelled if cancel.is_set() else JobState.completed
        except Exception as exc:  # noqa: BLE001
            job.state = JobState.failed
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished_at = _now()
            if job.started_at:
                job.duration_s = round((job.finished_at - job.started_at).total_seconds(), 2)

    async def _run(self, job: ScanJob, cancel: asyncio.Event) -> None:
        req = job.request
        s = self.settings
        concurrency = min(req.concurrency or s.max_concurrency, s.max_concurrency)
        job.workers = concurrency
        delay = (req.polite_delay_ms if req.polite_delay_ms is not None
                 else s.polite_delay_ms) / 1000.0
        job.target_label = label_targets(req.targets)

        ips, total = expand_targets(req.targets, s.max_targets)
        job.progress.total_ips = total

        live_ports = list(dict.fromkeys(s.web_ports + s.liveness_ports))

        async with http_probe.build_client(s.http_timeout, s.connect_timeout) as client:
            # --- Phase 0: detect a middlebox answering for every address ---
            blocked = await discovery.intercepted_ports(live_ports, s.connect_timeout)
            canary_fp = {}
            for port in sorted(p for p in blocked if p in s.web_ports):
                wr = await http_probe.probe_service(client, discovery.CANARY_IP, port)
                if wr is not None:
                    canary_fp[port] = wr.fingerprint
            job.intercepted_ports = sorted(blocked)
            clean_ports = [p for p in live_ports if p not in blocked]

            # --- Phase 1: liveness + latency -----------------------------
            sem = asyncio.Semaphore(concurrency)
            live: List[tuple[str, int | None, bool]] = []

            async def liveness(ip: str) -> None:
                if cancel.is_set():
                    return
                async with sem:
                    up, latency = await discovery.alive_latency(ip, clean_ports, s.connect_timeout)
                    verified = up
                    if not up and blocked:
                        # only intercepted ports answered: keep as a candidate
                        # that must prove itself with a genuine web response
                        up, latency = await discovery.alive_latency(ip, sorted(blocked), s.connect_timeout)
                job.progress.probed += 1
                if up:
                    live.append((ip, latency, verified))
                    if verified:
                        job.progress.online += 1

            await asyncio.gather(*(liveness(ip) for ip in ips))
            if cancel.is_set():
                return

            arp = discovery.read_arp_table()

            # --- Phase 2: web probe + assessment -------------------------
            probe_sem = asyncio.Semaphore(concurrency)
            devices: List[Device] = []

            async def inspect(ip: str, latency: int | None, verified: bool) -> None:
                if cancel.is_set():
                    return
                async with probe_sem:
                    open_all = await port_scanner.open_ports(ip, live_ports, s.connect_timeout)
                    other_open = [p for p in open_all if p not in s.web_ports and p not in blocked]

                    findings = []
                    web_open: List[int] = []
                    php_version = server = cms = None
                    seen_rules: set[str] = set()
                    for port in [p for p in open_all if p in s.web_ports]:
                        wr = await http_probe.probe_service(client, ip, port)
                        if wr is None:
                            continue
                        if port in canary_fp and wr.fingerprint == canary_fp[port]:
                            continue  # the middlebox answered, not the host
                        web_open.append(port)
                        php_version = php_version or wr.php_version
                        server = server or wr.server
                        cms = cms or wr.cms
                        for f in wr.findings:
                            if f.rule_id not in seen_rules:
                                seen_rules.add(f.rule_id)
                                findings.append(f)
                    if delay:
                        await asyncio.sleep(delay)

                if not verified:
                    if not web_open:
                        return  # phantom: nothing but the middlebox answered
                    job.progress.online += 1

                has_web = bool(web_open)
                has_tls = any(p in (443, 8443) for p in web_open)
                severity = vuln_rules.device_severity(findings) if has_web else Severity.safe
                service = ("HTTPS" if has_tls else "HTTP") if has_web else "ไม่มีบริการเว็บ"
                device = Device(
                    ip=ip, up=True, mac=arp.get(ip),
                    device_type=discovery.infer_device_type(ip, web_open, has_tls, bool(other_open)),
                    service=service, php_version=php_version, server=server, cms=cms,
                    open_ports=sorted(web_open), latency_ms=latency, severity=severity,
                    assessment=vuln_rules.thaicert_assessment(severity, has_web, findings),
                    findings=findings,
                )
                devices.append(device)
                if severity != Severity.safe:
                    job.progress.risks += 1

            await asyncio.gather(*(inspect(ip, lat, ver) for ip, lat, ver in live))

        order = {Severity.critical: 0, Severity.high: 1, Severity.low: 2, Severity.safe: 3}
        devices.sort(key=lambda d: (
            order[d.severity],
            0 if (d.php_version or d.open_ports) else 1,
            [int(o) for o in d.ip.split(".")],
        ))
        job.devices = devices
