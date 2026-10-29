"""Scan orchestration: liveness -> MAC/DNS/ports -> web probe -> assessment."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Dict, List

from ..config import Settings
from ..models import Device, JobState, ScanJob, Severity
from . import demo_scenarios, discovery, dns_resolver, http_probe, port_scanner, vuln_rules
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
            if job.request.demo_scenario:
                await self._run_demo(job, cancel)
            else:
                await self._run(job, cancel)
            job.state = JobState.cancelled if cancel.is_set() else JobState.completed
        except Exception as exc:  # noqa: BLE001
            job.state = JobState.failed
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished_at = _now()
            if job.started_at:
                job.duration_s = round(
                    (job.finished_at - job.started_at).total_seconds(), 2
                )

    async def _run_demo(self, job: ScanJob, cancel: asyncio.Event) -> None:
        scenario_id = job.request.demo_scenario or "gov-cert"
        job.demo_scenario = scenario_id
        scen = next(
            (x for x in demo_scenarios.DEMO_SCENARIOS if x["id"] == scenario_id),
            demo_scenarios.DEMO_SCENARIOS[0],
        )
        job.target_label = f"{scen['cidr']} ({scen['id']})"
        job.workers = self.settings.max_concurrency
        total = scen.get("total_ips", 254)
        job.progress.total_ips = total

        devices = demo_scenarios.build_demo_devices(
            scenario_id, self.settings.gov_suffixes
        )
        steps = 8
        for i in range(1, steps + 1):
            if cancel.is_set():
                return
            await asyncio.sleep(0.12)
            job.progress.probed = min(total, int((total * i) / steps))
            revealed = devices[: max(1, int((len(devices) * i) / steps))]
            job.progress.online = len(revealed)
            job.progress.risks = sum(
                1 for d in revealed if d.severity != Severity.safe
            )
        job.devices = devices
        job.progress.probed = total
        job.progress.online = len(devices)
        job.progress.risks = sum(1 for d in devices if d.severity != Severity.safe)

    async def _run(self, job: ScanJob, cancel: asyncio.Event) -> None:
        req = job.request
        s = self.settings
        concurrency = min(req.concurrency or s.max_concurrency, s.max_concurrency)
        job.workers = concurrency
        delay = (
            req.polite_delay_ms
            if req.polite_delay_ms is not None
            else s.polite_delay_ms
        ) / 1000.0
        job.target_label = label_targets(req.targets)

        ips, total = expand_targets(req.targets, s.max_targets)
        job.progress.total_ips = total

        live_ports = list(dict.fromkeys(s.web_ports + s.liveness_ports))
        resolver = dns_resolver.ReverseResolver(timeout=1.5)
        devices: List[Device] = []

        async with http_probe.build_client(s.http_timeout, s.connect_timeout) as client:
            # Phase 0: is a proxy/firewall answering for every address?
            blocked = await discovery.intercepted_ports(live_ports, s.connect_timeout)
            canary_fp: Dict[int, str] = {}
            for port in sorted(p for p in blocked if p in s.web_ports):
                wr = await http_probe.probe_service(client, discovery.CANARY_IP, port)
                if wr is not None:
                    canary_fp[port] = wr.fingerprint
            job.intercepted_ports = sorted(blocked)
            clean_ports = [p for p in live_ports if p not in blocked]

            # Phase 1: liveness + latency
            sem = asyncio.Semaphore(concurrency)
            live: List[tuple[str, int | None, bool]] = []

            async def liveness(ip: str) -> None:
                if cancel.is_set():
                    return
                async with sem:
                    up, latency = await discovery.alive_latency(ip, clean_ports, s.connect_timeout)
                    verified = up
                    if not up and blocked:
                        # only intercepted ports answered: a candidate that must
                        # prove itself with a genuine web response
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

            # Phase 2: web probe + assessment
            probe_sem = asyncio.Semaphore(concurrency)

            async def inspect(ip: str, latency: int | None, verified: bool) -> None:
                if cancel.is_set():
                    return
                async with probe_sem:
                    open_all, (_, hostname, matched_suffix) = await asyncio.gather(
                        port_scanner.open_ports(ip, live_ports, s.connect_timeout),
                        resolver.resolve_and_match(ip, s.gov_suffixes),
                    )
                    other_open = [p for p in open_all if p not in s.web_ports and p not in blocked]

                    findings = []
                    web_open: List[int] = []
                    php_version = server = cms = None
                    merged_headers: Dict[str, str] = {}
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
                        if not merged_headers and wr.headers:
                            merged_headers = dict(wr.headers)
                        for f in wr.findings:
                            if f.rule_id not in seen_rules:
                                seen_rules.add(f.rule_id)
                                findings.append(f)
                    if delay:
                        await asyncio.sleep(delay)

                if not verified:
                    if not web_open:
                        return  # phantom: only the middlebox answered
                    job.progress.online += 1

                has_web = bool(web_open)
                has_tls = any(p in (443, 8443) for p in web_open)
                severity = vuln_rules.device_severity(findings) if has_web else Severity.safe
                service = ("HTTPS" if has_tls else "HTTP") if has_web else "ไม่มีบริการเว็บ"
                devices.append(Device(
                    ip=ip, hostname=hostname, matched_suffix=matched_suffix, up=True,
                    mac=arp.get(ip),
                    device_type=discovery.infer_device_type(ip, web_open, has_tls, bool(other_open)),
                    service=service, php_version=php_version, server=server, cms=cms,
                    open_ports=sorted(web_open), latency_ms=latency, severity=severity,
                    assessment=vuln_rules.thaicert_assessment(severity, has_web, findings),
                    findings=findings, headers=merged_headers,
                ))
                if severity != Severity.safe:
                    job.progress.risks += 1

            await asyncio.gather(*(inspect(ip, lat, ver) for ip, lat, ver in live))

        order = {
            Severity.critical: 0,
            Severity.high: 1,
            Severity.low: 2,
            Severity.safe: 3,
        }
        devices.sort(
            key=lambda d: (
                order[d.severity],
                0 if (d.php_version or d.open_ports) else 1,
                [int(o) for o in d.ip.split(".")],
            )
        )
        job.devices = devices
