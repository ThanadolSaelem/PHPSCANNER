"""Scan orchestration: liveness -> MAC/DNS/ports -> web probe -> assessment."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, List

from ..config import Settings
from ..models import Confidence, Device, Finding, JobState, RouteHop, ScanJob, ServicePort, Severity
from . import demo_scenarios, discovery, dns_resolver, http_probe, nmap_scan, port_scanner, ports, vuln_rules
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

    @staticmethod
    def _label(req) -> str:
        if req.site_hosts:
            hosts = list(dict.fromkeys(req.site_hosts.values()))
            ip_specs = [t for t in req.targets if t not in req.site_hosts]
            parts = hosts[:2] + ([label_targets(ip_specs)] if ip_specs else [])
            extra = len(hosts) - 2
            return ", ".join(parts) + (f" และอีก {extra} เว็บ" if extra > 0 else "")
        return label_targets(req.targets)

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
        job.target_label = self._label(req)

        ips, total = expand_targets(req.targets, s.max_targets)
        job.progress.total_ips = total

        web_ports = sorted(set(s.web_ports) | set(req.extra_web_ports))
        scan_ports = ports.profile_ports(req.port_profile, req.custom_ports, web_ports)
        job.scanned_ports = scan_ports
        job.scan_mode = "deep" if req.scan_mode == "deep" else "fast"
        # A host counts as "online" if ANY port we're going to scan answers, so
        # the chosen port profile actually finds hosts (e.g. a box whose only
        # open port is MySQL/3306) instead of only adding detail to hosts that
        # already answered on a web/standard port. Liveness and the port scan
        # run over the same set.
        live_ports = list(dict.fromkeys(scan_ports + s.liveness_ports))
        resolver = dns_resolver.ReverseResolver(timeout=1.5)
        devices: List[Device] = []

        # Deep mode: one nmap -sV pass over all targets for service/version
        # breadth (falls back to the fast path if nmap isn't installed).
        deep = req.scan_mode == "deep" and nmap_scan.nmap_available()
        nmap_map: Dict[str, nmap_scan.NmapHost] = {}
        if deep:
            budget = min(900.0, 60.0 + 0.15 * total * len(scan_ports))
            nmap_map = await nmap_scan.run_nmap(req.targets, scan_ports, timeout=budget)
            if not nmap_map:
                job.note_deep = "nmap ไม่คืนผล (หมดเวลาหรือไม่พบเครื่อง) — ใช้วิธีเชื่อมต่อ TCP แทน"
                deep = False

        async with http_probe.build_client(s.http_timeout, s.connect_timeout) as client:
            # Phase 0: is a proxy/firewall answering for every address?
            check_ports = sorted(set(live_ports) | set(scan_ports))
            blocked = await discovery.intercepted_ports(check_ports, s.connect_timeout)
            canary_fp: Dict[int, str] = {}
            for port in sorted(p for p in blocked if p not in ports.NON_WEB_PORTS):
                wr = await http_probe.probe_service(client, discovery.CANARY_IP, port)
                if wr is not None:
                    canary_fp[port] = wr.fingerprint
            job.intercepted_ports = sorted(blocked)
            clean_ports = [p for p in live_ports if p not in blocked]

            # Phase 1: liveness + latency
            job.progress.phase = "liveness"
            sem = asyncio.Semaphore(concurrency)
            live: List[tuple[str, int | None, bool]] = []

            async def liveness(ip: str) -> None:
                if cancel.is_set():
                    return
                if deep:
                    host = nmap_map.get(ip)
                    up = bool(host and host.ports)
                    latency = None
                    verified = up
                    job.progress.probed += 1
                    if up:
                        live.append((ip, latency, verified))
                        job.progress.online += 1
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

            # Phase 2: port scan + web probe + assessment on online hosts
            job.progress.phase = "inspect"
            job.progress.to_inspect = len(live)
            probe_sem = asyncio.Semaphore(concurrency)

            async def inspect(ip: str, latency: int | None, verified: bool) -> None:
                if cancel.is_set():
                    return
                site_host = req.site_hosts.get(ip)
                async with probe_sem:
                    if site_host:
                        lookup = asyncio.sleep(0, (ip, site_host, dns_resolver.match_suffix(site_host, s.gov_suffixes)))
                    else:
                        lookup = resolver.resolve_and_match(ip, s.gov_suffixes)
                    if deep:
                        host = nmap_map.get(ip)
                        open_all = sorted(host.ports) if host else []
                        _, hostname, matched_suffix = await lookup
                    else:
                        open_all, (_, hostname, matched_suffix) = await asyncio.gather(
                            port_scanner.open_ports(ip, scan_ports, s.connect_timeout),
                            lookup,
                        )

                    findings = []
                    web_open: List[int] = []
                    php_version = server = cms = runtime = None
                    merged_headers: Dict[str, str] = {}
                    seen_rules: set[str] = set()
                    # probe HTTP on every open port that isn't a known non-web
                    # service — PHP on a custom port (e.g. 18080) must be read,
                    # not just standard web ports
                    probe_ports = [p for p in open_all if p not in ports.NON_WEB_PORTS]
                    for port in probe_ports:
                        if site_host:
                            wr = await http_probe.probe_service(client, ip, port, host=site_host)
                        else:
                            wr = await http_probe.probe_service(client, ip, port)
                        if wr is None:
                            continue
                        if port in canary_fp and wr.fingerprint == canary_fp[port]:
                            continue  # the middlebox answered, not the host
                        web_open.append(port)
                        php_version = php_version or wr.php_version
                        runtime = runtime or wr.runtime
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
                job.progress.inspected += 1

                if not verified:
                    if not web_open:
                        return  # phantom: only the middlebox answered
                    job.progress.online += 1

                # ports a middlebox answers for prove nothing; keep them only
                # when a genuine web response came back on them
                found = sorted({p for p in open_all if p not in blocked} | set(web_open))
                nhost = nmap_map.get(ip) if deep else None
                services = []
                for p in found:
                    sp = ServicePort(port=p, **ports.describe(p, web=p in web_open))
                    np = nhost.ports.get(p) if nhost else None
                    if np:
                        if np.name and (sp.name == "ไม่ทราบ" or not (p in web_open)):
                            sp.name = np.name.upper() if len(np.name) <= 5 else np.name
                        sp.product = np.label() or None
                    services.append(sp)
                # deep mode: nmap -sV can read PHP even when our header probe
                # could not — use it so the PHP2Shell check still runs
                if nhost and not php_version:
                    for np in nhost.ports.values():
                        m = re.search(r"PHP[/ ]?(\d+\.\d+\.\d+)", f"{np.extra} {np.version} {np.product}")
                        if m:
                            php_version = m.group(1)
                            runtime = runtime or f"PHP {php_version}"
                            verdict = vuln_rules.assess_php2shell(
                                vuln_rules.parse_php_version(f"PHP/{php_version}"), True)
                            if verdict and verdict.vulnerable and "php2shell" not in seen_rules:
                                findings.append(Finding(
                                    rule_id="php2shell", title="PHP2Shell — unauthenticated RCE in PHP core",
                                    severity=Severity.critical, confidence=Confidence.high,
                                    description="PHP2Shell (CVSS 9.2) " + verdict.detail + " (ตรวจพบเวอร์ชันด้วย nmap -sV)",
                                    evidence=f"nmap: PHP {php_version} บนพอร์ต {np.port}",
                                    recommendation="อัปเดต PHP เป็น 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 ขึ้นไป",
                                    cve=list(vuln_rules.PHP2SHELL_CVES), cvss=9.2, cwe="CWE-787"))
                                seen_rules.add("php2shell")
                            break
                has_web = bool(web_open)
                has_tls = any(p in (443, 8443) for p in web_open)
                other_open = [p for p in found if p not in web_ports]
                severity = vuln_rules.device_severity(findings) if (has_web or findings) else Severity.safe
                service = ("HTTPS" if has_tls else "HTTP") if has_web else "ไม่มีบริการเว็บ"
                devices.append(Device(
                    ip=ip, hostname=hostname, matched_suffix=matched_suffix, up=True,
                    mac=arp.get(ip),
                    device_type=discovery.infer_device_type(ip, web_open, has_tls, bool(other_open)),
                    service=service, php_version=php_version, server=server, cms=cms, runtime=runtime,
                    open_ports=sorted(web_open), services=services, latency_ms=latency,
                    severity=severity,
                    assessment=vuln_rules.thaicert_assessment(severity, has_web, findings),
                    findings=findings, headers=merged_headers,
                ))
                if severity != Severity.safe:
                    job.progress.risks += 1

            await asyncio.gather(*(inspect(ip, lat, ver) for ip, lat, ver in live))

            # Deep mode: map the network path to a capped number of live hosts
            if deep and devices and nmap_scan.traceroute_available() and not cancel.is_set():
                job.progress.phase = "traceroute"
                cap = getattr(s, "traceroute_max", 16)
                tr_sem = asyncio.Semaphore(min(8, concurrency))

                async def trace(dev: Device) -> None:
                    if cancel.is_set():
                        return
                    async with tr_sem:
                        hops = await nmap_scan.run_traceroute(dev.ip)
                    dev.route = [RouteHop(hop=h["hop"], ip=h["ip"], rtt_ms=h["rtt_ms"]) for h in hops]

                await asyncio.gather(*(trace(d) for d in devices[:cap]))

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
