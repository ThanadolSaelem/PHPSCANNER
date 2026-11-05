"""Scan orchestration:
- Fast Mode ("fast"): TCP connect liveness & port scan + HTTP/PHP probe + CybersRMUTL (security-audit-toolkit)
- Deep Mode ("deep"): Nmap service/version scan (-sT -sV) + Traceroute network path mapping
"""
from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from ..config import Settings
from ..models import Confidence, Device, Finding, JobState, RouteHop, ScanJob, ServicePort, Severity, WebEndpoint
from . import chain_runner, demo_scenarios, discovery, dns_resolver, http_probe, lan_fingerprint, nmap_scan, port_scanner, ports, vuln_rules
from .ip_utils import expand_targets, label_targets
from . import rce_batch
from .rce_batch import RceVerifyBatchStream


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScanEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run(self, job: ScanJob, cancel: asyncio.Event) -> None:
        job.state = JobState.running
        job.started_at = _now()
        run_task = asyncio.create_task(self._run_pipeline(job, cancel))
        cancel_task = asyncio.create_task(cancel.wait())
        try:
            done, _ = await asyncio.wait(
                {run_task, cancel_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel.is_set() or cancel_task in done:
                if not run_task.done():
                    run_task.cancel()
                    try:
                        await run_task
                    except (asyncio.CancelledError, Exception):
                        pass
                job.state = JobState.cancelled
            else:
                await run_task
                job.state = JobState.cancelled if cancel.is_set() else JobState.completed
        except asyncio.CancelledError:
            if not run_task.done():
                run_task.cancel()
            job.state = JobState.cancelled
        except Exception as exc:  # noqa: BLE001
            job.state = JobState.failed
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            if not cancel_task.done():
                cancel_task.cancel()
            job.finished_at = _now()
            if job.started_at:
                job.duration_s = round(
                    (job.finished_at - job.started_at).total_seconds(), 2
                )

    async def _run_pipeline(self, job: ScanJob, cancel: asyncio.Event) -> None:
        if job.request.demo_scenario:
            await self._run_demo(job, cancel)
            job.progress.fast_scan_complete = not cancel.is_set()
            return

        request = job.request.rce_verify
        if request is not None and request.all_scanned_targets:
            stream = RceVerifyBatchStream(job, self.settings, request, cancel)
            worker = asyncio.create_task(stream.run())
            try:
                await self._run(job, cancel, on_web_endpoint=stream.submit)
                job.progress.fast_scan_complete = not cancel.is_set()
                if job.progress.fast_scan_complete and job.request.lan_fingerprint:
                    await self._run_lan_fingerprint(job, cancel)
                if job.progress.fast_scan_complete and stream.discovered:
                    job.progress.phase = "rce_verify"
                if not worker.done():
                    await stream.finish()
                await worker
            except BaseException:
                if not worker.done():
                    await stream.finish()
                    worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
                raise
            return

        await self._run(job, cancel)
        job.progress.fast_scan_complete = not cancel.is_set()
        if job.progress.fast_scan_complete and job.request.lan_fingerprint:
            await self._run_lan_fingerprint(job, cancel)
        if cancel.is_set() or request is None:
            return
        job.progress.rce_verify_started = True
        await self._run_rce_verify(job, cancel)
        job.progress.rce_verify_done = True

    async def _run_rce_verify(self, job: ScanJob, cancel: asyncio.Event) -> None:
        request = job.request.rce_verify
        if request is None or cancel.is_set():
            return

        if request.all_scanned_targets:
            await self._run_rce_verify_batch(job, request, cancel)
            return

        if not request.target_url:
            job.rce_verify_result = {
                "ran": False, "verdict": "REJECTED", "summary": {},
                "evidence_dir": None, "evidence_files": [],
                "error": "target_url is required unless all_scanned_targets is enabled",
            }
            return

        parsed = urlsplit(request.target_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        scanned = any(
            endpoint.scheme.lower() == parsed.scheme.lower()
            and endpoint.port == port
            and host in {endpoint.ip.lower(), (endpoint.hostname or "").lower().rstrip(".")}
            and endpoint.ip == device.ip
            for device in job.devices
            for endpoint in device.web_endpoints
        )
        if not scanned:
            job.progress.phase = "rce_verify"
            job.rce_verify_result = {
                "ran": False,
                "target": request.target_url,
                "verdict": "SKIPPED",
                "summary": {},
                "evidence_dir": None,
                "evidence_files": [],
                "error": "URL/port ไม่พบในผล fast scan จึงไม่มีการส่ง active request",
            }
            return

        job.progress.phase = "rce_verify"
        evidence_dir = os.path.join(self.settings.data_dir, "rce-verify", job.id)
        result = await chain_runner.run_rce_verify_target(
            request.target_url,
            self.settings,
            evidence_dir=evidence_dir,
            operator=request.operator,
            lfi_url=request.lfi_url,
            session_endpoint=request.session_endpoint,
            timeout=request.timeout,
            no_verify_ssl=request.no_verify_ssl,
        )
        result["target"] = request.target_url
        if result.get("evidence_dir"):
            try:
                data_root = Path(self.settings.data_dir).resolve()
                expected = Path(evidence_dir).resolve()
                evidence_path = Path(result["evidence_dir"]).resolve()
                if evidence_path != expected or not evidence_path.is_relative_to(data_root):
                    raise ValueError("evidence path escaped its run directory")
                result["evidence_dir"] = os.path.relpath(evidence_path, data_root)
            except (OSError, TypeError, ValueError):
                result["evidence_dir"] = None
                result["error"] = "toolkit returned an invalid evidence path"
                result["verdict"] = "ERROR"
        job.rce_verify_result = result

    async def _run_lan_fingerprint(self, job: ScanJob, cancel: asyncio.Event) -> None:
        """Annotate only scan-confirmed devices; never change vulnerability results."""
        request = job.request
        if not request.lan_fingerprint or not request.lan_fingerprint_confirm or cancel.is_set():
            return
        if request.scan_mode != "fast" or not request.targets or request.sites:
            job.lan_fingerprint_result = {
                "status": "rejected_request",
                "error": "LAN fingerprinting requires a fast scan with direct IP/CIDR targets",
                "target_count": 0,
            }
            job.progress.lan_fingerprint_started = True
            job.progress.lan_fingerprint_done = True
            return
        if not self.settings.lan_fingerprint_enabled:
            job.lan_fingerprint_result = {"status": "disabled", "target_count": 0}
            job.progress.lan_fingerprint_started = True
            job.progress.lan_fingerprint_done = True
            return
        job.progress.phase = "lan_fingerprint"
        try:
            job.lan_fingerprint_result = await lan_fingerprint.fingerprint_devices(
                job.devices,
                self.settings,
                cancel,
                job.progress,
                multicast=bool(request.lan_multicast_discovery and request.lan_multicast_confirm),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # fingerprinting must not erase a completed fast-scan result
            job.lan_fingerprint_result = {
                "status": "error",
                "error": f"LAN fingerprint failed: {type(exc).__name__}",
                "target_count": len(job.devices),
            }
            job.progress.lan_fingerprint_started = True
            job.progress.lan_fingerprint_done = True
            job.progress.lan_fingerprint_total = len(job.devices)

    async def _run_rce_verify_batch(self, job: ScanJob, request, cancel: asyncio.Event) -> None:
        """Fallback for direct callers; the normal pipeline uses the live endpoint stream."""
        job.progress.phase = "rce_verify"
        stream = RceVerifyBatchStream(job, self.settings, request, cancel)
        worker = asyncio.create_task(stream.run())
        try:
            for device in job.devices:
                for endpoint in device.web_endpoints:
                    await stream.submit(endpoint)
        except BaseException:
            if not worker.done():
                await stream.finish()
                worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)
            raise
        if not worker.done():
            await stream.finish()
        await worker

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

    async def _run(
        self,
        job: ScanJob,
        cancel: asyncio.Event,
        on_web_endpoint: Optional[Callable[[WebEndpoint], Awaitable[None]]] = None,
    ) -> None:
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
        if req.port_profile == "custom" and req.extra_web_ports:
            scan_ports = sorted(set(scan_ports) | set(req.extra_web_ports))
        job.scanned_ports = scan_ports
        if req.port_profile == "custom":
            live_ports = list(scan_ports)
        else:
            live_ports = list(dict.fromkeys(scan_ports + s.liveness_ports))
        resolver = dns_resolver.ReverseResolver(timeout=1.5)
        devices: List[Device] = []

        # Deep mode: nmap (-sT -sV) + traceroute ONLY
        # Fast mode: TCP connect + CybersRMUTL (security-audit-toolkit)
        want_deep = req.scan_mode == "deep"
        deep = want_deep and nmap_scan.nmap_available()
        if want_deep and not deep:
            job.note_deep = "เครื่องนี้ยังไม่ได้ติดตั้ง nmap — ใช้โหมดเร็ว (TCP + CybersRMUTL) แทน"
        nmap_map: Dict[str, nmap_scan.NmapHost] = {}
        if deep:
            job.progress.phase = "nmap"
            budget = min(1800.0, 120.0 + 0.3 * total * len(scan_ports))
            nmap_map = await nmap_scan.run_nmap(req.targets, scan_ports, timeout=budget)
            if not nmap_map:
                job.note_deep = (
                    "nmap ไม่คืนผล (หมดเวลา เป้าหมายบล็อก หรือเครือข่ายที่รัน thscan "
                    "ออกไปหา nmap ไม่ได้) — ถอยไปใช้โหมดเร็ว (เชื่อมต่อ TCP) แทน"
                )
                deep = False
        job.scan_mode = "deep" if deep else "fast"

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
                    if up and host and host.ports:
                        first_port = sorted(host.ports)[0]
                        _, latency = await discovery.alive_latency(ip, [first_port], s.connect_timeout)
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
                        up, latency = await discovery.alive_latency(ip, sorted(blocked), s.connect_timeout)
                job.progress.probed += 1
                if up:
                    live.append((ip, latency, verified))
                    if verified:
                        job.progress.online += 1

            await asyncio.gather(*(liveness(ip) for ip in ips))
            if cancel.is_set():
                return

            # Fast Mode includes CybersRMUTL (security-audit-toolkit) without waiting for nmap
            chain_map: Dict[str, List[Finding]] = {}
            if not deep and chain_runner.available() and not cancel.is_set():
                job.progress.phase = "cybers_rmutl"
                rmutl_targets = [ip for ip, _, _ in live] or (ips if len(ips) <= 16 else [])
                if rmutl_targets:
                    chain_map = await chain_runner.run_for_targets(
                        rmutl_targets, req.site_hosts, s, cancel
                    )
                    live_ips = {ip for ip, _, _ in live}
                    for cip in chain_map:
                        if cip not in live_ips:
                            live.append((cip, None, True))
                            job.progress.online += 1
                    job.chain_result = {
                        "ran": True,
                        "hosts_flagged": len(chain_map),
                        "vulnerability_count": sum(len(v) for v in chain_map.values()),
                    }

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

                    # Attach any findings from CybersRMUTL (Fast Mode)
                    findings: List[Finding] = list(chain_map.get(ip, []))
                    seen_rules: set[str] = {f.rule_id for f in findings}
                    web_open: List[int] = []
                    web_endpoints: List[WebEndpoint] = []
                    tmeta = chain_runner.get_target_meta(ip) if hasattr(chain_runner, "get_target_meta") else {}
                    php_version = tmeta.get("php_version")
                    server = tmeta.get("server")
                    cms = tmeta.get("cms")
                    runtime = f"PHP {php_version}" if php_version else None
                    merged_headers: Dict[str, str] = {}
                    probe_ports = [p for p in open_all if p not in ports.NON_WEB_PORTS]
                    for port in probe_ports:
                        if site_host:
                            wr = await http_probe.probe_service(client, ip, port, host=site_host)
                        else:
                            wr = await http_probe.probe_service(client, ip, port)
                        if wr is None:
                            continue
                        if port in canary_fp and wr.fingerprint == canary_fp[port]:
                            continue
                        web_open.append(port)
                        web_endpoint = WebEndpoint(
                            ip=ip, hostname=wr.hostname or site_host or ip,
                            port=wr.probe_port or port,
                            scheme=wr.probe_scheme or wr.scheme,
                            http_title=wr.http_title,
                            server=wr.server,
                            powered_by=wr.powered_by,
                            technologies=wr.technologies,
                            banner_snippet=wr.banner_snippet or None,
                        )
                        web_endpoints.append(web_endpoint)
                        if on_web_endpoint is not None:
                            await on_web_endpoint(web_endpoint)
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
                    if not web_open and not findings:
                        return
                    job.progress.online += 1

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
                    mac=arp.get(ip) or tmeta.get("mac"),
                    device_type=discovery.infer_device_type(ip, web_open, has_tls, bool(other_open)),
                    device_type_confidence=Confidence.low,
                    device_type_source="fast-scan service role",
                    device_type_evidence=(
                        [f"TCP web ports: {', '.join(map(str, sorted(web_open)))}"] if web_open
                        else [f"TCP open ports: {', '.join(map(str, found))}"] if found else []
                    ),
                    service=service, php_version=php_version, server=server, cms=cms, runtime=runtime,
                    open_ports=sorted(web_open), web_endpoints=web_endpoints,
                    services=services, latency_ms=latency,
                    severity=severity,
                    assessment=vuln_rules.thaicert_assessment(severity, has_web, findings),
                    findings=findings, headers=merged_headers,
                    chain_result={"findings": len(chain_map.get(ip, []))} if ip in chain_map else None,
                ))
                if severity != Severity.safe:
                    job.progress.risks += 1

            await asyncio.gather(*(inspect(ip, lat, ver) for ip, lat, ver in live))

            # Deep mode: map the network path via traceroute
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
