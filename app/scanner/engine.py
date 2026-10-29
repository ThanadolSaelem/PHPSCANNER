"""Scan orchestration: discovery -> scope filter -> probe -> findings.

The engine runs a single :class:`ScanJob` to completion, updating its progress
in place so the API can stream it to the UI. It is cooperative-cancellable via
an :class:`asyncio.Event`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from ..config import Settings
from ..models import (HostResult, JobState, ScanJob, ServiceResult)
from . import http_probe, port_scanner
from .dns_resolver import ReverseResolver, match_suffix
from .ip_utils import expand_targets


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
            if cancel.is_set():
                job.state = JobState.cancelled
            else:
                job.state = JobState.completed
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            job.state = JobState.failed
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished_at = _now()

    async def _run(self, job: ScanJob, cancel: asyncio.Event) -> None:
        req = job.request
        suffixes = req.allowed_suffixes or self.settings.default_allowed_suffixes
        concurrency = min(
            req.concurrency or self.settings.max_concurrency,
            self.settings.max_concurrency,
        )
        ports = req.ports or self.settings.web_ports
        delay = (req.polite_delay_ms if req.polite_delay_ms is not None
                 else self.settings.polite_delay_ms) / 1000.0

        ips, total = expand_targets(req.targets, self.settings.max_targets)
        job.progress.total_ips = total

        resolver = ReverseResolver(self.settings.dns_servers, self.settings.dns_timeout)

        # --- Phase 1: reverse DNS + scope filter -------------------------
        dns_sem = asyncio.Semaphore(concurrency)
        in_scope: List[HostResult] = []

        async def resolve_one(ip: str) -> None:
            if cancel.is_set():
                return
            async with dns_sem:
                hostname = await resolver.reverse(ip)
            job.progress.resolved += 1
            matched = match_suffix(hostname, suffixes)
            if matched:
                host = HostResult(ip=ip, hostname=hostname, in_scope=True,
                                  matched_suffix=matched)
                in_scope.append(host)
                job.progress.in_scope += 1

        await asyncio.gather(*(resolve_one(ip) for ip in ips))
        if cancel.is_set():
            job.hosts = in_scope
            return

        # --- Phase 2: probe in-scope hosts -------------------------------
        probe_sem = asyncio.Semaphore(concurrency)
        async with http_probe.build_client(
            self.settings.http_timeout, self.settings.connect_timeout
        ) as client:

            async def probe_host(host: HostResult) -> None:
                if cancel.is_set():
                    return
                async with probe_sem:
                    found = await port_scanner.open_ports(
                        host.ip, ports, self.settings.connect_timeout
                    )
                    services: List[ServiceResult] = []
                    for port in found:
                        svc = await http_probe.probe_service(
                            client, host.ip, port, host.hostname
                        )
                        if svc is not None:
                            services.append(svc)
                            job.progress.findings += len(svc.findings)
                    if delay:
                        await asyncio.sleep(delay)
                host.services = services
                host.recompute_severity()
                job.progress.probed += 1

            await asyncio.gather(*(probe_host(h) for h in in_scope))

        # Keep hosts sorted by severity so the worst are first in the UI.
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
        in_scope.sort(key=lambda h: order.get(
            h.max_severity.value if h.max_severity else None, 5))
        job.hosts = in_scope
