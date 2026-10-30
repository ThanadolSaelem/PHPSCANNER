"""In-memory job registry with background execution, schedules, and JSON export."""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .audit import AuditLog
from .config import Settings
from .models import (
    Device,
    JobState,
    ScanJob,
    ScanProgress,
    ScanRequest,
    ScheduleCreate,
    ScheduleItem,
    Severity,
)
from .scanner import demo_scenarios
from .scanner.engine import ScanEngine


class JobStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine = ScanEngine(settings)
        self.audit = AuditLog(settings.data_dir)
        self._jobs: Dict[str, ScanJob] = {}
        self._cancels: Dict[str, asyncio.Event] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._schedules: Dict[str, ScheduleItem] = {}
        self._lock = asyncio.Lock()
        self._load_from_disk()

    # --- persistence -------------------------------------------------------
    def _sched_path(self) -> str:
        return os.path.join(self.settings.data_dir, "schedules.json")

    def _load_from_disk(self) -> None:
        """Restore scan history and schedules saved by previous runs."""
        results = os.path.join(self.settings.data_dir, "results")
        try:
            files = sorted(
                (os.path.join(results, f) for f in os.listdir(results) if f.endswith(".json")),
                key=os.path.getmtime, reverse=True,
            )[:100]
        except OSError:
            files = []
        for path in files:
            try:
                with open(path, encoding="utf-8") as fh:
                    job = ScanJob(**json.load(fh))
            except (OSError, ValueError, TypeError):
                continue
            if job.state in (JobState.running, JobState.queued):
                job.state = JobState.cancelled  # interrupted by a restart
            self._jobs[job.id] = job
        try:
            with open(self._sched_path(), encoding="utf-8") as fh:
                for raw in json.load(fh):
                    item = ScheduleItem(**raw)
                    self._schedules[item.id] = item
        except (OSError, ValueError, TypeError):
            pass

    def save_schedules(self) -> None:
        try:
            os.makedirs(self.settings.data_dir, exist_ok=True)
            with open(self._sched_path(), "w", encoding="utf-8") as fh:
                json.dump([x.dump_json_dict() for x in self._schedules.values()],
                          fh, ensure_ascii=False, indent=2)
        except OSError:
            pass

    async def create(self, request: ScanRequest) -> ScanJob:
        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(
            id=job_id,
            created_at=datetime.now(timezone.utc),
            request=request,
            demo_scenario=request.demo_scenario,
        )
        cancel = asyncio.Event()
        async with self._lock:
            self._jobs[job_id] = job
            self._cancels[job_id] = cancel
            self._tasks[job_id] = asyncio.create_task(self._run(job, cancel))
        self.audit.record(
            "scan_started",
            job_id=job_id,
            targets=request.targets,
            demo_scenario=request.demo_scenario,
            note=request.note,
        )
        return job

    async def _run(self, job: ScanJob, cancel: asyncio.Event) -> None:
        await self.engine.run(job, cancel)
        summ = job.summary()
        self.audit.record(
            "scan_finished",
            job_id=job.id,
            state=job.state.value,
            online=summ["online"],
            risks=summ["risks"],
            security_score=summ["security_score"],
            **summ["severity_counts"],
        )
        self._export(job)

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[dict]:
        return [
            j.summary()
            for j in sorted(
                self._jobs.values(), key=lambda j: j.created_at, reverse=True
            )
        ]

    async def cancel(self, job_id: str) -> bool:
        cancel = self._cancels.get(job_id)
        if cancel is None:
            return False
        cancel.set()
        self.audit.record("scan_cancelled", job_id=job_id)
        return True

    async def clear_history(self) -> int:
        async with self._lock:
            for ev in self._cancels.values():
                ev.set()
            count = len(self._jobs)
            self._jobs.clear()
            self._cancels.clear()
            self._tasks.clear()
        results = os.path.join(self.settings.data_dir, "results")
        try:
            for f in os.listdir(results):
                if f.endswith(".json"):
                    os.remove(os.path.join(results, f))
        except OSError:
            pass
        self.audit.record("history_cleared", removed_jobs=count)
        return count

    async def recheck_device(self, job_id: str, ip: str) -> Optional[dict]:
        """Verify a fix by scanning this one host again.

        Real jobs: the host is actually re-probed and its record replaced with
        what the network says now. Demo jobs have no real host, so the patch is
        simulated and clearly labelled as such.
        """
        job = self._jobs.get(job_id)
        if not job:
            return None
        idx = next((i for i, d in enumerate(job.devices) if d.ip == ip), None)
        if idx is None:
            return None
        before = job.devices[idx].severity
        now_iso = datetime.now(timezone.utc).isoformat()

        if job.demo_scenario:
            device = demo_scenarios.apply_patch_to_device(job.devices[idx])
            device.patched_at = now_iso
            simulated, online = True, True
        else:
            orig = job.request
            req = ScanRequest(
                targets=[ip], port_profile=orig.port_profile, custom_ports=orig.custom_ports,
                site_hosts={ip: orig.site_hosts[ip]} if ip in orig.site_hosts else {},
                extra_web_ports=orig.extra_web_ports,
            )
            probe = ScanJob(id="recheck-" + uuid.uuid4().hex[:6], created_at=datetime.now(timezone.utc),
                            request=req)
            await self.engine.run(probe, asyncio.Event())
            fresh = next((d for d in probe.devices if d.ip == ip), None)
            simulated, online = False, fresh is not None
            if fresh is not None:
                fresh.checked_at = now_iso
                job.devices[idx] = fresh
            device = job.devices[idx]

        order = {Severity.critical: 0, Severity.high: 1, Severity.low: 2, Severity.safe: 3}
        job.devices.sort(key=lambda d: (order[d.severity], 0 if (d.php_version or d.open_ports) else 1,
                                        [int(o) for o in d.ip.split(".")]))
        job.progress.risks = sum(1 for d in job.devices if d.severity != Severity.safe)
        self.audit.record(
            "device_patch_simulated" if simulated else "device_rechecked",
            job_id=job_id, ip=ip, online=online,
            severity_before=before.value, severity_after=device.severity.value,
            php_version=device.php_version,
        )
        self._export(job)
        return {"device": device, "simulated": simulated, "online": online,
                "severity_before": before.value}

    def list_schedules(self) -> List[ScheduleItem]:
        return list(self._schedules.values())

    def add_schedule(self, payload: ScheduleCreate) -> ScheduleItem:
        sched_id = "sched-" + uuid.uuid4().hex[:8]
        item = ScheduleItem(
            id=sched_id,
            name=payload.name,
            targets=payload.targets,
            cron=payload.cron,
            enabled=payload.enabled,
            port_profile=payload.port_profile,
            custom_ports=payload.custom_ports,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._schedules[sched_id] = item
        self.save_schedules()
        self.audit.record(
            "schedule_created",
            schedule_id=sched_id,
            name=payload.name,
            targets=payload.targets,
            cron=payload.cron,
        )
        return item

    def update_schedule(self, sched_id: str, payload: ScheduleCreate) -> Optional[ScheduleItem]:
        """Change a schedule in place, keeping its id and run history."""
        item = self._schedules.get(sched_id)
        if item is None:
            return None
        for field in ("name", "targets", "cron", "enabled", "port_profile", "custom_ports"):
            setattr(item, field, getattr(payload, field))
        self.save_schedules()
        self.audit.record(
            "schedule_updated", schedule_id=sched_id, name=payload.name,
            targets=payload.targets, cron=payload.cron,
        )
        return item

    def delete_schedule(self, sched_id: str) -> bool:
        if sched_id in self._schedules:
            del self._schedules[sched_id]
            self.save_schedules()
            self.audit.record("schedule_deleted", schedule_id=sched_id)
            return True
        return False

    def _export(self, job: ScanJob) -> None:
        try:
            out_dir = os.path.join(self.settings.data_dir, "results")
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, f"{job.id}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    job.dump_json_dict(), fh, ensure_ascii=False, indent=2
                )
        except OSError:
            pass
