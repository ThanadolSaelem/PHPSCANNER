"""In-memory job registry with background execution and JSON export.

Jobs live in memory for the life of the container (adequate for a single-team
tool). A completed job can be exported to the data directory for archival or
to feed a reporting pipeline.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .audit import AuditLog
from .config import Settings
from .models import ScanJob, ScanRequest
from .scanner.engine import ScanEngine


class JobStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine = ScanEngine(settings)
        self.audit = AuditLog(settings.data_dir)
        self._jobs: Dict[str, ScanJob] = {}
        self._cancels: Dict[str, asyncio.Event] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def create(self, request: ScanRequest) -> ScanJob:
        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(
            id=job_id,
            created_at=datetime.now(timezone.utc),
            request=request,
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
            **summ["severity_counts"],
        )
        self._export(job)

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[dict]:
        return [j.summary() for j in sorted(
            self._jobs.values(), key=lambda j: j.created_at, reverse=True)]

    async def cancel(self, job_id: str) -> bool:
        cancel = self._cancels.get(job_id)
        if cancel is None:
            return False
        cancel.set()
        self.audit.record("scan_cancelled", job_id=job_id)
        return True

    def _export(self, job: ScanJob) -> None:
        try:
            out_dir = os.path.join(self.settings.data_dir, "results")
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, f"{job.id}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(job.model_dump(mode="json"), fh, ensure_ascii=False, indent=2)
        except OSError:
            pass
