"""Streaming, resource-aware RCE verification for fast-scan discoveries.

The scan engine submits an endpoint as soon as an HTTP probe confirms it. This
worker consumes those records concurrently with the remaining passive scan.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import RceVerifyRequest, ScanJob, WebEndpoint
from . import chain_runner
from .resource_budget import MAX_RCE_WORKERS, available_memory_bytes, choose_batch_size

_QUEUE_END = None
MAX_DEFERRED_RESULT_ROWS = 1000


def endpoint_record(endpoint: WebEndpoint) -> Optional[Dict[str, Any]]:
    """Make a canonical target only from HTTP probe metadata."""
    scheme = endpoint.scheme.lower()
    host = (endpoint.hostname or endpoint.ip).strip().rstrip(".")
    port = int(endpoint.port)
    if scheme not in ("http", "https") or not host or not 1 <= port <= 65535:
        return None
    try:
        parsed_ip = ipaddress.ip_address(host)
        url_host = f"[{host}]" if parsed_ip.version == 6 else host
    except ValueError:
        url_host = host
    return {
        "target": f"{scheme}://{url_host}:{port}/",
        "ip": endpoint.ip,
        "hostname": host,
        "port": port,
        "scheme": scheme,
    }


class RceVerifyBatchStream:
    """Bounded queue consumer paired with the fast-scan endpoint producer."""

    def __init__(self, job: ScanJob, settings: Any, request: RceVerifyRequest,
                 cancel: asyncio.Event) -> None:
        self.job = job
        self.settings = settings
        self.request = request
        self.cancel = cancel
        configured_limit = int(settings.rce_verify_max_endpoints)
        self.endpoint_limit = max(1, min(100000, configured_limit)) if configured_limit > 0 else None
        self.max_workers = max(1, min(MAX_RCE_WORKERS, int(settings.rce_verify_max_workers)))
        queue_capacity = max(8, min(32, self.max_workers * 4))
        self.queue: asyncio.Queue[Optional[Dict[str, Any]]] = asyncio.Queue(maxsize=queue_capacity)
        self.seen: Set[Tuple[str, str, str, int]] = set()
        self.discovered = 0
        self.overflow = False
        self.producer_done = False
        self.sentinel_seen = False
        self.rows: List[Dict[str, Any]] = []
        self.deferred: List[Dict[str, Any]] = []
        self.deferred_omitted = 0
        self.batch_count = 0
        self.max_parallel = 0
        self.estimated_worker_mb = max(
            128, min(4096, int(settings.rce_verify_worker_memory_mb))
        )
        self.reserve_mb = max(128, min(16384, int(settings.rce_verify_memory_reserve_mb)))
        self.batch_timeout_s = max(
            60, min(14400, int(settings.rce_verify_batch_timeout_s))
        )
        self.deadline: Optional[float] = None
        self.stop_reason: Optional[str] = None
        self.job.progress.rce_verify_started = True
        self.job.progress.rce_verify_done = False
        self.job.progress.rce_verify_limit_reached = False
        self.job.progress.rce_verify_total = 0
        self.job.progress.rce_verify_completed = 0
        self.job.progress.rce_verify_active = 0
        self.job.progress.rce_verify_batch_size = 0
        self._publish("RUNNING")

    async def submit(self, endpoint: WebEndpoint) -> None:
        """Deduplicate and enqueue one successful probe with bounded backpressure."""
        if self.producer_done:
            return
        record = endpoint_record(endpoint)
        if record is None:
            return
        key = (
            record["ip"].lower(), record["scheme"],
            record["hostname"].lower(), record["port"],
        )
        if key in self.seen:
            return
        self.seen.add(key)
        self.discovered += 1
        self.job.progress.rce_verify_total = self.discovered
        if self.endpoint_limit is None or self.discovered <= self.endpoint_limit:
            record["_sequence"] = self.discovered
            await self.queue.put(record)
        else:
            self.overflow = True
            self.job.progress.rce_verify_limit_reached = True
        self._publish("RUNNING")

    async def finish(self) -> None:
        """Signal that fast-scan endpoint discovery is complete."""
        if self.producer_done:
            return
        self.producer_done = True
        await self.queue.put(_QUEUE_END)

    def _publish(self, verdict: str, error: Optional[str] = None) -> None:
        confirmed = any(
            row.get("verdict") in {"RCE_CONFIRMED", "CANARY_CONFIRMED"}
            for row in self.rows
        )
        if confirmed:
            verdict = "RCE_CONFIRMED"
        elif self.producer_done and verdict == "RUNNING":
            if self.discovered == 0:
                verdict = "SKIPPED"
                error = "fast scan ไม่พบ HTTP(S) endpoint ที่ยืนยันด้วย successful probe จึงไม่มี active request"
            elif self.overflow:
                verdict = "PARTIAL_ENDPOINT_LIMIT"
                extra = self.discovered - self.endpoint_limit
                error = (
                    f"พบ endpoint {self.discovered} รายการ เกินเพดาน {self.endpoint_limit}; "
                    f"ตรวจรายการที่เริ่มได้แล้ว ส่วนอีก {extra} endpoint ไม่ได้เริ่ม active request"
                )
            elif self.stop_reason:
                verdict = "PARTIAL"
                error = self._stop_message(self.stop_reason)
            else:
                verdict = "BATCH_COMPLETED"
        result: Dict[str, Any] = {
            "ran": any(row.get("ran") for row in self.rows),
            "mode": "batch",
            "verdict": verdict,
            "summary": {},
            "total_targets": self.discovered,
            "completed_targets": len(self.rows),
            "batch_count": self.batch_count,
            "max_parallel": self.max_parallel,
            "results": [*self.rows, *self.deferred],
            "endpoint_limit": self.endpoint_limit,
            "limit_reached": self.overflow,
            "evidence_dir": None,
        }
        if self.producer_done and (self.overflow or self.stop_reason):
            result["not_run_targets"] = max(0, self.discovered - len(self.rows))
        if self.deferred_omitted:
            result["deferred_details_omitted"] = self.deferred_omitted
        if error:
            result["error"] = error
        self.job.rce_verify_result = result

    @staticmethod
    def _stop_message(reason: str) -> str:
        return {
            "DEFERRED_RESOURCE_LIMIT": "หน่วยความจำว่างไม่พอสำหรับ batch ถัดไป; endpoint ที่ยังไม่เริ่มถูกระบุว่าไม่ได้ตรวจ",
            "DEFERRED_BATCH_TIMEOUT": "ถึงเพดานเวลารวมก่อน endpoint ที่เหลือเริ่มตรวจ",
            "CANCELLED_NOT_STARTED": "งานถูกยกเลิกก่อน endpoint ที่เหลือเริ่มตรวจ",
        }.get(reason, "endpoint ที่เหลือยังไม่ได้เริ่มตรวจ")

    def _deferred_row(self, endpoint: Dict[str, Any], reason: str) -> Dict[str, Any]:
        return {
            "ran": False,
            "target": endpoint["target"],
            **{key: endpoint[key] for key in ("ip", "hostname", "port", "scheme")},
            "verdict": reason,
            "summary": {},
            "evidence_dir": None,
            "evidence_files": [],
            "error": self._stop_message(reason),
        }

    def _record_deferred(self, endpoint: Dict[str, Any], reason: str) -> None:
        if len(self.deferred) < MAX_DEFERRED_RESULT_ROWS:
            self.deferred.append(self._deferred_row(endpoint, reason))
        else:
            self.deferred_omitted += 1

    async def _verify_one(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        evidence_dir = os.path.join(
            self.settings.data_dir, "rce-verify", self.job.id,
            f"{endpoint['_sequence']:04d}",
        )
        try:
            result = await chain_runner.run_rce_verify_target(
                endpoint["target"], self.settings,
                evidence_dir=evidence_dir,
                operator=self.request.operator,
                timeout=self.request.timeout,
                no_verify_ssl=self.request.no_verify_ssl,
                pinned_ip=endpoint["ip"],
                max_concurrency=self.max_workers,
            )
            if not isinstance(result, dict):
                raise TypeError("verifier returned a non-object result")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a target failure must not abort other endpoints
            result = {
                "ran": False, "verdict": "ERROR", "summary": {},
                "evidence_dir": None, "evidence_files": [],
                "error": f"{type(exc).__name__}: {exc}"[:1000],
            }
        result["target"] = endpoint["target"]
        result.update({key: endpoint[key] for key in ("ip", "hostname", "port", "scheme")})
        returned_dir = result.get("evidence_dir")
        if returned_dir:
            try:
                data_root = Path(self.settings.data_dir).resolve()
                expected = Path(evidence_dir).resolve()
                evidence_path = Path(returned_dir).resolve()
                if evidence_path != expected or not evidence_path.is_relative_to(data_root):
                    raise ValueError("toolkit returned an invalid evidence path")
                result["evidence_dir"] = os.path.relpath(evidence_path, data_root)
            except (OSError, TypeError, ValueError):
                result["evidence_dir"] = None
                result["error"] = "toolkit returned an invalid evidence path"
                result["verdict"] = "ERROR"
        return result

    async def run(self) -> None:
        """Consume discoveries with an adaptive, work-conserving worker pool."""
        active: Dict[asyncio.Task, Dict[str, Any]] = {}
        pending: Optional[Dict[str, Any]] = None
        get_task: Optional[asyncio.Task] = None
        sentinel_seen = False

        def accept(item: Optional[Dict[str, Any]]) -> None:
            nonlocal pending, sentinel_seen
            if item is _QUEUE_END:
                sentinel_seen = True
                return
            pending = item
            if self.deadline is None:
                self.deadline = time.monotonic() + self.batch_timeout_s

        async def collect(done: Set[asyncio.Task]) -> None:
            completed_rows: List[Dict[str, Any]] = []
            for task in done:
                endpoint = active.pop(task, None)
                if endpoint is None:
                    continue
                row = task.result()
                completed_rows.append(row)
            if not completed_rows:
                return
            self.rows.extend(completed_rows)
            peak_rss = max(
                (int(row.get("peak_rss_bytes") or 0) for row in completed_rows),
                default=0,
            )
            if peak_rss:
                self.estimated_worker_mb = max(
                    self.estimated_worker_mb,
                    min(4096, int((peak_rss * 1.5) / (1024 * 1024)) + 1),
                )
            self.job.progress.rce_verify_completed = len(self.rows)
            self.job.progress.rce_verify_active = len(active)
            self.job.progress.rce_verify_batch_size = len(active)
            self._publish("RUNNING")

        try:
            while not sentinel_seen or active or pending is not None:
                if self.cancel.is_set() and self.stop_reason is None:
                    self.stop_reason = "CANCELLED_NOT_STARTED"
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    if self.stop_reason is None:
                        self.stop_reason = "DEFERRED_BATCH_TIMEOUT"

                if self.stop_reason:
                    if pending is not None:
                        self._record_deferred(pending, self.stop_reason)
                        pending = None
                    if get_task is None and not sentinel_seen:
                        get_task = asyncio.create_task(self.queue.get())
                    wait_set = set(active)
                    if get_task is not None:
                        wait_set.add(get_task)
                    if not wait_set:
                        break
                    done, _ = await asyncio.wait(
                        wait_set, timeout=0.2, return_when=asyncio.FIRST_COMPLETED
                    )
                    await collect(done)
                    if get_task is not None and get_task in done:
                        item = get_task.result()
                        get_task = None
                        if item is _QUEUE_END:
                            sentinel_seen = True
                        else:
                            self._record_deferred(item, self.stop_reason)
                    continue

                if pending is None:
                    if get_task is not None:
                        if get_task.done():
                            item = get_task.result()
                            get_task = None
                            accept(item)
                            if sentinel_seen:
                                continue
                        else:
                            wait_set = set(active)
                            wait_set.add(get_task)
                            done, _ = await asyncio.wait(
                                wait_set, timeout=0.2,
                                return_when=asyncio.FIRST_COMPLETED,
                            )
                            await collect(done)
                            if get_task in done:
                                item = get_task.result()
                                get_task = None
                                accept(item)
                            continue
                    else:
                        try:
                            item = self.queue.get_nowait()
                        except asyncio.QueueEmpty:
                            if not sentinel_seen:
                                get_task = asyncio.create_task(self.queue.get())
                            elif active:
                                done, _ = await asyncio.wait(
                                    set(active), timeout=0.2,
                                    return_when=asyncio.FIRST_COMPLETED,
                                )
                                await collect(done)
                            continue
                        accept(item)
                        if sentinel_seen:
                            continue

                if pending is None:
                    continue

                free_slots = self.max_workers - len(active)
                if free_slots <= 0:
                    done, _ = await asyncio.wait(
                        set(active), timeout=0.2,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    await collect(done)
                    continue

                available = available_memory_bytes()
                if available is None:
                    capacity = 1 if not active else 0
                else:
                    capacity = choose_batch_size(
                        free_slots,
                        available_bytes=available,
                        max_workers=free_slots,
                        reserve_mb=self.reserve_mb,
                        worker_memory_mb=self.estimated_worker_mb,
                    )
                if capacity <= 0:
                    if active:
                        done, _ = await asyncio.wait(
                            set(active), timeout=0.2,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        await collect(done)
                    else:
                        self.stop_reason = "DEFERRED_RESOURCE_LIMIT"
                    continue

                batch = [pending]
                pending = None
                while len(batch) < capacity:
                    try:
                        item = self.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if item is _QUEUE_END:
                        sentinel_seen = True
                        break
                    batch.append(item)

                self.batch_count += 1
                for endpoint in batch:
                    task = asyncio.create_task(self._verify_one(endpoint))
                    active[task] = endpoint
                self.max_parallel = max(self.max_parallel, len(active))
                self.job.progress.rce_verify_active = len(active)
                self.job.progress.rce_verify_batch_size = len(active)
        except asyncio.CancelledError:
            self.stop_reason = "CANCELLED_NOT_STARTED"
            if pending is not None:
                self._record_deferred(pending, self.stop_reason)
                pending = None
            while not self.queue.empty():
                item = self.queue.get_nowait()
                if item is not _QUEUE_END:
                    self._record_deferred(item, self.stop_reason)
            for task in active:
                task.cancel()
            await asyncio.gather(*active, return_exceptions=True)
            active.clear()
            raise
        finally:
            if get_task is not None:
                get_task.cancel()
                await asyncio.gather(get_task, return_exceptions=True)
            for task in active:
                task.cancel()
            if active:
                await asyncio.gather(*active, return_exceptions=True)
            self.job.progress.rce_verify_active = 0
            self.job.progress.rce_verify_batch_size = 0
            self.job.progress.rce_verify_completed = len(self.rows)
            self.job.progress.rce_verify_done = True
            self._publish("RUNNING")
