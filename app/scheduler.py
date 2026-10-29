"""Runs saved schedules: a minimal 5-field cron evaluated in local (Thai) time.

Supported per field: ``*``, a number, ``a-b`` ranges, ``*/n`` / ``a-b/n`` steps
and comma lists — the subset people actually write ("0 2 * * *", "30 8 * * 1-5").
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from .models import ScanRequest

_FIELDS = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]  # min hour dom month dow(0=Sun)


class CronError(ValueError):
    pass


def _parse_field(text: str, lo: int, hi: int) -> Set[int]:
    out: Set[int] = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            if not step_s.isdigit() or int(step_s) < 1:
                raise CronError(f"step ไม่ถูกต้อง: {text}")
            step = int(step_s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a_s, b_s = part.split("-", 1)
            if not (a_s.isdigit() and b_s.isdigit()):
                raise CronError(f"ช่วงไม่ถูกต้อง: {text}")
            a, b = int(a_s), int(b_s)
        elif part.isdigit():
            a = b = int(part)
        else:
            raise CronError(f"รูปแบบไม่ถูกต้อง: {text}")
        if a < lo or b > hi or a > b:
            raise CronError(f"ค่าเกินช่วง {lo}-{hi}: {text}")
        out.update(range(a, b + 1, step))
    return out


def parse_cron(expr: str) -> List[Set[int]]:
    parts = expr.split()
    if len(parts) != 5:
        raise CronError("cron ต้องมี 5 ช่อง: นาที ชั่วโมง วัน เดือน วันในสัปดาห์")
    sets = [_parse_field(p, lo, hi) for p, (lo, hi) in zip(parts, _FIELDS)]
    if 7 in sets[4]:
        sets[4].add(0)
    return sets


def cron_matches(expr: str, when: datetime) -> bool:
    m, h, dom, mon, dow = parse_cron(expr)
    return (when.minute in m and when.hour in h and when.day in dom
            and when.month in mon and (when.isoweekday() % 7) in dow)


def next_run(expr: str, after: datetime) -> Optional[datetime]:
    sets = parse_cron(expr)
    t = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        m, h, dom, mon, dow = sets
        if (t.minute in m and t.hour in h and t.day in dom and t.month in mon
                and (t.isoweekday() % 7) in dow):
            return t
        t += timedelta(minutes=1)
    return None


def local_tz():
    name = os.environ.get("THSCAN_TZ", "Asia/Bangkok")
    if ZoneInfo is not None:
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001
            pass
    return timezone(timedelta(hours=7))


class Scheduler:
    """Background loop that starts a scan when a schedule's cron matches."""

    def __init__(self, store, interval: float = 20.0) -> None:
        self.store = store
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._fired: dict = {}

    def refresh_next_runs(self) -> None:
        now = datetime.now(local_tz())
        for item in self.store.list_schedules():
            try:
                nxt = next_run(item.cron, now) if item.enabled else None
            except CronError:
                nxt = None
            item.next_run = nxt.isoformat() if nxt else None

    async def tick(self, now: Optional[datetime] = None) -> List[str]:
        now = (now or datetime.now(local_tz())).replace(second=0, microsecond=0)
        started: List[str] = []
        for item in list(self.store.list_schedules()):
            if not item.enabled or self._fired.get(item.id) == now:
                continue
            try:
                due = cron_matches(item.cron, now)
            except CronError:
                continue
            if not due:
                continue
            self._fired[item.id] = now
            job = await self.store.create(ScanRequest(
                targets=item.targets, note=f"ตั้งเวลา: {item.name}",
                port_profile=item.port_profile, custom_ports=item.custom_ports))
            item.last_run = now.isoformat()
            item.last_job_id = job.id
            self.store.audit.record("schedule_fired", schedule_id=item.id, job_id=job.id)
            started.append(job.id)
        if started:
            self.store.save_schedules()
        self.refresh_next_runs()
        return started

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - never let the loop die
                pass
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None:
            self.refresh_next_runs()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
