from datetime import datetime

import pytest

from app.config import Settings
from app.scheduler import CronError, Scheduler, cron_matches, local_tz, next_run, parse_cron
from app.store import JobStore
from app.models import ScheduleCreate


def test_parse_and_match():
    t = datetime(2026, 10, 29, 2, 0, tzinfo=local_tz())  # Thursday
    assert cron_matches("0 2 * * *", t)
    assert not cron_matches("30 2 * * *", t)
    assert cron_matches("*/15 2 * * 1-5", t)
    assert not cron_matches("0 2 * * 0,6", t)
    with pytest.raises(CronError):
        parse_cron("61 * * * *")
    with pytest.raises(CronError):
        parse_cron("0 2 * *")


def test_next_run_weekly():
    t = datetime(2026, 10, 29, 9, 0, tzinfo=local_tz())  # Thu
    n = next_run("0 3 * * 1", t)  # Monday 03:00
    assert n.isoweekday() == 1 and n.hour == 3 and n.minute == 0


async def test_tick_fires_once_per_minute(tmp_path):
    s = Settings(); s.data_dir = str(tmp_path)
    store = JobStore(s)
    store.add_schedule(ScheduleCreate(name="n", targets=["10.0.0.1"], cron="0 2 * * *"))
    sch = Scheduler(store)
    when = datetime(2026, 10, 29, 2, 0, tzinfo=local_tz())
    started = await sch.tick(when)
    assert len(started) == 1
    assert await sch.tick(when) == []  # same minute: no double fire
    item = store.list_schedules()[0]
    assert item.last_job_id == started[0] and item.next_run
    await store.cancel(started[0])
    for t in list(store._tasks.values()):
        try:
            await t
        except Exception:
            pass
