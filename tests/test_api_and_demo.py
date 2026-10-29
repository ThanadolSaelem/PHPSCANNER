import asyncio
from datetime import datetime, timezone

import pytest

from app.config import Settings
from app.models import Device, ScanJob, ScanRequest, ScheduleCreate, Severity
from app.scanner import demo_scenarios
from app.store import JobStore


def _settings(tmp_path):
    s = Settings()
    s.data_dir = str(tmp_path)
    return s


async def _wait(store, job_id):
    for _ in range(100):
        if store.get(job_id).state.value in ("completed", "failed", "cancelled"):
            return store.get(job_id)
        await asyncio.sleep(0.05)
    raise AssertionError("job did not finish")


def test_demo_scenarios_build_and_score():
    suffixes = ["go.th", "or.th", "mi.th", "ac.th", "in.th"]
    gov = demo_scenarios.build_demo_devices("gov-cert", suffixes)
    assert len(gov) >= 6 and gov[0].severity == Severity.critical
    assert any(f.rule_id == "php2shell" for f in gov[0].findings)
    assert all(d.severity == Severity.safe for d in demo_scenarios.build_demo_devices("zero-trust", suffixes))
    # demo data must not borrow a real ministry's name
    assert not any("mof" in (d.hostname or "") for d in gov)


def test_fresh_install_has_no_fake_history(tmp_path):
    store = JobStore(_settings(tmp_path))
    assert store.list_jobs() == []
    assert store.list_schedules() == []


async def test_demo_recheck_is_labelled_simulated(tmp_path):
    store = JobStore(_settings(tmp_path))
    job = await store.create(ScanRequest(targets=[], demo_scenario="gov-cert"))
    job = await _wait(store, job.id)
    before = job.security_score()
    ip = next(d.ip for d in job.devices if d.severity == Severity.critical)
    res = await store.recheck_device(job.id, ip)
    assert res["simulated"] is True
    assert job.security_score() > before
    assert any(e["event"] == "device_patch_simulated" for e in store.audit.read_recent(20))


async def test_real_recheck_rescans_and_never_fakes(tmp_path, monkeypatch):
    store = JobStore(_settings(tmp_path))
    vuln = Device(ip="10.0.0.5", php_version="8.3.10", open_ports=[80], severity=Severity.critical)
    job = ScanJob(id="real1", created_at=datetime.now(timezone.utc),
                  request=ScanRequest(targets=["10.0.0.0/24"]), devices=[vuln])
    store._jobs[job.id] = job

    # host still vulnerable -> recheck must keep it critical (no fake fix)
    async def still_vuln(probe, cancel):
        probe.devices = [Device(ip="10.0.0.5", php_version="8.3.10", open_ports=[80], severity=Severity.critical)]
    monkeypatch.setattr(store.engine, "run", still_vuln)
    res = await store.recheck_device("real1", "10.0.0.5")
    assert res["simulated"] is False and res["online"] is True
    assert job.devices[0].severity == Severity.critical and job.devices[0].checked_at

    # host really fixed -> recheck reflects it
    async def fixed(probe, cancel):
        probe.devices = [Device(ip="10.0.0.5", php_version="8.3.36", open_ports=[80], severity=Severity.safe)]
    monkeypatch.setattr(store.engine, "run", fixed)
    await store.recheck_device("real1", "10.0.0.5")
    assert job.devices[0].severity == Severity.safe

    # host offline -> record unchanged, reported offline
    async def gone(probe, cancel):
        probe.devices = []
    monkeypatch.setattr(store.engine, "run", gone)
    res = await store.recheck_device("real1", "10.0.0.5")
    assert res["online"] is False and job.devices[0].php_version == "8.3.36"
    assert any(e["event"] == "device_rechecked" for e in store.audit.read_recent(20))


async def test_history_and_schedules_survive_restart(tmp_path):
    s = _settings(tmp_path)
    store = JobStore(s)
    job = await store.create(ScanRequest(targets=[], demo_scenario="zero-trust"))
    await _wait(store, job.id)
    sched = store.add_schedule(ScheduleCreate(name="Weekly", targets=["10.0.0.0/24"], cron="0 3 * * 1"))

    again = JobStore(s)
    assert again.get(job.id) is not None
    assert any(x.id == sched.id for x in again.list_schedules())
    assert again.delete_schedule(sched.id) and JobStore(s).list_schedules() == []


def test_csv_cell_neutralises_formulas():
    from app.main import _csv_cell
    assert _csv_cell("=HYPERLINK(\"x\")") == "'=HYPERLINK(\"x\")"
    assert _csv_cell("@cmd") == "'@cmd"
    assert _csv_cell("portal.go.th") == "portal.go.th"
    assert _csv_cell(None) == ""


def test_app_lifespan_starts_and_stops_scheduler():
    from fastapi.testclient import TestClient

    from app.main import app, scheduler

    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert scheduler._task is not None and not scheduler._task.done()
    assert scheduler._task is None
