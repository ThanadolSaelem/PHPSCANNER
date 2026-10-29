"""FastAPI application: REST API + static UI for thscan."""
from __future__ import annotations

import csv
import io
import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import settings
from .models import ScanRequest, ScheduleCreate
from .scanner import demo_scenarios, discovery
from .scanner.ip_utils import TargetError, expand_targets, out_of_scope
from .scheduler import CronError, Scheduler, local_tz, parse_cron
from .store import JobStore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = FastAPI(
    title="thscan",
    version=__version__,
    description="LAN & Enterprise device scanner with PHP2Shell / ThaiCERT compliance assessment",
)
store = JobStore(settings)
scheduler = Scheduler(store)


@app.on_event("startup")
async def _start_scheduler() -> None:
    scheduler.start()


@app.on_event("shutdown")
async def _stop_scheduler() -> None:
    await scheduler.stop()


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/config")
async def get_config() -> dict:
    return {
        "version": __version__,
        "web_ports": settings.web_ports,
        "liveness_ports": settings.liveness_ports,
        "max_targets": settings.max_targets,
        "max_concurrency": settings.max_concurrency,
        "allowed_cidrs": settings.allowed_cidrs,
        "gov_suffixes": settings.gov_suffixes,
        "timezone": getattr(local_tz(), "key", "Asia/Bangkok"),
        "demos": demo_scenarios.DEMO_SCENARIOS,
    }


@app.get("/api/demos")
async def get_demos() -> list:
    return demo_scenarios.DEMO_SCENARIOS


@app.get("/api/autodetect")
async def autodetect() -> dict:
    return {"subnets": discovery.autodetect_subnets()}


@app.post("/api/scans")
async def create_scan(req: ScanRequest) -> dict:
    if req.demo_scenario:
        valid_ids = {d["id"] for d in demo_scenarios.DEMO_SCENARIOS}
        if req.demo_scenario not in valid_ids:
            raise HTTPException(400, f"ไม่พบโหมดสาธิต: {req.demo_scenario}")
        scen = next(
            d for d in demo_scenarios.DEMO_SCENARIOS if d["id"] == req.demo_scenario
        )
        if not req.targets:
            req.targets = [scen["cidr"]]
        job = await store.create(req)
        return {"id": job.id, "total_ips": scen["total_ips"], **job.summary()}

    if not req.targets:
        raise HTTPException(400, "ไม่ได้ระบุเป้าหมาย")
    try:
        _, total = expand_targets(req.targets, settings.max_targets)
    except TargetError as exc:
        raise HTTPException(400, str(exc))
    bad = out_of_scope(req.targets, settings.allowed_networks())
    if bad:
        raise HTTPException(
            403,
            "เป้าหมายอยู่นอกขอบเขตที่อนุญาต (scope ที่ตั้งไว้ตอน deploy): "
            + ", ".join(bad)
            + " — อนุญาตเฉพาะ: "
            + ", ".join(settings.allowed_cidrs),
        )
    job = await store.create(req)
    return {"id": job.id, "total_ips": total, **job.summary()}


@app.get("/api/scans")
async def list_scans() -> list:
    return store.list_jobs()


@app.delete("/api/scans")
async def clear_scans() -> dict:
    removed = await store.clear_history()
    return {"cleared": True, "removed": removed}


@app.get("/api/scans/{job_id}")
async def get_scan(job_id: str) -> dict:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "ไม่พบงานสแกน")
    data = job.dump_json_dict()
    data["security_score"] = job.security_score()
    data["security_grade"] = job.security_grade()
    return data


@app.get("/api/scans/{job_id}/summary")
async def get_scan_summary(job_id: str) -> dict:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "ไม่พบงานสแกน")
    return job.summary()


@app.post("/api/scans/{job_id}/cancel")
async def cancel_scan(job_id: str) -> dict:
    if not await store.cancel(job_id):
        raise HTTPException(404, "ไม่พบงานสแกน")
    return {"cancelled": True}


@app.post("/api/scans/{job_id}/devices/{ip}/recheck")
async def recheck_device(job_id: str, ip: str) -> dict:
    """Scan one host again to verify a fix (simulated only for demo jobs)."""
    res = await store.recheck_device(job_id, ip)
    if res is None:
        raise HTTPException(404, "ไม่พบอุปกรณ์หรืองานสแกน")
    job = store.get(job_id)
    data = job.dump_json_dict() if job else {}
    if job:
        data["security_score"] = job.security_score()
        data["security_grade"] = job.security_grade()
    return {
        "device": res["device"].dump_json_dict(),
        "simulated": res["simulated"],
        "online": res["online"],
        "severity_before": res["severity_before"],
        "job": data,
    }


def _csv_cell(value: object) -> str:
    """Neutralise spreadsheet formulas (hostnames come from untrusted DNS)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.get("/api/scans/{job_id}/export.csv")
async def export_csv(job_id: str) -> Response:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "ไม่พบงานสแกน")
    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf)
    writer.writerow(
        [
            "ip",
            "hostname",
            "mac",
            "device_type",
            "service",
            "php_version",
            "cms",
            "open_ports",
            "latency_ms",
            "severity",
            "assessment",
            "cve",
        ]
    )
    for d in job.devices:
        cves = " ".join(sorted({c for f in d.findings for c in f.cve}))
        writer.writerow(_csv_cell(v) for v in
            [
                d.ip,
                d.hostname or "",
                d.mac or "",
                d.device_type,
                d.service,
                d.php_version or "",
                d.cms or "",
                " ".join(str(p) for p in d.open_ports),
                d.latency_ms if d.latency_ms is not None else "",
                d.severity.value,
                d.assessment,
                cves,
            ]
        )
    store.audit.record("export_csv", job_id=job_id)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="thscan-{job_id}.csv"'
        },
    )


@app.get("/api/scans/{job_id}/export.json")
async def export_json(job_id: str) -> Response:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "ไม่พบงานสแกน")
    payload = job.dump_json_dict()
    payload["security_score"] = job.security_score()
    payload["security_grade"] = job.security_grade()
    store.audit.record("export_json", job_id=job_id)
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="thscan-{job_id}.json"'
        },
    )


@app.get("/api/audit")
async def get_audit_log() -> dict:
    return {"entries": store.audit.read_recent(100)}


@app.get("/api/schedules")
async def list_schedules() -> list:
    scheduler.refresh_next_runs()
    return [s.dump_json_dict() for s in store.list_schedules()]


@app.post("/api/schedules")
async def create_schedule(payload: ScheduleCreate) -> dict:
    if not payload.name.strip() or not payload.targets:
        raise HTTPException(400, "กรุณาระบุชื่อตารางเวลาและเป้าหมาย")
    try:
        parse_cron(payload.cron)
    except CronError as exc:
        raise HTTPException(400, f"รูปแบบเวลาไม่ถูกต้อง: {exc}")
    try:
        expand_targets(payload.targets, settings.max_targets)
    except TargetError as exc:
        raise HTTPException(400, str(exc))
    bad = out_of_scope(payload.targets, settings.allowed_networks())
    if bad:
        raise HTTPException(403, f"เป้าหมายอยู่นอกขอบเขต: {', '.join(bad)}")
    item = store.add_schedule(payload)
    scheduler.refresh_next_runs()
    return item.dump_json_dict()


@app.delete("/api/schedules/{sched_id}")
async def remove_schedule(sched_id: str) -> dict:
    if not store.delete_schedule(sched_id):
        raise HTTPException(404, "ไม่พบตารางเวลา")
    return {"deleted": True}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
