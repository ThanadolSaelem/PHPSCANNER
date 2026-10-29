"""FastAPI application: REST API + static UI for thscan."""
from __future__ import annotations

import csv
import io
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import settings
from .models import ScanRequest
from .scanner import discovery
from .scanner.ip_utils import TargetError, expand_targets, out_of_scope
from .store import JobStore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = FastAPI(title="thscan", version=__version__,
              description="LAN device scanner with PHP2Shell / ThaiCERT assessment")
store = JobStore(settings)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/config")
async def get_config() -> dict:
    return {
        "version": __version__,
        "web_ports": settings.web_ports,
        "max_targets": settings.max_targets,
        "max_concurrency": settings.max_concurrency,
        "allowed_cidrs": settings.allowed_cidrs,
    }


@app.get("/api/autodetect")
async def autodetect() -> dict:
    """Local subnets this instance could scan (for the 'auto' target mode)."""
    return {"subnets": discovery.autodetect_subnets()}


@app.post("/api/scans")
async def create_scan(req: ScanRequest) -> dict:
    if not req.targets:
        raise HTTPException(400, "ไม่ได้ระบุเป้าหมาย")
    # validate syntax + size
    try:
        _, total = expand_targets(req.targets, settings.max_targets)
    except TargetError as exc:
        raise HTTPException(400, str(exc))
    # deploy-time scope enforcement
    bad = out_of_scope(req.targets, settings.allowed_networks())
    if bad:
        raise HTTPException(
            403,
            "เป้าหมายอยู่นอกขอบเขตที่อนุญาต (scope ที่ตั้งไว้ตอน deploy): "
            + ", ".join(bad)
            + " — อนุญาตเฉพาะ: " + ", ".join(settings.allowed_cidrs),
        )
    job = await store.create(req)
    return {"id": job.id, "total_ips": total, **job.summary()}


@app.get("/api/scans")
async def list_scans() -> list:
    return store.list_jobs()


@app.get("/api/scans/{job_id}")
async def get_scan(job_id: str) -> dict:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "ไม่พบงานสแกน")
    return job.model_dump(mode="json")


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


@app.get("/api/scans/{job_id}/export.csv")
async def export_csv(job_id: str) -> Response:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "ไม่พบงานสแกน")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "mac", "device_type", "service", "php_version",
                     "open_ports", "latency_ms", "severity", "assessment", "cve"])
    for d in job.devices:
        cves = " ".join(sorted({c for f in d.findings for c in f.cve}))
        writer.writerow([
            d.ip, d.mac or "", d.device_type, d.service, d.php_version or "",
            " ".join(str(p) for p in d.open_ports), d.latency_ms if d.latency_ms is not None else "",
            d.severity.value, d.assessment, cves,
        ])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="thscan-{job_id}.csv"'})


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
