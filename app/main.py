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
from .ip_utils_bridge import validate_targets
from .models import ScanRequest
from .store import JobStore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = FastAPI(title="thscan", version=__version__,
              description="Thai government web vulnerability scanner (PHP2Shell aware)")
store = JobStore(settings)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/config")
async def get_config() -> dict:
    return {
        "version": __version__,
        "default_allowed_suffixes": settings.default_allowed_suffixes,
        "web_ports": settings.web_ports,
        "max_targets": settings.max_targets,
        "max_concurrency": settings.max_concurrency,
        "require_authorization": settings.require_authorization,
    }


@app.post("/api/scans")
async def create_scan(req: ScanRequest) -> dict:
    if not req.targets:
        raise HTTPException(400, "No targets supplied.")
    if settings.require_authorization and not req.authorized:
        raise HTTPException(
            403,
            "Authorization required. You must confirm you are permitted to scan "
            "the supplied targets before a scan can start.",
        )
    ok, total, message = validate_targets(req.targets, settings.max_targets)
    if not ok:
        raise HTTPException(400, message)
    job = await store.create(req)
    return {"id": job.id, "total_ips": total, **job.summary()}


@app.get("/api/scans")
async def list_scans() -> list:
    return store.list_jobs()


@app.get("/api/scans/{job_id}")
async def get_scan(job_id: str) -> dict:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "Unknown job.")
    return job.model_dump(mode="json")


@app.get("/api/scans/{job_id}/summary")
async def get_scan_summary(job_id: str) -> dict:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "Unknown job.")
    return job.summary()


@app.post("/api/scans/{job_id}/cancel")
async def cancel_scan(job_id: str) -> dict:
    ok = await store.cancel(job_id)
    if not ok:
        raise HTTPException(404, "Unknown job.")
    return {"cancelled": True}


@app.get("/api/scans/{job_id}/export.json")
async def export_json(job_id: str) -> JSONResponse:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "Unknown job.")
    return JSONResponse(
        job.model_dump(mode="json"),
        headers={"Content-Disposition": f'attachment; filename="thscan-{job_id}.json"'},
    )


@app.get("/api/scans/{job_id}/export.csv")
async def export_csv(job_id: str) -> Response:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "Unknown job.")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ip", "hostname", "matched_suffix", "port", "scheme", "url",
        "status", "server", "php_version", "cms",
        "rule_id", "severity", "confidence", "cve", "title", "recommendation",
    ])
    for host in job.hosts:
        if not host.services:
            writer.writerow([host.ip, host.hostname or "", host.matched_suffix or "",
                             "", "", "", "", "", "", "", "", "", "", "", "", ""])
            continue
        for svc in host.services:
            if not svc.findings:
                writer.writerow([host.ip, host.hostname or "", host.matched_suffix or "",
                                 svc.port, svc.scheme, svc.url, svc.status_code or "",
                                 svc.server or "", svc.php_version or "", svc.cms or "",
                                 "", "", "", "", svc.title or "", ""])
                continue
            for f in svc.findings:
                writer.writerow([
                    host.ip, host.hostname or "", host.matched_suffix or "",
                    svc.port, svc.scheme, svc.url, svc.status_code or "",
                    svc.server or "", svc.php_version or "", svc.cms or "",
                    f.rule_id, f.severity.value, f.confidence.value,
                    " ".join(f.cve), svc.title or "", f.recommendation,
                ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="thscan-{job_id}.csv"'},
    )


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
