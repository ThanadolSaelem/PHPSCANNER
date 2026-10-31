"""FastAPI application: REST API + static UI for thscan."""
from __future__ import annotations

import csv
import io
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import settings
from .models import ScanRequest, ScheduleCreate
from .scanner import chain_runner, demo_scenarios, discovery, netlimit, ports, sites
from .scanner.ip_utils import TargetError, expand_targets, out_of_scope
from .scanner import nmap_scan
from .scheduler import CronError, Scheduler, local_tz, parse_cron
from .store import JobStore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    scheduler.start()
    try:
        yield
    finally:
        await scheduler.stop()


app = FastAPI(
    title="thscan",
    version=__version__,
    description="LAN & Enterprise device scanner with PHP2Shell / ThaiCERT compliance assessment",
    lifespan=lifespan,
)
store = JobStore(settings)
scheduler = Scheduler(store)


def _chain_available() -> bool:
    return settings.rce_chain_enabled and chain_runner.available()


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
        "enforce_scope": settings.enforce_scope,
        "deep_available": nmap_scan.nmap_available(),
        "chain_available": _chain_available(),
        "chain_timeout_s": settings.rce_chain_timeout_s,
        "traceroute_available": nmap_scan.traceroute_available(),
        "timezone": getattr(local_tz(), "key", "Asia/Bangkok"),
        "max_port_probes": settings.max_port_probes,
        "max_custom_ports": ports.MAX_CUSTOM_PORTS,
        "max_sites": sites.MAX_SITES,
        "max_sockets": netlimit.MAX_SOCKETS,
        "port_profiles": [
            {"id": pid, "label": label,
             "ports": ports.profile_ports(pid, "", settings.web_ports) if pid != "custom" else None}
            for pid, label in ports.PROFILES.items()
        ],
        "demos": demo_scenarios.DEMO_SCENARIOS,
    }


@app.get("/api/demos")
async def get_demos() -> list:
    return demo_scenarios.DEMO_SCENARIOS


@app.get("/api/autodetect")
async def autodetect() -> dict:
    return {"subnets": discovery.autodetect_subnets()}


async def _resolve_sites(texts: list) -> list:
    """Parse, resolve and check each link. Returns a list of report dicts."""
    out = []
    for text in texts[: sites.MAX_SITES]:
        # refused: resolvable but not allowed (wrong domain / out of scope)
        item = {"input": text, "host": None, "ips": [], "port": None, "suffix": None,
                "problems": [], "refused": False}
        try:
            site = await sites.resolve(sites.parse(text))
            item.update(host=site.host, ips=site.ips, port=site.port)
            # the gov-domain rule is a hard block only when scope is enforced;
            # otherwise it's advisory (we still record which suffix matched)
            problems = sites.check(site, settings.gov_suffixes)
            item["suffix"] = site.suffix
            if settings.enforce_scope:
                item["problems"] = problems
                item["refused"] = bool(problems)
        except sites.SiteError as exc:
            item["problems"] = [str(exc)]
        out.append(item)
    return out


@app.get("/api/resolve")
async def resolve_sites(q: str = Query("", max_length=4096)) -> dict:
    """Preview what a list of links resolves to, and whether it may be scanned."""
    texts = [t for t in (x.strip() for x in q.replace(",", "\n").splitlines()) if t]
    return {"sites": await _resolve_sites(texts)}


@app.post("/api/scans")
async def create_scan(req: ScanRequest) -> dict:
    # fields the server owns
    req.site_hosts, req.extra_web_ports, req.chain_target_url = {}, [], None
    if req.scan_mode not in {"fast", "deep", "chain"}:
        raise HTTPException(400, "ไม่รู้จักโหมดสแกนที่เลือก")
    is_chain = req.scan_mode == "chain"
    if is_chain:
        if not _chain_available():
            raise HTTPException(503, "ยังไม่ได้เปิดใช้ Security Audit Toolkit บนเซิร์ฟเวอร์นี้")
        if not req.rce_chain_confirmed:
            raise HTTPException(400, "กรุณายืนยันสิทธิ์และการตรวจแบบ active ก่อนเริ่มโหมด chain")
        if bool(req.targets) == bool(req.sites):
            raise HTTPException(400, "โหมด chain ต้องระบุ IP เดี่ยวหรือ URL เดี่ยวอย่างใดอย่างหนึ่ง")
        if req.targets and len(req.targets) != 1:
            raise HTTPException(400, "โหมด chain ตรวจ IP ได้ครั้งละหนึ่งเป้าหมาย")
        if req.sites and len(req.sites) != 1:
            raise HTTPException(400, "โหมด chain ตรวจ URL ได้ครั้งละหนึ่งเป้าหมาย")
    if req.demo_scenario:
        valid_ids = {d["id"] for d in demo_scenarios.DEMO_SCENARIOS}
        if req.demo_scenario not in valid_ids:
            raise HTTPException(400, f"ไม่พบโหมดสาธิต: {req.demo_scenario}")
        scen = next(
            d for d in demo_scenarios.DEMO_SCENARIOS if d["id"] == req.demo_scenario
        )
        req.sites = []
        if not req.targets:
            req.targets = [scen["cidr"]]
        job = await store.create(req)
        return {"id": job.id, "total_ips": scen["total_ips"], **job.summary()}

    if len(req.sites) > sites.MAX_SITES:
        raise HTTPException(400, f"ตรวจเว็บไซต์ได้ครั้งละไม่เกิน {sites.MAX_SITES} ลิงก์")
    direct_targets = list(req.targets)  # only these are bound by the IP scope
    if req.sites:
        report = await _resolve_sites(req.sites)
        if is_chain:
            item = report[0] if report else {}
            if len(item.get("ips", [])) != 1:
                raise HTTPException(400, "โหมด chain ต้อง resolve URL เป็น IPv4 เพียงหนึ่งหมายเลข")
            raw_site = req.sites[0].strip()
            parts = urlsplit(raw_site if "://" in raw_site else "http://" + raw_site)
            if parts.username or parts.password:
                raise HTTPException(400, "โหมด chain ไม่รองรับข้อมูลล็อกอินใน URL")
            parsed_site = sites.parse(raw_site)
            netloc = parsed_site.host + (f":{parsed_site.port}" if parsed_site.port else "")
            req.chain_target_url = urlunsplit(
                (parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")
            )
        problems = [p for r in report for p in r["problems"]]
        if problems:
            raise HTTPException(403 if any(r["refused"] for r in report) else 400,
                                " · ".join(problems))
        for r in report:
            for ip in r["ips"]:
                req.site_hosts.setdefault(ip, r["host"])
                if ip not in req.targets:
                    req.targets.append(ip)
            if r["port"] and r["port"] not in settings.web_ports:
                req.extra_web_ports.append(r["port"])
        req.extra_web_ports = sorted(set(req.extra_web_ports))

    if not req.targets:
        raise HTTPException(400, "ไม่ได้ระบุเป้าหมาย")
    try:
        expanded_targets, total = expand_targets(req.targets, settings.max_targets)
    except TargetError as exc:
        raise HTTPException(400, str(exc))
    if is_chain and (total != 1 or len(expanded_targets) != 1):
        raise HTTPException(400, "โหมด chain ตรวจได้ครั้งละหนึ่ง IPv4 เท่านั้น")
    # The IP scope is a hard limit only when THSCAN_ENFORCE_SCOPE is on. By
    # default the operator may scan anything they type; website targets are
    # never bound by the IP scope regardless.
    if settings.enforce_scope:
        bad = out_of_scope(direct_targets, settings.allowed_networks())
        if bad:
            raise HTTPException(
                403,
                "เป้าหมายอยู่นอกขอบเขตที่อนุญาต (scope ที่ตั้งไว้ตอน deploy): "
                + ", ".join(bad)
                + " — อนุญาตเฉพาะ: "
                + ", ".join(settings.allowed_cidrs),
            )
    try:
        scan_ports = ports.profile_ports(req.port_profile, req.custom_ports,
                                         sorted(set(settings.web_ports) | set(req.extra_web_ports)))
    except ports.PortSpecError as exc:
        raise HTTPException(400, str(exc))
    if is_chain and not req.chain_target_url:
        # The toolkit is a web audit pipeline; bind an IP target to one selected
        # HTTP(S) port so it inspects the service selected in the main scan.
        preferred = (80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 3000, 5000)
        chain_port = next((p for p in preferred if p in scan_ports), None)
        if chain_port is None and req.port_profile in {"custom", "web"}:
            chain_port = next((p for p in scan_ports if p not in ports.NON_WEB_PORTS), None)
        if chain_port is None:
            chain_port = 80
        scheme = "https" if chain_port in {443, 8443} else "http"
        default_port = 443 if scheme == "https" else 80
        netloc = expanded_targets[0] if chain_port == default_port else f"{expanded_targets[0]}:{chain_port}"
        req.chain_target_url = urlunsplit((scheme, netloc, "/", "", ""))
    if total * len(scan_ports) > settings.max_port_probes:
        raise HTTPException(
            400,
            f"งานนี้ต้องตรวจ {total:,} ที่อยู่ × {len(scan_ports):,} พอร์ต ซึ่งเกินขีดจำกัด "
            f"{settings.max_port_probes:,} ครั้ง — ลดขนาดช่วง IP หรือจำนวนพอร์ตลง",
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


@app.get("/api/scans/{job_id}/chain-artifacts/{artifact_path:path}")
async def download_chain_artifact(job_id: str, artifact_path: str) -> FileResponse:
    job = store.get(job_id)
    if job is None or not job.chain_result:
        raise HTTPException(404, "ไม่พบรายงาน chain")
    allowed = {
        item.get("path")
        for item in job.chain_result.get("artifacts", [])
        if isinstance(item, dict) and item.get("path")
    }
    if artifact_path not in allowed:
        raise HTTPException(404, "ไม่พบไฟล์รายงาน")
    root = (Path(settings.data_dir) / "chain" / job.id).resolve()
    path = (root / artifact_path).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        raise HTTPException(404, "ไม่พบไฟล์รายงาน")
    if not path.is_file():
        raise HTTPException(404, "ไม่พบไฟล์รายงาน")
    return FileResponse(str(path), filename=path.name)


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
            "runtime",
            "php_version",
            "cms",
            "open_ports",
            "open_services",
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
                d.runtime or "",
                d.php_version or "",
                d.cms or "",
                " ".join(str(p) for p in d.open_ports),
                " ".join(f"{x.port}/{x.name}" for x in d.services),
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


def _validate_schedule(payload: ScheduleCreate) -> None:
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
    if settings.enforce_scope:
        bad = out_of_scope(payload.targets, settings.allowed_networks())
        if bad:
            raise HTTPException(403, f"เป้าหมายอยู่นอกขอบเขต: {', '.join(bad)}")
    try:
        ports.profile_ports(payload.port_profile, payload.custom_ports, settings.web_ports)
    except ports.PortSpecError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/schedules")
async def create_schedule(payload: ScheduleCreate) -> dict:
    _validate_schedule(payload)
    item = store.add_schedule(payload)
    scheduler.refresh_next_runs()
    return item.dump_json_dict()


@app.put("/api/schedules/{sched_id}")
async def update_schedule(sched_id: str, payload: ScheduleCreate) -> dict:
    _validate_schedule(payload)
    item = store.update_schedule(sched_id, payload)
    if item is None:
        raise HTTPException(404, "ไม่พบตารางเวลา")
    scheduler.refresh_next_runs()
    return item.dump_json_dict()


@app.delete("/api/schedules/{sched_id}")
async def remove_schedule(sched_id: str) -> dict:
    if not store.delete_schedule(sched_id):
        raise HTTPException(404, "ไม่พบตารางเวลา")
    return {"deleted": True}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(
        os.path.join(STATIC_DIR, "index.html"),
        headers={"Cache-Control": "no-store"},
    )


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
