"""Pydantic models shared between the API and the scan engine."""
from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CompatBaseModel(BaseModel):
    def dump_json_dict(self) -> Dict[str, Any]:
        if hasattr(self, "model_dump"):
            return self.model_dump(mode="json")  # type: ignore[attr-defined]
        return json.loads(self.json())


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    low = "low"
    safe = "safe"


class Confidence(str, Enum):
    confirmed = "confirmed"
    high = "high"
    medium = "medium"
    low = "low"


class JobState(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    cancelled = "cancelled"
    failed = "failed"


class ScanRequest(CompatBaseModel):
    targets: List[str] = Field(default_factory=list)
    # websites given by link/domain; resolved by the API into ``targets``
    sites: List[str] = Field(default_factory=list)
    # which ports to check on each online host: web | common | top100 | custom
    port_profile: str = "common"
    custom_ports: str = ""
    # fast = pure-Python TCP connect (no deps); deep = nmap -sV + traceroute
    scan_mode: str = "fast"
    concurrency: Optional[int] = None
    polite_delay_ms: Optional[int] = None
    note: str = Field("")
    demo_scenario: Optional[str] = Field(None)
    # set by the server, never trusted from the client
    site_hosts: Dict[str, str] = Field(default_factory=dict)   # ip -> hostname
    extra_web_ports: List[int] = Field(default_factory=list)   # ports named in links


class Finding(CompatBaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str = ""
    recommendation: str = ""
    cve: List[str] = Field(default_factory=list)
    cvss: Optional[float] = None
    cwe: Optional[str] = None


class RouteHop(CompatBaseModel):
    hop: int
    ip: Optional[str] = None     # None / "*" = no reply at this hop
    rtt_ms: Optional[float] = None


class ServicePort(CompatBaseModel):
    port: int
    name: str
    description: str = ""
    note: Optional[str] = None
    product: Optional[str] = None  # deep mode: "Apache httpd 2.4.58" from nmap -sV


class Device(CompatBaseModel):
    ip: str
    hostname: Optional[str] = None
    matched_suffix: Optional[str] = None
    up: bool = True
    mac: Optional[str] = None
    device_type: str = "LAN Device"
    service: str = "ไม่มีบริการเว็บ"
    php_version: Optional[str] = None
    server: Optional[str] = None
    cms: Optional[str] = None
    runtime: Optional[str] = None  # human label: "PHP 8.2.35", "Node.js · Express", …
    route: List["RouteHop"] = Field(default_factory=list)  # deep mode: traceroute path
    open_ports: List[int] = Field(default_factory=list)  # web ports that answered HTTP
    services: List[ServicePort] = Field(default_factory=list)  # every open TCP port found
    latency_ms: Optional[int] = None
    severity: Severity = Severity.safe
    assessment: str = ""
    findings: List[Finding] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    patched_at: Optional[str] = None  # demo jobs only: simulated patch
    checked_at: Optional[str] = None  # real re-check of this host


class ScanProgress(CompatBaseModel):
    total_ips: int = 0
    probed: int = 0
    online: int = 0
    risks: int = 0
    phase: str = ""        # liveness | inspect
    to_inspect: int = 0    # hosts that answered liveness
    inspected: int = 0


class ScheduleCreate(CompatBaseModel):
    name: str
    targets: List[str]
    cron: str = "0 2 * * *"
    enabled: bool = True
    port_profile: str = "common"
    custom_ports: str = ""


class ScheduleItem(CompatBaseModel):
    id: str
    name: str
    targets: List[str]
    cron: str
    enabled: bool = True
    port_profile: str = "common"
    custom_ports: str = ""
    created_at: str
    last_run: Optional[str] = None
    last_job_id: Optional[str] = None
    next_run: Optional[str] = None


class ScanJob(CompatBaseModel):
    id: str
    state: JobState = JobState.queued
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    request: ScanRequest
    target_label: str = ""
    progress: ScanProgress = Field(default_factory=ScanProgress)
    devices: List[Device] = Field(default_factory=list)
    duration_s: Optional[float] = None
    workers: int = 0
    error: Optional[str] = None
    demo_scenario: Optional[str] = None
    intercepted_ports: List[int] = Field(default_factory=list)
    scanned_ports: List[int] = Field(default_factory=list)
    scan_mode: str = "fast"            # "fast" | "deep"
    note_deep: Optional[str] = None    # why deep mode fell back, if it did

    def security_score(self) -> int:
        if not self.devices:
            return 100
        penalty = 0
        for d in self.devices:
            if d.severity == Severity.critical:
                penalty += 22
            elif d.severity == Severity.high:
                penalty += 14
            elif d.severity == Severity.low:
                penalty += 4
        return max(0, min(100, 100 - penalty))

    def security_grade(self) -> str:
        score = self.security_score()
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 65:
            return "C"
        if score >= 50:
            return "D"
        return "F"

    def summary(self) -> Dict:
        sev_counts: Dict[str, int] = {s.value: 0 for s in Severity}
        php_servers = 0
        for d in self.devices:
            sev_counts[d.severity.value] += 1
            if d.php_version or d.open_ports:
                php_servers += 1
        return {
            "id": self.id,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "progress": self.progress.dump_json_dict(),
            "severity_counts": sev_counts,
            "online": len(self.devices),
            "risks": sum(1 for d in self.devices if d.severity != Severity.safe),
            "php_servers": php_servers,
            "target_label": self.target_label,
            "duration_s": self.duration_s,
            "workers": self.workers,
            "note": self.request.note,
            "demo_scenario": self.demo_scenario,
            "intercepted_ports": self.intercepted_ports,
            "port_profile": self.request.port_profile,
            "scanned_port_count": len(self.scanned_ports),
            "sites": self.request.sites,
            "security_score": self.security_score(),
            "security_grade": self.security_grade(),
        }
