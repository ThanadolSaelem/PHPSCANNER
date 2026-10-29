"""Pydantic models shared between the API and the scan engine."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


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


class ScanRequest(BaseModel):
    """Payload the UI sends to start a scan."""

    targets: List[str] = Field(
        ...,
        description="Targets to scan: CIDR (10.255.252.0/22), hyphen range "
        "(10.0.0.10-10.0.0.50) or single IP. One per entry.",
    )
    concurrency: Optional[int] = None
    polite_delay_ms: Optional[int] = None
    note: str = Field("", description="Free-text label stored in the audit log.")


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str = ""
    recommendation: str = ""
    cve: List[str] = Field(default_factory=list)


class Device(BaseModel):
    """A single online device discovered on the network."""

    ip: str
    up: bool = True
    mac: Optional[str] = None
    device_type: str = "LAN Device"
    service: str = "ไม่มีบริการเว็บ"
    php_version: Optional[str] = None
    server: Optional[str] = None
    cms: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    latency_ms: Optional[int] = None
    severity: Severity = Severity.safe
    assessment: str = ""
    findings: List[Finding] = Field(default_factory=list)


class ScanProgress(BaseModel):
    total_ips: int = 0
    probed: int = 0
    online: int = 0
    risks: int = 0


class ScanJob(BaseModel):
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
    intercepted_ports: List[int] = Field(default_factory=list)
    error: Optional[str] = None

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
            "progress": self.progress.model_dump(),
            "severity_counts": sev_counts,
            "online": len(self.devices),
            "risks": sum(1 for d in self.devices if d.severity != Severity.safe),
            "php_servers": php_servers,
            "target_label": self.target_label,
            "duration_s": self.duration_s,
            "workers": self.workers,
            "intercepted_ports": self.intercepted_ports,
            "note": self.request.note,
        }
