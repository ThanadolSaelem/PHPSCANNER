"""Pydantic models shared between the API and the scan engine."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    confirmed = "confirmed"   # version string read directly, clearly affected
    high = "high"             # strong version signal
    medium = "medium"         # partial version / heuristic
    low = "low"               # presence only; needs manual check


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
        description="IP ranges to scan: CIDR (203.0.113.0/24), hyphen range "
        "(203.0.113.10-203.0.113.50), or single IP. One per entry.",
    )
    allowed_suffixes: List[str] = Field(
        default_factory=list,
        description="Hostname suffixes to keep (e.g. go.th). Empty => server default.",
    )
    ports: List[int] = Field(default_factory=list, description="Override web ports.")
    concurrency: Optional[int] = None
    polite_delay_ms: Optional[int] = None
    authorized: bool = Field(
        False,
        description="Operator confirms they are authorized to scan the targets.",
    )
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


class ServiceResult(BaseModel):
    """A single reachable web service on a discovered host."""

    port: int
    scheme: str
    url: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    php_version: Optional[str] = None
    cms: Optional[str] = None
    title: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)


class HostResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    in_scope: bool = False
    matched_suffix: Optional[str] = None
    services: List[ServiceResult] = Field(default_factory=list)
    max_severity: Optional[Severity] = None

    def recompute_severity(self) -> None:
        order = [Severity.critical, Severity.high, Severity.medium,
                 Severity.low, Severity.info]
        best: Optional[Severity] = None
        for svc in self.services:
            for f in svc.findings:
                if best is None or order.index(f.severity) < order.index(best):
                    best = f.severity
        self.max_severity = best


class ScanProgress(BaseModel):
    total_ips: int = 0
    resolved: int = 0
    in_scope: int = 0
    probed: int = 0
    findings: int = 0


class ScanJob(BaseModel):
    id: str
    state: JobState = JobState.queued
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    request: ScanRequest
    progress: ScanProgress = Field(default_factory=ScanProgress)
    hosts: List[HostResult] = Field(default_factory=list)
    error: Optional[str] = None

    def summary(self) -> Dict:
        sev_counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for host in self.hosts:
            for svc in host.services:
                for f in svc.findings:
                    sev_counts[f.severity.value] += 1
        return {
            "id": self.id,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "progress": self.progress.model_dump(),
            "severity_counts": sev_counts,
            "hosts_in_scope": sum(1 for h in self.hosts if h.in_scope),
            "note": self.request.note,
        }
