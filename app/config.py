"""Runtime configuration.

Values can be overridden by environment variables (prefixed ``THSCAN_``) so the
container can be tuned without rebuilding.

The meaningful access control for this self-hosted tool is the deploy-time
**scope allowlist** (``THSCAN_ALLOWED_CIDRS``): the operator declares which
networks this instance may scan, and anything outside it is refused. A per-scan
"I am authorized" checkbox was removed deliberately — it could not be enforced
and gave a false sense of control. Every scan is still written to the audit log.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import List


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_list(name: str, default: List[str]) -> List[str]:
    val = os.environ.get(name)
    if not val:
        return list(default)
    return [item.strip() for item in val.split(",") if item.strip()]


@dataclass
class Settings:
    # --- Scope (deploy-time access control) ------------------------------
    # The networks this instance is permitted to scan. Defaults to the private
    # (RFC1918) ranges, so out of the box it only scans local networks. An
    # operator scanning a routable range must list it here explicitly.
    allowed_cidrs: List[str] = field(
        default_factory=lambda: _env_list(
            "THSCAN_ALLOWED_CIDRS",
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        )
    )

    # --- Safety rails ----------------------------------------------------
    max_targets: int = _env_int("THSCAN_MAX_TARGETS", 65536)
    max_concurrency: int = _env_int("THSCAN_MAX_CONCURRENCY", 50)
    connect_timeout: float = float(os.environ.get("THSCAN_CONNECT_TIMEOUT", "1.5"))
    http_timeout: float = float(os.environ.get("THSCAN_HTTP_TIMEOUT", "6"))
    polite_delay_ms: int = _env_int("THSCAN_POLITE_DELAY_MS", 0)

    # Ports used both to detect a live host and to find web services.
    web_ports: List[int] = field(
        default_factory=lambda: [
            int(p) for p in _env_list("THSCAN_WEB_PORTS", ["80", "443", "8080", "8443"])
        ]
    )
    # Extra ports probed only to decide whether a host is alive (not web).
    liveness_ports: List[int] = field(
        default_factory=lambda: [
            int(p) for p in _env_list("THSCAN_LIVENESS_PORTS", ["22", "445", "3389", "53"])
        ]
    )

    data_dir: str = os.environ.get("THSCAN_DATA_DIR", "/data")

    # --- helpers ---------------------------------------------------------
    def allowed_networks(self) -> List[ipaddress.IPv4Network]:
        nets: List[ipaddress.IPv4Network] = []
        for cidr in self.allowed_cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.version == 4:
                    nets.append(net)
            except ValueError:
                continue
        return nets


settings = Settings()
