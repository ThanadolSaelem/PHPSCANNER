"""Runtime configuration.

Values can be overridden by environment variables (prefixed ``THSCAN_``) so the
container can be tuned without rebuilding. Everything here has conservative,
safe defaults — the limits exist to keep the scanner from behaving like a DoS
tool against the networks it is pointed at.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: List[str]) -> List[str]:
    val = os.environ.get(name)
    if not val:
        return list(default)
    return [item.strip() for item in val.split(",") if item.strip()]


@dataclass
class Settings:
    # --- Discovery scope -------------------------------------------------
    # Only hostnames ending in one of these suffixes are kept. The defaults
    # cover Thai government (go.th), state organizations/SOEs (or.th) and the
    # military (mi.th). Operators may widen/narrow this in the UI per scan.
    default_allowed_suffixes: List[str] = field(
        default_factory=lambda: _env_list(
            "THSCAN_ALLOWED_SUFFIXES", ["go.th", "or.th", "mi.th"]
        )
    )

    # --- Safety rails ----------------------------------------------------
    # Hard cap on how many IP addresses a single scan may expand to. This is a
    # guard against accidentally pointing the tool at, say, a /8.
    max_targets: int = _env_int("THSCAN_MAX_TARGETS", 65536)
    # Maximum concurrent host probes.
    max_concurrency: int = _env_int("THSCAN_MAX_CONCURRENCY", 50)
    # Per-connection timeout (seconds).
    connect_timeout: float = float(os.environ.get("THSCAN_CONNECT_TIMEOUT", "4"))
    http_timeout: float = float(os.environ.get("THSCAN_HTTP_TIMEOUT", "8"))
    dns_timeout: float = float(os.environ.get("THSCAN_DNS_TIMEOUT", "4"))
    # Optional artificial delay (ms) added per host to be gentle on targets.
    polite_delay_ms: int = _env_int("THSCAN_POLITE_DELAY_MS", 0)

    # Ports probed for web services.
    web_ports: List[int] = field(
        default_factory=lambda: [
            int(p) for p in _env_list("THSCAN_WEB_PORTS", ["80", "443", "8080", "8443"])
        ]
    )

    # Require the operator to tick the "I am authorized" box before a scan
    # starts. Strongly recommended; can be disabled only for isolated lab use.
    require_authorization: bool = _env_bool("THSCAN_REQUIRE_AUTH", True)

    # Custom DNS resolver(s) for reverse lookups (empty => system resolver).
    dns_servers: List[str] = field(
        default_factory=lambda: _env_list("THSCAN_DNS_SERVERS", [])
    )

    # Where job state + audit log are persisted inside the container.
    data_dir: str = os.environ.get("THSCAN_DATA_DIR", "/data")


settings = Settings()
