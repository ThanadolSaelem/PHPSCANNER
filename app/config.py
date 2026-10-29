"""Runtime configuration."""
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


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_list(name: str, default: List[str]) -> List[str]:
    val = os.environ.get(name)
    if not val:
        return list(default)
    return [item.strip() for item in val.split(",") if item.strip()]


def _default_data_dir() -> str:
    env_dir = os.environ.get("THSCAN_DATA_DIR")
    if env_dir:
        return env_dir
    if os.access("/data", os.W_OK):
        return "/data"
    # local runs (run.sh / run.bat): keep history next to the app so it survives reboots
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


@dataclass
class Settings:
    allowed_cidrs: List[str] = field(
        default_factory=lambda: _env_list(
            "THSCAN_ALLOWED_CIDRS",
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        )
    )
    max_targets: int = _env_int("THSCAN_MAX_TARGETS", 65536)
    max_concurrency: int = _env_int("THSCAN_MAX_CONCURRENCY", 50)
    connect_timeout: float = _env_float("THSCAN_CONNECT_TIMEOUT", 1.5)
    http_timeout: float = _env_float("THSCAN_HTTP_TIMEOUT", 6.0)
    polite_delay_ms: int = _env_int("THSCAN_POLITE_DELAY_MS", 0)
    web_ports: List[int] = field(
        default_factory=lambda: [
            int(p) for p in _env_list("THSCAN_WEB_PORTS", ["80", "443", "8080", "8443"])
            if p.isdigit()
        ]
    )
    liveness_ports: List[int] = field(
        default_factory=lambda: [
            int(p) for p in _env_list("THSCAN_LIVENESS_PORTS", ["22", "445", "3389", "53"])
            if p.isdigit()
        ]
    )
    gov_suffixes: List[str] = field(
        default_factory=lambda: _env_list(
            "THSCAN_GOV_SUFFIXES",
            ["go.th", "or.th", "mi.th", "ac.th", "in.th"],
        )
    )
    data_dir: str = field(default_factory=_default_data_dir)

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
