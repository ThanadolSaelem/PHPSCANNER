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


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


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
    # upper bound on (addresses x ports) for one scan
    max_port_probes: int = _env_int("THSCAN_MAX_PORT_PROBES", 2_000_000)
    connect_timeout: float = _env_float("THSCAN_CONNECT_TIMEOUT", 3.5)
    http_timeout: float = _env_float("THSCAN_HTTP_TIMEOUT", 8.0)
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
    # When False (the default), the operator may run the standard fast/deep scan
    # against any target they type; deployment scope and gov-domain rules are
    # advisory labels. Set THSCAN_ENFORCE_SCOPE=1 to impose them as scan limits.
    # RCE and LAN fingerprinting are separate active options with their own
    # server-side gates and per-run consent; LAN fingerprinting also enforces a
    # directly attached RFC1918 interface boundary independent of this setting.
    enforce_scope: bool = _env_bool("THSCAN_ENFORCE_SCOPE", False)
    traceroute_max: int = _env_int("THSCAN_TRACEROUTE_MAX", 16)
    rce_chain_enabled: bool = _env_bool("THSCAN_RCE_CHAIN_ENABLED", True)
    rce_chain_timeout_s: int = _env_int("THSCAN_RCE_CHAIN_TIMEOUT", 90)
    rce_verify_enabled: bool = _env_bool("THSCAN_RCE_VERIFY_ENABLED", False)
    rce_verify_total_timeout_s: int = _env_int("THSCAN_RCE_VERIFY_TOTAL_TIMEOUT", 180)
    rce_verify_max_endpoints: int = _env_int("THSCAN_RCE_VERIFY_MAX_ENDPOINTS", 0)
    rce_verify_max_workers: int = _env_int("THSCAN_RCE_VERIFY_MAX_WORKERS", 2)
    rce_verify_memory_reserve_mb: int = _env_int("THSCAN_RCE_VERIFY_MEMORY_RESERVE_MB", 1024)
    rce_verify_worker_memory_mb: int = _env_int("THSCAN_RCE_VERIFY_WORKER_MEMORY_MB", 512)
    rce_verify_batch_timeout_s: int = _env_int("THSCAN_RCE_VERIFY_BATCH_TIMEOUT", 7200)
    rce_verify_token: str = field(
        default_factory=lambda: os.environ.get("THSCAN_RCE_VERIFY_TOKEN", "")
    )
    # LAN fingerprinting is separately opt-in and never grants raw-socket access.
    lan_fingerprint_enabled: bool = _env_bool("THSCAN_LAN_FINGERPRINT_ENABLED", False)
    lan_fingerprint_max_targets: int = _env_int("THSCAN_LAN_FINGERPRINT_MAX_TARGETS", 256)
    lan_fingerprint_max_workers: int = _env_int("THSCAN_LAN_FINGERPRINT_MAX_WORKERS", 4)
    lan_fingerprint_probe_timeout_s: float = _env_float("THSCAN_LAN_FINGERPRINT_PROBE_TIMEOUT", 0.8)
    lan_fingerprint_total_timeout_s: int = _env_int("THSCAN_LAN_FINGERPRINT_TOTAL_TIMEOUT", 90)
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
