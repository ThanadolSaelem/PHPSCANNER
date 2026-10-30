"""Device discovery for a local/authorized network."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
from typing import Dict, List, Optional, Tuple

from . import netlimit

_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
_ZERO_MAC = "00:00:00:00:00:00"


async def _probe_port(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    async with netlimit.slot():
        return await _probe_port_unlimited(ip, port, timeout)


async def _probe_port_unlimited(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        fut = asyncio.open_connection(ip, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        rtt = (loop.time() - start) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return True, rtt
    except ConnectionRefusedError:
        return True, (loop.time() - start) * 1000.0
    except (asyncio.TimeoutError, OSError):
        return False, None


async def _accepts_tcp(ip: str, port: int, timeout: float) -> bool:
    """Return True ONLY when a full TCP handshake succeeds (SYN-ACK).
    Unlike ``_probe_port``, a TCP RST (``ConnectionRefusedError``) returns False
    so a router rejecting RFC 5737 canary traffic is never mistaken for a proxy."""
    async with netlimit.slot():
        try:
            fut = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False


# A documentation address (RFC 5737 TEST-NET-2) that can never be a real host.
# Anything that completes a TCP handshake for it is a middlebox answering for every address.
CANARY_IP = "198.51.100.1"


async def intercepted_ports(ports: List[int], timeout: float,
                            canary: str = CANARY_IP) -> set:
    """Ports on which a transparent proxy/middlebox accepts TCP for a non-existent IP."""
    canary_timeout = min(timeout, 1.5)
    results = await asyncio.gather(*(_accepts_tcp(canary, p, canary_timeout) for p in ports))
    return {p for p, ok in zip(ports, results) if ok}


async def alive_latency(
    ip: str, ports: List[int], timeout: float
) -> Tuple[bool, Optional[int]]:
    if not ports:
        return False, None
    results = await asyncio.gather(*(_probe_port(ip, p, timeout) for p in ports))
    rtts = [rtt for ok, rtt in results if ok and rtt is not None]
    up = any(ok for ok, _ in results)
    return up, (round(min(rtts)) if rtts else None)


def read_arp_table() -> Dict[str, str]:
    table: Dict[str, str] = {}
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3].lower()
                    if _MAC_RE.match(mac) and mac != _ZERO_MAC:
                        table[ip] = mac
    except (OSError, StopIteration):
        pass
    if not table:
        table = _arp_command_table()
    return table


_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\D+?((?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2})", re.IGNORECASE)


def _arp_command_table() -> Dict[str, str]:
    """Fallback for Windows/macOS: parse ``arp -a`` (fixed args, no user input)."""
    import subprocess
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table: Dict[str, str] = {}
    for ip, mac in _ARP_LINE.findall(out):
        norm = ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.lower()))
        if norm not in (_ZERO_MAC, "ff:ff:ff:ff:ff:ff"):
            table[ip] = norm
    return table


def infer_device_type(
    ip: str, open_web_ports: List[int], has_tls: bool, has_other_open: bool
) -> str:
    try:
        last = int(ip.rsplit(".", 1)[1])
    except (ValueError, IndexError):
        last = -1
    if last in (1, 254):
        return "Gateway Router"
    if open_web_ports:
        return "Web Server (HTTPS)" if has_tls else "Web Server (HTTP)"
    return "LAN Device"


def autodetect_subnets() -> List[Dict[str, str]]:
    subnets: List[Dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, ip: str, prefix: int = 24) -> None:
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            return
        key = str(net)
        if key not in seen and ip != "127.0.0.1" and not ip.startswith("127."):
            seen.add(key)
            subnets.append({"name": name, "cidr": key})

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            add("เครือข่ายหลัก (Primary LAN)", s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add("อินเทอร์เฟซภายใน (Local NIC)", info[4][0])
    except (OSError, socket.gaierror):
        pass

    default_sub = os.environ.get("THSCAN_DEFAULT_SUBNET", "").strip()
    if not subnets and default_sub:
        parts = default_sub.split("/")
        try:
            prefix = int(parts[1]) if len(parts) > 1 else 24
        except ValueError:
            prefix = 24
        add("ค่าตั้งต้น (Default Subnet)", parts[0], prefix)

    if not subnets:
        add("เครือข่ายจำลองมาตรฐาน (Fallback LAN)", "192.168.1.0", 24)
    return subnets
