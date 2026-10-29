"""Device discovery for a local/authorized network.

Non-privileged techniques only:
  * liveness + latency via TCP connect (a refused connection still proves the
    host is up — no raw sockets, no ICMP, no elevated privileges)
  * MAC address read from the kernel ARP neighbour table (same-L2 hosts only)
  * local subnet autodetect from the primary route

MAC and L2 details are only available for hosts on the same broadcast domain as
the scanner; across a router they come back empty, which is expected.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
from typing import Dict, List, Optional, Tuple

_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
_ZERO_MAC = "00:00:00:00:00:00"


async def _probe_port(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    """Return ``(reachable, rtt_ms)``. Reachable means the host answered at all
    (connection accepted *or* refused); timeout/error means no answer."""
    loop = asyncio.get_event_loop()
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


# A documentation address (RFC 5737 TEST-NET-2) that can never be a real host.
# Anything that answers for it is a middlebox answering for every address.
CANARY_IP = "198.51.100.1"


async def intercepted_ports(ports: List[int], timeout: float,
                            canary: str = CANARY_IP) -> set:
    """Ports on which *something* answers for an address that cannot exist."""
    results = await asyncio.gather(*(_probe_port(canary, p, timeout) for p in ports))
    return {p for p, (ok, _) in zip(ports, results) if ok}


async def alive_latency(ip: str, ports: List[int], timeout: float
                        ) -> Tuple[bool, Optional[int]]:
    """Is *ip* up, and what is the lowest round-trip latency (ms)?

    *ports* should already exclude intercepted ports (see intercepted_ports).
    """
    if not ports:
        return False, None
    results = await asyncio.gather(*(_probe_port(ip, p, timeout) for p in ports))
    rtts = [rtt for ok, rtt in results if ok and rtt is not None]
    up = any(ok for ok, _ in results)
    return up, (round(min(rtts)) if rtts else None)


def read_arp_table() -> Dict[str, str]:
    """Map ip -> mac from the kernel ARP table (Linux ``/proc/net/arp``)."""
    table: Dict[str, str] = {}
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            next(fh, None)  # header
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
        parts = re.split(r"[:-]", mac.lower())
        norm = ":".join(p.zfill(2) for p in parts)
        if norm != _ZERO_MAC and norm != "ff:ff:ff:ff:ff:ff":
            table[ip] = norm
    return table


def infer_device_type(ip: str, open_web_ports: List[int], has_tls: bool,
                      has_other_open: bool) -> str:
    """Heuristic label for a device based on where it sits and what it serves."""
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
    """Best-effort list of local subnets the scanner could target (/24 guesses)."""
    subnets: List[Dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, ip: str, prefix: int = 24) -> None:
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            return
        key = str(net)
        if key not in seen and ip != "127.0.0.1":
            seen.add(key)
            subnets.append({"name": name, "cidr": key})

    # primary route
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            add("เครือข่ายหลัก", s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass

    # any other IPv4 on the host
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add("อินเทอร์เฟซ", info[4][0])
    except (OSError, socket.gaierror):
        pass

    if not subnets and os.environ.get("THSCAN_DEFAULT_SUBNET"):
        add("ค่าตั้งต้น", os.environ["THSCAN_DEFAULT_SUBNET"].split("/")[0],
            int((os.environ["THSCAN_DEFAULT_SUBNET"].split("/") + ["24"])[1]))
    return subnets
