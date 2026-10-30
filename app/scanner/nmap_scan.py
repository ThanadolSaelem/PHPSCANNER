"""Deep-mode discovery with nmap and traceroute.

Fast mode (the default) uses the pure-Python TCP connect scanner and needs no
external tools. Deep mode shells out to ``nmap`` for service/version detection
and to ``traceroute`` for the network path. Both are run with fixed argument
lists (never a shell string) on targets that the API has already validated as
IPv4 addresses/CIDRs, so there is no command injection surface.

nmap ``-sT`` (TCP connect) and ``traceroute`` on Linux both work without root,
so deep mode runs unprivileged inside the container.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def traceroute_available() -> bool:
    return shutil.which("traceroute") is not None or shutil.which("tracepath") is not None


@dataclass
class NmapPort:
    port: int
    name: str = ""
    product: str = ""      # e.g. "Apache httpd"
    version: str = ""      # e.g. "2.4.58"
    extra: str = ""        # e.g. "PHP 8.3.10"

    def label(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) or self.name.upper() or ""


@dataclass
class NmapHost:
    ip: str
    up: bool = False
    hostname: Optional[str] = None
    ports: Dict[int, NmapPort] = field(default_factory=dict)  # only open ports


# ---- parsing (pure, unit-tested without running nmap) ----------------------
def parse_nmap_xml(xml_text: str) -> Dict[str, NmapHost]:
    """Parse ``nmap -oX -`` output into {ip: NmapHost} with open ports only."""
    out: Dict[str, NmapHost] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for host in root.findall("host"):
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                addr = a.get("addr")
                break
        if not addr:
            continue
        status = host.find("status")
        up = status is not None and status.get("state") == "up"
        hn = host.find("hostnames/hostname")
        info = NmapHost(ip=addr, up=up, hostname=hn.get("name") if hn is not None else None)
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                pid = int(port.get("portid", "0"))
            except ValueError:
                continue
            svc = port.find("service")
            np = NmapPort(port=pid)
            if svc is not None:
                np.name = svc.get("name", "") or ""
                np.product = svc.get("product", "") or ""
                np.version = svc.get("version", "") or ""
                np.extra = svc.get("extrainfo", "") or ""
            info.ports[pid] = np
            info.up = True  # an open port means the host is up
        if info.up or info.ports:
            out[addr] = info
    return out


_HOP_RE = re.compile(
    r"^\s*(\d+)\s+(?:(\*)|([\d.]+)(?:\s+\(([\d.]+)\))?\s+([\d.]+)\s*ms)"
)


def parse_traceroute(text: str) -> List[dict]:
    """Parse ``traceroute -n`` output into [{hop, ip, rtt_ms}]. A line with no
    reply (``* * *``) becomes {hop, ip: None, rtt_ms: None}."""
    hops: List[dict] = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        n = int(m.group(1))
        rest = m.group(2).strip()
        if rest.startswith("*"):
            hops.append({"hop": n, "ip": None, "rtt_ms": None})
            continue
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        rtt_m = re.search(r"([\d.]+)\s*ms", rest)
        hops.append({
            "hop": n,
            "ip": ip_m.group(1) if ip_m else None,
            "rtt_ms": round(float(rtt_m.group(1)), 1) if rtt_m else None,
        })
    return hops


# ---- running (async subprocess) --------------------------------------------
async def _run(argv: List[str], timeout: float) -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
    except (OSError, ValueError):
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return None
    return out.decode("utf-8", errors="replace")


async def run_nmap(targets: List[str], ports: List[int], timeout: float = 240.0,
                   extra_args: Optional[List[str]] = None) -> Dict[str, NmapHost]:
    """TCP-connect service/version scan of *targets* on *ports*. -Pn so nmap
    scans every target without a privileged ping sweep."""
    if not targets or not ports or not nmap_available():
        return {}
    port_spec = ",".join(str(p) for p in sorted(set(ports)))
    # --host-timeout caps time per host so one slow/filtered target can't stall
    # the whole run; --max-retries keeps probes bounded on lossy links.
    argv = ["nmap", "-sT", "-sV", "--version-light", "-Pn", "-T4",
            "--host-timeout", "120s", "--max-retries", "2",
            "-p", port_spec, "-oX", "-", *(extra_args or []), *targets]
    xml = await _run(argv, timeout)
    return parse_nmap_xml(xml) if xml else {}


async def run_traceroute(ip: str, max_hops: int = 20, per_hop_timeout: float = 2.0,
                         total_timeout: float = 30.0) -> List[dict]:
    if shutil.which("traceroute"):
        argv = ["traceroute", "-n", "-q", "1", "-m", str(max_hops),
                "-w", str(per_hop_timeout), ip]
    elif shutil.which("tracepath"):
        argv = ["tracepath", "-n", "-m", str(max_hops), ip]
    else:
        return []
    out = await _run(argv, total_timeout)
    return parse_traceroute(out) if out else []
