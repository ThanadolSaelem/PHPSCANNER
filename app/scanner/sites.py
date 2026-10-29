"""Website targets given as a link or domain (``https://www.agency.go.th/``).

A link is resolved to IPv4 addresses exactly once, when the scan is created.
The scan then talks only to those addresses (with the name sent as Host/SNI),
and each address must be inside the deploy-time scope. Because the name is
never looked up again, a DNS change mid-scan cannot point it elsewhere.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

from .dns_resolver import match_suffix

MAX_SITES = 20
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class SiteError(ValueError):
    pass


@dataclass
class Site:
    text: str                     # what the user typed
    host: str                     # normalised hostname (punycode for Thai IDN)
    port: Optional[int] = None    # explicit port from the link, if any
    ips: List[str] = field(default_factory=list)
    suffix: Optional[str] = None  # matched government suffix


def looks_like_site(spec: str) -> bool:
    """True for anything that is not an IP / CIDR / range spec."""
    s = spec.strip()
    return bool(s) and ("://" in s or re.search(r"[a-zA-Z฀-๿]", s) is not None)


def parse(text: str) -> Site:
    raw = text.strip()
    if not raw or len(raw) > 2048:
        raise SiteError("ลิงก์ว่างหรือยาวเกินไป")
    url = raw if "://" in raw else "http://" + raw
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise SiteError(f"ลิงก์ไม่ถูกต้อง: {raw}")
    if parts.scheme.lower() not in ("http", "https"):
        raise SiteError(f"รองรับเฉพาะลิงก์ http:// หรือ https:// ({raw})")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise SiteError(f"ไม่พบชื่อโดเมนในลิงก์: {raw}")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise SiteError(f"ลิงก์นี้เป็นเลข IP — ใส่ในโหมด “เครือข่าย” แทน ({host})")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise SiteError(f"ชื่อโดเมนไม่ถูกต้อง: {host}")
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        raise SiteError(f"ชื่อโดเมนไม่ถูกต้อง: {host}")
    if port is None and parts.scheme.lower() == "https":
        port = 443
    return Site(text=raw, host=host, port=port)


async def resolve(site: Site, timeout: float = 4.0) -> Site:
    """Look the name up with the operating system's resolver, like a browser
    would — so VPN / split-horizon DNS and hosts-file entries all work."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(site.host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise SiteError(f"ค้นหา DNS ของ {site.host} ไม่สำเร็จ (หมดเวลา)")
    except socket.gaierror as exc:
        if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            raise SiteError(f"ไม่พบโดเมน {site.host} ในระบบ DNS")
        raise SiteError(f"ค้นหา DNS ของ {site.host} ไม่สำเร็จ ({exc.strerror})")
    ips = {info[4][0] for info in infos}
    if not ips:
        raise SiteError(f"โดเมน {site.host} ไม่มีที่อยู่ IPv4")
    site.ips = sorted(ips, key=lambda a: tuple(int(o) for o in a.split(".")))[:8]
    return site


def check(site: Site, suffixes: List[str], allowed: "list[ipaddress.IPv4Network]") -> List[str]:
    """Problems that stop this site from being scanned (empty list = OK)."""
    problems: List[str] = []
    site.suffix = match_suffix(site.host, suffixes)
    if not site.suffix:
        problems.append(f"{site.host} ไม่ใช่โดเมนหน่วยงาน (อนุญาตเฉพาะ {', '.join(suffixes)})")
    outside = [ip for ip in site.ips
               if not any(ipaddress.ip_address(ip) in net for net in allowed)]
    if outside:
        problems.append(f"{site.host} ชี้ไปที่ {', '.join(outside)} ซึ่งอยู่นอกขอบเขตที่อนุญาต")
    return problems
