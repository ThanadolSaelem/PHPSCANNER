"""Non-destructive HTTP(S) probing of a single web service."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import httpx

from ..models import Finding
from . import netlimit, vuln_rules

USER_AGENT = "thscan/2.0 (+defensive php2shell check; ThaiCERT compliance; non-destructive)"
_MAX_BODY = 262_144


@dataclass
class WebResult:
    port: int
    scheme: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    php_version: Optional[str] = None
    cms: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    # Stable shape of the response, used to recognise a middlebox (proxy /
    # firewall) that answers on behalf of every address.
    fingerprint: str = ""


_VOLATILE = {"date", "set-cookie", "content-length", "age", "expires", "etag", "last-modified"}


def response_fingerprint(status: Optional[int], headers: Dict[str, str]) -> str:
    names = sorted(h for h in headers if h not in _VOLATILE)
    return f"{status}|{','.join(names)}|{headers.get('server', '')}"


async def probe_service(
    client: httpx.AsyncClient, ip: str, port: int, host: Optional[str] = None
) -> Optional[WebResult]:
    """Fetch ``/`` from *ip*:*port*. With *host*, send it as Host/SNI so a
    name-based virtual host (a website given by link) answers as itself."""
    scheme = "https" if port in (443, 8443) else "http"
    res = await _try(client, scheme, ip, port, host)
    if res is not None:
        return res
    if port not in (80, 443):
        other = "http" if scheme == "https" else "https"
        return await _try(client, other, ip, port, host)
    return None


_REDIRECTS = (301, 302, 303, 307, 308)
_MAX_HOPS = 3


async def _try(
    client: httpx.AsyncClient, scheme: str, ip: str, port: int, host: Optional[str] = None
) -> Optional[WebResult]:
    """GET the page, following redirects only while they stay on the same host.

    Every request goes to *ip* (never to a name looked up again), so a redirect
    or a DNS change can't send the scan to an address outside the scope.
    """
    name = host or ip
    path = "/"
    hop_headers: Dict[str, str] = {}
    for _ in range(_MAX_HOPS + 1):
        url = f"{scheme}://{ip}:{port}{path}"
        headers = {"User-Agent": USER_AGENT}
        ext = {}
        if host:
            headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
            if scheme == "https":
                ext["sni_hostname"] = host
        try:
            async with netlimit.slot():
                resp = await client.get(url, headers=headers, extensions=ext)
        except (httpx.HTTPError, OSError, ValueError):
            return None
        if resp.status_code not in _REDIRECTS or "location" not in resp.headers:
            break
        nxt = _same_host_redirect(resp.headers["location"], scheme, name, port, url)
        if nxt is None:
            break  # leaves the host: report this response, don't follow
        hop_headers.update({k.lower(): v for k, v in resp.headers.items()})
        scheme, port, path = nxt

    headers_lc: Dict[str, str] = {k.lower(): v for k, v in resp.headers.items()}
    merged = {**{k: v for k, v in hop_headers.items() if k != "location"}, **headers_lc}
    body = ""
    try:
        body = resp.content[:_MAX_BODY].decode(
            resp.encoding or "utf-8", errors="replace"
        )
    except (UnicodeDecodeError, LookupError, httpx.HTTPError):
        body = ""

    findings, php_version, cms, server = vuln_rules.evaluate(
        scheme=scheme, headers=merged, body=body
    )
    return WebResult(
        port=port,
        scheme=scheme,
        status_code=resp.status_code,
        server=server,
        powered_by=merged.get("x-powered-by"),
        php_version=php_version,
        cms=cms,
        findings=findings,
        headers=merged,
        fingerprint=response_fingerprint(resp.status_code, headers_lc),
    )


def _same_host_redirect(
    location: str, scheme: str, name: str, port: int, current: str
) -> Optional[Tuple[str, int, str]]:
    """Return ``(scheme, port, path)`` if *location* stays on this host, else None.

    "This host" is the website name being checked or the IP we connect to.
    """
    try:
        target = urlsplit(urljoin(current, location))
        new_scheme = target.scheme.lower()
        new_host = (target.hostname or "").lower().rstrip(".")
        new_port = target.port or (443 if new_scheme == "https" else 80)
    except ValueError:
        return None
    if new_scheme not in ("http", "https"):
        return None
    if new_host not in {name.lower().rstrip("."), urlsplit(current).hostname}:
        return None
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    return new_scheme, new_port, path


def build_client(http_timeout: float, connect_timeout: float) -> httpx.AsyncClient:
    timeout = httpx.Timeout(http_timeout, connect=connect_timeout)
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=20)
    return httpx.AsyncClient(
        verify=False,
        follow_redirects=False,  # followed by hand, same host only (see _try)
        timeout=timeout,
        limits=limits,
        trust_env=False,
    )
