"""Non-destructive HTTP(S) probing of a single web service."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

from ..models import Finding
from . import vuln_rules

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
    client: httpx.AsyncClient, ip: str, port: int
) -> Optional[WebResult]:
    scheme = "https" if port in (443, 8443) else "http"
    res = await _try(client, scheme, ip, port)
    if res is not None:
        return res
    if port not in (80, 443):
        other = "http" if scheme == "https" else "https"
        return await _try(client, other, ip, port)
    return None


async def _try(
    client: httpx.AsyncClient, scheme: str, ip: str, port: int
) -> Optional[WebResult]:
    url = f"{scheme}://{ip}:{port}/"
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT})
    except (httpx.HTTPError, OSError):
        return None

    headers: Dict[str, str] = {k.lower(): v for k, v in resp.headers.items()}
    body = ""
    try:
        body = resp.content[:_MAX_BODY].decode(
            resp.encoding or "utf-8", errors="replace"
        )
    except (UnicodeDecodeError, LookupError, httpx.HTTPError):
        body = ""

    findings, php_version, cms, server = vuln_rules.evaluate(
        scheme=scheme, headers=headers, body=body
    )
    return WebResult(
        port=port,
        scheme=scheme,
        status_code=resp.status_code,
        server=server,
        powered_by=headers.get("x-powered-by"),
        php_version=php_version,
        cms=cms,
        findings=findings,
        headers=headers,
        fingerprint=response_fingerprint(resp.status_code, headers),
    )


def build_client(http_timeout: float, connect_timeout: float) -> httpx.AsyncClient:
    timeout = httpx.Timeout(http_timeout, connect=connect_timeout)
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=20)
    return httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        max_redirects=3,
        timeout=timeout,
        limits=limits,
        trust_env=False,
    )
