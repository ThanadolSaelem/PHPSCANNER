"""Non-destructive HTTP(S) probing of a single web service.

We issue one GET to the site root with a clearly identifying User-Agent and
read a bounded slice of the body. No fuzzing, no path brute-forcing, no
authentication attempts, no payloads — just what a browser's first request
would reveal.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

import httpx

from ..models import ServiceResult
from . import vuln_rules

USER_AGENT = (
    "thscan/1.0 (+defensive vulnerability scanner; PHP2Shell check; "
    "non-destructive; contact your CERT)"
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MAX_BODY = 262_144  # 256 KiB is plenty for fingerprinting


def _title(body: str) -> Optional[str]:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


async def probe_service(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
    hostname: Optional[str],
) -> Optional[ServiceResult]:
    """Probe http and https on *port*; return a result if either answers.

    We always connect to the IP we discovered (never a fresh forward lookup)
    and present the discovered hostname in the ``Host`` header so name-based
    virtual hosts route correctly.
    """
    scheme = "https" if port in (443, 8443) else "http"
    result = await _try(client, scheme, ip, port, hostname)
    if result is not None:
        return result
    # Fall back to the other scheme on non-standard ports.
    if port not in (80, 443):
        other = "http" if scheme == "https" else "https"
        return await _try(client, other, ip, port, hostname)
    return None


async def _try(
    client: httpx.AsyncClient,
    scheme: str,
    ip: str,
    port: int,
    hostname: Optional[str],
) -> Optional[ServiceResult]:
    url = f"{scheme}://{ip}:{port}/"
    headers = {"User-Agent": USER_AGENT}
    # Route virtual hosts by sending the discovered name as Host, while the
    # connection still goes to the known IP above.
    if hostname:
        headers["Host"] = hostname
    try:
        resp = await client.get(url, headers=headers)
    except (httpx.HTTPError, OSError):
        return None

    headers: Dict[str, str] = {k.lower(): v for k, v in resp.headers.items()}
    body = ""
    try:
        raw = resp.content[:_MAX_BODY]
        body = raw.decode(resp.encoding or "utf-8", errors="replace")
    except (UnicodeDecodeError, LookupError, httpx.HTTPError):
        body = ""

    findings, php_version, cms, server = vuln_rules.evaluate(
        scheme=scheme,
        status_code=resp.status_code,
        headers=headers,
        body=body,
    )

    # Human-readable URL uses the hostname; the connection above used the IP.
    authority = hostname or ip
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    display_url = f"{scheme}://{authority}/" if default_port else f"{scheme}://{authority}:{port}/"

    return ServiceResult(
        port=port,
        scheme=scheme,
        url=display_url,
        status_code=resp.status_code,
        server=server,
        powered_by=headers.get("x-powered-by"),
        php_version=php_version,
        cms=cms,
        title=_title(body),
        findings=findings,
    )


def build_client(http_timeout: float, connect_timeout: float) -> httpx.AsyncClient:
    timeout = httpx.Timeout(http_timeout, connect=connect_timeout)
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=20)
    return httpx.AsyncClient(
        verify=False,          # self-signed certs are common on gov appliances
        follow_redirects=True,
        max_redirects=3,
        timeout=timeout,
        limits=limits,
        trust_env=False,
    )
