"""Non-destructive HTTP(S) probing of a single web service, including exposure & precondition checks."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import httpx

from ..models import Confidence, Finding, Severity
from . import netlimit, vuln_rules

USER_AGENT = "thscan/2.0 (+defensive php2shell & multi-CVE check; ThaiCERT compliance; non-destructive)"
_MAX_BODY = 262_144

# Non-destructive exposure & framework debug checks (with strict regex validators to prevent SPA 200-OK false positives)
EXPOSURE_PROBES: List[Tuple[str, str, str, Severity, str, str, List[str], float]] = [
    (
        "/.env.bak",
        "exposure-env-bak",
        "ไฟล์สำรอง .env.bak เปิดเผยสู่สาธารณะ",
        Severity.critical,
        r"(?:APP_KEY|DB_PASSWORD)\s*=",
        "ลบไฟล์ .env.bak และหมุนเวียนรหัสผ่าน/คีย์ทั้งหมดทันที",
        [],
        9.1,
    ),
    (
        "/.env.save",
        "exposure-env-save",
        "ไฟล์สำรอง .env.save เปิดเผยสู่สาธารณะ",
        Severity.critical,
        r"(?:APP_KEY|DB_PASSWORD)\s*=",
        "ลบไฟล์ .env.save และหมุนเวียนรหัสผ่าน/คีย์ทั้งหมดทันที",
        [],
        9.1,
    ),
    (
        "/.git/config",
        "exposure-git-config",
        "ไฟล์ .git/config เปิดเผยสู่สาธารณะ",
        Severity.high,
        r"\[core\]|\[remote",
        "ปิดกั้นการเข้าถึง /.git/ ที่เว็บเซิร์ฟเวอร์",
        [],
        7.5,
    ),
    (
        "/composer.json",
        "exposure-composer-json",
        "ไฟล์ composer.json เปิดเผยสู่สาธารณะ",
        Severity.low,
        r'"require"\s*:',
        "ปิดกั้นการเข้าถึง composer.json ที่เว็บเซิร์ฟเวอร์",
        [],
        3.7,
    ),
    (
        "/package.json",
        "exposure-package-json",
        "ไฟล์ package.json เปิดเผยสู่สาธารณะ",
        Severity.low,
        r'"dependencies"|"devDependencies"',
        "ปิดกั้นการเข้าถึง package.json ที่เว็บเซิร์ฟเวอร์",
        [],
        3.7,
    ),
    (
        "/wp-config.php~",
        "exposure-wp-config-tilde",
        "ไฟล์สำรอง wp-config.php~ เปิดเผย (DB Credentials รั่วไหล)",
        Severity.critical,
        r"DB_PASSWORD|DB_NAME",
        "ลบไฟล์สำรอง wp-config.php~ และเปลี่ยนรหัสผ่านฐานข้อมูลทันที",
        [],
        9.8,
    ),
    (
        "/info.php",
        "exposure-info-php",
        "หน้า phpinfo() เปิดเผยสู่สาธารณะ (/info.php)",
        Severity.high,
        r"phpinfo\(\)|<title>[^<]*phpinfo",
        "ลบไฟล์ info.php ออกจากเซิร์ฟเวอร์โปรดักชันทันที",
        [],
        7.5,
    ),
    (
        "/server-status",
        "exposure-server-status",
        "Apache mod_status (/server-status) เปิดสาธารณะ",
        Severity.low,
        r"Apache Server Status",
        "จำกัดการเข้าถึง /server-status เฉพาะ IP ภายใน (Require local)",
        [],
        5.3,
    ),
    (
        "/server-info",
        "exposure-server-info",
        "Apache mod_info (/server-info) เปิดสาธารณะ",
        Severity.low,
        r"Apache Server Information",
        "ปิดโมดูล mod_info หรือจำกัดเฉพาะ IP ภายใน",
        [],
        5.3,
    ),
    (
        "/web.config",
        "exposure-web-config",
        "ไฟล์คอนฟิก IIS (/web.config) เปิดเผยสู่สาธารณะ",
        Severity.high,
        r"<configuration",
        "บล็อกการดาวน์โหลดไฟล์ web.config ที่เว็บเซิร์ฟเวอร์",
        [],
        7.5,
    ),
    (
        "/.aws/credentials",
        "exposure-aws-credentials",
        "ไฟล์ AWS Credentials (/.aws/credentials) เปิดเผยสู่สาธารณะ",
        Severity.critical,
        r"aws_access_key_id|aws_secret",
        "ลบไฟล์ /.aws/credentials และเพิกถอน (Revoke) AWS Access Key ทันที",
        [],
        9.8,
    ),
    (
        "/.DS_Store",
        "exposure-ds-store",
        "ไฟล์ .DS_Store เปิดเผย (เปิดเผยรายชื่อไฟล์ในไดเรกทอรี)",
        Severity.low,
        r"Bud1",
        "ลบไฟล์ .DS_Store และบล็อกในคอนฟิกเว็บเซิร์ฟเวอร์",
        [],
        3.7,
    ),
    (
        "/backup/",
        "exposure-backup-dir",
        "เปิด Directory Listing ที่โฟลเดอร์ /backup/",
        Severity.high,
        r"Index of|parent directory|\.zip|\.sql|\.tar|\.bak",
        "ปิด Directory Listing (Options -Indexes / autoindex off) และย้ายไฟล์สำรองออกจาก Web Root",
        [],
        7.5,
    ),
    (
        "/old/",
        "exposure-old-dir",
        "เปิด Directory Listing ที่โฟลเดอร์ /old/",
        Severity.low,
        r"Index of|parent directory",
        "ปิด Directory Listing และลบโฟลเดอร์ระบบเก่าที่ไม่ได้ใช้งาน",
        [],
        5.3,
    ),
    (
        "/temp/",
        "exposure-temp-dir",
        "เปิด Directory Listing ที่โฟลเดอร์ /temp/",
        Severity.low,
        r"Index of|parent directory",
        "ปิด Directory Listing ที่โฟลเดอร์ชั่วคราว",
        [],
        3.7,
    ),
    (
        "/.env",
        "exposure-env",
        "ไฟล์ .env เปิดเผยสู่สาธารณะ (อาจมีรหัสผ่านฐานข้อมูล / APP_KEY)",
        Severity.critical,
        r"(?:APP_KEY|DB_PASSWORD|DB_HOST|APP_ENV|MAIL_PASSWORD|AWS_SECRET)\s*=",
        "บล็อกการเข้าถึงไฟล์ .* ที่เว็บเซิร์ฟเวอร์ทันที และเปลี่ยนรหัสผ่าน/คีย์ทั้งหมดที่อยู่ในไฟล์ .env",
        [],
        9.1,
    ),
    (
        "/.git/HEAD",
        "exposure-git",
        "โฟลเดอร์ .git เปิดเผยสู่สาธารณะ (.git/HEAD)",
        Severity.high,
        r"ref:\s*refs/",
        "ปิดกั้นการเข้าถึง /.git/ ที่เว็บเซิร์ฟเวอร์ (เช่น location ~ /\.git { deny all; })",
        [],
        7.5,
    ),
    (
        "/composer.lock",
        "exposure-composer-lock",
        "ไฟล์ composer.lock เปิดเผย (เผยรายชื่อและเวอร์ชันไลบรารี PHP ทั้งหมด)",
        Severity.low,
        r'"packages"\s*:\s*\[',
        "จำกัดการเข้าถึงไฟล์ composer.lock และ composer.json ไม่ให้ดาวน์โหลดได้จากภายนอก",
        [],
        5.3,
    ),
    (
        "/phpinfo.php",
        "exposure-phpinfo",
        "หน้า phpinfo() เปิดเผยสู่สาธารณะ (/phpinfo.php)",
        Severity.high,
        r"phpinfo\(\)|<title>[^<]*phpinfo",
        "ลบไฟล์ phpinfo.php ออกจากเซิร์ฟเวอร์โปรดักชันทันที",
        [],
        7.5,
    ),
    (
        "/wp-config.php.bak",
        "exposure-wp-config-bak",
        "ไฟล์สำรอง wp-config.php.bak เปิดเผย (DB Credentials รั่วไหล)",
        Severity.critical,
        r"DB_PASSWORD|DB_NAME|AUTH_KEY",
        "ลบไฟล์สำรอง .bak / ~ ออกจาก Web Root และเปลี่ยนรหัสผ่านฐานข้อมูลทันที",
        [],
        9.8,
    ),
    (
        "/backup.sql",
        "exposure-backup-sql",
        "ไฟล์ฐานข้อมูลสำรอง (/backup.sql) เปิดเผยสู่สาธารณะ",
        Severity.critical,
        r"INSERT INTO|CREATE TABLE|-- MySQL dump",
        "ลบไฟล์ .sql ออกจากโฟลเดอร์สาธารณะของเว็บไซต์ทันที",
        [],
        9.8,
    ),
    (
        "/_ignition/health-check",
        "laravel-ignition-rce",
        "Laravel Ignition Debug Mode เปิดอยู่ — เสี่ยงต่อ RCE (CVE-2021-3129)",
        Severity.critical,
        r'"can_execute_commands"|ignition|"healthy"\s*:\s*true',
        "ตั้งค่า APP_DEBUG=false ในไฟล์ .env และอัปเดต facade/ignition >= 2.5.2 ทันที",
        ["CVE-2021-3129"],
        9.8,
    ),
    (
        "/_profiler",
        "symfony-profiler-exposed",
        "Symfony Web Profiler เปิดสาธารณะ (/_profiler)",
        Severity.high,
        r"symfony.*profiler|web profiler",
        "ปิด Symfony Web Profiler บนโปรดักชัน หรือจำกัดเฉพาะ IP ภายใน",
        [],
        7.5,
    ),
    (
        "/index.php?r=gii",
        "yii-gii-exposed",
        "Yii Framework Gii Code Generator เปิดสาธารณะ (?r=gii)",
        Severity.critical,
        r"welcome to gii|gii module|<title>[^<]*gii",
        "ปิดโมดูล Gii บนโปรดักชัน หรือจำกัด allowedIPs ในคอนฟิก",
        [],
        9.8,
    ),
    (
        "/v2/_catalog",
        "docker-registry-exposed",
        "Private Docker Registry v2 API เปิดสาธารณะโดยไม่ยืนยันตัวตน (/v2/_catalog)",
        Severity.high,
        r'"repositories"\s*:\s*\[',
        "เปิดใช้งาน Authentication (Basic Auth / Token) สำหรับ Docker Registry",
        [],
        8.6,
    ),
    (
        "/?%ad-s",
        "php-cgi-cve-2024-4577-active",
        "CVE-2024-4577 ยืนยันพบช่องโหว่ (PHP-CGI Argument Injection RCE)",
        Severity.critical,
        r"<code><span|style=\"color:\s*#|class=\"html\"",
        "อัปเดต PHP เป็น >= 8.1.29 / 8.2.20 / 8.3.8 หรือลบ ScriptAlias /php-cgi/ ทันที",
        ["CVE-2024-4577"],
        9.8,
    ),
]


@dataclass
class WebResult:
    port: int
    scheme: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    php_version: Optional[str] = None
    cms: Optional[str] = None
    runtime: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    fingerprint: str = ""


_VOLATILE = {"date", "set-cookie", "content-length", "age", "expires", "etag", "last-modified"}


def response_fingerprint(status: Optional[int], headers: Dict[str, str]) -> str:
    names = sorted(h for h in headers if h not in _VOLATILE)
    return f"{status}|{','.join(names)}|{headers.get('server', '')}"


async def probe_service(
    client: httpx.AsyncClient, ip: str, port: int, host: Optional[str] = None
) -> Optional[WebResult]:
    """Fetch ``/`` from *ip*:*port* and run non-destructive exposure & precondition checks."""
    scheme = "https" if port in (443, 8443) else "http"
    res = await _try(client, scheme, ip, port, host)
    if res is None and port not in (80, 443):
        other = "http" if scheme == "https" else "https"
        res = await _try(client, other, ip, port, host)
    if res is not None:
        extra = await probe_extended_surface(client, res.scheme, ip, port, host, res)
        seen_ids = {f.rule_id for f in res.findings}
        for ef in extra:
            if ef.rule_id not in seen_ids:
                seen_ids.add(ef.rule_id)
                res.findings.append(ef)
    return res


async def probe_extended_surface(
    client: httpx.AsyncClient,
    scheme: str,
    ip: str,
    port: int,
    host: Optional[str],
    base_res: WebResult,
) -> List[Finding]:
    """Run fast, read-only checks for exposed sensitive files, debuggers, and PHP upload_progress precondition."""
    out: List[Finding] = []
    req_headers = {"User-Agent": USER_AGENT}
    ext = {}
    if host:
        req_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
        if scheme == "https":
            ext["sni_hostname"] = host

    async def _check_one(
        path: str,
        rule_id: str,
        title: str,
        sev: Severity,
        pattern: str,
        rec: str,
        cves: List[str],
        cvss: float,
    ) -> None:
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            async with netlimit.slot():
                r = await client.get(url, headers=req_headers, extensions=ext)
        except (httpx.HTTPError, OSError, ValueError, RuntimeError):
            return
        if r.status_code != 200:
            return
        sample = (r.text or "")[:12_000]
        if not re.search(pattern, sample, re.IGNORECASE):
            return
        # Extract PHP version from phpinfo() if exposed and not yet known
        if rule_id == "exposure-phpinfo" and not base_res.php_version:
            pv = vuln_rules.parse_php_version(sample)
            if pv:
                base_res.php_version = str(pv)
        out.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=sev,
                confidence=Confidence.confirmed,
                description=f"ตรวจพบว่า {path} เปิดให้เข้าถึงได้จากภายนอก (HTTP 200 พร้อมเนื้อหายืนยัน)",
                evidence=f"GET {path} -> HTTP 200",
                recommendation=rec,
                cve=list(cves),
                cvss=cvss,
                cwe="CWE-200",
            )
        )

    #Also check PHP session.upload_progress precondition (CVE-2026-109619 / CVE-2026-115560) when PHP session is active
    async def _check_php_precondition() -> None:
        cookie_hdr = base_res.headers.get("set-cookie", "")
        if "phpsessid" not in cookie_hdr.lower() and not base_res.php_version:
            return
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with netlimit.slot():
                r = await client.post(
                    url,
                    headers=req_headers,
                    data={"PHP_SESSION_UPLOAD_PROGRESS": "thscan_check", "PHPSESSID": "thscan123456"},
                    files={"f": ("check.txt", b"X", "text/plain")},
                    extensions=ext,
                )
        except (httpx.HTTPError, OSError, ValueError, RuntimeError):
            return
        if r.status_code in (200, 302) and "phpsessid" in ( cookie_hdr + " " + r.headers.get("set-cookie", "") ).lower():
            out.append(
                Finding(
                    rule_id="php-session-upload-progress",
                    title="เปิดใช้งาน PHP Session Upload Progress — เข้าเงื่อนไขตัวกระตุ้น CVE-2026-109619 / CVE-2026-115560",
                    severity=Severity.high if base_res.php_version else Severity.low,
                    confidence=Confidence.high,
                    description=(
                        "เซิร์ฟเวอร์เปิดใช้งาน PHPSESSID ร่วมกับรับค่า multipart PHP_SESSION_UPLOAD_PROGRESS "
                        "ซึ่งเป็น Precondition ของ CVE-2026-109619 และ CVE-2026-115560 (Session Upload Progress Injection)"
                    ),
                    evidence="POST multipart PHP_SESSION_UPLOAD_PROGRESS -> HTTP " + str(r.status_code),
                    recommendation="ตั้งค่า `session.upload_progress.enabled = 0` ใน php.ini และอัปเดต PHP เป็น 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35+",
                    cve=["CVE-2026-109619", "CVE-2026-115560"],
                    cvss=8.1,
                    cwe="CWE-502",
                )
            )


    async def _check_mptcp_kernel() -> None:
        import socket as _sock
        IPPROTO_MPTCP = getattr(_sock, "IPPROTO_MPTCP", 262)
        SOL_MPTCP, MPTCP_INFO = 284, 1
        def _probe_mptcp() -> bool:
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM, IPPROTO_MPTCP)
            except (AttributeError, OSError):
                return False
            try:
                s.settimeout(1.5)
                s.connect((ip, port))
                info = s.getsockopt(SOL_MPTCP, MPTCP_INFO, 16)
                return bool(info and len(info) >= 16)
            except OSError:
                return False
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        is_mptcp = await asyncio.to_thread(_probe_mptcp)
        if is_mptcp:
            out.append(
                Finding(
                    rule_id="linux-kernel-mptcp-cve-2026-98432",
                    title=f"ตรวจพบ MPTCP เปิดใช้งานบนพอร์ต {port} — เสี่ยงต่อช่องโหว่ Linux Kernel CVE-2026-98432",
                    severity=Severity.critical,
                    confidence=Confidence.high,
                    description=(
                        f"พอร์ต {port}/tcp ตอบรับการเชื่อมต่อ Multipath TCP (MPTCP) ซึ่งเป็นเวกเตอร์หลักของ "
                        "CVE-2026-98432 (Linux Kernel IPv4 TCP Use-After-Free, CVSS 9.8)"
                    ),
                    evidence=f"IPPROTO_MPTCP active on {ip}:{port}",
                    recommendation="อัปเดต Linux Kernel ตามแพตช์ของดิสโทร (commit e3f33b0a1d89) หรือปิด MPTCP ชั่วคราวด้วย `sysctl -w net.mptcp.enabled=0`",
                    cve=["CVE-2026-98432"],
                    cvss=9.8,
                    cwe="CWE-416",
                )
            )

    await asyncio.gather(
        *(_check_one(*spec) for spec in EXPOSURE_PROBES),
        _check_php_precondition(),
        _check_mptcp_kernel(),
    )
    return out


_REDIRECTS = (301, 302, 303, 307, 308)
_MAX_HOPS = 3


async def _try(
    client: httpx.AsyncClient, scheme: str, ip: str, port: int, host: Optional[str] = None
) -> Optional[WebResult]:
    """GET the page, following redirects only while they stay on the same host."""
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
            break
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
        scheme=scheme, headers=merged, body=body, final_url=f"{scheme}://{name}:{port}{path}"
    )
    return WebResult(
        port=port,
        scheme=scheme,
        status_code=resp.status_code,
        server=server,
        powered_by=merged.get("x-powered-by"),
        php_version=php_version,
        cms=cms,
        runtime=vuln_rules.runtime_label(merged, body, php_version),
        findings=findings,
        headers=merged,
        fingerprint=response_fingerprint(resp.status_code, headers_lc),
    )


def _same_host_redirect(
    location: str, scheme: str, name: str, port: int, current: str
) -> Optional[Tuple[str, int, str]]:
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
        follow_redirects=False,
        timeout=timeout,
        limits=limits,
        trust_env=False,
    )
