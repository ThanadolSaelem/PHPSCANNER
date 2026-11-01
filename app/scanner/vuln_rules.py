"""Vulnerability rules — version-based & precondition-aware, non-destructive, low false positive.

Covers:
- PHP 2026 CVEs: CVE-2026-109618 (OOM UAF), CVE-2026-109619 (Stale Global State UAF), CVE-2026-115560 (Session Upload Progress Injection)
- Historical PHP CVEs: CVE-2024-4577 (PHP-CGI RCE), CVE-2022-31626 (pdo_mysql RCE), CVE-2019-11043 (PHP-FPM RCE), CVE-2016-5385 (httpoxy) + PHP_EOL
- NGINX 2026 CVEs: CVE-2026-15176 (alias+rewrite), CVE-2026-93479 (map+regex), CVE-2026-97205 (AIO+SSI), CVE-2026-95101 (HTTP/3 QUIC), CVE-2026-97629 (TLS Tickets)
- Historical NGINX CVEs: CVE-2021-23017 (DNS resolver), CVE-2022-41742 (mp4 module) + NGINX_EOL
- Node.js / Next.js 2026 & Historical CVEs: CVE-2026-111497 (Brotli RCE), CVE-2026-105482 (DNS NUL), CVE-2026-105483 (TLS Unicode IP), CVE-2026-106069 (TLS Identity), CVE-2021-22930, CVE-2023-30581
- GitLab CVE: CVE-2026-110264 + Unauthenticated GraphQL / Public API surface
- Framework Debug & Exposure Rules: CVE-2021-3129 (Laravel Ignition), Symfony Profiler/Debug, Yii Gii, Docker API (2375) / Registry, .env, .git, composer.lock, phpinfo
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urlsplit

from ..models import Confidence, Finding, Severity

_PHP_RE = re.compile(r"php/?\s*v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_NGINX_RE = re.compile(r"(?:nginx|openresty)/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_NODE_VER_RE = re.compile(
    r'(?:node(?:\.js)?[ /v]+v?|"node(?:Version|_version)?"\s*:\s*"v?)(\d+)\.(\d+)\.(\d+)',
    re.IGNORECASE,
)
_GITLAB_VER_RE = re.compile(
    r'(?:GitLab (?:Community|Enterprise) Edition[^0-9]{0,40}|"version"\s*:\s*"v?|gon\.version\s*=\s*[\'"]v?)(\d+)\.(\d+)\.(\d+)',
    re.IGNORECASE,
)


class PhpVersion(NamedTuple):
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def parse_php_version(*sources: Optional[str]) -> Optional[PhpVersion]:
    for src in sources:
        if not src:
            continue
        m = _PHP_RE.search(src)
        if m:
            return PhpVersion(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def parse_nginx_version(*sources: Optional[str]) -> Optional[Tuple[int, int, int]]:
    for src in sources:
        if not src:
            continue
        m = _NGINX_RE.search(src)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def parse_node_version(*sources: Optional[str]) -> Optional[Tuple[int, int, int]]:
    for src in sources:
        if not src:
            continue
        m = _NODE_VER_RE.search(src)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def php_present(*sources: Optional[str]) -> bool:
    return any(src and "php" in src.lower() for src in sources)


_PHP_COOKIE_RE = re.compile(r"(?:^|[;,\s])PHPSESSID=", re.IGNORECASE)
_PHP_URL_RE = re.compile(r"\.php(?:[/?#]|$)", re.IGNORECASE)
_PHP_REF_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*['"](?!https?:|//)[^'"]*\.php(?:[?#][^'"]*)?['"]""",
    re.IGNORECASE,
)
_PHP_ERROR_RES = (
    re.compile(r"</b> on line <b>\d+</b>", re.IGNORECASE),
    re.compile(r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)\s*:[^<]{0,80}in\s+<b>[^<]+</b>", re.IGNORECASE),
    re.compile(r"Call to undefined function", re.IGNORECASE),
    re.compile(r"<title>phpinfo\(\)</title>", re.IGNORECASE),
)

_ERROR_SCAN = 200_000


def urlsplit_path(url: str) -> str:
    try:
        parts = urlsplit(url)
        return parts.path + ("?" + parts.query if parts.query else "")
    except ValueError:
        return url


def php_signals(
    headers: Dict[str, str], body: str, final_url: str = ""
) -> tuple[bool, str]:
    hits: List[str] = []
    cookie = headers.get("set-cookie", "")
    if _PHP_COOKIE_RE.search(cookie):
        hits.append("คุกกี้ PHPSESSID")
    if final_url and _PHP_URL_RE.search(urlsplit_path(final_url)):
        hits.append("หน้าเว็บลงท้ายด้วย .php")
    sample = body[:_ERROR_SCAN]
    if _PHP_REF_RE.search(sample):
        hits.append("ลิงก์ภายในชี้ไปไฟล์ .php")
    if any(r.search(sample) for r in _PHP_ERROR_RES):
        hits.append("ข้อความ error ของ PHP")
    xgen = headers.get("x-generator", "")
    if "php" in xgen.lower():
        hits.append("X-Generator ระบุ PHP")
    return (bool(hits), " · ".join(hits))


PHP2SHELL_FIXED: Dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
PHP2SHELL_OLDEST_FIXED_BRANCH = (8, 2)
PHP2SHELL_CVES = ["CVE-2026-109618", "CVE-2026-109619"]

PHP_EOL: Dict[tuple[int, int], str] = {
    (8, 1): "2025-12-31", (8, 0): "2023-11-26",
    (7, 4): "2022-11-28", (7, 3): "2021-12-06", (7, 2): "2020-11-30",
    (7, 1): "2019-12-01", (7, 0): "2019-01-10",
    (5, 6): "2018-12-31", (5, 5): "2016-07-21", (5, 4): "2015-09-14", (5, 3): "2014-08-14",
}

HISTORICAL_PHP_CVES = [
    {
        "cve": "CVE-2024-4577",
        "title": "PHP-CGI Argument Injection RCE (CVE-2024-4577)",
        "severity": Severity.critical,
        "cvss": 9.8,
        "ranges": [((8, 1, 0), (8, 1, 29)), ((8, 2, 0), (8, 2, 20)), ((8, 3, 0), (8, 3, 8))],
        "fixed": "8.1.29 / 8.2.20 / 8.3.8",
        "desc": "ช่องโหว่ Argument Injection ใน PHP-CGI (CVSS 9.8) อาจทำให้ผู้โจมตีสั่งรันโค้ดจากระยะไกล (RCE)",
        "rec": "อัปเดต PHP เป็น 8.1.29 / 8.2.20 / 8.3.8 ขึ้นไป และปิด ScriptAlias php-cgi หากไม่ใช้งาน",
    },
    {
        "cve": "CVE-2022-31626",
        "title": "PHP pdo_mysql Password Buffer Overflow RCE (CVE-2022-31626)",
        "severity": Severity.critical,
        "cvss": 9.8,
        "ranges": [((7, 4, 0), (7, 4, 30)), ((8, 0, 0), (8, 0, 20)), ((8, 1, 0), (8, 1, 7))],
        "fixed": "7.4.30 / 8.0.20 / 8.1.7",
        "desc": "ช่องโหว่ Buffer Overflow ในส่วนขยาย pdo_mysql ของ PHP (CVSS 9.8)",
        "rec": "อัปเดต PHP เป็น 7.4.30 / 8.0.20 / 8.1.7 หรือย้ายไป PHP 8.3/8.4 LTS",
    },
    {
        "cve": "CVE-2019-11043",
        "title": "PHP-FPM env_path_info Underflow RCE (CVE-2019-11043)",
        "severity": Severity.critical,
        "cvss": 9.8,
        "ranges": [((7, 1, 0), (7, 1, 33)), ((7, 2, 0), (7, 2, 24)), ((7, 3, 0), (7, 3, 11))],
        "fixed": "7.1.33 / 7.2.24 / 7.3.11",
        "desc": "ช่องโหว่ Buffer Underflow ใน PHP-FPM เมื่อใช้งานคู่กับ nginx fastcgi_split_path_info (CVSS 9.8)",
        "rec": "อัปเกรด PHP ไปยังสาขาที่ยังรองรับ (PHP 8.3/8.4) และตรวจสอบคอนฟิก fastcgi_split_path_info",
    },
    {
        "cve": "CVE-2016-5385",
        "title": "PHP httpoxy HTTP_PROXY Injection (CVE-2016-5385)",
        "severity": Severity.high,
        "cvss": 8.1,
        "ranges": [((5, 5, 0), (5, 5, 38)), ((5, 6, 0), (5, 6, 24)), ((7, 0, 0), (7, 0, 9))],
        "fixed": "5.5.38 / 5.6.24 / 7.0.9",
        "desc": "ช่องโหว่การสวมรอยตัวแปรสภาพแวดล้อม HTTP_PROXY ใน PHP รุ่นเก่า (CVSS 8.1)",
        "rec": "ย้ายระบบขึ้นเป็น PHP 8.3/8.4 และกรอง Header Proxy ที่เว็บเซิร์ฟเวอร์",
    },
]

NGINX_VULN_2026 = [
    {
        "cve": "CVE-2026-15176",
        "title": "NGINX Heap Buffer Overflow — alias + rewrite (CVE-2026-15176)",
        "severity": Severity.critical,
        "cvss": 9.8,
        "ranges": [((0, 1, 29), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
        "desc": "NGINX อยู่ในช่วงกระทบของ CVE-2026-15176 (Heap Buffer Overflow เมื่อใช้ alias ร่วมกับ rewrite)",
        "rec": "อัปเดต NGINX เป็น 1.30.6+ (stable) หรือ 1.31.7+ (mainline) และตรวจคอนฟิกด้วย `nginx -T | grep -B5 -A15 alias`",
    },
    {
        "cve": "CVE-2026-93479",
        "title": "NGINX Heap Buffer Overflow — map + regex (CVE-2026-93479)",
        "severity": Severity.critical,
        "cvss": 9.8,
        "ranges": [((1, 30, 0), (1, 30, 5)), ((1, 31, 2), (1, 31, 6))],
        "desc": "NGINX อยู่ในช่วงกระทบของ CVE-2026-93479 (Heap Buffer Overflow เมื่อใช้ map regex ร่วมกับ capture variables)",
        "rec": "อัปเดต NGINX เป็น 1.30.6+ หรือ 1.31.7+ และตรวจคอนฟิกด้วย `nginx -T | grep -B3 -A10 'map.*~'`",
    },
    {
        "cve": "CVE-2026-97205",
        "title": "NGINX Use-After-Free — AIO + SSI (CVE-2026-97205)",
        "severity": Severity.critical,
        "cvss": 9.8,
        "ranges": [((0, 8, 11), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
        "desc": "NGINX อยู่ในช่วงกระทบของ CVE-2026-97205 (Use-After-Free เมื่อเปิด aio on ร่วมกับ ssi on)",
        "rec": "อัปเดต NGINX เป็น 1.30.6+ หรือ 1.31.7+ และตรวจ `nginx -T | grep -E 'aio\s+on|ssi\s+on'`",
    },
    {
        "cve": "CVE-2026-95101",
        "title": "NGINX HTTP/3 QUIC Request Body Injection (CVE-2026-95101)",
        "severity": Severity.low,
        "cvss": 6.5,
        "ranges": [((1, 25, 0), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
        "desc": "NGINX อยู่ในช่วงกระทบของ CVE-2026-95101 (Request Body Injection เมื่อเปิดใช้งาน HTTP/3 QUIC)",
        "rec": "อัปเดต NGINX เป็น 1.30.6+ หรือ 1.31.7+ และตรวจ `nginx -T | grep -E 'listen.*quic|http3\s+on'`",
    },
    {
        "cve": "CVE-2026-97629",
        "title": "NGINX TLS Session Ticket Forgery (CVE-2026-97629)",
        "severity": Severity.low,
        "cvss": 6.5,
        "ranges": [((1, 23, 2), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
        "desc": "NGINX อยู่ในช่วงกระทบของ CVE-2026-97629 (TLS Session Ticket Key ไม่ได้เริ่มต้นครบถ้วน)",
        "rec": "อัปเดต NGINX เป็น 1.30.6+ หรือ 1.31.7+ หรือตั้ง `ssl_session_tickets off;` ในคอนฟิก HTTPS",
    },
]

HISTORICAL_NGINX_CVES = [
    {
        "cve": "CVE-2021-23017",
        "title": "NGINX DNS Resolver Off-by-One RCE (CVE-2021-23017)",
        "severity": Severity.high,
        "cvss": 8.1,
        "lo": (0, 6, 18),
        "fixed": (1, 20, 1),
        "desc": "NGINX รุ่นต่ำกว่า 1.20.1 มีช่องโหว่ Off-by-One ใน DNS resolver (CVSS 8.1)",
        "rec": "อัปเกรด NGINX เป็นรุ่นล่าสุด (1.30.6+ / 1.31.7+)",
    },
    {
        "cve": "CVE-2022-41742",
        "title": "NGINX ngx_http_mp4_module Memory Corruption (CVE-2022-41742)",
        "severity": Severity.high,
        "cvss": 7.0,
        "lo": (1, 1, 3),
        "fixed": (1, 22, 1),
        "desc": "NGINX รุ่นต่ำกว่า 1.22.1 มีช่องโหว่ในโมดูล mp4 (CVSS 7.0)",
        "rec": "อัปเกรด NGINX เป็นรุ่นล่าสุด (1.30.6+ / 1.31.7+)",
    },
]

NODEJS_PATCHED = {
    18: (18, 20, 8),
    20: (20, 19, 2),
    22: (22, 15, 1),
    23: (23, 11, 1),
    24: (24, 1, 0),
}

NODEJS_SIGNS = (
    "express", "next.js", "nextjs", "nuxt", "fastify", "koa",
    "node.js", "nodejs", "undici", "sveltekit", "remix", "hapi",
    "nestjs", "adonis", "sails", "meteor", "astro",
)



DEVICE_SIGS = [
    ("Synology DSM", [r"\bsynology\b", r"x-syno", r"/webman/", r"synohdpack"], "NAS"),
    ("QNAP QTS", [r"\bqnap\b", r"/cgi-bin/filemanager", r"\bQTS\b"], "NAS"),
    ("TrueNAS/FreeNAS", [r"truenas", r"freenas"], "NAS"),
    ("pfSense", [r"pfsense"], "Firewall"),
    ("OPNsense", [r"opnsense"], "Firewall"),
    ("Fortinet FortiGate", [r"fortigate", r"fortios", r"x-forti"], "Firewall"),
    ("MikroTik RouterOS", [r"mikrotik", r"routeros"], "Network"),
    ("Ubiquiti UniFi", [r"\bunifi\b", r"ubiquiti"], "Network"),
    ("cPanel", [r"\bcpanel\b", r"x-cpanel"], "Control Panel"),
    ("Plesk", [r"\bplesk\b"], "Control Panel"),
    ("DirectAdmin", [r"directadmin"], "Control Panel"),
    ("Webmin", [r"\bwebmin\b"], "Control Panel"),
    ("HestiaCP", [r"hestia\s*control\s*panel", r"\bhestiacp\b"], "Control Panel"),
    ("CyberPanel", [r"cyberpanel"], "Control Panel"),
    ("aaPanel / BT-Panel", [r"aapanel", r"bt-panel"], "Control Panel"),
    ("Hikvision Camera/NVR", [r"hikvision", r"dnvrs-webs", r"dvrdvs-webs"], "CCTV/Camera"),
    ("Dahua Camera/NVR", [r"\bdahua\b", r"/rpc2_login"], "CCTV/Camera"),
    ("Axis Camera", [r"/axis-cgi/", r"server:\s*axis"], "CCTV/Camera"),
    ("WampServer", [r"\bwampserver\b", r"wamp\s*server"], "Windows Web Stack"),
    ("Laragon", [r"\blaragon\b", r"getting started with laragon"], "Windows Web Stack"),
]

DB_ERROR_SIGS = [
    ("MySQL/MariaDB", [r"you have an error in your sql syntax", r"\bmysqli?_(?:connect|query|fetch)", r"supplied argument is not a valid mysql"]),
    ("PostgreSQL", [r"\bpg_(?:query|connect|exec)\b", r"\bPG::", r"org\.postgresql"]),
    ("MSSQL", [r"system\.data\.sqlclient", r"odbc sql server driver"]),
    ("SQLite", [r"sqlite3?::", r"sqliteexception", r"unable to open database file"]),
    ("Oracle", [r"\bORA-\d{4,5}\b", r"oracle error"]),
    ("MongoDB", [r"mongoerror"]),
]

ADMIN_TOOL_SIGS = [
    ("phpMyAdmin", [r"phpmyadmin", r"pma_"]),
    ("Adminer", [r"\badminer\b"]),
    ("phpPgAdmin", [r"phppgadmin"]),
    ("Jenkins", [r"x-jenkins"]),
    ("Grafana", [r"\bgrafana\b"]),
    ("Kibana", [r"\bkibana\b"]),
]

OS_EOL_PATTERNS = [
    (r"\bcentos\b.*\b[678]\b|\bel[678]\b", "CentOS 6/7/8", Severity.high, 7.5),
    (r"windows.*(server\s*)?(2003|2008|2012)", "Windows Server 2003/2008/2012", Severity.high, 8.1),
    (r"\bubuntu\b.*\b(1[02468]\.04|19\.\d+|21\.\d+|23\.\d+)\b", "Ubuntu รุ่นหมดอายุ (EOL)", Severity.low, 5.3),
    (r"\b(wheezy|jessie|stretch|buster)\b|\bdebian\b.*\b([789]|10)\b", "Debian ≤10 (EOL)", Severity.low, 5.3),
]


class Php2ShellVerdict(NamedTuple):
    vulnerable: bool
    confidence: Confidence
    detail: str


def assess_php2shell(
    version: Optional[PhpVersion], php_seen: bool
) -> Optional[Php2ShellVerdict]:
    if version is None:
        if php_seen:
            return Php2ShellVerdict(
                False,
                Confidence.low,
                "PHP ทำงานอยู่แต่ไม่เปิดเผยเวอร์ชัน (expose_php ปิด) ตรวจยืนยันบนเครื่องอีกครั้ง",
            )
        return None

    branch = (version.major, version.minor)
    fixed = PHP2SHELL_FIXED.get(branch)
    if fixed is not None:
        if version.as_tuple() < fixed:
            return Php2ShellVerdict(
                True,
                Confidence.confirmed,
                f"PHP {version} ต่ำกว่ารุ่นที่แพตช์ {fixed[0]}.{fixed[1]}.{fixed[2]} ของสาขานี้",
            )
        return Php2ShellVerdict(
            False,
            Confidence.confirmed,
            f"PHP {version} เป็นรุ่นที่แพตช์แล้วของสาขานี้",
        )
    if branch < PHP2SHELL_OLDEST_FIXED_BRANCH:
        return Php2ShellVerdict(
            True,
            Confidence.high,
            f"PHP {version} อยู่บนสาขาที่หมดอายุ (End-of-Life) ไม่มีแพตช์ — ควรย้ายไปรุ่นที่รองรับ",
        )
    return Php2ShellVerdict(
        False,
        Confidence.medium,
        f"PHP {version} อยู่บนสาขาใหม่กว่าประกาศ — ตรวจยืนยันว่ามีแพตช์แล้ว",
    )


def detect_cms(body: str, headers: Dict[str, str]) -> Optional[str]:
    text = body[:200_000].lower()
    gen = headers.get("x-generator", "").lower()
    cookie = headers.get("set-cookie", "").lower()
    hdr_keys = {k.lower() for k in headers}
    if "_gitlab_session" in cookie or any(k.startswith("x-gitlab") for k in hdr_keys) or "gitlab" in gen:
        return "GitLab"
    if "wp-content" in text or "wp-includes" in text or 'content="wordpress' in text:
        return "WordPress"
    if 'content="joomla' in text or "/media/jui/" in text or "joomla" in gen:
        return "Joomla"
    if "drupal" in gen or "drupal.settings" in text or 'content="drupal' in text:
        return "Drupal"
    if "laravel_session" in cookie or "xsrf-token" in cookie:
        return "Laravel"
    if "nextcloud" in text or "oc_sessionpassphrase" in cookie:
        return "Nextcloud"
    if "moodle" in text or "moodlesession" in cookie:
        return "Moodle"
    return None


def evaluate(
    *, scheme: str, headers: Dict[str, str], body: str, final_url: str = ""
) -> tuple[List[Finding], Optional[str], Optional[str], Optional[str]]:
    findings: List[Finding] = []
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    version = parse_php_version(server, powered_by, headers.get("x-php-version"))
    sig_present, sig_evidence = php_signals(headers, body, final_url)
    seen = php_present(server, powered_by) or sig_present
    cms = detect_cms(body, headers)
    evidence = "; ".join(
        filter(
            None,
            [
                f"Server: {server}" if server else "",
                f"X-Powered-By: {powered_by}" if powered_by else "",
            ],
        )
    )

    # --- 1. PHP2Shell & Historical PHP CVEs ---
    verdict = assess_php2shell(version, seen)
    if verdict is not None and verdict.vulnerable:
        findings.append(
            Finding(
                rule_id="php2shell",
                title="PHP2Shell — unauthenticated RCE in PHP core",
                severity=Severity.critical,
                confidence=verdict.confidence,
                description="PHP2Shell เป็นช่องโหว่ memory-safety ใน PHP core (CVSS 9.2) "
                "ที่อาจทำให้รันโค้ดจากระยะไกลโดยไม่ต้องยืนยันตัวตน " + verdict.detail,
                evidence=evidence or verdict.detail,
                recommendation="อัปเดต PHP เป็นรุ่นที่แพตช์: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 "
                "หรือใหม่กว่าในสาขาเดียวกัน (สาขา EOL ให้ย้ายไปรุ่นที่รองรับ)",
                cve=list(PHP2SHELL_CVES),
                cvss=9.2,
                cwe="CWE-787",
            )
        )
        if version is not None and (version.major, version.minor) < PHP2SHELL_OLDEST_FIXED_BRANCH:
            eol_date = PHP_EOL.get((version.major, version.minor), "สิ้นสุดการสนับสนุนแล้ว")
            findings.append(
                Finding(
                    rule_id="php-eol",
                    title=f"PHP สาขา {version.major}.{version.minor} หมดอายุการสนับสนุน (End-of-Life: {eol_date})",
                    severity=Severity.high,
                    confidence=Confidence.confirmed,
                    description=f"PHP {version} สิ้นสุดระยะเวลาได้รับแพตช์ความปลอดภัยอย่างเป็นทางการจาก PHP Group แล้ว ({eol_date})",
                    evidence=evidence or f"PHP/{version}",
                    recommendation="วางแผนย้ายระบบขึ้นเป็น PHP 8.3 (LTS) หรือ PHP 8.4 ทันที",
                    cve=["CVE-2026-109618"],
                    cvss=8.1,
                    cwe="CWE-1104",
                )
            )
    elif verdict is not None and verdict.confidence == Confidence.low:
        why = sig_evidence or "ตรวจพบว่า PHP ทำงานอยู่"
        findings.append(
            Finding(
                rule_id="php-undetermined",
                title="พบ PHP แต่ซ่อนเวอร์ชัน — ยืนยันความปลอดภัยจากภายนอกไม่ได้",
                severity=Severity.low,
                confidence=Confidence.low,
                description=(
                    "เครื่องนี้ใช้ PHP (สัญญาณ: " + why + ") แต่ไม่เปิดเผยเวอร์ชัน "
                    "การตรวจจากภายนอกจึง “ไม่สรุปว่าปลอดภัย” — อาจยังติด PHP2Shell ได้ "
                    "ต้องยืนยันเวอร์ชันบนเครื่องจริง ไม่ใช่ถือว่าผ่าน"
                ),
                evidence="; ".join(filter(None, [evidence, sig_evidence])),
                recommendation="ตรวจเวอร์ชันบนเครื่องของทุก PHP-FPM pool / container ด้วย `php -v` "
                "และยืนยันว่าอยู่ที่ 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 ขึ้นไป (รวมแพตช์ backport ของ distro)",
                cve=list(PHP2SHELL_CVES),
                cvss=3.7,
                cwe="CWE-200",
            )
        )

    if version is not None:
        vt = version.as_tuple()
        for hmeta in HISTORICAL_PHP_CVES:
            if any(lo <= vt < hi for lo, hi in hmeta["ranges"]):
                findings.append(
                    Finding(
                        rule_id=f"php-{hmeta['cve'].lower()}",
                        title=hmeta["title"],
                        severity=hmeta["severity"],
                        confidence=Confidence.high,
                        description=f"{hmeta['desc']} (พบ PHP {version} · แก้ไขในรุ่น {hmeta['fixed']})",
                        evidence=evidence or f"PHP/{version}",
                        recommendation=hmeta["rec"],
                        cve=[hmeta["cve"]],
                        cvss=hmeta["cvss"],
                        cwe="CWE-119",
                    )
                )

    # --- 2. NGINX 2026 & Historical CVEs (when explicit nginx/x.y.z version is exposed) ---
    nginx_vt = parse_nginx_version(server)
    if nginx_vt is not None:
        nver_str = f"{nginx_vt[0]}.{nginx_vt[1]}.{nginx_vt[2]}"
        alt_svc = headers.get("alt-svc", "").lower()
        for nmeta in NGINX_VULN_2026:
            if any(lo <= nginx_vt <= hi for lo, hi in nmeta["ranges"]):
                # For HTTP/3 CVE-2026-95101 only flag if Alt-Svc advertises h3/quic; for TLS ticket CVE-2026-97629 only on https
                if nmeta["cve"] == "CVE-2026-95101" and "h3" not in alt_svc and "quic" not in alt_svc:
                    continue
                if nmeta["cve"] == "CVE-2026-97629" and scheme != "https":
                    continue
                findings.append(
                    Finding(
                        rule_id=f"nginx-{nmeta['cve'].lower()}",
                        title=nmeta["title"],
                        severity=nmeta["severity"],
                        confidence=Confidence.medium,
                        description=f"{nmeta['desc']} (พบ NGINX {nver_str})",
                        evidence=f"Server: {server}",
                        recommendation=nmeta["rec"],
                        cve=[nmeta["cve"]],
                        cvss=nmeta["cvss"],
                        cwe="CWE-787",
                    )
                )
        for hng in HISTORICAL_NGINX_CVES:
            if hng["lo"] <= nginx_vt < hng["fixed"]:
                findings.append(
                    Finding(
                        rule_id=f"nginx-{hng['cve'].lower()}",
                        title=hng["title"],
                        severity=hng["severity"],
                        confidence=Confidence.high,
                        description=f"{hng['desc']} (พบ NGINX {nver_str})",
                        evidence=f"Server: {server}",
                        recommendation=hng["rec"],
                        cve=[hng["cve"]],
                        cvss=hng["cvss"],
                        cwe="CWE-193",
                    )
                )

    # --- 3. GitLab CVE-2026-110264 ---
    if cms == "GitLab":
        gl_m = _GITLAB_VER_RE.search(body[:60_000])
        if gl_m:
            gl_vt = (int(gl_m.group(1)), int(gl_m.group(2)), int(gl_m.group(3)))
            gl_str = f"{gl_vt[0]}.{gl_vt[1]}.{gl_vt[2]}"
            if ((16, 0, 0) <= gl_vt < (18, 5, 2)) or ((18, 6, 0) <= gl_vt < (18, 6, 2)) or ((18, 7, 0) <= gl_vt < (18, 7, 1)):
                findings.append(
                    Finding(
                        rule_id="gitlab-cve-2026-110264",
                        title=f"GitLab {gl_str} อยู่ในช่วงกระทบ CVE-2026-110264",
                        severity=Severity.high,
                        confidence=Confidence.confirmed,
                        description=f"ตรวจพบ GitLab {gl_str} ซึ่งต่ำกว่ารุ่นที่แพตช์ (18.5.2 / 18.6.2 / 18.7.1) เสี่ยงต่อ CVE-2026-110264",
                        evidence=f"GitLab {gl_str}",
                        recommendation="อัปเกรด GitLab เป็น 18.5.2 / 18.6.2 / 18.7.1 ขึ้นไปทันที",
                        cve=["CVE-2026-110264"],
                        cvss=8.5,
                        cwe="CWE-287",
                    )
                )

    # --- 4. Server Banner Version Disclosure & HSTS ---
    if server and re.search(r"\d+\.\d+", server):
        srv_l = server.lower()
        if "apache" in srv_l:
            how = "Apache: ตั้ง ServerTokens Prod และ ServerSignature Off"
        elif "nginx" in srv_l:
            how = "Nginx: ตั้ง server_tokens off"
        elif seen:
            how = "PHP: ตั้ง expose_php = Off และซ่อน Server header ที่เว็บเซิร์ฟเวอร์"
        else:
            how = "ปิดการแสดงเวอร์ชันในหน้าตั้งค่าของอุปกรณ์/เซิร์ฟเวอร์ (ถ้าทำได้) หรือซ่อนด้วย reverse proxy"
        findings.append(
            Finding(
                rule_id="version-disclosure",
                title="เปิดเผยเวอร์ชันซอฟต์แวร์ (Server Banner Disclosure)",
                severity=Severity.low,
                confidence=Confidence.high,
                description="Server header เปิดเผยเวอร์ชันซอฟต์แวร์ ทำให้ผู้โจมตีเลือก exploit ได้แม่นยำขึ้น",
                evidence=f"Server: {server}",
                recommendation="ตั้งค่าให้ซ่อนเวอร์ชัน — " + how,
                cvss=3.1,
                cwe="CWE-200",
            )
        )

    if scheme == "https" and "strict-transport-security" not in {
        k.lower() for k in headers
    }:
        findings.append(
            Finding(
                rule_id="missing-hsts",
                title="ไม่ได้เปิดใช้ HSTS (Strict-Transport-Security)",
                severity=Severity.low,
                confidence=Confidence.high,
                description="ไม่มี Strict-Transport-Security header — การเชื่อมต่ออาจถูกโจมตีแบบ SSL Stripping ลดระดับเป็น HTTP",
                evidence="ไม่พบ Strict-Transport-Security header บนพอร์ต HTTPS",
                recommendation="เพิ่ม header Strict-Transport-Security: max-age=31536000; includeSubDomains ที่เว็บเซิร์ฟเวอร์",
                cvss=4.3,
                cwe="CWE-319",
            )
        )

    # --- 5. Node.js / Express / Next.js & CVE-2026-111497 / 105482 / 105483 / 106069 ---
    low_pb = (powered_by or "").lower()
    node_srv = bool(re.search(r"node(?:\.js)?", (server or "").lower()))
    fw = (
        "Express" if "express" in low_pb
        else "Next.js" if ("next.js" in low_pb or "x-nextjs-cache" in {k.lower() for k in headers})
        else "Nuxt" if "nuxt" in low_pb
        else "Node.js" if node_srv or any(s in low_pb for s in NODEJS_SIGNS)
        else None
    )
    if fw and version is None:
        node_vt = parse_node_version(server, powered_by)
        if node_vt is not None:
            patched_min = NODEJS_PATCHED.get(node_vt[0])
            if (patched_min and node_vt < patched_min) or node_vt[0] < 18:
                n_str = f"{node_vt[0]}.{node_vt[1]}.{node_vt[2]}"
                findings.append(
                    Finding(
                        rule_id="nodejs-cve-2026-111497",
                        title=f"Node.js {n_str} อยู่ในช่วงกระทบ CVE-2026-111497 (Brotli OOB Write RCE) และชุด CVE ปี 2026",
                        severity=Severity.critical,
                        confidence=Confidence.confirmed,
                        description=f"Node.js {n_str} ({fw}) ต่ำกว่ารุ่นที่แพตช์ เสี่ยงต่อ CVE-2026-111497 (Brotli RCE), CVE-2026-105482, CVE-2026-105483 และ CVE-2026-106069",
                        evidence=f"Node.js {n_str} ({fw})",
                        recommendation="อัปเกรด Node.js เป็น >= 18.20.8 / 20.19.2 / 22.15.1 / 23.11.1 หรือ 24 LTS ทันที",
                        cve=["CVE-2026-111497", "CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069"],
                        cvss=9.8,
                        cwe="CWE-787",
                    )
                )
        findings.append(
            Finding(
                rule_id="nodejs-detected",
                title=f"พบเซิร์ฟเวอร์ Node.js ({fw}) — ตรวจสอบเวอร์ชันและปิดการเปิดเผย framework",
                severity=Severity.low,
                confidence=Confidence.high,
                description=f"เครื่องนี้ให้บริการด้วย {fw} (Node.js) การตรวจจากภายนอกอ่านเวอร์ชัน "
                "ไม่ได้ ควรยืนยันบนเครื่องว่าใช้ Node.js รุ่น LTS ที่ยังได้รับแพตช์ความปลอดภัย",
                evidence="; ".join(filter(None, [f"X-Powered-By: {powered_by}" if powered_by else "",
                                                 f"Server: {server}" if node_srv else ""])) or fw,
                recommendation="อัปเดต Node.js เป็น LTS ล่าสุด (>= 20.19.2 / 22.15.1 เพื่อกัน CVE-2026-111497) · ปิด X-Powered-By "
                "(ใน Express: app.disable('x-powered-by')) · อัปเดต dependency ด้วย `npm audit fix`",
                cwe="CWE-1104",
            )
        )

    # --- 6. Symfony Debug Header Check ---
    have = {k.lower() for k in headers}
    if "x-debug-token" in have or "x-debug-token-link" in have:
        findings.append(
            Finding(
                rule_id="symfony-debug-token",
                title="พบ Symfony Debug Mode เปิดอยู่บนโปรดักชัน (X-Debug-Token)",
                severity=Severity.high,
                confidence=Confidence.confirmed,
                description="เซิร์ฟเวอร์ส่ง header X-Debug-Token ซึ่งบ่งชี้ว่าเปิดโหมด Debug ของ Symfony ทิ้งไว้ อาจเปิดเผยตัวแปรระบบและฐานข้อมูล",
                evidence="Header: X-Debug-Token",
                recommendation="ตั้งค่า APP_ENV=prod และ APP_DEBUG=0 ในไฟล์ .env บนเครื่องโปรดักชัน",
                cvss=7.5,
                cwe="CWE-489",
            )
        )

    # --- 7. Baseline HTTP Security Headers ---
    is_app = bool(seen or fw) or "set-cookie" in headers or "<form" in body[:_ERROR_SCAN].lower()
    missing = [name for header, name in (
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-frame-options", "X-Frame-Options / CSP frame-ancestors"),
        ("content-security-policy", "Content-Security-Policy"),
    ) if header not in have and not (header == "x-frame-options" and "content-security-policy" in have)]
    if is_app and missing:
        findings.append(
            Finding(
                rule_id="missing-security-headers",
                title="ขาด HTTP security header พื้นฐาน",
                severity=Severity.low,
                confidence=Confidence.high,
                description="เว็บแอปนี้ไม่ได้ตั้ง security header บางตัวที่ช่วยกัน clickjacking, MIME "
                "sniffing และ XSS — ใช้ได้กับทั้งเว็บ PHP, Node.js และอื่น ๆ",
                evidence="ขาด: " + ", ".join(missing),
                recommendation="เพิ่ม: X-Content-Type-Options: nosniff, X-Frame-Options: DENY (หรือ "
                "Content-Security-Policy ที่มี frame-ancestors), และตั้ง Content-Security-Policy",
                cwe="CWE-693",
            )
        )


    # --- 8. Database Error Leaks, Exposed Admin Tools, OS EOL & Device Signatures ---
    blob_low = (
        " ".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body[:60_000]
    ).lower()

    for db_name, db_pats in DB_ERROR_SIGS:
        if any(re.search(p, blob_low) for p in db_pats):
            findings.append(
                Finding(
                    rule_id=f"db-error-leak-{db_name.lower().split('/')[0]}",
                    title=f"พบข้อความ Error ของฐานข้อมูล {db_name} รั่วไหลบนหน้าเว็บ",
                    severity=Severity.high,
                    confidence=Confidence.confirmed,
                    description=f"หน้าเว็บแสดงข้อความข้อผิดพลาดของฐานข้อมูล {db_name} ซึ่งช่วยผู้โจมตีทำ SQL Injection หรือเรียนรู้โครงสร้างตาราง",
                    evidence=f"Database error signature: {db_name}",
                    recommendation="ปิดการแสดงผลข้อผิดพลาดของฐานข้อมูลสู่หน้าเว็บ (ตั้ง display_errors = Off) และตรวจสอบช่องโหว่ SQL Injection",
                    cvss=7.5,
                    cwe="CWE-209",
                )
            )
            break

    for tool_name, tool_pats in ADMIN_TOOL_SIGS:
        if any(re.search(p, blob_low) for p in tool_pats):
            findings.append(
                Finding(
                    rule_id=f"admin-tool-{tool_name.lower()}",
                    title=f"พบหน้าจัดการระบบ {tool_name} เปิดให้เข้าถึงได้จากเครือข่าย",
                    severity=Severity.low,
                    confidence=Confidence.high,
                    description=f"ตรวจพบระบบจัดการ {tool_name} เปิดให้เข้าถึงผ่านเว็บ ควรจำกัดสิทธิ์เฉพาะเครือข่ายผู้ดูแลระบบหรือผ่าน VPN",
                    evidence=f"Detected {tool_name}",
                    recommendation=f"จำกัด IP ที่เข้าถึง {tool_name} ที่ไฟร์วอลล์/เว็บเซิร์ฟเวอร์ และบังคับใช้รหัสผ่านที่รัดกุมหรือ 2FA",
                    cvss=5.3,
                    cwe="CWE-284",
                )
            )
            break

    srv_low = (server or "").lower()
    for os_rx, os_label, os_sev, os_cvss in OS_EOL_PATTERNS:
        if re.search(os_rx, srv_low):
            findings.append(
                Finding(
                    rule_id="os-eol-banner",
                    title=f"ระบบปฏิบัติการอาจสิ้นสุดการสนับสนุนแล้ว (EOL): {os_label}",
                    severity=os_sev,
                    confidence=Confidence.medium,
                    description=f"แบนเนอร์ของเซิร์ฟเวอร์ระบุ {os_label} ซึ่งสิ้นสุดระยะเวลาได้รับแพตช์ความปลอดภัยแล้ว",
                    evidence=f"Server: {server}",
                    recommendation="ตรวจสอบเวอร์ชัน OS จริงบนเครื่อง (`/etc/os-release` หรือ `winver`) และวางแผนอัปเกรดเป็นรุ่น LTS ที่ยังรองรับ",
                    cvss=os_cvss,
                    cwe="CWE-1104",
                )
            )
            break

    for dev_name, dev_pats, dev_cat in DEVICE_SIGS:
        if any(re.search(p, blob_low) for p in dev_pats):
            if dev_cat in ("Windows Web Stack",) and seen:
                findings.append(
                    Finding(
                        rule_id="windows-php-cgi-risk",
                        title=f"พบชุดเว็บเซิร์ฟเวอร์ {dev_name} ร่วมกับ PHP บน Windows — เสี่ยงต่อ CVE-2024-4577",
                        severity=Severity.high,
                        confidence=Confidence.high,
                        description=f"ตรวจพบ {dev_name} รัน PHP บน Windows ซึ่งมีความเสี่ยงสูงต่อช่องโหว่ PHP-CGI Argument Injection (CVE-2024-4577)",
                        evidence=f"Stack: {dev_name}",
                        recommendation="อัปเดต PHP เป็น >= 8.1.29 / 8.2.20 / 8.3.8 และปิด ScriptAlias php-cgi หากไม่จำเป็น",
                        cve=["CVE-2024-4577"],
                        cvss=9.8,
                        cwe="CWE-78",
                    )
                )
            break

    return findings, (str(version) if version else None), cms, server


def runtime_label(
    headers: Dict[str, str], body: str = "", php_version: Optional[str] = None
) -> str:
    pb = headers.get("x-powered-by", "")
    low = pb.lower()
    server = headers.get("server", "")
    if php_version:
        return f"PHP {php_version}"
    if "php" in low or php_signals(headers, body)[0]:
        return "PHP (ซ่อนเวอร์ชัน)"
    if "express" in low:
        return "Node.js · Express"
    if "next.js" in low or "x-nextjs-cache" in {k.lower() for k in headers}:
        return "Node.js · Next.js"
    if re.search(r"node(?:\.js)?", (server + " " + low)):
        return "Node.js"
    if "asp.net" in low:
        return "ASP.NET"
    if server:
        return server
    return "เว็บ (ไม่ทราบ runtime)"


_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.low: 2,
    Severity.safe: 3,
}


def device_severity(findings: List[Finding]) -> Severity:
    best = Severity.safe
    for f in findings:
        if _ORDER[f.severity] < _ORDER[best]:
            best = f.severity
    return best


def thaicert_assessment(
    severity: Severity, has_web: bool, findings: List[Finding]
) -> str:
    if not has_web and not findings:
        return "ตรวจพบการเชื่อมต่อในวง LAN · ไม่พบบริการเว็บหรือ PHP · ปลอดภัยจาก php2shell"
    if severity == Severity.critical:
        if any(x.rule_id == "php2shell" for x in findings):
            return "พบช่องโหว่ php2shell — ควรรีบแก้ไขโดยด่วน"
        top = next((x for x in findings if x.severity == Severity.critical), None)
        return (top.title + " — ควรรีบแก้ไขโดยด่วน") if top else "พบช่องโหว่ระดับวิกฤต (php2shell) — ควรรีบแก้ไขโดยด่วน"
    if severity == Severity.high:
        if any(x.rule_id == "php-eol" for x in findings):
            return "พบความเสี่ยงระดับสูง (PHP สาขาหมดอายุ EOL) — ควรอัปเกรดทันที"
        top = next((x for x in findings if x.severity == Severity.high), None)
        return (top.title + " — ควรอัปเกรดหรือปิดกั้นทันที") if top else "พบความเสี่ยงระดับสูง (PHP สาขาหมดอายุ EOL) — ควรอัปเกรดทันที"
    if severity == Severity.low:
        if any(x.rule_id == "php-undetermined" for x in findings):
            return "พบ PHP แต่ซ่อนเวอร์ชัน — ยืนยันจากภายนอกไม่ได้ ต้องตรวจเวอร์ชันบนเครื่อง (อย่าเพิ่งถือว่าผ่าน)"
        f = next((x for x in findings if x.rule_id != "php2shell"), None)
        return (
            (f.title + " — ความเสี่ยงต่ำ ควรปรับปรุง")
            if f
            else "พบความเสี่ยงระดับต่ำ ควรปรับปรุง"
        )
    return "มีบริการเว็บ/PHP แต่ไม่พบช่องโหว่ php2shell — ผ่านเกณฑ์ ThaiCERT"
