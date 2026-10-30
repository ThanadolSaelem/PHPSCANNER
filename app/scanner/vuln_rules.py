"""Vulnerability rules — version-based, non-destructive, low false positive."""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlsplit

from ..models import Confidence, Finding, Severity

_PHP_RE = re.compile(r"php/?\s*v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


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


def php_present(*sources: Optional[str]) -> bool:
    return any(src and "php" in src.lower() for src in sources)


# Signals that PHP is serving this site even when it hides its version
# (expose_php = Off, behind nginx / a CDN). Each is first-party only, so a
# third-party link or widget can't trip them. These never *confirm* a version —
# they only stop a hidden-version site from being scored "safe".
_PHP_COOKIE_RE = re.compile(r"(?:^|[;,\s])PHPSESSID=", re.IGNORECASE)
_PHP_URL_RE = re.compile(r"\.php(?:[/?#]|$)", re.IGNORECASE)
# a .php target in a *relative* or root-relative href/src/action (same-site)
_PHP_REF_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*['"](?!https?:|//)[^'"]*\.php(?:[?#][^'"]*)?['"]""",
    re.IGNORECASE,
)
# PHP runtime error/notice shapes — distinctive enough to avoid prose matches
_PHP_ERROR_RES = (
    re.compile(r"</b> on line <b>\d+</b>", re.IGNORECASE),
    re.compile(r"\b(?:Fatal error|Parse error|Warning|Notice|Deprecated)\s*:[^<]{0,80}in\s+<b>[^<]+</b>", re.IGNORECASE),
    re.compile(r"Call to undefined function", re.IGNORECASE),
    re.compile(r"<title>phpinfo\(\)</title>", re.IGNORECASE),
)


def php_signals(
    headers: Dict[str, str], body: str, final_url: str = ""
) -> tuple[bool, str]:
    """Infer that PHP is running without reading a version. Returns
    ``(present, evidence)`` where *evidence* names the signal(s) for the report.
    Conservative on purpose: a false "PHP present" only asks a human to verify,
    but it must not fire on a plain static site."""
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


_ERROR_SCAN = 200_000


def urlsplit_path(url: str) -> str:
    """The path (+query) of *url*, so ``.php`` is matched on the path, not a
    ``.php`` that appears only inside a query string value of another page."""
    try:
        parts = urlsplit(url)
        return parts.path + ("?" + parts.query if parts.query else "")
    except ValueError:
        return url


PHP2SHELL_FIXED: Dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
PHP2SHELL_OLDEST_FIXED_BRANCH = (8, 2)
PHP2SHELL_CVES = ["CVE-2026-109618", "CVE-2026-109619"]


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
    # "PHP is here" is inferred from the banner *or* from first-party signals
    # (PHPSESSID, a .php page, PHP errors) so a site that hides its version is
    # never scored "safe" just because the banner is clean.
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
            findings.append(
                Finding(
                    rule_id="php-eol",
                    title=f"PHP สาขา {version.major}.{version.minor} หมดอายุการสนับสนุน (End-of-Life)",
                    severity=Severity.high,
                    confidence=Confidence.confirmed,
                    description=f"PHP {version} สิ้นสุดระยะเวลาได้รับแพตช์ความปลอดภัยอย่างเป็นทางการจาก PHP Group แล้ว",
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

    if server and re.search(r"\d+\.\d+", server):
        findings.append(
            Finding(
                rule_id="version-disclosure",
                title="เปิดเผยเวอร์ชันซอฟต์แวร์ (Server Banner Disclosure)",
                severity=Severity.low,
                confidence=Confidence.high,
                description="Server header เปิดเผยเวอร์ชันซอฟต์แวร์ ทำให้ผู้โจมตีเลือก exploit ได้แม่นยำขึ้น",
                evidence=f"Server: {server}",
                recommendation="ตั้งค่าให้ซ่อนเวอร์ชัน (Apache: ServerTokens Prod, Nginx: server_tokens off, PHP: expose_php = Off)",
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

    return findings, (str(version) if version else None), cms, server


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
    if not has_web:
        return "ตรวจพบการเชื่อมต่อในวง LAN · ไม่พบบริการเว็บหรือ PHP · ปลอดภัยจาก php2shell"
    if severity == Severity.critical:
        return "พบช่องโหว่ php2shell — ควรรีบแก้ไขโดยด่วน"
    if severity == Severity.high:
        return "พบความเสี่ยงระดับสูง (PHP สาขาหมดอายุ EOL) — ควรอัปเกรดทันที"
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
