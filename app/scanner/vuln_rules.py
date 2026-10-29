"""Vulnerability rules — version-based, non-destructive, low false positive.

We never send an exploit or destructive payload. We read what a service
voluntarily advertises (HTTP response headers, generator tags) and reason about
it. Version matching against the official fixed releases is the primary signal
because it produces the fewest false positives and is safe on production.

The headline rule is PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Each device
also gets a plain-language ThaiCERT-style assessment line for the UI.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional

from ..models import Confidence, Finding, Severity

_PHP_RE = re.compile(r"php/?\s*v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


class PhpVersion(NamedTuple):
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:  # pragma: no cover - trivial
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


# PHP2Shell fixed releases, by branch.
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


def assess_php2shell(version: Optional[PhpVersion], php_seen: bool) -> Optional[Php2ShellVerdict]:
    """Decide exposure to PHP2Shell. ``None`` when PHP is not involved at all."""
    if version is None:
        if php_seen:
            return Php2ShellVerdict(False, Confidence.low,
                "PHP ทำงานอยู่แต่ไม่เปิดเผยเวอร์ชัน (expose_php ปิด) ตรวจยืนยันบนเครื่องอีกครั้ง")
        return None

    branch = (version.major, version.minor)
    fixed = PHP2SHELL_FIXED.get(branch)
    if fixed is not None:
        if version.as_tuple() < fixed:
            return Php2ShellVerdict(True, Confidence.confirmed,
                f"PHP {version} ต่ำกว่ารุ่นที่แพตช์ {fixed[0]}.{fixed[1]}.{fixed[2]} ของสาขานี้")
        return Php2ShellVerdict(False, Confidence.confirmed,
            f"PHP {version} เป็นรุ่นที่แพตช์แล้วของสาขานี้")
    if branch < PHP2SHELL_OLDEST_FIXED_BRANCH:
        return Php2ShellVerdict(True, Confidence.high,
            f"PHP {version} อยู่บนสาขาที่หมดอายุ (End-of-Life) ไม่มีแพตช์ — ควรย้ายไปรุ่นที่รองรับ")
    return Php2ShellVerdict(False, Confidence.medium,
        f"PHP {version} อยู่บนสาขาใหม่กว่าประกาศ — ตรวจยืนยันว่ามีแพตช์แล้ว")


def detect_cms(body: str, headers: Dict[str, str]) -> Optional[str]:
    text = body[:200_000].lower()
    gen = headers.get("x-generator", "").lower()
    if "wp-content" in text or "wp-includes" in text or 'content="wordpress' in text:
        return "WordPress"
    if 'content="joomla' in text or "/media/jui/" in text or "joomla" in gen:
        return "Joomla"
    if "drupal" in gen or "drupal.settings" in text or 'content="drupal' in text:
        return "Drupal"
    return None


def evaluate(*, scheme: str, headers: Dict[str, str], body: str
             ) -> tuple[List[Finding], Optional[str], Optional[str], Optional[str]]:
    """Run the rules against one probed web service.

    Returns ``(findings, php_version_str, cms, server)``.
    """
    findings: List[Finding] = []
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    version = parse_php_version(server, powered_by, headers.get("x-php-version"))
    seen = php_present(server, powered_by)
    cms = detect_cms(body, headers)
    evidence = "; ".join(filter(None, [
        f"Server: {server}" if server else "",
        f"X-Powered-By: {powered_by}" if powered_by else "",
    ]))

    verdict = assess_php2shell(version, seen)
    if verdict is not None and verdict.vulnerable:
        findings.append(Finding(
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
        ))
    elif verdict is not None and verdict.confidence == Confidence.low:
        findings.append(Finding(
            rule_id="php-undetermined",
            title="PHP present, version undisclosed",
            severity=Severity.low,
            confidence=Confidence.low,
            description="PHP ทำงานอยู่แต่ซ่อนเวอร์ชัน ตรวจยืนยัน php2shell จากระยะไกลไม่ได้ " + verdict.detail,
            evidence=evidence,
            recommendation="ตรวจเวอร์ชัน PHP บนเครื่องและยืนยันว่าอยู่ที่รุ่นที่แพตช์แล้ว",
            cve=list(PHP2SHELL_CVES),
        ))

    if server and re.search(r"\d+\.\d+", server):
        findings.append(Finding(
            rule_id="version-disclosure",
            title="เปิดเผยเวอร์ชันซอฟต์แวร์",
            severity=Severity.low,
            confidence=Confidence.high,
            description="Server header เปิดเผยเวอร์ชันซอฟต์แวร์ ทำให้วางแผนโจมตีง่ายขึ้น",
            evidence=f"Server: {server}",
            recommendation="ตั้งค่าให้ซ่อนเวอร์ชัน (ServerTokens Prod, expose_php=Off)",
        ))

    if scheme == "https" and "strict-transport-security" not in {k.lower() for k in headers}:
        findings.append(Finding(
            rule_id="missing-hsts",
            title="ไม่ได้เปิดใช้ HSTS",
            severity=Severity.low,
            confidence=Confidence.high,
            description="ไม่มี Strict-Transport-Security header — การเชื่อมต่ออาจถูกลดเป็น HTTP",
            evidence="ไม่พบ Strict-Transport-Security header",
            recommendation="เปิดใช้ HSTS ที่เว็บเซิร์ฟเวอร์",
        ))

    return findings, (str(version) if version else None), cms, server


_ORDER = {Severity.critical: 0, Severity.high: 1, Severity.low: 2, Severity.safe: 3}


def device_severity(findings: List[Finding]) -> Severity:
    best = Severity.safe
    for f in findings:
        if _ORDER[f.severity] < _ORDER[best]:
            best = f.severity
    return best


def thaicert_assessment(severity: Severity, has_web: bool, findings: List[Finding]) -> str:
    """One plain-Thai assessment line for the device, in ThaiCERT style."""
    if not has_web:
        return "ตรวจพบการเชื่อมต่อในวง LAN · ไม่พบบริการเว็บหรือ PHP · ปลอดภัยจาก php2shell"
    if severity == Severity.critical:
        return "พบช่องโหว่ php2shell — ควรรีบแก้ไขโดยด่วน"
    if severity == Severity.low:
        f = next((x for x in findings if x.rule_id != "php2shell"), None)
        return (f.title + " — ความเสี่ยงต่ำ ควรปรับปรุง") if f else "พบความเสี่ยงระดับต่ำ ควรปรับปรุง"
    return "มีบริการเว็บ/PHP แต่ไม่พบช่องโหว่ php2shell — ผ่านเกณฑ์ ThaiCERT"
