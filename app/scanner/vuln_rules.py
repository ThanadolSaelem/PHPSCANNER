"""Vulnerability rules — version-based, non-destructive, low false positive.

Design principle: we never send an exploit or a destructive payload. We read
what a service voluntarily advertises (HTTP response headers, generator tags,
well-known marker files) and reason about it. Version matching against the
official fixed releases is deliberately the primary signal because it produces
the fewest false positives and is completely safe to run against production.

The headline rule is PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Additional
hygiene rules give operators a fuller picture without adding noise — each has
an explicit confidence level so the UI can let teams filter out anything below
"high" if they only care about confirmed exposure.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional

from ..models import Confidence, Finding, Severity


# --- PHP version handling -------------------------------------------------

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
    """Extract a PHP x.y.z version from any of the header strings given."""
    for src in sources:
        if not src:
            continue
        m = _PHP_RE.search(src)
        if m:
            return PhpVersion(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def php_present(*sources: Optional[str]) -> bool:
    """True if PHP is advertised at all, even without a full version."""
    for src in sources:
        if src and "php" in src.lower():
            return True
    return False


# PHP2Shell fixed releases, by branch. A service on branch x.y is vulnerable if
# its patch level is below the fixed one. Branches older than the oldest fixed
# branch (8.2) are End-of-Life and, per the advisory, affected back to 5.4.0
# with no vendor patch available.
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
    """Decide whether a service is exposed to PHP2Shell.

    Returns ``None`` when PHP is not involved at all (no finding to raise).
    """
    if version is None:
        if php_seen:
            return Php2ShellVerdict(
                vulnerable=False,
                confidence=Confidence.low,
                detail=(
                    "PHP is present but its exact version is not disclosed "
                    "(expose_php is likely off). Verify the build manually "
                    "against the fixed releases."
                ),
            )
        return None

    branch = (version.major, version.minor)
    fixed = PHP2SHELL_FIXED.get(branch)

    if fixed is not None:
        if version.as_tuple() < fixed:
            return Php2ShellVerdict(
                vulnerable=True,
                confidence=Confidence.confirmed,
                detail=(
                    f"PHP {version} is below the fixed release "
                    f"{fixed[0]}.{fixed[1]}.{fixed[2]} for its branch."
                ),
            )
        return Php2ShellVerdict(
            vulnerable=False,
            confidence=Confidence.confirmed,
            detail=f"PHP {version} is at or above the fixed release for its branch.",
        )

    # Branch not in the fixed table.
    if branch < PHP2SHELL_OLDEST_FIXED_BRANCH:
        return Php2ShellVerdict(
            vulnerable=True,
            confidence=Confidence.high,
            detail=(
                f"PHP {version} is on an End-of-Life branch ({branch[0]}.{branch[1]}). "
                "The advisory reports the flaw back to 5.4.0 and no patch is "
                "available for this branch — upgrade to a supported PHP."
            ),
        )
    # Branch newer than anything we know about (e.g. a future 8.6) — assume the
    # vendor shipped a fix there and do not cry wolf.
    return Php2ShellVerdict(
        vulnerable=False,
        confidence=Confidence.medium,
        detail=f"PHP {version} is on a branch newer than the advisory; verify it carries the fix.",
    )


# --- CMS fingerprinting ---------------------------------------------------

def detect_cms(body: str, headers: Dict[str, str]) -> Optional[str]:
    text = body[:200_000].lower()
    gen = headers.get("x-generator", "").lower()
    if "wp-content" in text or "wp-includes" in text or 'content="wordpress' in text:
        return "WordPress"
    if 'content="joomla' in text or "/media/jui/" in text or "joomla" in gen:
        return "Joomla"
    if "drupal" in gen or "drupal.settings" in text or "/sites/default/files" in text \
            or 'content="drupal' in text:
        return "Drupal"
    return None


# --- Rule evaluation ------------------------------------------------------

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


def evaluate(
    *,
    scheme: str,
    status_code: Optional[int],
    headers: Dict[str, str],
    body: str,
) -> tuple[List[Finding], Optional[str], Optional[str], Optional[str]]:
    """Run every rule against one probed service.

    Returns ``(findings, php_version_str, cms, detected_server)``.
    """
    findings: List[Finding] = []
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")

    version = parse_php_version(server, powered_by, headers.get("x-php-version"))
    seen = php_present(server, powered_by)
    cms = detect_cms(body, headers)

    # --- PHP2Shell ---
    verdict = assess_php2shell(version, seen)
    if verdict is not None and verdict.vulnerable:
        sev = Severity.critical if verdict.confidence in (Confidence.confirmed, Confidence.high) else Severity.high
        findings.append(Finding(
            rule_id="php2shell",
            title="PHP2Shell — unauthenticated RCE in PHP core",
            severity=sev,
            confidence=verdict.confidence,
            description=(
                "PHP2Shell is a pair of memory-safety flaws in PHP core "
                "(CVSS 9.2) that can allow unauthenticated remote code "
                "execution. " + verdict.detail
            ),
            evidence="; ".join(filter(None, [
                f"Server: {server}" if server else "",
                f"X-Powered-By: {powered_by}" if powered_by else "",
            ])) or verdict.detail,
            recommendation=(
                "Upgrade PHP to a fixed release: 8.5.12, 8.4.27, 8.3.36 or "
                "8.2.35 (or later within the branch). EOL branches must move to "
                "a supported version. Until patched, apply the vendor/WAF "
                "mitigations."
            ),
            cve=list(PHP2SHELL_CVES),
        ))
    elif verdict is not None and verdict.confidence == Confidence.low:
        findings.append(Finding(
            rule_id="php2shell-undetermined",
            title="PHP present, version undisclosed — PHP2Shell status unknown",
            severity=Severity.info,
            confidence=Confidence.low,
            description=(
                "PHP is in use but the version is hidden, so PHP2Shell exposure "
                "cannot be confirmed remotely. " + verdict.detail
            ),
            evidence="; ".join(filter(None, [
                f"Server: {server}" if server else "",
                f"X-Powered-By: {powered_by}" if powered_by else "",
            ])),
            recommendation=(
                "Check the running PHP build on the host and confirm it is at a "
                "fixed release (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later)."
            ),
            cve=list(PHP2SHELL_CVES),
        ))

    # --- Server version disclosure (hygiene, informational) ---
    if server and re.search(r"\d+\.\d+", server):
        findings.append(Finding(
            rule_id="version-disclosure",
            title="Software version disclosed in Server header",
            severity=Severity.low,
            confidence=Confidence.high,
            description="The Server header reveals specific software versions, "
                        "aiding targeted attacks.",
            evidence=f"Server: {server}",
            recommendation="Suppress version tokens (e.g. ServerTokens Prod, "
                           "expose_php=Off).",
        ))

    # --- Missing transport security (only meaningful over https-capable hosts) ---
    if scheme == "https":
        if "strict-transport-security" not in {k.lower() for k in headers}:
            findings.append(Finding(
                rule_id="missing-hsts",
                title="HSTS not enabled",
                severity=Severity.low,
                confidence=Confidence.high,
                description="No Strict-Transport-Security header; connections can "
                            "be downgraded to HTTP.",
                evidence="Strict-Transport-Security header absent",
                recommendation="Add Strict-Transport-Security with a sane max-age.",
            ))

    return findings, (str(version) if version else None), cms, server
