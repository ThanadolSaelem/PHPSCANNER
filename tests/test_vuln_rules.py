from app.models import Confidence, Severity
from app.scanner import vuln_rules as vr


def test_parse_version_from_headers():
    assert vr.parse_php_version("PHP/8.3.12") == (8, 3, 12)
    assert vr.parse_php_version("Apache", "PHP/7.4.33") == (7, 4, 33)
    assert vr.parse_php_version("nginx") is None


def test_parse_version_various_formats():
    assert vr.parse_php_version("php 8.2.10") == (8, 2, 10)
    assert vr.parse_php_version("Server: Apache/2.4 PHP/8.4.1") == (8, 4, 1)


# --- PHP2Shell verdicts --------------------------------------------------

def test_vulnerable_below_fix_in_branch():
    v = vr.assess_php2shell(vr.PhpVersion(8, 3, 35), True)
    assert v.vulnerable is True
    assert v.confidence == Confidence.confirmed


def test_safe_at_fix():
    v = vr.assess_php2shell(vr.PhpVersion(8, 3, 36), True)
    assert v.vulnerable is False


def test_safe_above_fix():
    v = vr.assess_php2shell(vr.PhpVersion(8, 5, 20), True)
    assert v.vulnerable is False


def test_each_branch_boundary():
    for branch, fixed in vr.PHP2SHELL_FIXED.items():
        below = vr.PhpVersion(fixed[0], fixed[1], fixed[2] - 1)
        assert vr.assess_php2shell(below, True).vulnerable is True, branch
        at = vr.PhpVersion(*fixed)
        assert vr.assess_php2shell(at, True).vulnerable is False, branch


def test_eol_branch_vulnerable():
    v = vr.assess_php2shell(vr.PhpVersion(7, 4, 33), True)
    assert v.vulnerable is True
    assert v.confidence == Confidence.high


def test_future_branch_not_flagged():
    v = vr.assess_php2shell(vr.PhpVersion(8, 6, 0), True)
    assert v.vulnerable is False


def test_php_present_but_no_version_is_low_conf_not_vuln():
    v = vr.assess_php2shell(None, True)
    assert v.vulnerable is False
    assert v.confidence == Confidence.low


def test_no_php_no_verdict():
    assert vr.assess_php2shell(None, False) is None


# --- End-to-end rule evaluation -----------------------------------------

def test_evaluate_flags_critical_for_vulnerable_php():
    findings, ver, cms, server = vr.evaluate(
        scheme="https",
        status_code=200,
        headers={"server": "Apache", "x-powered-by": "PHP/8.3.10"},
        body="<html></html>",
    )
    assert ver == "8.3.10"
    ids = {f.rule_id for f in findings}
    assert "php2shell" in ids
    php2 = next(f for f in findings if f.rule_id == "php2shell")
    assert php2.severity == Severity.critical
    assert "CVE-2026-109618" in php2.cve


def test_evaluate_no_php2shell_when_patched():
    findings, ver, _, _ = vr.evaluate(
        scheme="https", status_code=200,
        headers={"server": "nginx", "x-powered-by": "PHP/8.3.36"},
        body="",
    )
    assert ver == "8.3.36"
    assert all(f.rule_id != "php2shell" for f in findings)


def test_cms_detection():
    assert vr.detect_cms('<meta name="generator" content="WordPress 6.4">', {}) == "WordPress"
    assert vr.detect_cms("", {"x-generator": "Drupal 10"}) == "Drupal"
    assert vr.detect_cms('<meta name="generator" content="Joomla! 4">', {}) == "Joomla"
    assert vr.detect_cms("plain page", {}) is None
