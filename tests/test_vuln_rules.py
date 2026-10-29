from app.models import Confidence, Severity
from app.scanner import vuln_rules as vr


def test_parse_version():
    assert vr.parse_php_version("PHP/8.3.12") == (8, 3, 12)
    assert vr.parse_php_version("Apache", "PHP/7.4.33") == (7, 4, 33)
    assert vr.parse_php_version("nginx") is None


def test_each_branch_boundary():
    for branch, fixed in vr.PHP2SHELL_FIXED.items():
        below = vr.PhpVersion(fixed[0], fixed[1], fixed[2] - 1)
        assert vr.assess_php2shell(below, True).vulnerable is True, branch
        assert vr.assess_php2shell(vr.PhpVersion(*fixed), True).vulnerable is False, branch


def test_eol_branch_vulnerable_high():
    v = vr.assess_php2shell(vr.PhpVersion(7, 4, 33), True)
    assert v.vulnerable is True and v.confidence == Confidence.high


def test_future_branch_not_flagged():
    assert vr.assess_php2shell(vr.PhpVersion(8, 6, 0), True).vulnerable is False


def test_no_php_no_verdict():
    assert vr.assess_php2shell(None, False) is None
    assert vr.assess_php2shell(None, True).confidence == Confidence.low


def test_evaluate_critical_for_vulnerable():
    findings, ver, cms, server = vr.evaluate(
        scheme="https", headers={"server": "Apache", "x-powered-by": "PHP/8.3.10"}, body="")
    assert ver == "8.3.10"
    php2 = next(f for f in findings if f.rule_id == "php2shell")
    assert php2.severity == Severity.critical
    assert "CVE-2026-109618" in php2.cve


def test_evaluate_patched_no_php2shell():
    findings, ver, _, _ = vr.evaluate(
        scheme="https", headers={"server": "nginx", "x-powered-by": "PHP/8.3.36"}, body="")
    assert ver == "8.3.36"
    assert all(f.rule_id != "php2shell" for f in findings)


def test_cms_detection():
    assert vr.detect_cms('<meta name="generator" content="WordPress 6.4">', {}) == "WordPress"
    assert vr.detect_cms("", {"x-generator": "Drupal 10"}) == "Drupal"
    assert vr.detect_cms("plain", {}) is None


def test_device_severity_and_assessment():
    findings, *_ = vr.evaluate(scheme="https", headers={"x-powered-by": "PHP/8.3.10"}, body="")
    assert vr.device_severity(findings) == Severity.critical
    assert "php2shell" in vr.thaicert_assessment(Severity.critical, True, findings)
    # no web service -> safe LAN message
    assert "LAN" in vr.thaicert_assessment(Severity.safe, False, [])
    assert vr.device_severity([]) == Severity.safe
