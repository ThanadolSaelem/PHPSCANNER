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


def test_php_signals_catch_hidden_version():
    # PHPSESSID cookie alone is enough to say "PHP is here"
    present, why = vr.php_signals({"set-cookie": "PHPSESSID=abc123; path=/; HttpOnly"}, "", "")
    assert present and "PHPSESSID" in why
    # a .php page after redirects
    present, _ = vr.php_signals({}, "", "https://www.agency.go.th/index.php")
    assert present
    # a same-site .php link, and a PHP runtime error
    assert vr.php_signals({}, '<a href="/login.php">', "")[0]
    assert vr.php_signals({}, "<b>Fatal error</b>: ... in <b>/var/www/x.php</b> on line <b>12</b>", "")[0]


def test_php_signals_do_not_fire_on_static_site():
    # a plain static page, even one that links OUT to someone else's .php, is not PHP
    present, _ = vr.php_signals(
        {"set-cookie": "visited=1"},
        '<a href="https://other.example/tool.php">ext</a> plain php word in prose',
        "https://www.agency.go.th/about",
    )
    assert present is False


def test_hidden_version_php_is_not_safe():
    # ThaiCERT-style: nginx banner, expose_php Off, but a PHPSESSID cookie leaks.
    # Must land on "undetermined" (low), never "safe".
    findings, ver, _, _ = vr.evaluate(
        scheme="https",
        headers={"server": "nginx", "set-cookie": "PHPSESSID=9f; path=/"},
        body="<html>welcome</html>",
    )
    assert ver is None
    undet = next(f for f in findings if f.rule_id == "php-undetermined")
    assert undet.severity == Severity.low and "PHPSESSID" in undet.evidence
    assert vr.device_severity(findings) == Severity.low  # not safe
    assert "ยืนยัน" in vr.thaicert_assessment(Severity.low, True, findings)


def test_truly_static_site_stays_safe():
    # a plain HTTP static site: no PHP finding at all, device stays safe
    findings, ver, _, _ = vr.evaluate(
        scheme="http", headers={"server": "nginx"}, body="<html>static</html>")
    assert ver is None
    assert not any(f.rule_id in ("php2shell", "php-undetermined", "php-eol") for f in findings)
    assert vr.device_severity(findings) == Severity.safe


def test_nodejs_detected_and_labelled():
    findings, ver, _, _ = vr.evaluate(
        scheme="https", headers={"server": "nginx", "x-powered-by": "Express",
                                 "set-cookie": "connect.sid=x"}, body="<form>")
    assert ver is None
    node = next(f for f in findings if f.rule_id == "nodejs-detected")
    assert node.severity == Severity.low and "Express" in node.title
    assert vr.runtime_label({"x-powered-by": "Express"}) == "Node.js · Express"
    assert vr.runtime_label({"server": "nginx", "x-powered-by": "PHP/8.3.10"}, php_version="8.3.10") == "PHP 8.3.10"
    assert vr.runtime_label({"server": "nginx/1.29.8"}) == "nginx/1.29.8"


def test_missing_headers_only_flags_real_apps():
    # an app (has a session cookie) missing headers → flagged
    app = vr.evaluate(scheme="https", headers={"server": "nginx", "x-powered-by": "Express",
                                               "set-cookie": "s=1"}, body="")[0]
    assert any(f.rule_id == "missing-security-headers" for f in app)
    # a bare static page → not flagged
    static = vr.evaluate(scheme="http", headers={"server": "nginx"}, body="<html>hi</html>")[0]
    assert not any(f.rule_id == "missing-security-headers" for f in static)


def test_device_severity_and_assessment():
    findings, *_ = vr.evaluate(scheme="https", headers={"x-powered-by": "PHP/8.3.10"}, body="")
    assert vr.device_severity(findings) == Severity.critical
    assert "php2shell" in vr.thaicert_assessment(Severity.critical, True, findings)
    # no web service -> safe LAN message
    assert "LAN" in vr.thaicert_assessment(Severity.safe, False, [])
    assert vr.device_severity([]) == Severity.safe


def test_nginx_2026_and_historical_cves():
    findings, _, _, _ = vr.evaluate(
        scheme="https",
        headers={"server": "nginx/1.30.2", "alt-svc": 'h3=":443"'},
        body="<html>ok</html>",
    )
    cves = {c for f in findings for c in f.cve}
    assert {
        "CVE-2026-15176",
        "CVE-2026-93479",
        "CVE-2026-97205",
        "CVE-2026-95101",
        "CVE-2026-97629",
    } <= cves


def test_historical_php_cves():
    findings, _, _, _ = vr.evaluate(
        scheme="http",
        headers={"x-powered-by": "PHP/8.1.10"},
        body="",
    )
    cves = {c for f in findings for c in f.cve}
    assert "CVE-2024-4577" in cves


def test_nodejs_2026_cves_and_gitlab_cve():
    findings_node, _, _, _ = vr.evaluate(
        scheme="https",
        headers={"x-powered-by": "Express", "server": "Node.js/20.11.0"},
        body="",
    )
    node_cves = {c for f in findings_node for c in f.cve}
    assert "CVE-2026-111497" in node_cves and "CVE-2026-105482" in node_cves

    findings_gl, _, cms, _ = vr.evaluate(
        scheme="https",
        headers={"set-cookie": "_gitlab_session=abc"},
        body='<html><script>window.gon={};gon.version="18.5.1";</script></html>',
    )
    assert cms == "GitLab"
    assert any("CVE-2026-110264" in f.cve for f in findings_gl)


def test_chain_runner_parses_all_16_toolkit_buckets():
    from app.scanner import chain_runner

    sample_scan_single_target = {
        "target": "http://10.0.0.5",
        "reachable": True,
        "nginx_cves": {
            "CVE-2026-15176": {
                "cve": "CVE-2026-15176",
                "name": "Heap Buffer Overflow (alias+rewrite)",
                "severity": "Critical",
                "status": "likely-vulnerable",
                "reason": "NGINX 1.30.1 กระทบ + พบ alias/rewrite",
                "host_check": "nginx -T | grep alias",
            }
        },
        "cve_115560": {
            "cve": "CVE-2026-115560",
            "name": "Session Upload Progress Injection",
            "severity": "Medium-High",
            "status": "vulnerable-conditions",
            "reason": "พบการใช้ PHP session + upload_progress reachable",
            "mitigation": "session.upload_progress.enabled = 0",
        },
        "exposure_cves": {
            "EXPOSURE-env": {
                "cve": "EXPOSURE-env",
                "name": "ไฟล์ .env เปิดเผย",
                "severity": "Critical",
                "status": "vulnerable",
                "reason": "เข้าถึง /.env ได้ (HTTP 200)",
            }
        },
        "framework_cves": {
            "CVE-2021-3129": {
                "cve": "CVE-2021-3129",
                "name": "Laravel Ignition RCE",
                "severity": "Critical",
                "status": "vulnerable",
                "reason": "เข้าถึง /_ignition/health-check ได้",
            }
        },
        "lfi_findings": [
            {
                "path": "/view.php",
                "param": "page",
                "url": "http://10.0.0.5/view.php?page=FUZZ",
                "best_evidence": "phpfilter leaked",
                "confidence": "high",
            }
        ],
    }
    parsed = chain_runner.parse_toolkit_findings(sample_scan_single_target)
    titles = " | ".join(f.title for f in parsed)
    assert len(parsed) == 5
    assert "Heap Buffer Overflow" in titles
    assert "Session Upload Progress" in titles
    assert ".env" in titles
    assert "Laravel Ignition" in titles
    assert "Local File Inclusion" in titles
