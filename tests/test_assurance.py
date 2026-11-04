"""The four assurance statuses, backport caveat, and internal verification."""
from fastapi.testclient import TestClient

from app import main
from app.scanner import vuln_rules as vr


def _ver(s):
    return vr.parse_php_version(f"PHP/{s}")


def test_status_mapping():
    assert vr.php2shell_status(_ver("8.2.10"), True) == "affected"   # below fix
    assert vr.php2shell_status(_ver("8.2.35"), True) == "fixed"      # at fix
    assert vr.php2shell_status(_ver("7.4.33"), True) == "affected"   # EOL branch
    assert vr.php2shell_status(_ver("8.9.0"), True) == "likely"      # newer than announced
    assert vr.php2shell_status(None, True) == "unverified"           # hidden version
    assert vr.php2shell_status(None, False) == "none"                # no PHP


def test_status_from_internal_evidence():
    assert vr.status_from_evidence("8.1.2", False) == "affected"
    assert vr.status_from_evidence("8.1.2", True) == "fixed"   # distro backport attested
    assert vr.status_from_evidence("8.3.36", False) == "fixed"
    assert vr.status_from_evidence(None, False) == "unverified"


def test_parse_inventory_from_php_v_and_dpkg():
    assert vr.parse_inventory("PHP 8.2.35 (cli) (built: ...)") == "8.2.35"
    assert vr.parse_inventory("ii  php8.1  8.1.2-1ubuntu2.19  amd64  server-side HTML") == "8.1.2"
    # lowest wins (most conservative) when several PHP packages are present
    assert vr.parse_inventory("php7.4 7.4.33-1\nphp8.1 8.1.2-1") == "7.4.33"
    assert vr.parse_inventory("nginx 1.29.8") is None


def test_backport_caveat_on_affected_finding():
    findings, *_ = vr.evaluate(scheme="https",
                               headers={"x-powered-by": "PHP/8.2.10"}, body="")
    php2 = next(f for f in findings if f.rule_id == "php2shell")
    assert "backport" in php2.description.lower()


def _inject_demo_job(jid="t-assure"):
    """Build a completed demo job and register it in the store (the API demo
    flow runs async, which a sync TestClient won't drive)."""
    from datetime import datetime, timezone
    from app.models import JobState, ScanJob, ScanRequest
    from app.scanner import demo_scenarios
    devs = demo_scenarios.build_demo_devices("gov-cert", ["go.th", "or.th", "mi.th", "ac.th", "in.th"])
    job = ScanJob(id=jid, created_at=datetime.now(timezone.utc),
                  request=ScanRequest(demo_scenario="gov-cert"), devices=devs,
                  state=JobState.completed)
    job.demo_scenario = "gov-cert"
    job.progress.total_ips = len(devs) + 5   # a few hosts we couldn't reach
    main.store._jobs[jid] = job
    return jid


def test_verify_endpoint_moves_status():
    client = TestClient(main.app)
    jid = _inject_demo_job()
    job = client.get(f"/api/scans/{jid}").json()
    victim = next(d for d in job["devices"] if d["php_status"] == "affected")

    # operator confirms a distro backport on the box → status becomes fixed
    r = client.post(f"/api/scans/{jid}/devices/{victim['ip']}/verify",
                    json={"backport_fixed": True, "measured_version": "8.1.2",
                          "method": "php -v", "verifier": "ops", "evidence": "USN-xxxx"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "fixed" and body["status_before"] == "affected"
    dev = body["device"]
    assert dev["php_status"] == "fixed" and dev["verification"]["backport_fixed"] is True
    assert all(f["rule_id"] != "php2shell" for f in dev["findings"])

    # inventory paste path: a vulnerable version parsed → affected
    other = next(d for d in job["devices"] if d["php_status"] in ("fixed", "unverified", "likely"))
    r2 = client.post(f"/api/scans/{jid}/devices/{other['ip']}/verify",
                     json={"inventory_text": "ii php8.2 8.2.10-1ubuntu amd64"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "affected"


def test_summary_has_status_counts_and_coverage():
    client = TestClient(main.app)
    jid = _inject_demo_job("t-assure-2")
    s = client.get(f"/api/scans/{jid}/summary").json()
    assert set(s["status_counts"]) >= {"affected", "fixed", "unverified", "none"}
    assert s["unreachable"] == 5   # total_ips - online
