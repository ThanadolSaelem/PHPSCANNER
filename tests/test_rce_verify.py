import asyncio
import inspect
import json
import os
import sys
from types import ModuleType, SimpleNamespace

from fastapi.testclient import TestClient

from app.scanner import rce_verify

_TOKEN = "test-secret-" + "x" * 40


def test_adapter_forwards_upstream_options_and_public_override(monkeypatch, tmp_path):
    module = ModuleType("security_audit_toolkit")
    module.is_private_host = lambda _target: False
    module.run_rce_verify = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "security_audit_toolkit", module)
    calls = {}

    class FakeProcess:
        returncode = 0

        async def communicate(self, input=None):
            payload = json.loads(input)
            calls["payload"] = payload
            os.makedirs(payload["evidence_dir"], exist_ok=True)
            with open(os.path.join(payload["evidence_dir"], "summary.json"), "w") as f:
                f.write("{}")
            result = {"verdict": "NOT_CONFIRMED", "summary": {"verdict": "NOT_CONFIRMED"},
                      "evidence_dir": payload["evidence_dir"]}
            output = b"toolkit output\n__THSCAN_RCE_VERIFY_RESULT__" + json.dumps(result).encode() + b"\n"
            return output, b""

        def kill(self):
            self.returncode = -9

        async def wait(self):
            return self.returncode

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(rce_verify.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    target = "https://public.example.gov:8443/portal"
    evidence = str(tmp_path / "evidence")
    result = asyncio.run(rce_verify.run(
        target,
        evidence_dir=evidence,
        lfi_url="http://lfi.other.example/index.php?page=FUZZ",
        session_endpoint="https://login.other.example/upload.php",
        timeout=12,
        total_timeout=25,
        no_verify_ssl=True,
        operator="authorized tester",
        pinned_ip="203.0.113.9",
        max_concurrency=2,
    ))

    assert result["ran"] is True
    assert result["target"] == target
    assert result["verdict"] == "NOT_CONFIRMED"
    assert "summary.json" in result["evidence_files"]
    assert calls["payload"]["lfi_url"].endswith("FUZZ")
    assert calls["payload"]["session_endpoint"].endswith("upload.php")
    assert calls["payload"]["timeout"] == 12
    assert calls["payload"]["no_verify_ssl"] is True
    assert calls["payload"]["pinned_ip"] == "203.0.113.9"
    assert "i_own_this_target=True" in rce_verify._CHILD_RUNNER
    assert "out-of-scan HTTP origin blocked" in rce_verify._CHILD_RUNNER
    assert "out-of-scan DNS lookup blocked" in rce_verify._CHILD_RUNNER


def _configure_api(monkeypatch, tmp_path):
    from app import main

    class FakeStore:
        def __init__(self):
            self.audit = SimpleNamespace(record=lambda *args, **kwargs: None)

    monkeypatch.setattr(main, "store", FakeStore())
    monkeypatch.setattr(main.settings, "rce_verify_enabled", True)
    monkeypatch.setattr(main.settings, "rce_verify_token", _TOKEN)
    monkeypatch.setattr(main.settings, "data_dir", str(tmp_path))
    calls = {}

    async def fake_run(target, settings, **kwargs):
        calls.update(target=target, **kwargs)
        return {"ran": True, "target": target, "verdict": "NOT_CONFIRMED",
                "summary": {"verdict": "NOT_CONFIRMED"}, "evidence_dir": kwargs["evidence_dir"],
                "evidence_files": []}

    monkeypatch.setattr(main.chain_runner, "run_rce_verify_target", fake_run)
    return main, calls


def test_standalone_api_requires_token_and_confirmation_then_forwards_full_options(monkeypatch, tmp_path):
    main, calls = _configure_api(monkeypatch, tmp_path)
    path = "/api/rce-verify"
    headers = {"Authorization": f"Bearer {_TOKEN}"}
    body = {
        "target_url": "https://public.example.gov:8443/portal?lang=th",
        "lfi_url": "http://lfi.example.net/index.php?page=FUZZ",
        "session_endpoint": "https://login.example.net/upload.php",
        "timeout": 7,
        "no_verify_ssl": True,
        "operator": "agency-cert",
        "confirm": True,
    }

    with TestClient(main.app) as client:
        no_auth = client.post(path, json=body)
        assert no_auth.status_code == 401
        no_consent = client.post(path, json={**body, "confirm": False}, headers=headers)
        assert no_consent.status_code == 400
        bad_lfi = client.post(path, json={**body, "lfi_url": "https://lfi.example.net/page"}, headers=headers)
        assert bad_lfi.status_code == 400
        ok = client.post(path, json=body, headers=headers)

    assert ok.status_code == 200
    assert calls["target"] == body["target_url"]
    assert calls["lfi_url"] == body["lfi_url"]
    assert calls["session_endpoint"] == body["session_endpoint"]
    assert calls["timeout"] == 7
    assert calls["no_verify_ssl"] is True
    assert calls["operator"] == "agency-cert"
    assert calls["evidence_dir"].startswith(str(tmp_path))
    assert "i_own_this_target" not in calls
    assert "allowed_redirect_hosts" not in calls


def test_standalone_api_rejects_invalid_urls_and_disabled_mode(monkeypatch, tmp_path):
    main, _ = _configure_api(monkeypatch, tmp_path)
    path = "/api/rce-verify"
    headers = {"Authorization": f"Bearer {_TOKEN}"}
    body = {"target_url": "ftp://example.gov/file", "confirm": True}

    with TestClient(main.app) as client:
        bad_url = client.post(path, json=body, headers=headers)
        monkeypatch.setattr(main.settings, "rce_verify_enabled", False)
        disabled = client.post(path, json={"target_url": "https://example.gov/", "confirm": True},
                               headers=headers)

    assert bad_url.status_code == 400
    assert disabled.status_code == 403


def test_combined_scan_api_requires_authorization_and_queues_rce_options(monkeypatch, tmp_path):
    main, _ = _configure_api(monkeypatch, tmp_path)
    monkeypatch.setattr(main.settings, "enforce_scope", False)
    monkeypatch.setattr(main.chain_runner, "rce_verify_available", lambda: True)
    calls = {}

    class FakeJob:
        id = "combined-job"

        @staticmethod
        def summary():
            return {"id": "combined-job", "state": "queued", "rce_verify_requested": True}

    class FakeStore:
        audit = SimpleNamespace(record=lambda *args, **kwargs: None)

        async def create(self, request):
            calls["request"] = request
            return FakeJob()

    monkeypatch.setattr(main, "store", FakeStore())
    body = {
        "targets": ["192.0.2.10"],
        "port_profile": "web",
        "scan_mode": "fast",
        "rce_verify": {
            "all_scanned_targets": True,
            "timeout": 8,
            "operator": "unit-test",
            "confirm": True,
        },
    }
    headers = {"Authorization": f"Bearer {_TOKEN}"}

    with TestClient(main.app) as client:
        unauthenticated = client.post("/api/scans", json=body)
        no_consent = client.post(
            "/api/scans",
            json={**body, "rce_verify": {**body["rce_verify"], "confirm": False}},
            headers=headers,
        )
        out_of_scope_aux = client.post(
            "/api/scans",
            json={**body, "rce_verify": {**body["rce_verify"],
                                          "lfi_url": "https://other.example/page?x=FUZZ"}},
            headers=headers,
        )
        accepted = client.post("/api/scans", json=body, headers=headers)

    assert unauthenticated.status_code == 401
    assert no_consent.status_code == 400
    assert out_of_scope_aux.status_code == 400
    assert accepted.status_code == 200
    assert calls["request"].rce_verify.all_scanned_targets is True
    assert calls["request"].rce_verify.target_url is None
    assert calls["request"].rce_verify.confirm is True
    assert "authorization" not in calls["request"].dump_json_dict()


def test_engine_chains_batch_after_fast_scan_and_skips_when_no_web_endpoint(monkeypatch, tmp_path):
    import asyncio
    from datetime import datetime, timezone

    from app.config import Settings
    from app.models import Device, RceVerifyRequest, ScanJob, ScanRequest, WebEndpoint
    from app.scanner import engine as eng

    calls = {}

    async def fake_scan(_engine, job, cancel):
        job.devices = [Device(
            ip="192.0.2.10", open_ports=[80],
            web_endpoints=[WebEndpoint(ip="192.0.2.10", hostname="192.0.2.10", port=80, scheme="http")],
        )]
        job.progress.total_ips = 1
        job.progress.probed = 1
        job.progress.to_inspect = 1
        job.progress.inspected = 1

    async def fake_verify(target, settings, **kwargs):
        calls.update(target=target, phase=job.progress.phase, **kwargs)
        return {"ran": True, "target": target, "verdict": "NOT_CONFIRMED",
                "summary": {}, "evidence_dir": kwargs["evidence_dir"], "evidence_files": []}

    settings = Settings()
    settings.data_dir = str(tmp_path)
    request = ScanRequest(
        targets=["192.0.2.10"],
        scan_mode="fast",
        rce_verify=RceVerifyRequest(all_scanned_targets=True, confirm=True),
    )
    job = ScanJob(id="rce-job", created_at=datetime.now(timezone.utc), request=request)
    monkeypatch.setattr(eng.ScanEngine, "_run", fake_scan)
    monkeypatch.setattr(eng.chain_runner, "run_rce_verify_target", fake_verify)

    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))

    assert job.state.value == "completed", job.error
    assert calls["phase"] == "rce_verify"
    assert calls["target"] == "http://192.0.2.10:80/"
    assert calls["pinned_ip"] == "192.0.2.10"
    assert job.rce_verify_result["verdict"] == "BATCH_COMPLETED"
    assert job.rce_verify_result["results"][0]["evidence_dir"] == "rce-verify/rce-job/0001"

    calls.clear()
    request = ScanRequest(
        targets=["192.0.2.10"],
        scan_mode="fast",
        rce_verify=RceVerifyRequest(all_scanned_targets=True, confirm=True),
    )
    job = ScanJob(id="skip-job", created_at=datetime.now(timezone.utc), request=request)
    async def fake_scan_without_web(_engine, scan_job, cancel):
        scan_job.devices = [Device(ip="192.0.2.11", open_ports=[80])]
    monkeypatch.setattr(eng.ScanEngine, "_run", fake_scan_without_web)
    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))
    assert not calls
    assert job.rce_verify_result["verdict"] == "SKIPPED"
    assert "ไม่มี active request" in job.rce_verify_result["error"]


def test_batch_deduplicates_endpoints_and_adapts_concurrency(monkeypatch, tmp_path):
    import asyncio
    from datetime import datetime, timezone

    from app.config import Settings
    from app.models import Device, RceVerifyRequest, ScanJob, ScanRequest, WebEndpoint
    from app.scanner import engine as eng

    async def fake_scan(_engine, scan_job, cancel):
        return None
    monkeypatch.setattr(eng.ScanEngine, "_run", fake_scan)

    settings = Settings()
    settings.data_dir = str(tmp_path)
    settings.rce_verify_max_endpoints = 10
    settings.rce_verify_max_workers = 2
    settings.rce_verify_memory_reserve_mb = 256
    settings.rce_verify_worker_memory_mb = 128
    request = ScanRequest(
        targets=["192.0.2.20"], scan_mode="fast",
        rce_verify=RceVerifyRequest(all_scanned_targets=True, confirm=True),
    )
    job = ScanJob(id="batch-job", created_at=datetime.now(timezone.utc), request=request)
    job.devices = [
        Device(ip="192.0.2.20", open_ports=[80, 443], web_endpoints=[
            WebEndpoint(ip="192.0.2.20", hostname="agency.example", port=80, scheme="http"),
            WebEndpoint(ip="192.0.2.20", hostname="agency.example", port=80, scheme="http"),
            WebEndpoint(ip="192.0.2.20", hostname="agency.example", port=443, scheme="https"),
        ]),
        Device(ip="192.0.2.21", open_ports=[8080], web_endpoints=[
            WebEndpoint(ip="192.0.2.21", hostname="192.0.2.21", port=8080, scheme="http"),
        ]),
    ]
    monkeypatch.setattr(eng, "available_memory_bytes", lambda: 2 * 1024**3)
    active = 0
    peak_active = 0
    calls = []

    async def fake_verify(target, _settings, **kwargs):
        nonlocal active, peak_active
        active += 1
        peak_active = max(peak_active, active)
        calls.append((target, kwargs["pinned_ip"]))
        await asyncio.sleep(0.01)
        active -= 1
        return {
            "ran": True, "target": target, "verdict": "NOT_CONFIRMED",
            "summary": {}, "evidence_dir": kwargs["evidence_dir"],
            "evidence_files": [], "peak_rss_bytes": 96 * 1024**2,
        }

    monkeypatch.setattr(eng.chain_runner, "run_rce_verify_target", fake_verify)
    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))

    assert len(calls) == 3
    assert peak_active == 2
    assert job.rce_verify_result["total_targets"] == 3
    assert job.rce_verify_result["completed_targets"] == 3
    assert job.rce_verify_result["batch_count"] == 2
    assert job.rce_verify_result["max_parallel"] == 2
    assert {target for target, _ip in calls} == {
        "http://agency.example:80/",
        "https://agency.example:443/",
        "http://192.0.2.21:8080/",
    }


def test_batch_endpoint_cap_rejects_before_any_active_request(monkeypatch, tmp_path):
    import asyncio
    from datetime import datetime, timezone

    from app.config import Settings
    from app.models import Device, RceVerifyRequest, ScanJob, ScanRequest, WebEndpoint
    from app.scanner import engine as eng

    async def fake_scan(_engine, scan_job, cancel):
        return None
    monkeypatch.setattr(eng.ScanEngine, "_run", fake_scan)

    settings = Settings()
    settings.data_dir = str(tmp_path)
    settings.rce_verify_max_endpoints = 2
    job = ScanJob(
        id="too-many", created_at=datetime.now(timezone.utc),
        request=ScanRequest(targets=["192.0.2.30"], scan_mode="fast",
                            rce_verify=RceVerifyRequest(all_scanned_targets=True, confirm=True)),
    )
    job.devices = [Device(ip="192.0.2.30", open_ports=[80, 81, 82], web_endpoints=[
        WebEndpoint(ip="192.0.2.30", hostname="192.0.2.30", port=p, scheme="http")
        for p in (80, 81, 82)
    ])]
    calls = []

    async def fake_verify(*args, **kwargs):
        calls.append(args)

    monkeypatch.setattr(eng.chain_runner, "run_rce_verify_target", fake_verify)
    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))

    assert not calls
    assert job.rce_verify_result["verdict"] == "REJECTED_LIMIT"
    assert "ไม่มีการตัดหรือสุ่ม" in job.rce_verify_result["error"]


def test_batch_stops_before_wave_when_memory_is_below_reserve(monkeypatch, tmp_path):
    import asyncio
    from datetime import datetime, timezone

    from app.config import Settings
    from app.models import Device, RceVerifyRequest, ScanJob, ScanRequest, WebEndpoint
    from app.scanner import engine as eng

    async def fake_scan(_engine, scan_job, cancel):
        return None
    monkeypatch.setattr(eng.ScanEngine, "_run", fake_scan)

    settings = Settings()
    settings.data_dir = str(tmp_path)
    settings.rce_verify_max_endpoints = 10
    settings.rce_verify_memory_reserve_mb = 1024
    settings.rce_verify_worker_memory_mb = 512
    job = ScanJob(
        id="low-memory", created_at=datetime.now(timezone.utc),
        request=ScanRequest(targets=["192.0.2.40"], scan_mode="fast",
                            rce_verify=RceVerifyRequest(all_scanned_targets=True, confirm=True)),
    )
    job.devices = [Device(ip="192.0.2.40", open_ports=[80], web_endpoints=[
        WebEndpoint(ip="192.0.2.40", hostname="192.0.2.40", port=80, scheme="http"),
    ])]
    monkeypatch.setattr(eng, "available_memory_bytes", lambda: 900 * 1024**2)
    calls = []

    async def fake_verify(*args, **kwargs):
        calls.append(args)

    monkeypatch.setattr(eng.chain_runner, "run_rce_verify_target", fake_verify)
    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))

    assert not calls
    assert job.rce_verify_result["verdict"] == "PARTIAL"
    assert job.rce_verify_result["results"][0]["verdict"] == "DEFERRED_RESOURCE_LIMIT"


def test_batch_size_planner_is_bounded_and_falls_back_to_one_worker():
    from app.scanner.resource_budget import choose_batch_size

    assert choose_batch_size(20, available_bytes=None, max_workers=8,
                             reserve_mb=1024, worker_memory_mb=512) == 1
    assert choose_batch_size(20, available_bytes=900 * 1024**2, max_workers=4,
                             reserve_mb=1024, worker_memory_mb=512) == 0
    assert choose_batch_size(20, available_bytes=3 * 1024**3, max_workers=8,
                             reserve_mb=1024, worker_memory_mb=512) == 4


def test_result_summary_is_bounded_before_job_persistence():
    summary = {"output": "x" * 40000}
    bounded = rce_verify._bounded_summary(summary, max_bytes=1024)
    assert bounded["truncated"] is True
    assert len(bounded["preview"]) <= 16000


def test_toolkit_keeps_upstream_redirect_behavior():
    import security_audit_toolkit as toolkit

    signature = inspect.signature(toolkit.run_rce_verify)
    assert "allowed_redirect_hosts" not in signature.parameters
    assert "allowed_redirect_ports" not in signature.parameters
    assert not hasattr(toolkit, "_apply_rce_redirect_policy")
