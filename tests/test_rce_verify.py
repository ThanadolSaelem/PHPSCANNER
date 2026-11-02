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
    ))

    assert result["ran"] is True
    assert result["target"] == target
    assert result["verdict"] == "NOT_CONFIRMED"
    assert "summary.json" in result["evidence_files"]
    assert calls["payload"]["lfi_url"].endswith("FUZZ")
    assert calls["payload"]["session_endpoint"].endswith("upload.php")
    assert calls["payload"]["timeout"] == 12
    assert calls["payload"]["no_verify_ssl"] is True
    assert "i_own_this_target=True" in rce_verify._CHILD_RUNNER


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
            "target_url": "http://192.0.2.10/",
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
        accepted = client.post("/api/scans", json=body, headers=headers)

    assert unauthenticated.status_code == 401
    assert no_consent.status_code == 400
    assert accepted.status_code == 200
    assert calls["request"].rce_verify.target_url == "http://192.0.2.10/"
    assert calls["request"].rce_verify.confirm is True
    assert "authorization" not in calls["request"].dump_json_dict()


def test_engine_chains_rce_after_fast_scan_and_skips_unscanned_url(monkeypatch, tmp_path):
    import asyncio
    from datetime import datetime, timezone

    from app.config import Settings
    from app.models import Device, RceVerifyRequest, ScanJob, ScanRequest
    from app.scanner import engine as eng

    calls = {}

    async def fake_scan(_engine, job, cancel):
        job.devices = [Device(ip="192.0.2.10", open_ports=[80])]
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
        rce_verify=RceVerifyRequest(target_url="http://192.0.2.10/", confirm=True),
    )
    job = ScanJob(id="rce-job", created_at=datetime.now(timezone.utc), request=request)
    monkeypatch.setattr(eng.ScanEngine, "_run", fake_scan)
    monkeypatch.setattr(eng.chain_runner, "run_rce_verify_target", fake_verify)

    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))

    assert job.state.value == "completed", job.error
    assert calls["phase"] == "rce_verify"
    assert calls["target"] == "http://192.0.2.10/"
    assert job.rce_verify_result["verdict"] == "NOT_CONFIRMED"
    assert job.rce_verify_result["evidence_dir"] == "rce-verify/rce-job"

    calls.clear()
    request = ScanRequest(
        targets=["192.0.2.10"],
        scan_mode="fast",
        rce_verify=RceVerifyRequest(target_url="http://192.0.2.11/", confirm=True),
    )
    job = ScanJob(id="skip-job", created_at=datetime.now(timezone.utc), request=request)
    asyncio.run(eng.ScanEngine(settings).run(job, asyncio.Event()))
    assert not calls
    assert job.rce_verify_result["verdict"] == "SKIPPED"
    assert "ไม่มีการส่ง active request" in job.rce_verify_result["error"]


def test_toolkit_keeps_upstream_redirect_behavior():
    import security_audit_toolkit as toolkit

    signature = inspect.signature(toolkit.run_rce_verify)
    assert "allowed_redirect_hosts" not in signature.parameters
    assert "allowed_redirect_ports" not in signature.parameters
    assert not hasattr(toolkit, "_apply_rce_redirect_policy")
