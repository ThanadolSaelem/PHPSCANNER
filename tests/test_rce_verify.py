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


def test_toolkit_keeps_upstream_redirect_behavior():
    import security_audit_toolkit as toolkit

    signature = inspect.signature(toolkit.run_rce_verify)
    assert "allowed_redirect_hosts" not in signature.parameters
    assert "allowed_redirect_ports" not in signature.parameters
    assert not hasattr(toolkit, "_apply_rce_redirect_policy")
