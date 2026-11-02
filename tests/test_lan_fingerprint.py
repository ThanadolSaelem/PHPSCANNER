import asyncio
import struct
from types import SimpleNamespace

from app.config import Settings
from app.models import Confidence, Device, ScanProgress, ScanRequest
from app.scanner import lan_fingerprint


_IFACES = [{"name": "en0", "address": "192.168.50.2", "cidr": "192.168.50.0/24"}]
_DIRECT_ROUTES = [(lan_fingerprint.ipaddress.IPv4Network("192.168.50.0/24"), "en0", True)]


def test_scope_requires_rfc1918_and_one_real_on_link_interface(monkeypatch):
    error, mapping = lan_fingerprint.validate_targets(["192.168.50.20"], _IFACES)
    assert error is None
    assert mapping["192.168.50.20"]["name"] == "en0"

    error, mapping = lan_fingerprint.validate_targets(["192.168.50.2"], _IFACES)
    assert error is None
    assert mapping["192.168.50.2"]["address"] == "192.168.50.2"

    for target in ("8.8.8.8", "192.0.2.1", "10.0.0.9"):
        error, mapping = lan_fingerprint.validate_targets([target], _IFACES)
        assert error
        assert mapping == {}

    monkeypatch.setattr(lan_fingerprint, "_load_route_table", lambda: _DIRECT_ROUTES)
    monkeypatch.setattr(lan_fingerprint, "_selected_route_source", lambda _target: "192.168.50.2")
    error, mapping = lan_fingerprint.validate_targets(
        ["192.168.50.20"], _IFACES, require_direct_route=True
    )
    assert error is None
    assert mapping["192.168.50.20"]["name"] == "en0"

    # The same subnet is rejected when the kernel selects a gateway route.
    routes = [(lan_fingerprint.ipaddress.IPv4Network("192.168.50.0/24"), "en0", False)]
    assert not lan_fingerprint._has_direct_route(
        lan_fingerprint.ipaddress.IPv4Address("192.168.50.20"), _IFACES[0], routes
    )
    monkeypatch.setattr(lan_fingerprint, "_load_route_table", lambda: routes)
    error, mapping = lan_fingerprint.validate_targets(
        ["192.168.50.20"], _IFACES, require_direct_route=True
    )
    assert error and "route" in error
    assert mapping == {}

    monkeypatch.setattr(lan_fingerprint, "_load_route_table", lambda: _DIRECT_ROUTES)
    monkeypatch.setattr(lan_fingerprint, "_selected_route_source", lambda _target: "192.168.50.3")
    error, mapping = lan_fingerprint.validate_targets(
        ["192.168.50.20"], _IFACES, require_direct_route=True
    )
    assert error and "route" in error
    assert mapping == {}

    monkeypatch.setattr(lan_fingerprint, "_load_route_table", lambda: None)
    error, mapping = lan_fingerprint.validate_targets(
        ["192.168.50.20"], _IFACES, require_direct_route=True
    )
    assert error and "fail-closed" in error
    assert mapping == {}


def test_scope_rejects_ambiguous_routes_and_too_many_targets():
    overlapping = _IFACES + [{"name": "vpn0", "address": "192.168.50.3", "cidr": "192.168.50.0/24"}]
    error, _ = lan_fingerprint.validate_targets(["192.168.50.20"], overlapping)
    assert "กำกวม" in error

    targets = [f"192.168.50.{i}" for i in range(1, 258)]
    error, _ = lan_fingerprint.validate_targets(targets, _IFACES)
    assert "256" in error


def test_local_interface_telemetry_failure_fails_closed(monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "net_if_addrs", lambda: (_ for _ in ()).throw(OSError("unavailable")))
    assert lan_fingerprint.discovery.local_ipv4_interfaces() == []


def test_local_interface_inventory_excludes_down_interfaces(monkeypatch):
    import psutil

    address = SimpleNamespace(family=lan_fingerprint.socket.AF_INET, address="192.168.50.2", netmask="255.255.255.0")
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {"en0": [address], "en1": [address]})
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {
        "en0": SimpleNamespace(isup=True), "en1": SimpleNamespace(isup=False),
    })
    assert lan_fingerprint.discovery.local_ipv4_interfaces() == [
        {"name": "en0", "address": "192.168.50.2", "cidr": "192.168.50.0/24"},
    ]


def test_macos_route_reader_requires_up_non_gateway_interface(monkeypatch):
    monkeypatch.setattr(lan_fingerprint.sys, "platform", "darwin")
    monkeypatch.setattr(lan_fingerprint.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=0,
        stdout=(
            "Destination Gateway Flags Netif Expire\n"
            "default 192.168.50.1 UGSc en0\n"
            "192.168.50/24 link#4 UCS en0\n"
            "10.0.0/8 192.168.50.1 UGSc en0\n"
        ),
    ))
    monkeypatch.setattr(lan_fingerprint, "_selected_route_source", lambda _target: "192.168.50.2")
    routes = lan_fingerprint._load_route_table()
    assert routes is not None
    target = lan_fingerprint.ipaddress.IPv4Address("192.168.50.20")
    assert lan_fingerprint._has_direct_route(target, _IFACES[0], routes)
    assert not lan_fingerprint._has_direct_route(
        lan_fingerprint.ipaddress.IPv4Address("10.0.0.20"), _IFACES[0], routes
    )


def test_windows_route_reader_rejects_gateway_and_uses_local_interface_address(monkeypatch):
    monkeypatch.setattr(lan_fingerprint.sys, "platform", "win32")
    monkeypatch.setattr(lan_fingerprint.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=0,
        stdout=(
            "Network Destination Netmask Gateway Interface Metric\n"
            "0.0.0.0 0.0.0.0 192.168.50.1 192.168.50.2 25\n"
            "192.168.50.0 255.255.255.0 On-link 192.168.50.2 281\n"
            "10.0.0.0 255.0.0.0 192.168.50.1 192.168.50.2 25\n"
        ),
    ))
    monkeypatch.setattr(lan_fingerprint, "_selected_route_source", lambda _target: "192.168.50.2")
    routes = lan_fingerprint._load_route_table()
    assert routes is not None
    windows_interface = {"name": "Ethernet", "address": "192.168.50.2", "cidr": "192.168.50.0/24"}
    assert lan_fingerprint._has_direct_route(
        lan_fingerprint.ipaddress.IPv4Address("192.168.50.20"), windows_interface, routes
    )
    assert not lan_fingerprint._has_direct_route(
        lan_fingerprint.ipaddress.IPv4Address("10.0.0.20"), windows_interface, routes
    )


def test_device_classifier_requires_specific_model_hint_for_phone_claim():
    label, confidence, evidence = lan_fingerprint._classify([
        "mDNS TXT model=iPhone16,2",
    ])
    assert label == "Apple iPhone (model hint)"
    assert confidence == Confidence.medium
    assert evidence == ["mDNS model=iPhone16,2"]

    label, confidence, _ = lan_fingerprint._classify([
        "mDNS _airplay._tcp.local -> Speaker._airplay._tcp.local",
    ])
    assert label == "Apple ecosystem service (device class unknown)"
    assert confidence == Confidence.low


def test_nbns_response_parser_extracts_names_without_network_io():
    name = b"DESKTOP-01".ljust(15, b" ") + b"\x00" + struct.pack("!H", 0)
    rdata = b"\x01" + name + (b"\x00" * 6)
    answer = b"\x00" + struct.pack("!HHIH", 0x0021, 1, 60, len(rdata)) + rdata
    question = lan_fingerprint._nbns_name_query(1)[12:]
    packet = struct.pack("!HHHHHH", 1, 0x8000, 1, 1, 0, 0) + question + answer
    assert lan_fingerprint._parse_nbns(packet, expected_transaction_id=1) == ["NetBIOS DESKTOP-01 <0x00> (unique)"]
    assert lan_fingerprint._parse_nbns(packet, expected_transaction_id=2) == []
    assert lan_fingerprint._parse_nbns(packet) == ["NetBIOS DESKTOP-01 <0x00> (unique)"]
    assert lan_fingerprint._parse_nbns(b"short") == []


def test_nbns_query_accepts_only_matching_transaction_and_target_source(monkeypatch):
    class FakeSocket:
        def __init__(self, peer):
            self.peer = peer
            self.transaction_id = None

        def bind(self, _address):
            pass

        def settimeout(self, _timeout):
            pass

        def sendto(self, payload, _address):
            self.transaction_id = struct.unpack_from("!H", payload)[0]

        def recvfrom(self, _size):
            name = b"DESKTOP-01".ljust(15, b" ") + b"\x00" + struct.pack("!H", 0)
            rdata = b"\x01" + name + (b"\x00" * 6)
            answer = b"\x00" + struct.pack("!HHIH", 0x0021, 1, 60, len(rdata)) + rdata
            question = lan_fingerprint._nbns_name_query(self.transaction_id)[12:]
            packet = struct.pack("!HHHHHH", self.transaction_id, 0x8000, 1, 1, 0, 0) + question + answer
            return packet, (self.peer, 137)

        def close(self):
            pass

    current = {"peer": "192.168.50.20"}
    monkeypatch.setattr(lan_fingerprint.socket, "socket", lambda *_args: FakeSocket(current["peer"]))
    assert lan_fingerprint._query_nbns("192.168.50.2", "192.168.50.20", 0.1) == [
        "NetBIOS DESKTOP-01 <0x00> (unique)"
    ]
    current["peer"] = "192.168.50.99"
    assert lan_fingerprint._query_nbns("192.168.50.2", "192.168.50.20", 0.1) == []


def test_fingerprint_default_is_unicast_only_and_records_low_confidence(monkeypatch):
    calls = []
    monkeypatch.setattr(lan_fingerprint.discovery, "local_ipv4_interfaces", lambda: _IFACES)
    monkeypatch.setattr(lan_fingerprint, "_load_route_table", lambda: _DIRECT_ROUTES)
    monkeypatch.setattr(lan_fingerprint, "_selected_route_source", lambda _target: "192.168.50.2")
    monkeypatch.setattr(lan_fingerprint, "_query_nbns", lambda local, target, timeout: calls.append((local, target)) or ["NetBIOS PC-1 <0x00> (unique)"])
    monkeypatch.setattr(lan_fingerprint, "_query_multicast", lambda *args: (_ for _ in ()).throw(AssertionError("multicast must be opt-in")))
    device = Device(ip="192.168.50.20")
    progress = ScanProgress()
    settings = Settings()
    result = asyncio.run(lan_fingerprint.fingerprint_devices([device], settings, asyncio.Event(), progress))

    assert calls == [("192.168.50.2", "192.168.50.20")]
    assert result["status"] == "completed"
    assert result["multicast_enabled"] is False
    assert device.lan_fingerprint_status == "matched"
    assert "Workstation" in device.device_type
    assert device.device_type_confidence == Confidence.low
    assert device.device_type_source == "NetBIOS"
    assert progress.lan_fingerprint_completed == progress.lan_fingerprint_total == 1
    assert progress.lan_fingerprint_done is True


def test_multicast_requires_option_and_only_retains_scan_target_responses(monkeypatch):
    monkeypatch.setattr(lan_fingerprint.discovery, "local_ipv4_interfaces", lambda: _IFACES)
    monkeypatch.setattr(lan_fingerprint, "_load_route_table", lambda: _DIRECT_ROUTES)
    monkeypatch.setattr(lan_fingerprint, "_selected_route_source", lambda _target: "192.168.50.2")
    calls = []
    monkeypatch.setattr(lan_fingerprint, "_query_multicast", lambda iface, timeout, cancel=None: calls.append(iface["name"]) or {
        "192.168.50.20": ["SSDP ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"],
        "192.168.50.99": ["SSDP ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"],
    })
    monkeypatch.setattr(lan_fingerprint, "_query_nbns", lambda *args: [])
    device = Device(ip="192.168.50.20")
    progress = ScanProgress()
    result = asyncio.run(lan_fingerprint.fingerprint_devices(
        [device], Settings(), asyncio.Event(), progress, multicast=True,
    ))
    assert calls == ["en0"]
    assert result["multicast_enabled"] is True
    assert device.device_type == "Possible router / Internet gateway"
    assert device.device_type_confidence == Confidence.medium
    assert all("192.168.50.99" not in row for row in device.device_type_evidence)


def test_endpoint_cap_short_circuits_before_any_probe(monkeypatch):
    monkeypatch.setattr(lan_fingerprint.discovery, "local_ipv4_interfaces", lambda: _IFACES)
    monkeypatch.setattr(lan_fingerprint, "_query_nbns", lambda *args: (_ for _ in ()).throw(AssertionError("must not probe")))
    settings = Settings()
    settings.lan_fingerprint_max_targets = 1
    devices = [Device(ip="192.168.50.10"), Device(ip="192.168.50.11")]
    progress = ScanProgress()
    result = asyncio.run(lan_fingerprint.fingerprint_devices(devices, settings, asyncio.Event(), progress))
    assert result["status"] == "rejected_cap"
    assert all(d.lan_fingerprint_status == "rejected_cap" for d in devices)
    assert progress.lan_fingerprint_done is True


def test_api_gates_feature_consent_scope_sites_cap_and_multicast(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from app import main

    created = []

    class FakeJob:
        id = "lan-job"

        @staticmethod
        def summary():
            return {"id": "lan-job", "state": "queued", "lan_fingerprint_requested": True}

    class FakeStore:
        audit = SimpleNamespace(record=lambda *args, **kwargs: None)

        async def create(self, request):
            created.append(request)
            return FakeJob()

    monkeypatch.setattr(main, "store", FakeStore())
    monkeypatch.setattr(main.settings, "enforce_scope", False)
    monkeypatch.setattr(main.settings, "lan_fingerprint_enabled", False)
    monkeypatch.setattr(main.settings, "lan_fingerprint_max_targets", 256)
    monkeypatch.setattr(main.discovery, "local_ipv4_interfaces", lambda: _IFACES)
    body = {"targets": ["192.168.50.20"], "scan_mode": "fast", "lan_fingerprint": True}

    with TestClient(main.app) as client:
        disabled = client.post("/api/scans", json={**body, "lan_fingerprint_confirm": True})
        monkeypatch.setattr(main.settings, "lan_fingerprint_enabled", True)
        no_consent = client.post("/api/scans", json=body)
        public_target = client.post("/api/scans", json={
            **body, "targets": ["8.8.8.8"], "lan_fingerprint_confirm": True,
        })
        routed_target = client.post("/api/scans", json={
            **body, "targets": ["10.0.0.9"], "lan_fingerprint_confirm": True,
        })
        website_target = client.post("/api/scans", json={
            "sites": ["https://example.com"], "scan_mode": "fast",
            "lan_fingerprint": True, "lan_fingerprint_confirm": True,
        })
        missing_multicast_consent = client.post("/api/scans", json={
            **body, "lan_fingerprint_confirm": True, "lan_multicast_discovery": True,
        })
        monkeypatch.setattr(main.settings, "lan_fingerprint_max_targets", 1)
        too_many = client.post("/api/scans", json={
            **body, "targets": ["192.168.50.20", "192.168.50.21"],
            "lan_fingerprint_confirm": True,
        })
        monkeypatch.setattr(main.settings, "lan_fingerprint_max_targets", 256)
        accepted = client.post("/api/scans", json={
            **body, "lan_fingerprint_confirm": True,
            "lan_multicast_discovery": True, "lan_multicast_confirm": True,
        })

    assert disabled.status_code == 403
    assert no_consent.status_code == 400
    assert public_target.status_code == 403
    assert routed_target.status_code == 403
    assert website_target.status_code == 400
    assert missing_multicast_consent.status_code == 400
    assert too_many.status_code == 400
    assert accepted.status_code == 200, accepted.text
    assert len(created) == 1
    assert created[0].lan_fingerprint is True
    assert created[0].lan_fingerprint_confirm is True
    assert created[0].lan_multicast_discovery is True
    assert created[0].lan_multicast_confirm is True


def test_engine_runs_fingerprint_after_fast_scan_only_for_confirmed_devices(monkeypatch, tmp_path):
    from datetime import datetime, timezone

    from app.models import JobState, ScanJob
    from app.scanner import engine

    settings = Settings()
    settings.data_dir = str(tmp_path)
    settings.lan_fingerprint_enabled = True
    request = ScanRequest(
        targets=["192.168.50.20"], scan_mode="fast",
        lan_fingerprint=True, lan_fingerprint_confirm=True,
    )
    job = ScanJob(id="lan-engine", created_at=datetime.now(timezone.utc), request=request)
    state = {"scan_running": False}

    async def fake_scan(_engine, scan_job, cancel, on_web_endpoint=None):
        state["scan_running"] = True
        scan_job.devices = [Device(ip="192.168.50.20")]
        await asyncio.sleep(0)
        scan_job.progress.probed = 1
        state["scan_running"] = False

    async def fake_fingerprint(devices, _settings, _cancel, progress, *, multicast=False):
        assert state["scan_running"] is False
        assert job.progress.fast_scan_complete is True
        assert [d.ip for d in devices] == ["192.168.50.20"]
        assert multicast is False
        progress.lan_fingerprint_started = True
        progress.lan_fingerprint_total = progress.lan_fingerprint_completed = 1
        progress.lan_fingerprint_done = True
        devices[0].device_type = "Workstation / SMB-compatible host (OS unconfirmed)"
        return {"status": "completed", "target_count": 1, "matched": 1}

    monkeypatch.setattr(engine.ScanEngine, "_run", fake_scan)
    monkeypatch.setattr(engine.lan_fingerprint, "fingerprint_devices", fake_fingerprint)
    asyncio.run(engine.ScanEngine(settings).run(job, asyncio.Event()))

    assert job.state == JobState.completed
    assert job.progress.lan_fingerprint_done is True
    assert job.lan_fingerprint_result["matched"] == 1
    assert job.devices[0].device_type.startswith("Workstation")


def test_lan_fingerprint_does_not_wait_for_inflight_rce_batch(monkeypatch, tmp_path):
    from datetime import datetime, timezone

    from app.models import JobState, RceVerifyRequest, ScanJob, WebEndpoint
    from app.scanner import engine

    settings = Settings()
    settings.data_dir = str(tmp_path)
    settings.lan_fingerprint_enabled = True
    request = ScanRequest(
        targets=["192.168.50.20"], scan_mode="fast",
        lan_fingerprint=True, lan_fingerprint_confirm=True,
        rce_verify=RceVerifyRequest(all_scanned_targets=True, confirm=True),
    )
    job = ScanJob(id="lan-rce-overlap", created_at=datetime.now(timezone.utc), request=request)
    stream_state = {"stream": None, "fingerprinting_while_rce_active": False}

    class FakeStream:
        def __init__(self, _job, _settings, _request, _cancel):
            self.job = _job
            self.discovered = 0
            self.finished = False
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            stream_state["stream"] = self

        async def run(self):
            self.started.set()
            await self.release.wait()
            self.job.progress.rce_verify_done = True

        async def submit(self, _endpoint):
            self.discovered += 1
            self.job.progress.rce_verify_started = True

        async def finish(self):
            self.finished = True
            self.release.set()

    async def fake_scan(_engine, scan_job, _cancel, on_web_endpoint=None):
        scan_job.devices = [Device(ip="192.168.50.20")]
        await on_web_endpoint(WebEndpoint(ip="192.168.50.20", hostname="192.168.50.20", port=80, scheme="http"))
        await asyncio.sleep(0)
        await stream_state["stream"].started.wait()

    async def fake_fingerprint(devices, _settings, _cancel, progress, *, multicast=False):
        stream = stream_state["stream"]
        assert job.progress.fast_scan_complete is True
        assert stream.discovered == 1
        assert stream.finished is False
        stream_state["fingerprinting_while_rce_active"] = True
        progress.lan_fingerprint_started = True
        progress.lan_fingerprint_done = True
        progress.lan_fingerprint_total = progress.lan_fingerprint_completed = len(devices)
        return {"status": "completed", "target_count": len(devices), "matched": 0}

    monkeypatch.setattr(engine, "RceVerifyBatchStream", FakeStream)
    monkeypatch.setattr(engine.ScanEngine, "_run", fake_scan)
    monkeypatch.setattr(engine.lan_fingerprint, "fingerprint_devices", fake_fingerprint)
    asyncio.run(engine.ScanEngine(settings).run(job, asyncio.Event()))

    assert stream_state["fingerprinting_while_rce_active"] is True
    assert stream_state["stream"].finished is True
    assert job.state == JobState.completed
    assert job.progress.rce_verify_done is True
