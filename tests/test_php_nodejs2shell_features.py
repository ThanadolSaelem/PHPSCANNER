"""Unit tests for features integrated from PHP-NodeJS2Shell:
1. IEEE OUI MAC Vendor Lookup & Device Category Inference (app/scanner/mac_vendors.py)
2. Tamper-Evident SHA-256 Hash-Chained Audit Log (app/audit.py)
3. Multi-Vector L3/L4 UDP/ICMP Host Discovery (app/scanner/discovery.py)
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

from app.audit import AuditLog, GENESIS_HASH
from app.scanner import discovery
mac_vendors = discovery


def test_mac_vendor_lookup_and_category_inference():
    assert mac_vendors.lookup_mac_vendor("00:11:32:aa:bb:cc") == "Synology Inc."
    assert mac_vendors.lookup_mac_vendor("24-5E-BE-11-22-33") == "QNAP Systems"
    assert mac_vendors.lookup_mac_vendor("c0:56:e3:01:02:03") == "Hikvision Digital"
    assert mac_vendors.lookup_mac_vendor("4c:5e:0c:99:88:77") == "MikroTik (RouterBoard)"
    assert mac_vendors.lookup_mac_vendor("00:50:56:12:34:56") == "VMware"
    assert mac_vendors.lookup_mac_vendor("02:42:ac:11:00:02") == "Docker Container"
    assert mac_vendors.lookup_mac_vendor("00:00:00:00:00:00") is None
    assert mac_vendors.lookup_mac_vendor(None) is None

    # Device type inference enriched by MAC vendor
    assert discovery.infer_device_type("10.0.0.50", [], False, False, mac="00:11:32:aa:bb:cc") == "NAS Storage"
    assert discovery.infer_device_type("10.0.0.60", [], False, False, mac="c0:56:e3:01:02:03") == "IP Camera / NVR"
    assert discovery.infer_device_type("10.0.0.70", [], False, False, mac="00:09:0f:01:02:03") == "Gateway Router"


def test_audit_log_sha256_hash_chain_and_tamper_detection():
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(tmp)
        e1 = log.record("scan_started", job_id="job1", targets=["10.0.0.0/24"])
        e2 = log.record("scan_finished", job_id="job1", online=5, risks=1)
        assert e1["prev_hash"] == GENESIS_HASH
        assert len(e1["sha256"]) == 64
        assert e2["prev_hash"] == e1["sha256"]
        assert len(e2["sha256"]) == 64

        v = log.verify_chain()
        assert v["valid"] is True
        assert v["checked"] == 2
        assert v["head_sha256"] == e2["sha256"]

        # Persist across reload
        log2 = AuditLog(tmp)
        e3 = log2.record("export_csv", job_id="job1")
        assert e3["prev_hash"] == e2["sha256"]
        assert log2.verify_chain()["valid"] is True
        assert log2.verify_chain()["checked"] == 3

        # Tamper with an entry on disk -> verify_chain() must detect it
        log_path = Path(tmp) / "audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["online"] = 999  # altered without recomputing sha256 chain
        lines[1] = json.dumps(tampered, ensure_ascii=False)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert log2.verify_chain()["valid"] is False


def test_multi_vector_discovery_fallback():
    calls = []

    async def fake_probe_port(ip, port, timeout):
        return False, None

    async def fake_mv_probe(ip, timeout=0.65):
        calls.append(ip)
        return True, 4.2, "udp-netbios-icmp-unreach"

    orig_probe = discovery._probe_port
    orig_mv = discovery.multi_vector_probe
    try:
        discovery._probe_port = fake_probe_port
        discovery.multi_vector_probe = fake_mv_probe

        # Private IP with enable_multi_vector=True falls back to UDP/ICMP multi-vector probe
        up, lat = asyncio.run(
            discovery.alive_latency("192.168.1.55", [80, 443], 1.0, enable_multi_vector=True)
        )
        assert up is True and lat == 4
        assert calls == ["192.168.1.55"]
    finally:
        discovery._probe_port = orig_probe
        discovery.multi_vector_probe = orig_mv
