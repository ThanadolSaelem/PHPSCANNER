"""The engine must not report phantom devices when a proxy/firewall answers
for every address (e.g. a transparent proxy on 80/443)."""
import asyncio
from datetime import datetime, timezone

from app.config import Settings
from app.models import ScanJob, ScanRequest
from app.scanner import discovery, engine as eng, http_probe, port_scanner

PROXY_FP = "403|content-type,x-deny-reason|"
REAL_FP = "200|content-type,server,x-powered-by|Apache"


async def test_phantom_hosts_are_dropped(monkeypatch, tmp_path):
    async def fake_intercepted(ports, timeout, canary=discovery.CANARY_IP):
        return {80}

    async def fake_alive(ip, ports, timeout):
        # only the intercepted port 80 ever "answers"
        return (80 in ports), 3

    async def fake_open_ports(ip, ports, timeout):
        return [80]

    async def fake_probe(client, ip, port):
        if ip == "10.0.0.2":  # the one real web server
            return http_probe.WebResult(port=80, scheme="http", status_code=200,
                                        server="Apache", php_version="8.3.10",
                                        fingerprint=REAL_FP)
        return http_probe.WebResult(port=80, scheme="http", status_code=403,
                                    fingerprint=PROXY_FP)

    monkeypatch.setattr(discovery, "intercepted_ports", fake_intercepted)
    monkeypatch.setattr(discovery, "alive_latency", fake_alive)
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {})
    monkeypatch.setattr(port_scanner, "open_ports", fake_open_ports)
    monkeypatch.setattr(http_probe, "probe_service", fake_probe)

    s = Settings(); s.web_ports = [80]; s.liveness_ports = []; s.data_dir = str(tmp_path)
    job = ScanJob(id="t", created_at=datetime.now(timezone.utc),
                  request=ScanRequest(targets=["10.0.0.1-10.0.0.4"]))
    await eng.ScanEngine(s).run(job, asyncio.Event())

    assert job.state.value == "completed", job.error
    assert [d.ip for d in job.devices] == ["10.0.0.2"]
    assert job.progress.online == 1
    assert job.intercepted_ports == [80]


def test_fingerprint_ignores_volatile_headers():
    a = http_probe.response_fingerprint(403, {"date": "x", "content-type": "t", "x-deny-reason": "p"})
    b = http_probe.response_fingerprint(403, {"date": "y", "content-type": "t", "x-deny-reason": "p"})
    assert a == b
