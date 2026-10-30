"""Deep mode: nmap XML / traceroute parsers and the engine's deep path."""
import asyncio
from datetime import datetime, timezone

from app.config import Settings
from app.models import ScanJob, ScanRequest
from app.scanner import nmap_scan


def test_parse_nmap_xml_open_ports_and_service():
    xml = """<nmaprun><host><status state="up"/>
      <address addr="10.0.0.9" addrtype="ipv4"/>
      <hostnames><hostname name="box.local"/></hostnames>
      <ports>
        <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
        <port protocol="tcp" portid="18080"><state state="open"/>
          <service name="http" product="Apache httpd" version="2.4.58" extrainfo="PHP 8.2.10"/></port>
      </ports></host></nmaprun>"""
    hosts = nmap_scan.parse_nmap_xml(xml)
    h = hosts["10.0.0.9"]
    assert h.up and h.hostname == "box.local"
    assert list(h.ports) == [18080]          # closed port 22 dropped
    assert h.ports[18080].label() == "Apache httpd 2.4.58"
    assert h.ports[18080].extra == "PHP 8.2.10"


def test_parse_nmap_xml_handles_garbage():
    assert nmap_scan.parse_nmap_xml("not xml") == {}
    assert nmap_scan.parse_nmap_xml("<nmaprun></nmaprun>") == {}


def test_parse_traceroute_with_timeouts():
    text = ("traceroute to 10.0.0.5 (10.0.0.5), 20 hops max\n"
            " 1  10.0.0.1  1.21 ms\n"
            " 2  * \n"
            " 3  10.0.0.5  3.4 ms\n")
    hops = nmap_scan.parse_traceroute(text)
    assert hops == [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.2},
        {"hop": 2, "ip": None, "rtt_ms": None},
        {"hop": 3, "ip": "10.0.0.5", "rtt_ms": 3.4},
    ]


async def test_engine_deep_mode_uses_nmap_and_traceroute(monkeypatch, tmp_path):
    from app.scanner import discovery, engine as eng, http_probe

    async def fake_intercepted(ports_, timeout, canary=discovery.CANARY_IP):
        return set()

    async def fake_run_nmap(targets, ports, timeout=240.0, extra_args=None):
        h = nmap_scan.NmapHost(ip="10.0.0.9", up=True)
        # PHP on a non-standard port, read by nmap -sV (no header probe needed)
        h.ports[18080] = nmap_scan.NmapPort(port=18080, name="http",
                                            product="Apache httpd", version="2.4.58",
                                            extra="PHP 8.2.10")
        h.ports[3306] = nmap_scan.NmapPort(port=3306, name="mysql", product="MySQL", version="8.0")
        return {"10.0.0.9": h}

    async def fake_traceroute(ip, **kw):
        return [{"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0},
                {"hop": 2, "ip": ip, "rtt_ms": 2.0}]

    async def fake_probe(client, ip, port, host=None):
        return None  # header probe reads nothing; nmap must carry the detection

    monkeypatch.setattr(discovery, "intercepted_ports", fake_intercepted)
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {})
    monkeypatch.setattr(nmap_scan, "nmap_available", lambda: True)
    monkeypatch.setattr(nmap_scan, "traceroute_available", lambda: True)
    monkeypatch.setattr(nmap_scan, "run_nmap", fake_run_nmap)
    monkeypatch.setattr(nmap_scan, "run_traceroute", fake_traceroute)
    monkeypatch.setattr(http_probe, "probe_service", fake_probe)

    s = Settings(); s.web_ports = [80, 443]; s.liveness_ports = []; s.data_dir = str(tmp_path)
    req = ScanRequest(targets=["10.0.0.9"], port_profile="custom",
                      custom_ports="18080,3306", scan_mode="deep")
    job = ScanJob(id="d", created_at=datetime.now(timezone.utc), request=req)
    await eng.ScanEngine(s).run(job, asyncio.Event())

    assert job.state.value == "completed", job.error
    assert job.scan_mode == "deep"
    (d,) = job.devices
    assert d.php_version == "8.2.10"          # pulled from nmap -sV
    assert d.severity.value == "critical"     # PHP2Shell assessed from it
    assert any(f.rule_id == "php2shell" for f in d.findings)
    prods = {sp.port: sp.product for sp in d.services}
    assert prods[18080] == "Apache httpd 2.4.58" and prods[3306] == "MySQL 8.0"
    assert [h.ip for h in d.route] == ["10.0.0.1", "10.0.0.9"]  # traceroute path


async def test_deep_mode_falls_back_when_nmap_missing(monkeypatch, tmp_path):
    from app.scanner import discovery, engine as eng, http_probe, port_scanner

    async def fake_intercepted(ports_, timeout, canary=discovery.CANARY_IP):
        return set()

    async def fake_alive(ip, ports_, timeout):
        return False, None

    async def fake_open(ip, ports_, timeout):
        return []

    monkeypatch.setattr(discovery, "intercepted_ports", fake_intercepted)
    monkeypatch.setattr(discovery, "alive_latency", fake_alive)
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {})
    monkeypatch.setattr(port_scanner, "open_ports", fake_open)
    monkeypatch.setattr(nmap_scan, "nmap_available", lambda: False)  # not installed

    s = Settings(); s.web_ports = [80]; s.liveness_ports = []; s.data_dir = str(tmp_path)
    req = ScanRequest(targets=["10.0.0.9"], port_profile="web", scan_mode="deep")
    job = ScanJob(id="f", created_at=datetime.now(timezone.utc), request=req)
    await eng.ScanEngine(s).run(job, asyncio.Event())
    assert job.state.value == "completed"  # ran via the fast path, no crash
    # the badge must not claim "deep" when it ran fast; the note explains why
    assert job.scan_mode == "fast" and job.note_deep and "nmap" in job.note_deep


async def test_deep_falls_back_when_nmap_returns_nothing(monkeypatch, tmp_path):
    from app.scanner import discovery, engine as eng, http_probe, port_scanner

    async def none_set(*a, **k):
        return set()

    async def fake_alive(ip, ports_, timeout):
        return False, None

    async def fake_open(ip, ports_, timeout):
        return []

    async def empty_nmap(targets, ports, timeout=240.0, extra_args=None):
        return {}  # nmap ran but found nothing (timeout / egress blocked)

    monkeypatch.setattr(discovery, "intercepted_ports", none_set)
    monkeypatch.setattr(discovery, "alive_latency", fake_alive)
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {})
    monkeypatch.setattr(port_scanner, "open_ports", fake_open)
    monkeypatch.setattr(nmap_scan, "nmap_available", lambda: True)
    monkeypatch.setattr(nmap_scan, "run_nmap", empty_nmap)

    s = Settings(); s.web_ports = [80]; s.liveness_ports = []; s.data_dir = str(tmp_path)
    req = ScanRequest(targets=["10.0.0.9"], port_profile="web", scan_mode="deep")
    job = ScanJob(id="e", created_at=datetime.now(timezone.utc), request=req)
    await eng.ScanEngine(s).run(job, asyncio.Event())
    assert job.state.value == "completed"
    assert job.scan_mode == "fast"          # fell back → badge says fast
    assert job.note_deep and "ถอยไปใช้โหมดเร็ว" in job.note_deep


async def test_deep_custom_ports_21_22_high_latency_subnet(monkeypatch, tmp_path):
    from app.scanner import discovery, dns_resolver, engine as eng, http_probe

    captured_argv = []

    async def fake_run(argv, timeout):
        captured_argv.extend(argv)
        return """<nmaprun><host><status state="up"/>
          <address addr="203.158.167.4" addrtype="ipv4"/>
          <hostnames><hostname name="1now.rmutl.ac.th"/></hostnames>
          <ports>
            <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.5"/></port>
            <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
          </ports></host></nmaprun>"""

    async def fake_intercepted(ports_, timeout, canary=discovery.CANARY_IP):
        return set()

    async def fake_alive(ip, ports_, timeout):
        return (ip == "203.158.167.4"), (530 if ip == "203.158.167.4" else None)

    async def fake_resolve_match(self, ip, suffixes):
        if ip == "203.158.167.4":
            return ip, "1now.rmutl.ac.th", "ac.th"
        return ip, None, None

    monkeypatch.setattr(nmap_scan, "nmap_available", lambda: True)
    monkeypatch.setattr(nmap_scan, "traceroute_available", lambda: False)
    monkeypatch.setattr(nmap_scan, "_run", fake_run)
    monkeypatch.setattr(discovery, "intercepted_ports", fake_intercepted)
    monkeypatch.setattr(discovery, "alive_latency", fake_alive)
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {})
    monkeypatch.setattr(dns_resolver.ReverseResolver, "resolve_and_match", fake_resolve_match)

    s = Settings()
    s.data_dir = str(tmp_path)
    req = ScanRequest(
        targets=["203.158.167.0/29"],
        port_profile="custom",
        custom_ports="21, 22",
        scan_mode="deep",
    )
    job = ScanJob(id="rmutl", created_at=datetime.now(timezone.utc), request=req)
    await eng.ScanEngine(s).run(job, asyncio.Event())

    assert job.state.value == "completed", job.error
    assert job.scanned_ports == [21, 22]
    assert "-T3" in captured_argv
    assert "21,22" in captured_argv
    assert job.progress.online == 1
    assert len(job.devices) == 1
    dev = job.devices[0]
    assert dev.ip == "203.158.167.4"
    assert dev.hostname == "1now.rmutl.ac.th"
    assert dev.latency_ms == 530
    assert [sp.port for sp in dev.services] == [21, 22]
