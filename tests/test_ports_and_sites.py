"""Port profiles, website (link) targets and the same-host redirect rule."""
import asyncio
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main
from app.config import settings
from app.models import ScanJob, ScanRequest
from app.scanner import http_probe, netlimit, ports, sites


# --- ports -----------------------------------------------------------------
def test_parse_ports_ranges_and_dedup():
    assert ports.parse_ports("22, 80,80 8000-8002") == [22, 80, 8000, 8001, 8002]


@pytest.mark.parametrize("spec", ["", "abc", "0", "70000", "90-80", "1-65535"])
def test_parse_ports_rejects_bad_input(spec):
    with pytest.raises(ports.PortSpecError):
        ports.parse_ports(spec)


def test_profiles_always_include_web_ports():
    assert ports.profile_ports("web", "", [80, 8443]) == [80, 8443]
    common = ports.profile_ports("common", "", [80, 8443])
    assert {22, 3389, 80, 8443} <= set(common)
    assert len(ports.profile_ports("top100", "", [80])) == 100
    with pytest.raises(ports.PortSpecError):
        ports.profile_ports("everything", "", [80])


def test_describe_known_and_unknown():
    assert ports.describe(3389)["name"] == "RDP" and ports.describe(3389)["note"]
    assert ports.describe(22)["note"] is None
    assert ports.describe(4444)["name"] == "ไม่ทราบ"


# --- sites -----------------------------------------------------------------
def test_site_parse_and_check():
    s = sites.parse("https://www.agency.go.th/path")
    assert (s.host, s.port) == ("www.agency.go.th", 443)
    # a government domain is allowed regardless of where it resolves (CDN, public IP)
    s.ips = ["10.1.2.3"]
    assert sites.check(s, ["go.th"]) == []
    s.ips = ["8.8.8.8"]
    assert sites.check(s, ["go.th"]) == []
    other = sites.parse("example.com")
    assert "ไม่ใช่โดเมนหน่วยงาน" in sites.check(other, ["go.th"])[0]


@pytest.mark.parametrize("text", ["ftp://a.go.th", "http://10.0.0.1/", "a_b.go.th", "x" * 3000])
def test_site_parse_rejects(text):
    with pytest.raises(sites.SiteError):
        sites.parse(text)


# --- API -------------------------------------------------------------------
@pytest.fixture
def api(monkeypatch):
    created = []

    async def fake_create(req: ScanRequest):
        created.append(req)
        return ScanJob(id="x", created_at=datetime.now(timezone.utc), request=req)

    async def fake_resolve(site, timeout=4.0):
        site.ips = {"web.agency.go.th": ["10.9.9.9"], "cdn.agency.go.th": ["8.8.8.8"],
                    "shop.example.com": ["10.9.9.8"]}[site.host]
        return site

    monkeypatch.setattr(main.store, "create", fake_create)
    monkeypatch.setattr(sites, "resolve", fake_resolve)
    monkeypatch.setattr(settings, "allowed_cidrs", ["10.0.0.0/8"])
    monkeypatch.setattr(settings, "gov_suffixes", ["go.th"])
    return TestClient(main.app), created


def test_scan_by_link_uses_resolved_ip_and_host(api):
    client, created = api
    r = client.post("/api/scans", json={"sites": ["http://web.agency.go.th:8081/"],
                                         "site_hosts": {"1.1.1.1": "evil"}})
    assert r.status_code == 200, r.text
    req = created[0]
    assert req.targets == ["10.9.9.9"]
    assert req.site_hosts == {"10.9.9.9": "web.agency.go.th"}  # client value ignored
    assert req.extra_web_ports == [8081]


def test_gov_link_out_of_scope_is_allowed(api):
    # cdn.agency.go.th resolves to 8.8.8.8 (outside THSCAN_ALLOWED_CIDRS) but is
    # a government domain, so it is scanned — scope does not bind website targets.
    client, created = api
    r = client.post("/api/scans", json={"sites": ["cdn.agency.go.th"]})
    assert r.status_code == 200, r.text
    assert created[0].targets == ["8.8.8.8"]
    assert created[0].site_hosts == {"8.8.8.8": "cdn.agency.go.th"}


def test_non_gov_link_is_refused(api):
    client, created = api
    assert client.post("/api/scans", json={"sites": ["shop.example.com"]}).status_code == 403
    assert not created


def test_direct_ip_target_still_bound_by_scope(api):
    # the deploy-time IP scope still applies to directly-typed IP/CIDR targets
    client, created = api
    assert client.post("/api/scans", json={"targets": ["8.8.8.0/24"]}).status_code == 403
    assert client.post("/api/scans", json={"targets": ["10.0.0.0/28"]}).status_code == 200


def test_resolve_preview(api):
    client, _ = api
    res = client.get("/api/resolve", params={"q": "web.agency.go.th\nshop.example.com"}).json()["sites"]
    assert res[0]["ips"] == ["10.9.9.9"] and not res[0]["problems"]
    assert res[1]["refused"] is True  # not a government domain
    # a government domain outside the IP scope is not refused
    gov = client.get("/api/resolve", params={"q": "cdn.agency.go.th"}).json()["sites"][0]
    assert gov["refused"] is False and not gov["problems"]


def test_port_profile_validation_and_budget(api, monkeypatch):
    client, _ = api
    bad = client.post("/api/scans", json={"targets": ["10.0.0.1"], "port_profile": "custom",
                                           "custom_ports": "99999"})
    assert bad.status_code == 400
    monkeypatch.setattr(settings, "max_port_probes", 1000)
    big = client.post("/api/scans", json={"targets": ["10.0.0.0/24"], "port_profile": "top100"})
    assert big.status_code == 400 and "เกินขีดจำกัด" in big.json()["detail"]
    ok = client.post("/api/scans", json={"targets": ["10.0.0.0/28"], "port_profile": "web"})
    assert ok.status_code == 200


# --- HTTP probe --------------------------------------------------------------
async def test_probe_sends_host_and_sni_and_stays_on_host():
    seen = []

    def handler(request: httpx.Request):
        seen.append((str(request.url), request.headers.get("host"), request.extensions.get("sni_hostname")))
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "https://web.agency.go.th/home",
                                                "x-powered-by": "PHP/8.3.10"})
        if request.url.path == "/home":
            return httpx.Response(302, headers={"location": "https://evil.example/steal"})
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await http_probe._try(client, "http", "10.9.9.9", 80, "web.agency.go.th")
    assert [u for u, _, _ in seen] == ["http://10.9.9.9/", "https://10.9.9.9/home"]
    assert seen[1][1] == "web.agency.go.th" and seen[1][2] == "web.agency.go.th"
    assert res is not None and res.php_version == "8.3.10"  # header from the first hop kept


def test_connection_limiter_works_across_event_loops():
    async def use():
        async with netlimit.slot():
            return True

    assert asyncio.run(use()) and asyncio.run(use())


async def test_engine_scans_site_by_host_and_lists_services(monkeypatch, tmp_path):
    from app.config import Settings
    from app.scanner import discovery, engine as eng, port_scanner

    calls = []

    async def fake_intercepted(ports_, timeout, canary=discovery.CANARY_IP):
        return {3128}  # a proxy port that answers for every address

    async def fake_alive(ip, ports_, timeout):
        return True, 4

    async def fake_open(ip, ports_, timeout):
        return [p for p in (22, 443, 3128, 3306) if p in ports_]

    async def fake_probe(client, ip, port, host=None):
        calls.append((ip, port, host))
        return http_probe.WebResult(port=port, scheme="https", status_code=200,
                                    php_version="8.4.27", fingerprint="x")

    monkeypatch.setattr(discovery, "intercepted_ports", fake_intercepted)
    monkeypatch.setattr(discovery, "alive_latency", fake_alive)
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {})
    monkeypatch.setattr(port_scanner, "open_ports", fake_open)
    monkeypatch.setattr(http_probe, "probe_service", fake_probe)

    s = Settings(); s.web_ports = [80, 443]; s.liveness_ports = []; s.data_dir = str(tmp_path)
    req = ScanRequest(targets=["10.9.9.9"], port_profile="top100",
                      site_hosts={"10.9.9.9": "web.agency.go.th"})
    job = ScanJob(id="t", created_at=datetime.now(timezone.utc), request=req)
    await eng.ScanEngine(s).run(job, asyncio.Event())

    assert job.state.value == "completed", job.error
    (d,) = job.devices
    assert d.hostname == "web.agency.go.th" and d.matched_suffix == "go.th"
    assert calls == [("10.9.9.9", 443, "web.agency.go.th")]
    assert [x.port for x in d.services] == [22, 443, 3306]  # 3128 was the proxy
    assert d.services[2].name == "MySQL" and d.services[2].note
    assert job.target_label == "web.agency.go.th"
