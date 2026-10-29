import ipaddress

from app.scanner import discovery
from app.scanner.ip_utils import out_of_scope, label_targets


def test_infer_device_type():
    assert discovery.infer_device_type("192.168.1.1", [], False, False) == "Gateway Router"
    assert discovery.infer_device_type("192.168.1.254", [], False, False) == "Gateway Router"
    assert discovery.infer_device_type("192.168.1.20", [443], True, False) == "Web Server (HTTPS)"
    assert discovery.infer_device_type("192.168.1.21", [80], False, False) == "Web Server (HTTP)"
    assert discovery.infer_device_type("192.168.1.50", [], False, True) == "LAN Device"


def test_autodetect_returns_list():
    subs = discovery.autodetect_subnets()
    assert isinstance(subs, list)
    for s in subs:
        assert "cidr" in s and "name" in s
        ipaddress.ip_network(s["cidr"])  # valid CIDR


def test_read_arp_table_is_dict():
    # may be empty in a container, but must not raise and must be a dict
    assert isinstance(discovery.read_arp_table(), dict)


# --- scope enforcement ---
PRIV = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def test_scope_allows_private():
    assert out_of_scope(["192.168.1.0/24", "10.255.252.0/22"], PRIV) == []


def test_scope_rejects_public():
    bad = out_of_scope(["8.8.8.0/24"], PRIV)
    assert bad == ["8.8.8.0/24"]


def test_scope_rejects_range_crossing_boundary():
    # a /15 straddling outside 192.168/16 is not fully covered
    assert out_of_scope(["192.167.0.0/15"], PRIV) == ["192.167.0.0/15"]


def test_empty_scope_rejects_everything():
    assert out_of_scope(["10.0.0.0/24"], []) == ["10.0.0.0/24"]


def test_label_targets():
    assert label_targets(["10.0.0.0/22"]) == "10.0.0.0/22"
    assert label_targets(["10.0.0.0/24", "10.0.1.0/24"]) == "2 ช่วง"


def test_arp_line_parser_windows_and_mac():
    sample = ("  192.168.1.1          00-11-22-33-44-55     dynamic\n"
              "? (192.168.1.7) at 0:1b:2c:3:4d:5e on en0\n"
              "  192.168.1.255        ff-ff-ff-ff-ff-ff     static\n")
    found = {ip: mac for ip, mac in discovery._ARP_LINE.findall(sample)}
    assert "192.168.1.1" in found and "192.168.1.7" in found
