import pytest

from app.scanner.ip_utils import TargetError, expand_targets, count_targets


def test_cidr_expansion_excludes_network_broadcast():
    ips, total = expand_targets(["203.0.113.0/30"], 100)
    # /30 => 4 addresses, .hosts() yields the 2 usable ones
    assert ips == ["203.0.113.1", "203.0.113.2"]
    assert total == 2


def test_slash31_includes_both():
    ips, _ = expand_targets(["203.0.113.0/31"], 100)
    assert ips == ["203.0.113.0", "203.0.113.1"]


def test_hyphen_range():
    ips, total = expand_targets(["198.51.100.10-198.51.100.12"], 100)
    assert ips == ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
    assert total == 3


def test_hyphen_shorthand_last_octet():
    ips, _ = expand_targets(["198.51.100.10-12"], 100)
    assert ips == ["198.51.100.10", "198.51.100.11", "198.51.100.12"]


def test_single_ip():
    ips, _ = expand_targets(["203.0.113.7"], 100)
    assert ips == ["203.0.113.7"]


def test_dedup_across_specs():
    ips, total = expand_targets(["203.0.113.1", "203.0.113.1/32"], 100)
    assert ips == ["203.0.113.1"]
    assert total == 2  # raw count counts both, list is deduped


def test_cap_enforced():
    with pytest.raises(TargetError):
        expand_targets(["10.0.0.0/8"], 65536)


def test_invalid_rejected():
    with pytest.raises(TargetError):
        expand_targets(["not-an-ip"], 100)
    with pytest.raises(TargetError):
        expand_targets(["203.0.113.50-203.0.113.10"], 100)  # end before start


def test_ipv6_rejected():
    with pytest.raises(TargetError):
        expand_targets(["2001:db8::/120"], 100)


def test_count_targets():
    assert count_targets(["203.0.113.0/30", "203.0.113.7"]) == 3
    assert count_targets(["# comment", ""]) == 0
