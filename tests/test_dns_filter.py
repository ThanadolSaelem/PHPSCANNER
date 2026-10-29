from app.scanner.dns_resolver import match_suffix


SUFFIXES = ["go.th", "or.th", "mi.th"]


def test_matches_gov():
    assert match_suffix("www.mof.go.th", SUFFIXES) == "go.th"
    assert match_suffix("portal.nbtc.or.th", SUFFIXES) == "or.th"


def test_exact_suffix_match():
    assert match_suffix("go.th", SUFFIXES) == "go.th"


def test_case_and_trailing_dot_insensitive():
    assert match_suffix("WWW.MOF.GO.TH.", SUFFIXES) == "go.th"


def test_non_th_rejected():
    assert match_suffix("example.com", SUFFIXES) is None
    assert match_suffix("gov.uk", SUFFIXES) is None


def test_label_boundary_not_substring():
    # must not match a suffix that is only a trailing substring, not a label
    assert match_suffix("notgo.th", SUFFIXES) is None
    assert match_suffix("evilgo.th", SUFFIXES) is None


def test_lookalike_domain_rejected():
    # go.th appearing as a non-terminal label must not match
    assert match_suffix("www.go.th.attacker.com", SUFFIXES) is None


def test_none_hostname():
    assert match_suffix(None, SUFFIXES) is None


def test_leading_dot_suffix_config():
    assert match_suffix("x.ac.th", [".ac.th"]) == "ac.th"
