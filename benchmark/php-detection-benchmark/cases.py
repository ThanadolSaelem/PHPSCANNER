"""Ground-truth test matrix for PHP2Shell *detection* (CVE-2026-109618 /
CVE-2026-109619). Tool-agnostic: each case is an HTTP response a target would
return, plus the label a document-compliant external scan SHOULD produce.

This is a detection benchmark, not an exploit. No payloads are sent to anything;
the fixtures only serve these canned responses on 127.0.0.1. "Confirmed
affected" is deliberately NOT a label reachable from an external banner alone —
per the cloud-provider guidance, a version number can be backported, so a banner
only warrants "possibly_affected" until authorized internal evidence rules out a
backport.

label.status (document taxonomy):
    possibly_affected   banner shows a version below the branch fix (candidate)
    evidence_of_patch   banner shows a version at/above the branch fix
    undetermined        PHP is present but the version is hidden / unreliable
    none                no reliable evidence of PHP at all
    confirmed_affected  only with authorized internal evidence (not external)

label.risk (coarse, for precision/recall & the safety metric):
    at_risk | not_at_risk | needs_verification

label.realworld (optional): the ground truth a perfect internal check would
reach, when it differs from what an external scan can see (e.g. a distro
backport). Used to document false-positive risk, not scored against the scanner.
"""

FIX = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
PHP_LINK = '<!doctype html><meta charset="utf-8"><title>app</title><a href="/info.php">info</a>'
PLAIN = '<!doctype html><meta charset="utf-8"><title>home</title><p>static page</p>'
WP_BODY = '<!doctype html><meta name="generator" content="WordPress 6.6"><link href="/wp-content/themes/x/style.css">'
PHP_ERR = ('<br /><b>Warning</b>: include(): Failed opening required file '
           'in <b>/var/www/app.php</b> on line <b>42</b><br />')


def case(cid, port, title, status, headers, body, exp_status, risk,
         version=None, runtime=None, cms=None, realworld=None, note=""):
    return {
        "id": cid, "port": port, "title": title,
        "response": {"status": status, "headers": headers, "body": body},
        "label": {"status": exp_status, "risk": risk, "version": version,
                  "runtime": runtime, "cms": cms, "realworld": realworld, "note": note},
    }


def _apache(v, exposed=True):
    h = {"Server": "Apache/2.4.62 (Debian)"}
    if exposed:
        h["X-Powered-By"] = f"PHP/{v}"
    return h


CASES = [
    # --- A. version boundary per supported branch (Apache + mod_php, exposed) ---
    case("82-vuln", 9001, "PHP 8.2.34 · exposed", 200, _apache("8.2.34"), PLAIN,
         "possibly_affected", "at_risk", "8.2.34", "PHP 8.2.34"),
    case("82-fixed", 9002, "PHP 8.2.35 · exposed", 200, _apache("8.2.35"), PLAIN,
         "evidence_of_patch", "not_at_risk", "8.2.35", "PHP 8.2.35"),
    case("83-vuln", 9003, "PHP 8.3.35 · exposed", 200, _apache("8.3.35"), PLAIN,
         "possibly_affected", "at_risk", "8.3.35", "PHP 8.3.35"),
    case("83-fixed", 9004, "PHP 8.3.36 · exposed", 200, _apache("8.3.36"), PLAIN,
         "evidence_of_patch", "not_at_risk", "8.3.36", "PHP 8.3.36"),
    case("84-vuln", 9005, "PHP 8.4.26 · exposed", 200, _apache("8.4.26"), PLAIN,
         "possibly_affected", "at_risk", "8.4.26", "PHP 8.4.26"),
    case("84-fixed", 9006, "PHP 8.4.27 · exposed", 200, _apache("8.4.27"), PLAIN,
         "evidence_of_patch", "not_at_risk", "8.4.27", "PHP 8.4.27"),
    case("85-vuln", 9007, "PHP 8.5.11 · exposed (newest branch)", 200, _apache("8.5.11"), PLAIN,
         "possibly_affected", "at_risk", "8.5.11", "PHP 8.5.11"),
    case("85-fixed", 9008, "PHP 8.5.12 · exposed", 200, _apache("8.5.12"), PLAIN,
         "evidence_of_patch", "not_at_risk", "8.5.12", "PHP 8.5.12"),

    # --- B. EOL branches (no upstream fix; distro may still backport) ---
    case("74-eol", 9009, "PHP 7.4.33 · EOL · exposed", 200, _apache("7.4.33"), PLAIN,
         "possibly_affected", "at_risk", "7.4.33", "PHP 7.4.33",
         note="EOL upstream; a distro LTS may still backport — verify on the box"),
    case("56-eol", 9010, "PHP 5.6.40 · ancient EOL · exposed", 200, _apache("5.6.40"), PLAIN,
         "possibly_affected", "at_risk", "5.6.40", "PHP 5.6.40"),

    # --- C. hidden version (expose_php Off) — the signal matrix ---
    case("hidden-link", 9011, "8.2.34 hidden · only a .php link", 200,
         _apache("8.2.34", exposed=False), PHP_LINK,
         "undetermined", "needs_verification", None, None,
         note="no X-Powered-By; PHP inferred from the .php link only"),
    case("hidden-cookie", 9012, "hidden · PHPSESSID cookie", 200,
         {"Server": "Apache/2.4.62", "Set-Cookie": "PHPSESSID=9f1c2b; path=/; HttpOnly"}, PLAIN,
         "undetermined", "needs_verification", None, None,
         note="PHP inferred from the session cookie"),
    case("hidden-error", 9013, "hidden · PHP error in body", 200,
         {"Server": "Apache/2.4.62"}, PHP_ERR,
         "undetermined", "needs_verification", None, None,
         note="PHP inferred from a runtime error shape"),
    case("hidden-patched", 9014, "8.2.35 PATCHED but hidden", 200,
         _apache("8.2.35", exposed=False), PHP_LINK,
         "undetermined", "needs_verification", None, None,
         realworld="evidence_of_patch",
         note="patched in reality, but a hidden version must NOT be read as fixed"),

    # --- D. runtime / server fingerprint diversity ---
    case("nginx-fpm", 9015, "nginx + PHP-FPM · 8.3.35", 200,
         {"Server": "nginx/1.27.2", "X-Powered-By": "PHP/8.3.35"}, PLAIN,
         "possibly_affected", "at_risk", "8.3.35", "PHP 8.3.35"),
    case("litespeed", 9016, "LiteSpeed · 8.2.34", 200,
         {"Server": "LiteSpeed", "X-Powered-By": "PHP/8.2.34"}, PLAIN,
         "possibly_affected", "at_risk", "8.2.34", "PHP 8.2.34"),
    case("frankenphp", 9017, "FrankenPHP (Caddy) · 8.3.36", 200,
         {"Server": "Caddy", "X-Powered-By": "PHP/8.3.36"}, PLAIN,
         "evidence_of_patch", "not_at_risk", "8.3.36", "PHP 8.3.36"),

    # --- E. framework signals (hidden version, CMS detection) ---
    case("wordpress-hidden", 9018, "WordPress · hidden version", 200,
         {"Server": "Apache/2.4.62", "Set-Cookie": "wordpress_test_cookie=1; path=/"}, WP_BODY,
         "undetermined", "needs_verification", None, None, cms="WordPress"),
    case("laravel-hidden", 9019, "Laravel · hidden version", 200,
         {"Server": "nginx", "Set-Cookie": "laravel_session=eyJ; path=/; HttpOnly"}, PHP_LINK,
         "undetermined", "needs_verification", None, None, cms="Laravel"),

    # --- F. real-world obstacles / decoys ---
    case("cdn-stripped", 9020, "behind CDN · headers stripped", 200,
         {"Server": "cloudflare", "CF-Ray": "abc"}, PLAIN,
         "none", "not_at_risk", None, None,
         realworld="unknown",
         note="external scan is blind here; could be PHP behind the CDN — a coverage limit, not 'safe'"),
    case("node-decoy", 9021, "Node.js / Express (not PHP)", 200,
         {"Server": "nginx", "X-Powered-By": "Express"}, PLAIN,
         "none", "not_at_risk", None, "Node.js · Express"),
    case("static-nginx", 9022, "static site · no PHP", 200,
         {"Server": "nginx/1.27.2"}, PLAIN,
         "none", "not_at_risk", None, None),

    # --- G. the key false-positive case: distro backport ---
    case("backport", 9023, "distro backport · old number, patched", 200,
         {"Server": "Apache/2.4.62 (Ubuntu)", "X-Powered-By": "PHP/8.1.2"}, PHP_LINK,
         "possibly_affected", "at_risk", "8.1.2", "PHP 8.1.2",
         realworld="evidence_of_patch",
         note="package 8.1.2-1ubuntu2.19 is backport-patched; external scan must flag for "
              "verification, NOT confirm — internal evidence moves it to fixed"),
]

# quick integrity check when run directly
if __name__ == "__main__":
    ports = [c["port"] for c in CASES]
    assert len(ports) == len(set(ports)), "duplicate ports"
    print(f"{len(CASES)} cases, ports {min(ports)}–{max(ports)}")
