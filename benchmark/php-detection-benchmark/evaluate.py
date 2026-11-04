"""Score a PHP2Shell *detection* result against the benchmark ground truth.

Standalone: needs only the Python standard library (no thscan, no deps). It
fetches each running fixture over HTTP and classifies it with a built-in
reference detector that follows the cloud-provider audit taxonomy, then reports:

  - exact-status accuracy   (matches the document status)
  - risk-class accuracy      (at_risk / not_at_risk / needs_verification)
  - FALSE-SAFE count         (the critical metric: an at-risk/needs-verify host
                              reported not_at_risk — must be 0)
  - precision / recall for the "at_risk" class
  - runtime / CMS accuracy

Modes:
  python3 evaluate.py                 # score the built-in reference detector
  python3 evaluate.py --results f.json# score another tool's output instead
                                      # f.json = {"9001":"possibly_affected", ...}
                                      # (document taxonomy, or thscan's native
                                      #  affected/likely/fixed/unverified/none)

Run fixtures.py first (or `./run.sh` to do both).
"""
import argparse
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cases import CASES  # noqa: E402

HOST = "127.0.0.1"
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
RISK = {
    "confirmed_affected": "at_risk", "possibly_affected": "at_risk",
    "evidence_of_patch": "not_at_risk", "none": "not_at_risk",
    "undetermined": "needs_verification",
}
# a tool that emits thscan's native statuses is mapped into the document taxonomy
THSCAN_TO_DOC = {
    "affected": "confirmed_affected", "likely": "possibly_affected",
    "fixed": "evidence_of_patch", "unverified": "undetermined", "none": "none",
}

_VER = re.compile(r"php[/ ]?v?(\d+)\.(\d+)\.(\d+)", re.I)
_PHP_REF = re.compile(r"""(?:href|src|action)\s*=\s*['"](?!https?:|//)[^'"]*\.php(?:[?#][^'"]*)?['"]""", re.I)
_PHP_ERR = re.compile(r"</b> on line <b>\d+</b>|Call to undefined function|<title>phpinfo", re.I)


def fetch(port):
    req = urllib.request.Request(f"http://{HOST}:{port}/", headers={"User-Agent": "benchmark/1.0"})
    with urllib.request.urlopen(req, timeout=6) as r:
        raw = r.read(262144)
        enc = r.headers.get_content_charset() or "utf-8"
        body = raw.decode(enc, "replace")
        hdr = {k.lower(): v for k, v in r.headers.items()}
        cookies = "; ".join(r.headers.get_all("Set-Cookie") or [])
        if cookies:
            hdr["set-cookie"] = cookies
        return hdr, body


def detect_cms(body, hdr):
    t, cookie = body.lower(), hdr.get("set-cookie", "").lower()
    if "wp-content" in t or "wp-includes" in t or 'content="wordpress' in t or "wordpress_" in cookie:
        return "WordPress"
    if "laravel_session" in cookie or "xsrf-token" in cookie:
        return "Laravel"
    if 'content="joomla' in t or "/media/jui/" in t:
        return "Joomla"
    if "drupal.settings" in t or 'content="drupal' in t:
        return "Drupal"
    return None


def reference_classify(hdr, body):
    """The document-aligned reference detector (what a correct tool should do)."""
    pb, server = hdr.get("x-powered-by", ""), hdr.get("server", "")
    low = pb.lower()
    m = _VER.search(pb) or _VER.search(server)
    version = (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None
    cms = detect_cms(body, hdr)
    node = "express" in low or "next.js" in low or re.search(r"\bnode(?:\.js)?\b", low + " " + server.lower())
    php_sig = ("php" in low or "phpsessid" in hdr.get("set-cookie", "").lower()
               or bool(_PHP_REF.search(body)) or bool(_PHP_ERR.search(body)) or bool(cms))

    if version is not None and "php" in low:
        branch = (version[0], version[1])
        fix = FIXED.get(branch)
        if fix:
            status = "possibly_affected" if version < fix else "evidence_of_patch"
        else:
            status = "possibly_affected"  # EOL or a branch with no published fix row
        runtime = "PHP %d.%d.%d" % version
    elif php_sig and not node:
        status, runtime = "undetermined", "PHP"
    elif node:
        status, runtime = "none", ("Node.js · Express" if "express" in low else "Node.js")
    else:
        status, runtime = "none", (server or None)
    return status, runtime, cms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", help="JSON {port: status} from a tool under test")
    args = ap.parse_args()
    tool = None
    if args.results:
        with open(args.results, encoding="utf-8") as f:
            tool = {str(k): v for k, v in json.load(f).items()}

    rows = []
    exact_ok = risk_ok = false_safe = tp = fp = fn = 0
    rt_ok = rt_tot = cms_ok = cms_tot = 0
    unreached = []

    for c in CASES:
        lab, port = c["label"], str(c["port"])
        try:
            hdr, body = fetch(c["port"])
        except Exception as e:  # noqa: BLE001
            unreached.append((c["id"], str(e)))
            continue
        if tool is not None:
            raw = tool.get(port, "none")
            status = THSCAN_TO_DOC.get(raw, raw)
            runtime, cms = None, None
        else:
            status, runtime, cms = reference_classify(hdr, body)
        got_risk, exp_risk = RISK.get(status, "not_at_risk"), lab["risk"]
        ex, rk = (status == lab["status"]), (got_risk == exp_risk)
        fs = exp_risk in ("at_risk", "needs_verification") and got_risk == "not_at_risk"
        exact_ok += ex; risk_ok += rk; false_safe += fs
        if exp_risk == "at_risk" and got_risk == "at_risk":
            tp += 1
        elif exp_risk != "at_risk" and got_risk == "at_risk":
            fp += 1
        elif exp_risk == "at_risk":
            fn += 1
        if tool is None and lab["runtime"]:
            rt_tot += 1; rt_ok += bool(runtime and lab["runtime"].split()[0].lower() in runtime.lower())
        if tool is None and lab["cms"]:
            cms_tot += 1; cms_ok += (cms == lab["cms"])
        rows.append((c["id"], lab["status"], status, exp_risk, got_risk, ex, fs))

    w = max((len(r[0]) for r in rows), default=4)
    print(f"\n{'case':<{w}}  {'expected':<18} {'got':<18} risk(exp/got)      exact flag")
    print("-" * (w + 70))
    for cid, exp, got, er, gr, ex, fs in rows:
        flag = "FALSE-SAFE!" if fs else ("" if ex else "status-dev")
        print(f"{cid:<{w}}  {exp:<18} {got:<18} {er:>7}/{gr:<10} {'Y' if ex else '-':^5} {flag}")

    n = len(rows)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    print("\n== summary ==")
    print(f"scored                : {n}/{len(CASES)}  ({'reference detector' if tool is None else args.results})")
    if unreached:
        print(f"UNREACHED             : {len(unreached)}  (is fixtures.py running? {unreached[:3]})")
    print(f"exact-status accuracy : {exact_ok}/{n} ({100*exact_ok//n if n else 0}%)")
    print(f"risk-class accuracy   : {risk_ok}/{n} ({100*risk_ok//n if n else 0}%)")
    print(f"FALSE-SAFE            : {false_safe}   (must be 0)")
    print(f"at_risk precision     : {prec:.2f}   recall: {rec:.2f}")
    if tool is None:
        print(f"runtime accuracy      : {rt_ok}/{rt_tot}")
        print(f"CMS accuracy          : {cms_ok}/{cms_tot}")
    print("\n'status-dev' = right risk bucket, different exact wording (e.g. a tool that calls a")
    print("bare banner 'confirmed' where the document expects 'possibly'). FALSE-SAFE is the")
    print("only failure that matters for safety.")
    return 1 if (false_safe or unreached) else 0


if __name__ == "__main__":
    sys.exit(main())
