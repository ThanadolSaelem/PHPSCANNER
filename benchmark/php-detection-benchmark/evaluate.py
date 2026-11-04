"""Score a PHP2Shell *detection* tool against the benchmark ground truth.

Reference scorer for thscan: it probes each running fixture with thscan's own
HTTP detection path (app.scanner.http_probe + vuln_rules), maps the result to
the document's four-status taxonomy, and reports:

  - exact-status accuracy   (strict: matches the document status)
  - risk-class accuracy      (at_risk / not_at_risk / needs_verification)
  - FALSE-SAFE count         (the critical metric: a host that is at_risk or
                              needs_verification but was reported not_at_risk)
  - precision / recall for the "at_risk" class
  - runtime / CMS accuracy

Another tool can reuse the fixtures + cases.py labels and plug in its own
scorer; only this file is thscan-specific.
"""
import asyncio
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

from cases import CASES  # noqa: E402
from app.scanner import http_probe, vuln_rules  # noqa: E402

HOST = "127.0.0.1"

# thscan's php_status -> the document's four-status taxonomy. thscan is stricter
# on a bare banner (it says "affected"); the document reserves "confirmed" for
# internal evidence, so this mapping makes the deviation visible, not hidden.
THSCAN_TO_DOC = {
    "affected": "confirmed_affected",
    "likely": "possibly_affected",
    "fixed": "evidence_of_patch",
    "unverified": "undetermined",
    "none": "none",
}
RISK = {
    "confirmed_affected": "at_risk", "possibly_affected": "at_risk",
    "evidence_of_patch": "not_at_risk", "none": "not_at_risk",
    "undetermined": "needs_verification",
}


async def thscan_status(port):
    async with http_probe.build_client(6.0, 2.0) as client:
        wr = await http_probe.probe_service(client, HOST, port)
    if wr is None:
        return "none", None, None, None
    ver = wr.php_version
    pv = vuln_rules.parse_php_version(f"PHP/{ver}") if ver else None
    seen = bool(ver) or any(f.rule_id == "php-undetermined" for f in wr.findings)
    return vuln_rules.php2shell_status(pv, seen), ver, wr.runtime, wr.cms


async def main():
    rows, exact_ok, risk_ok, false_safe = [], 0, 0, 0
    tp = fp = fn = 0  # for the at_risk class (treating needs_verification as its own bucket)
    rt_ok = rt_tot = cms_ok = cms_tot = 0

    for c in CASES:
        lab = c["label"]
        st, ver, runtime, cms = await thscan_status(c["port"])
        doc = THSCAN_TO_DOC[st]
        got_risk = RISK[doc]
        exp_risk = lab["risk"]
        ex = (doc == lab["status"])
        rk = (got_risk == exp_risk)
        exact_ok += ex
        risk_ok += rk
        # the one error we never tolerate: calling an at-risk/needs-verify host safe
        fs = exp_risk in ("at_risk", "needs_verification") and got_risk == "not_at_risk"
        false_safe += fs
        # precision/recall for "at_risk"
        if exp_risk == "at_risk" and got_risk == "at_risk":
            tp += 1
        elif exp_risk != "at_risk" and got_risk == "at_risk":
            fp += 1
        elif exp_risk == "at_risk" and got_risk != "at_risk":
            fn += 1
        if lab["runtime"]:
            rt_tot += 1
            rt_ok += bool(runtime and lab["runtime"].split()[0].lower() in runtime.lower())
        if lab["cms"]:
            cms_tot += 1
            cms_ok += (cms == lab["cms"])
        rows.append((c["id"], lab["status"], doc, exp_risk, got_risk, ex, rk, fs, lab.get("note", "")))

    n = len(CASES)
    w = max(len(r[0]) for r in rows)
    print(f"\n{'case':<{w}}  {'expected':<18} {'thscan→doc':<18} risk(exp/got)   exact risk  flag")
    print("-" * (w + 74))
    for cid, exp, doc, er, gr, ex, rk, fs, note in rows:
        flag = "FALSE-SAFE!" if fs else ("" if ex else "status-dev")
        print(f"{cid:<{w}}  {exp:<18} {doc:<18} {er:>7}/{gr:<7}  {'Y' if ex else '-':^5} {'Y' if rk else '-':^4}  {flag}")

    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    print("\n== summary ==")
    print(f"cases                 : {n}")
    print(f"exact-status accuracy : {exact_ok}/{n} ({100*exact_ok//n}%)")
    print(f"risk-class accuracy   : {risk_ok}/{n} ({100*risk_ok//n}%)")
    print(f"FALSE-SAFE            : {false_safe}   (must be 0 — a hidden/at-risk host called safe)")
    print(f"at_risk precision     : {prec:.2f}   recall: {rec:.2f}")
    print(f"runtime accuracy      : {rt_ok}/{rt_tot}")
    print(f"CMS accuracy          : {cms_ok}/{cms_tot}")
    print("\nnote: 'status-dev' = thscan reports a bare banner as confirmed-affected while the")
    print("document reserves that for internal evidence (expects possibly_affected). Same risk")
    print("bucket, stricter wording. FALSE-SAFE is the only failure that matters for safety.")
    # fail the run only on a genuine safety error
    return 1 if false_safe else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
