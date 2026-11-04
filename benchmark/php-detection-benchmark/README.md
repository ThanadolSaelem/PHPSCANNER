# PHP2Shell Detection Benchmark

A tool-agnostic benchmark for *detecting* PHP2Shell exposure
(CVE-2026-109618 / CVE-2026-109619), aligned with the cloud-provider audit
guidance: version/patch evidence, **no exploitation**.

> This is **not** an exploit and **not** proof of code execution. Fixtures are
> canned HTTP responses served on `127.0.0.1` only. No PHP is run, no payload is
> sent. "Confirmed affected" is deliberately unreachable from an external banner
> alone — a version number can be backported.

23 ground-truth cases (see `cases.py`) cover every supported branch
(8.2–8.5) with fixed/one-below pairs, EOL branches (7.4, 5.6), hidden-version
signal variants (.php link, PHPSESSID, PHP error, patched-but-hidden), runtime
diversity (Apache mod_php, nginx+FPM, LiteSpeed, FrankenPHP), framework
fingerprints (WordPress, Laravel), real-world obstacles (CDN-stripped, Node
decoy, static), and the key distro-backport false-positive case.

## Range + live scoreboard (Juice-Shop style)

```sh
python3 range.py      # or ./run.sh   — then open http://127.0.0.1:9000/
```
Scan 127.0.0.1:9001-9023, paste your `{port: status}` into the board, and it
grades live (solved / exact / **FALSE-SAFE must be 0**). Docker: `docker compose up`.

## Headless CLI scorer

Runs standalone on `python3` alone (no thscan, no deps):

```sh
python3 fixtures.py &        # serve the 23 targets
python3 evaluate.py          # score the built-in reference detector
# or: PYTHON=python3 ./run.sh
```

Score any other tool by feeding its `{port: status}` output:

```sh
python3 evaluate.py --results tool.json
```

Or with Docker (reproducible, loopback-only):

```sh
./pin-digests.sh && docker compose up -d && python3 evaluate.py && docker compose down
```

`evaluate.py` is the thscan reference scorer; it reports **FALSE-SAFE** (must be
0), risk-class accuracy, exact-status accuracy, precision/recall, and
runtime/CMS accuracy. Another tool can reuse the fixtures + `cases.py` labels
with its own scorer. Thai docs: `README_TH.md`. Version sources: `SOURCES.md`.
