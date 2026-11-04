#!/usr/bin/env sh
# Start the full range: targets + the live scoreboard web UI.
# Open http://127.0.0.1:9000/ in a browser, scan 127.0.0.1:9001-9023, paste your
# results, and watch the board update. No Docker, no deps — stdlib only.
# For the headless CLI scorer instead, run: python3 evaluate.py  (see README).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
exec "$PY" "$HERE/range.py"
