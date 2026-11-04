#!/usr/bin/env sh
# Start the fixtures locally, score thscan against them, then stop.
# No Docker required. Run from this directory.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"

"$PY" "$HERE/fixtures.py" &
FX=$!
trap 'kill "$FX" 2>/dev/null || true' EXIT
# wait for the first fixture to answer
i=0
while [ "$i" -lt 40 ]; do
  if "$PY" - <<PYCHK 2>/dev/null; then break; fi
import socket,sys
s=socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1",9001))==0 else 1)
PYCHK
  i=$((i+1)); sleep 0.25
done

"$PY" "$HERE/evaluate.py"
