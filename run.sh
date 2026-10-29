#!/usr/bin/env sh
# thscan — start the app locally (Linux / macOS). Usage: ./run.sh
set -e
cd "$(dirname "$0")"
PY=python3; command -v $PY >/dev/null 2>&1 || PY=python
if ! $PY -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  echo "[thscan] Python 3.11 or newer is required: https://www.python.org/downloads/"
  exit 1
fi
if [ ! -d .venv ]; then
  echo "[thscan] creating virtualenv..."
  $PY -m venv .venv
fi
. .venv/bin/activate
echo "[thscan] installing requirements..."
if ! pip install -q -r requirements.txt; then
  echo ""
  echo "[thscan] installing requirements failed."
  echo "  If .venv was made by an older checkout, delete it and run ./run.sh again:"
  echo "    rm -rf .venv && ./run.sh"
  exit 1
fi
PORT="${THSCAN_PORT:-8000}"
echo ""
echo "  thscan is running ->  http://localhost:$PORT"
echo "  (press Ctrl+C to stop)"
echo ""
( sleep 2; (xdg-open "http://localhost:$PORT" || open "http://localhost:$PORT") >/dev/null 2>&1 || true ) &
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
