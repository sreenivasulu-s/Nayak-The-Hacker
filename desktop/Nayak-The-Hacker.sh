#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_LOG="/tmp/nayak-backend.log"
FRONTEND_LOG="/tmp/nayak-frontend.log"

cd "$ROOT"

# Start backend
if ! curl -fsS http://127.0.0.1:8000/ >/dev/null 2>&1; then
    if [ -x "$HOME/vuln-scanner/venv/bin/python" ]; then
        PY="$HOME/vuln-scanner/venv/bin/python"
    else
        PY="python3"
    fi

    nohup "$PY" -m uvicorn backend.main:app \
        --host 127.0.0.1 \
        --port 8000 \
        </dev/null >"$BACKEND_LOG" 2>&1 &
fi

# Serve production frontend
if ! curl -fsS http://127.0.0.1:5173/ >/dev/null 2>&1; then
    nohup python3 -m http.server 5173 \
        --bind 127.0.0.1 \
        --directory "$ROOT/frontend/dist" \
        </dev/null >"$FRONTEND_LOG" 2>&1 &
fi

sleep 2

# Launch app-like Chromium window
chromium \
    --app=http://127.0.0.1:5173/ \
    --disable-session-crashed-bubble \
    --no-first-run \
    --disable-features=Translate \
    >/tmp/nayak-chromium.log 2>&1 &
