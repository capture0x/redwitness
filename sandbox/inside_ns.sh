#!/usr/bin/env bash
# Runs INSIDE the network namespace (called by run_e2e.sh). It only terminates the processes it started itself.
set -u
ROOT="$1"; WORK="$2"; MODE="$3"; SOCK="$4"
OUT="$WORK/out"; mkdir -p "$OUT"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
start() { "$@" >>"$WORK/$(basename "$1").$$.log" 2>&1 & PIDS+=($!); }
waitport() { for _ in $(seq 1 120); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.5; done; echo "PORT $1 NOT READY"; return 1; }

ip link set lo up
{
  echo "== network interfaces (only loopback should exist)"; ip -br addr
  echo "== default route (there should be none)"; ip route show default | grep . || echo "none"
  echo "== outside network attempts (all must fail)"
  timeout 3 curl -s -o /dev/null -w "curl https://example.com -> %{http_code}\n" https://example.com || echo "curl https://example.com -> NO ACCESS"
  python3 - <<'PY'
import socket
for host in ("1.1.1.1", "8.8.8.8", "93.184.216.34"):
    try:
        socket.create_connection((host, 443), 2); print(host, "-> CONNECTED (!)")
    except OSError as e:
        print(host, "-> no access:", e.strerror)
PY
} | tee "$OUT/isolation.txt"

export REDWITNESS_DATABASE_URL="postgresql://postgres@/redwitness?host=$SOCK"
export REDWITNESS_SCOPE_KEYS="k1:$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
export REDWITNESS_ADMIN_PASSWORD="e2e-admin-password-1"
export NEXT_TELEMETRY_DISABLED=1 ANTHROPIC_API_KEY="" REDWITNESS_ALLOWED_HOSTS="localhost"

start python3 "$ROOT/sandbox/mock_llm.py" --port 9100
start python3 "$ROOT/sandbox/mock_mcp.py" --port 9400
mkdir -p "$WORK/jobs/in" "$WORK/jobs/out"; export REDWITNESS_SANDBOX_DIR="$WORK/jobs"
start env RUNNER_JOBS="$WORK/jobs" python3 "$ROOT/runner/runner.py"
if [ "$MODE" = ollama ]; then
  start python3 "$ROOT/sandbox/relay.py" inside --sock "$SOCK/ollama.sock" --port 11434
  start python3 "$ROOT/sandbox/target_app.py" --port 9200 --model "${TARGET_MODEL:-llama3.2:3b}"
fi
# NO SUBSHELL: PIDs must enter the PIDS array (PIDs recorded in a subshell are lost and the process lingers).
# `env -C` changes the directory; Next.js is started directly with node (npx creates no intermediate process, a single PID).
start env -C "$ROOT/backend" .venv/bin/python -m uvicorn main:create_app --factory --host 127.0.0.1 --port 8000 --log-level warning
start env -C "$ROOT/frontend" node node_modules/next/dist/bin/next start -p 3000
waitport 9100 && waitport 9400 && waitport 8000 && waitport 3000 || { echo "INFRASTRUCTURE DID NOT START"; for f in "$WORK"/*.log; do echo "--- $f"; tail -n 5 "$f"; done; exit 2; }
[ "$MODE" = ollama ] && { waitport 9200 || exit 2; }

cd "$ROOT/frontend"
if [ "$MODE" = ollama ]; then LIBF="$ROOT/sandbox/e2e_library_real.json"; else LIBF="$ROOT/sandbox/e2e_library.json"; fi
OUT="$OUT" MODE="$MODE" LIB="$LIBF" ADMIN_PW="$REDWITNESS_ADMIN_PASSWORD" node e2e/e2e.mjs 2>&1 | tee "$OUT/e2e-$MODE.log"
RC=${PIPESTATUS[0]}
if [ "$MODE" = mock ]; then
  ADMIN_PW="$REDWITNESS_ADMIN_PASSWORD" python3 "$ROOT/sandbox/e2e_modules.py" 2>&1 | tee "$OUT/e2e-modules.log"
  [ "${PIPESTATUS[0]}" -eq 0 ] || RC=1
fi
exit "$RC"
