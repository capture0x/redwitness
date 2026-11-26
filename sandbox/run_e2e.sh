#!/usr/bin/env bash
# Fully isolated E2E: PostgreSQL (unix socket only) + {fake LLM, API, UI, Chromium} inside a network namespace.
# Usage: sandbox/run_e2e.sh [mock|ollama]      Output: $E2E_WORKDIR (default: a temporary directory)/out
set -u
MODE="${1:-mock}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${E2E_WORKDIR:-$(mktemp -d)}"; mkdir -p "$WORK"
PGBIN="$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)"
# A unix socket path can be at most ~107 bytes: a SHORT directory owned by this script, for the socket files only.
SOCK="$(mktemp -d /tmp/rl-sock.XXXXXX)"
PIDS=()
cleanup() { "$PGBIN/pg_ctl" -D "$WORK/pgdata" -m immediate stop >/dev/null 2>&1; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$SOCK"; }
trap cleanup EXIT

"$PGBIN/initdb" -D "$WORK/pgdata" -U postgres -A trust -E UTF8 --no-sync >/dev/null
# NO TCP: unix socket only (sockets cross network namespaces)
"$PGBIN/pg_ctl" -D "$WORK/pgdata" -o "-c listen_addresses='' -c unix_socket_directories=$SOCK -c fsync=off" -w -l "$WORK/pg.log" start >/dev/null
"$PGBIN/psql" -h "$SOCK" -U postgres -qc "CREATE DATABASE aiveritx"
if [ "$MODE" = ollama ]; then
  python3 "$ROOT/sandbox/relay.py" outside --sock "$SOCK/ollama.sock" --target 127.0.0.1:11434 >"$WORK/relay-outside.log" 2>&1 & PIDS+=($!)
  sleep 1
fi
echo "work directory: $WORK"
unshare -rn bash "$ROOT/sandbox/inside_ns.sh" "$ROOT" "$WORK" "$MODE" "$SOCK"
RC=$?
echo "exit code: $RC   outputs: $WORK/out"
exit $RC
