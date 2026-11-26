#!/usr/bin/env bash
# Looks for a FAKE api key / cookie / password you typed during a test run in every place it must NOT be:
# container logs, the database dump, temp files inside the containers, and (optionally) files you downloaded (PDF/CSV/JSON).
#
# Usage:
#   FAKE_KEY='sk-FAKE-leaktest-9f3a7c1d2b' ./scripts/secret-leak-check.sh [extra-file ...]
#   FAKE_KEY=... SESSION_COOKIE='<value of rl_session from browser dev tools>' ./scripts/secret-leak-check.sh ~/Downloads/report.pdf
# Use a made-up key (not a real one) for this test. The script prints only WHERE a match was found, never the matched value.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${FAKE_KEY:?set FAKE_KEY to the fake key you typed in the target form}"
COOKIE="${SESSION_COOKIE:-}"
ADMIN_PW="$(grep -E '^AIVERITX_ADMIN_PASSWORD=' .env 2>/dev/null | cut -d= -f2-)"
SIGNKEY="$(grep -E '^AIVERITX_SCOPE_KEYS=' .env 2>/dev/null | cut -d= -f2- | sed 's/^[^:]*://')"
PGPW="$(grep -E '^POSTGRES_PASSWORD=' .env 2>/dev/null | cut -d= -f2-)"

# name=secret pairs to search for (empty values are skipped)
NAMES=(fake_key session_cookie admin_password scope_signing_key postgres_password)
VALUES=("$FAKE_KEY" "$COOKIE" "$ADMIN_PW" "$SIGNKEY" "$PGPW")

hits=0; checked=0
report() { printf '  %-6s %s\n' "$1" "$2"; }
scan() {  # scan <label> <file>
  local label="$1" file="$2" i
  checked=$((checked+1))
  for i in "${!NAMES[@]}"; do
    [ -n "${VALUES[$i]}" ] || continue
    if grep -aqF -- "${VALUES[$i]}" "$file" 2>/dev/null; then
      report "LEAK" "${NAMES[$i]} found in: $label"; hits=$((hits+1))
    fi
  done
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "== 1. Container logs (db, backend, frontend)"
for s in db backend frontend; do
  docker compose logs --no-color "$s" > "$T/log-$s.txt" 2>&1 && scan "docker logs: $s" "$T/log-$s.txt" || report "SKIP" "cannot read logs of $s (is it running?)"
done

echo "== 2. Database content (full SQL dump)"
if docker compose exec -T db pg_dump -U aiveritx aiveritx > "$T/db.sql" 2>"$T/db.err"; then
  scan "database dump (all tables, incl. audit log)" "$T/db.sql"
  # the dump should also contain NO bearer/cookie-looking header text
  if grep -aiE "authorization: *bearer [A-Za-z0-9._-]{12,}|rl_session=[A-Za-z0-9._-]{12,}" "$T/db.sql" >/dev/null; then
    report "LEAK" "a Bearer token / rl_session cookie pattern is in the database dump"; hits=$((hits+1))
  fi
else report "SKIP" "pg_dump failed: $(head -c 200 "$T/db.err")"; fi

echo "== 3. Files inside the containers (/tmp, app dir, uploads)"
for s in backend frontend; do
  if docker compose exec -T "$s" sh -c 'tar -cf - /tmp /app 2>/dev/null' > "$T/fs-$s.tar" 2>/dev/null && [ -s "$T/fs-$s.tar" ]; then
    scan "files in container $s (/tmp, /app)" "$T/fs-$s.tar"
  else report "SKIP" "could not archive /tmp,/app of $s"; fi
done

echo "== 4. Container metadata (docker inspect: env, args)"
docker compose ps -q 2>/dev/null | xargs -r docker inspect > "$T/inspect.json" 2>/dev/null
# Keys placed in .env on purpose (env_file) are EXPECTED here; the fake key typed in the UI must not be.
if [ -s "$T/inspect.json" ]; then
  grep -aqF -- "$FAKE_KEY" "$T/inspect.json" && { report "LEAK" "fake_key found in docker inspect output"; hits=$((hits+1)); }
  checked=$((checked+1))
fi

echo "== 5. Files you pass as arguments (PDF / CSV / JSON exports)"
for f in "$@"; do
  [ -f "$f" ] || { report "SKIP" "not a file: $f"; continue; }
  case "$f" in
    *.pdf) if command -v pdftotext >/dev/null; then pdftotext "$f" "$T/pdf.txt" 2>/dev/null; scan "PDF text: $f" "$T/pdf.txt"; fi; scan "PDF raw bytes: $f" "$f" ;;
    *)     scan "file: $f" "$f" ;;
  esac
done

echo "== 6. Host working tree (the repo directory, excluding .env and dependencies)"
if grep -rIlF --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=.next --exclude-dir=_archive --exclude=.env --exclude=secret-leak-check.sh --exclude=REAL_WORLD_CHECKLIST.md -- "$FAKE_KEY" . 2>/dev/null | head -5 | grep . ; then
  report "LEAK" "fake_key found in the files listed above"; hits=$((hits+1))
fi

echo
echo "Sources checked: $checked   Leaks: $hits"
if [ "$hits" -eq 0 ]; then echo "RESULT: PASS - no tested secret was found in logs, database, temp files or exports."; else echo "RESULT: FAIL - see LEAK lines above. Do NOT publish until fixed."; fi
exit $(( hits > 0 ))
