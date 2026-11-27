#!/usr/bin/env bash
# RedWitness installer: checks Docker, creates .env with random secrets, asks for the judge key, then builds and starts the whole stack.
#   ./install.sh                interactive
#   ./install.sh --yes          no questions (reads ANTHROPIC_API_KEY / REDWITNESS_PORT from the environment)
#   ./install.sh --sandbox      also start the isolated sandbox runner
#   ./install.sh --no-start     prepare .env only
set -euo pipefail
cd "$(dirname "$0")"

START=1; PASS=()
for a in "$@"; do
  case "$a" in
    --no-start) START=0 ;;
    -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) PASS+=("$a") ;;
  esac
done

red()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { red "$*"; exit 1; }

bold "RedWitness installer"
if [ "$START" = 1 ]; then
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Engine or Docker Desktop first: https://docs.docker.com/get-docker/"
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing. Update Docker, or install the compose plugin: https://docs.docker.com/compose/install/"
  docker info >/dev/null 2>&1 || die "Cannot reach the Docker daemon. Start Docker, or add your user to the docker group, then run this again."
fi

NEW_ENV=0; [ -e .env ] || NEW_ENV=1
export REDWITNESS_INSTALLER=1
./scripts/init-env.sh | sed 's/^/  /'
./scripts/setup-wizard.sh "${PASS[@]+"${PASS[@]}"}"

PORT="$(grep -E '^REDWITNESS_PORT=' .env | tail -n1 | cut -d= -f2-)"; PORT="${PORT:-3000}"
if [ "$START" = 0 ]; then
  echo "Prepared .env. Start later with: docker compose up -d --build"
  exit 0
fi

if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$"; then
  if ! docker compose ps --status running 2>/dev/null | grep -q frontend; then
    die "Port ${PORT} is already in use. Choose another with ./install.sh --port 3100 (or set REDWITNESS_PORT in .env)."
  fi
fi

bold "Building and starting (the first build takes a few minutes)..."
if ! docker compose up -d --build --wait --wait-timeout 420; then
  red "Something did not become healthy. Last lines of each service:"
  docker compose ps
  docker compose logs --tail 20
  die "Fix the problem above and run ./install.sh again (nothing was lost; .env is kept)."
fi

echo
bold "RedWitness is running: http://localhost:${PORT}"
if [ "$NEW_ENV" = 1 ]; then
  echo "  Username : admin"
  echo "  Password : $(grep -E '^REDWITNESS_ADMIN_PASSWORD=' .env | cut -d= -f2-)   (first sign-in only; change it on the Users page)"
fi
echo "  Back up REDWITNESS_SCOPE_KEYS in .env: without it, signed scopes can no longer be verified."
grep -qE '^ANTHROPIC_API_KEY=.+|^OPENAI_API_KEY=.+' .env || echo "  No judge key yet: add ANTHROPIC_API_KEY to .env, run 'docker compose up -d', then open Settings."
echo "  The Getting started panel on the dashboard takes you through the first scan."
