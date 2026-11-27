#!/usr/bin/env bash
# Generates .env (if missing): a random PostgreSQL password, the scope signing key, the admin password and the session secret.
# It does NOT overwrite an existing .env (losing the signing key invalidates previously signed scopes).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -e .env ]; then
  echo ".env already exists; left untouched. (To start from scratch, back it up and delete it first.)"
  exit 0
fi

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
rand_pw()  { head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20; }

ADMIN_PW="$(rand_pw)"
umask 077
cat > .env <<EOF
POSTGRES_PASSWORD=$(rand_hex 16)
REDWITNESS_SCOPE_KEYS=k1:$(rand_hex 32)
REDWITNESS_ADMIN_PASSWORD=${ADMIN_PW}
REDWITNESS_SESSION_SECRET=$(rand_hex 32)
REDWITNESS_COOKIE_SECURE=0
REDWITNESS_PORT=3000
# Put your judge LLM key here (or give another variable name in Settings):
ANTHROPIC_API_KEY=
EOF

echo ".env created (mode 600)."
[ -n "${REDWITNESS_INSTALLER:-}" ] && exit 0
echo "  Username      : admin"
echo "  Password      : ${ADMIN_PW}   (REDWITNESS_ADMIN_PASSWORD in .env; change it on the Users page after the first sign-in)"
echo "  Signing key   : REDWITNESS_SCOPE_KEYS in .env - BACK IT UP"
echo "Next step      : docker compose up -d --build   ->  http://localhost:3000"
