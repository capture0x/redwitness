#!/usr/bin/env bash
# Interactive setup: asks for the judge LLM key, the UI port and the optional sandbox runner, and writes the answers to .env (mode 600).
# Safe to run again: existing values are kept unless you type a new one. Without a terminal (CI, pipes) nothing is asked.
#   ./scripts/setup-wizard.sh            ask questions
#   ./scripts/setup-wizard.sh --yes      ask nothing; take ANTHROPIC_API_KEY / REDWITNESS_PORT from the environment if set
set -euo pipefail
cd "$(dirname "$0")/.."

ASSUME_YES=0; SANDBOX=0; PORT_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1 ;;
    --sandbox) SANDBOX=1 ;;
    --port) PORT_ARG="${2:-}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -e .env ] || { echo ".env is missing: run ./scripts/init-env.sh first." >&2; exit 1; }
INTERACTIVE=0; [ "$ASSUME_YES" = 0 ] && [ -t 0 ] && INTERACTIVE=1

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
get_env() { grep -E "^$1=" .env | tail -n1 | cut -d= -f2- || true; }
set_env() {
  local k="$1" v="$2" tmp; tmp="$(mktemp .env.XXXXXX)"
  grep -v "^${k}=" .env > "$tmp" || true
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  chmod 600 "$tmp"; mv "$tmp" .env
}
valid_secret() { [[ "$1" =~ ^[A-Za-z0-9._~+/=:-]{8,300}$ ]]; }

if [ "$INTERACTIVE" = 1 ]; then
  bold "RedWitness setup"
  echo "Keys are written only to .env on this machine (never to the database) and are not shown on screen."
  echo
  echo "1) Judge LLM: the model that decides whether an answer broke a rule. A strong model is recommended."
  echo "   [1] Anthropic (Claude)   [2] OpenAI or another OpenAI-compatible API   [3] Skip, I will add a key later"
  read -r -p "Choose 1-3 [1]: " choice; choice="${choice:-1}"
  case "$choice" in
    1) var=ANTHROPIC_API_KEY ;;
    2) var=OPENAI_API_KEY ;;
    *) var="" ;;
  esac
  if [ -n "$var" ]; then
    cur="$(get_env "$var")"
    if [ -n "$cur" ]; then
      read -r -p "$var is already set. Keep it? [Y/n]: " keep; [[ "${keep:-Y}" =~ ^[Nn] ]] && cur=""
    fi
    if [ -z "$cur" ]; then
      read -r -s -p "Paste your $var (input hidden, Enter to skip): " key; echo
      if [ -z "$key" ]; then echo "Skipped. Add it to .env later."
      elif valid_secret "$key"; then set_env "$var" "$key"; echo "Saved $var."
      else echo "That does not look like an API key (spaces or odd characters). Skipped; add it to .env by hand." >&2; fi
    fi
    [ "$var" = OPENAI_API_KEY ] && echo "After sign-in choose Settings -> Judge LLM -> provider openai_compat, set the model and endpoint, and enter OPENAI_API_KEY as the key variable name."
  fi
  echo
  read -r -p "2) UI port on this machine [$(get_env REDWITNESS_PORT)]: " port; PORT_ARG="${port:-$PORT_ARG}"
  echo
  echo "3) Optional sandbox runner: analyses unsafe model output (HTML, SQL) in an isolated container with no network."
  read -r -p "Enable it? [y/N]: " sb; [[ "${sb:-N}" =~ ^[Yy] ]] && SANDBOX=1
else
  [ -n "${ANTHROPIC_API_KEY:-}" ] && [ -z "$(get_env ANTHROPIC_API_KEY)" ] && valid_secret "$ANTHROPIC_API_KEY" && set_env ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY"
  [ -z "$PORT_ARG" ] && PORT_ARG="${REDWITNESS_PORT:-}"
fi

if [ -n "$PORT_ARG" ]; then
  if [[ "$PORT_ARG" =~ ^[0-9]+$ ]] && [ "$PORT_ARG" -ge 1024 ] && [ "$PORT_ARG" -le 65535 ]; then set_env REDWITNESS_PORT "$PORT_ARG"
  else echo "Port must be a number from 1024 to 65535; keeping $(get_env REDWITNESS_PORT)." >&2; fi
fi
[ "$SANDBOX" = 1 ] && set_env COMPOSE_PROFILES sandbox
exit 0
