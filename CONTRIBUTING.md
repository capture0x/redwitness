# Contributing to RedWitness

Thank you for helping. RedWitness is a security tool, so a good contribution is one that makes results **more trustworthy**, not only more numerous. This guide shows how to get set up and what a pull request needs.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Ways to help

- **Report a bug** or **suggest a feature** with the issue templates. A clear reproduction beats a long description.
- **Improve the docs**: unclear wording, a missing step, a wrong command.
- **Add test library content** (cases, templates, importer layouts) using harmless marker text.
- **Fix a bug or build a feature.** For anything larger than a small fix, open an issue first so we can agree on the approach.

## Design rules (please keep them)

These are the reasons the results can be trusted. A change that weakens one is unlikely to be accepted.

1. **The engine holds no attack content.** Test messages, tool definitions and transform wording live in the versioned, hashed test library, never in Python or TypeScript.
2. **Safety controls live in code, outside the model.** Scope, limits, addresses and permissions are enforced by code. Text from the target or from a judge is untrusted data.
3. **Every request to a target goes through the signed-scope gate and the Governor.** No shortcut, not even for tests of a new feature.
4. **Evidence over opinion.** A finding needs a verbatim quote, a replay and, where code can decide, a deterministic rule. A model never overrules evidence the code can check.
5. **Nothing dangerous is generated or executed.** Fake tools return canned text, model files are parsed and never loaded, shell output is never run.
6. **Secrets never reach the database.** API keys live in `.env` or server memory only.

## Development setup

You need Docker with Compose v2 for the full stack, Python 3.12+, Node 20.9+ and PostgreSQL 14+ for local work.

```bash
git clone https://github.com/capture0x/redwitness.git && cd redwitness
./install.sh --yes          # full stack at http://localhost:3000
```

### Running without Docker

```bash
# Backend
cd backend && python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
export REDWITNESS_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/redwitness
export REDWITNESS_SCOPE_KEYS=k1:$(python -c "import secrets;print(secrets.token_hex(32))")
export REDWITNESS_ADMIN_PASSWORD='at-least-12-characters'
uvicorn main:create_app --factory --host 127.0.0.1 --port 8000

# UI (another terminal)
cd frontend && npm install && npm run dev          # http://localhost:3000  (/api -> 127.0.0.1:8000)
```

To run the production build locally, use `npm run build && npm start`. The build uses `output: "standalone"`, so `npm start` runs `node .next/standalone/server.js` and the `postbuild` step copies `.next/static` next to it. Plain `next start` is not the right command for this build (use `npm run start:next` only if you know why); without the copied assets the page loads without JavaScript and stays on "Verifying session…". The Dockerfile does the same copy.

Folders: `backend/` (FastAPI, engine, tests), `frontend/` (Next.js), `runner/` (sandbox runner), `sandbox/` (isolated E2E), `docs/`.

## Tests

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest tests -q
cd frontend && npm ci && npm run typecheck && npm run build
sandbox/run_e2e.sh mock                         # strict browser checks inside an isolated network namespace
```

- Backend tests are **hermetic**: a real PostgreSQL, a fake target and a fake judge. A test must never reach the outside network.
- Add or update a test with every change. A bug fix starts with a test that fails.
- A change that touches scope, Governor, replay, impact, verifier or sandbox code needs a test that proves the **refusal** path too, not only the happy path.
- If you change visible UI text or the menu, update `frontend/e2e/e2e.mjs`.
- **Isolated E2E (`sandbox/`)** runs in a network namespace where only the `lo` interface remains (`unshare -rn`) and proves on every run that outside network access is impossible. It can also run with real local Ollama models (`sandbox/run_e2e.sh ollama`). Latest run output: [`docs/e2e-run/`](docs/e2e-run/).
- **Module E2E (`sandbox/e2e_modules.py`)** runs after the UI test and drives Defense efficacy, reasoning chains and sandboxed verification through the real HTTP API with the real runner process. No model and no API key needed.
- **CI** (`.github/workflows/ci.yml`): backend (PostgreSQL service, Python 3.12 and 3.14), UI (`npm ci`, typecheck, build), `pip-audit` and `npm audit --omit=dev`. Dependabot runs weekly.

## Code style

- Python: type hints, small functions, no new dependency without a reason in the PR.
- TypeScript: strict types, no `any` in new code where a type is easy to write; reuse the components in `frontend/components/ui`.
- Keep the existing look (glassmorphism, spacing, colours). Use `EmptyState` for empty pages and `Label help="..."` for field help.
- Comments explain **why**, not what. Remove commented-out code.
- Error messages tell the person what to do next ("Open Settings → Judge LLM and ..."), not only what failed.
- Write English in code, comments, UI text and docs.

## Pull requests

1. Fork, create a branch (`fix/replay-count`, `feat/new-importer`), keep the change focused.
2. Run the tests above and fill in the pull request template.
3. Write a commit message that says what and why, in the imperative ("Cap text-only bypass at high").
4. Be ready for review comments; small follow-up commits are fine, we squash on merge.

## Adding test library content

Library files are JSON or YAML (see `docs/` and `backend/starter_kit/`). Rules for contributed cases:

- Use harmless marker text and planted canaries. No real credentials, no working malware, no personal data.
- Tag every case with its category and, where it fits, `attack_family` and `owasp_category`.
- Say in the PR where the idea comes from. Imported payloads from other projects must respect their licence.

## Questions

Open a discussion or an issue with the question label. Please search existing issues first.
