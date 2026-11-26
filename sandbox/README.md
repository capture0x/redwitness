# sandbox - isolated end-to-end (E2E) test environment

Nothing leaves for the outside network. `run_e2e.sh` leaves only the `lo` interface inside a **network namespace** (`unshare -rn`); as its first
step the script proves that outside access is impossible (`isolation.txt`), and the E2E test re-verifies this as a check.

```
sandbox/run_e2e.sh mock      # deterministic: fake target + fake judge, strict checks (≈6 min): RBAC, scope signing, runs, reports, **document cleanup, OWASP matrix/scan/filter, judge advisory**
sandbox/run_e2e.sh ollama    # real local models: target llama3.2:3b, judge qwen2.5-coder:7b (pipeline verification)
```
Requirements: `unshare` (user-namespace permission), PostgreSQL binaries (`/usr/lib/postgresql/*/bin`), `backend/.venv`
(`pip install -r backend/requirements.txt`), a built `frontend` (`npm run build`), the system Chromium (`CHROMIUM=/usr/bin/chromium`),
and a running local Ollama for the ollama mode. Output: `$E2E_WORKDIR/out` (screenshots, PDF, `results-*.json`).

| File | Purpose |
|---|---|
| `mock_llm.py` | Local fake LLM: the "AcmeBot" target (REST + SSE), `/ingest`, a deterministic judge. The vulnerabilities are not real techniques; they are test scaffolding triggered by `[[qa:...]]` markers. It also answers the plain requests of the OWASP starter kit with deliberately mixed behavior: some categories vulnerable, one unclear, most clean |
| `e2e_library.json` | An 11-case QA library (leak, unstable, multi-turn, inline/ingest documents, tool call, 429, refusal + variant) |
| `e2e_library_real.json` | 4 plain questions for the real model |
| `target_app.py` | A chat application built on Ollama (server-side hidden system instruction + canary) |
| `relay.py` | The ONLY bridge between the namespace and the local Ollama: a unix socket (the outside network stays closed) |
| `inside_ns.sh` / `run_e2e.sh` | Orchestration inside/outside the namespace; it only terminates the processes it started itself |
| `../frontend/e2e/e2e.mjs` | UI-driven scenario with a real Chromium (Playwright) |

PostgreSQL runs **outside** the namespace, over a unix socket only (no TCP): Postgres refuses to start as root and sockets cross
namespaces. The socket path is kept in a short `/tmp/rl-sock.*` directory because of the 107-byte limit (the script removes it itself).
Note: the fake judge is not an LLM; the mock mode exercises the pipeline (gates, engine, verification, reports, UI), not judge quality.
