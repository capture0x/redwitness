# Real-world verification checklist

Everything so far was verified against a scripted mock target and judge. This list is for the first run against a **real hosted model** with a **real judge**. Only test models and accounts you own or are authorised to test, and set a spending cap on the API keys you use.

## A. Bring the stack up
1. `./scripts/init-env.sh` (creates `.env`, mode 600; prints the admin password).
2. Put the **judge** key in `.env` (`ANTHROPIC_API_KEY=...`). For an OpenAI target you can also add `OPENAI_API_KEY=...` and refer to it by name (*API key variable*), so the key is never typed into the UI.
3. `docker compose up -d --build`, then `docker compose ps`. Expected: `db` healthy, `backend` healthy, `frontend` up.
4. `docker compose logs backend | tail -30`: no traceback; no key text.
5. Open http://localhost:3000 and sign in as `admin`.

## B. Judge and target (UI)
1. **Settings → Judge:** provider `anthropic`, model e.g. `claude-sonnet-5-5`, key variable `ANTHROPIC_API_KEY`. The status bar must stop showing "judge not configured".
2. **Targets → New:** provider `openai_compat`, base URL `https://api.openai.com/v1` (the engine appends `/chat/completions`), model of your choice, and either *API key variable* `OPENAI_API_KEY` **or** paste the key (kept in server memory only; it is gone after a backend restart).
3. Keep the judge and the target on **different** models/accounts if you can; a model grading itself is weaker evidence.

## C. First real scan
1. **Quick scan:** pick the target, accept the plan. Read the plan screen: the request/token caps (`max_requests` 600, `max_total_tokens` 400k) are the ceiling, not the expectation. A first run is cheap, but watch the provider's usage page.
2. For a cheaper first run use **Library → Import** with `docs/examples/real-target-smoke.json` (3 probes) and run it against a scope that allows `prompt_injection_direct` and `system_prompt_extraction`.
3. Approve the signed scope (the approval dialog lists exactly what is granted; `branching_allowed` and similar must be off).

### What to check during and after the run
| Where | Expected |
|---|---|
| **Live stream** | Attempts appear one by one with outcome (`judged:...`, `refused`, `error`); token and request counters rise; the run ends in `completed` (or `stopped` after the stop button) - never stuck on `running`. |
| **Errors** | HTTP 401/403 from the target means key or URL is wrong (the message should name the status, not the key). 429 should show backoff, not a crash. |
| **Findings** | Each finding has: class, severity, the verbatim **quote** from the response, judge reasoning, replay result (2 of 3 style verification), OWASP/ATLAS/ASI badges. `RT-001`: a modern model usually passes (no finding); a finding there is worth reading closely. |
| **False positives** | Open every finding and confirm the quote really is in the target's reply. A quote that is not in the reply must not exist (the engine rejects it). |
| **Counters** | Run detail: requests ≈ attempts + replays; tokens > 0; cost-relevant totals match the provider dashboard within a reasonable margin. |
| **PDF report** | Opens; has summary, findings with evidence, the Threat Matrix (ATLAS/ASI/families), scope digest and library hash. Target output appears as data, not as markup. No API key, cookie or env value anywhere (run the script below on the PDF). |
| **CSV** | `attack_family` and `source` are the last columns; fields starting with `= + - @` are neutralised (no formula injection). |
| **Audit** | *Audit* page lists scope signing, run start/stop and the library import with hashes. |
| **Kill switch** | Start a run and press **Stop all** (sidebar); the run must end quickly and no further requests arrive at the provider. |

## D. Secret-leak test
1. Create a second target with a **fake** key, e.g. `sk-FAKE-leaktest-9f3a7c1d2b` (it will fail with 401 at the provider, which is fine and also tests the error path).
2. Run the quick scan or the smoke library against it so the key is used. Also sign in so a session cookie exists.
3. Copy the `rl_session` cookie value from the browser dev tools (Application → Cookies).
4. Download the PDF and CSV of the run.
5. Run:
```bash
FAKE_KEY='sk-FAKE-leaktest-9f3a7c1d2b' SESSION_COOKIE='<rl_session value>' \
  ./scripts/secret-leak-check.sh ~/Downloads/report.pdf ~/Downloads/findings.csv
```
Expected: `RESULT: PASS`. The script also looks for the admin password, scope signing key and database password from `.env`. These must not appear in logs, the database, container temp files or exports. `.env` itself and `docker inspect` showing keys you put in `.env` on purpose are expected and are not reported (only the fake UI key is checked there).
6. Manual extras:
```bash
docker compose logs --no-color | grep -iE "sk-[A-Za-z0-9]{8,}|bearer [A-Za-z0-9._-]{12,}|rl_session=" || echo "clean"
docker compose exec -T db psql -U redwitness -c "\dt"        # which tables exist
docker compose exec -T db psql -U redwitness -c "select * from audit order by 1 desc limit 5"
```

## E. After a restart
`docker compose restart backend`: the typed fake key must be **gone** (target asks for the key again), signed scopes still verify, previous runs and findings are still listed.

## F. Report back
If anything fails, paste: the failing step, `docker compose ps`, `docker compose logs --no-color backend | tail -80` with keys redacted, and the browser console error if it is a UI issue.
