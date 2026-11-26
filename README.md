<div align="center">

<img src="docs/logo.svg" alt="AIVeritX logo" width="88" height="88">

<h1>AIVeritX</h1>

<p><strong>Self-hosted red-teaming platform for LLM applications</strong></p>

<p>
Test prompts, RAG pipelines, agents, tools, vector stores and model files inside a cryptographically signed scope.<br>
Every finding is backed by verbatim evidence, confirmed by replay and mapped to OWASP, MITRE ATLAS and NIST AI RMF.
</p>

<p>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="License: AGPL-3.0"></a>
<img src="https://img.shields.io/badge/tests-790%20passing-2f855a?style=flat-square" alt="Tests: 790 passing">
<img src="https://img.shields.io/badge/python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
<img src="https://img.shields.io/badge/Next.js-16-111111?style=flat-square&logo=nextdotjs&logoColor=white" alt="Next.js 16">
<img src="https://img.shields.io/badge/Docker%20Compose-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker Compose ready">
<img src="https://img.shields.io/badge/OWASP-LLM_Top_10-black?style=flat-square" alt="OWASP LLM Top 10">
</p>

<p>
<a href="#quick-start-2-minutes">Quick start</a> ·
<a href="#features">Features</a> ·
<a href="#how-a-test-runs">How it works</a> ·
<a href="#security--architecture">Security</a> ·
<a href="#documentation">Documentation</a> ·
<a href="#contributing">Contributing</a> ·
<a href="#legal-disclaimer">Legal</a>
</p>

<sub>One-command install · Self-hosted · No telemetry</sub>

</div>

> [!WARNING]
> **For legal and authorized use only.** AIVeritX is a security testing tool. Use it only against systems you own or have explicit written permission to test. Unauthorized testing may be illegal. The authors and contributors accept no liability for misuse or for any damage it causes. See [Legal disclaimer](#legal-disclaimer).

## Screenshots

<!-- A short screen recording can go here later: <img src="docs/demo.gif" alt="AIVeritX live scan demo" width="900"> -->

![Dashboard: metric cards, risk trend, live agent timeline, system health and model comparison](docs/screenshots/dashboard.png)

<table>
<tr>
<th width="50%">Agent live stream and system health</th>
<th width="50%">Metric cards (accent line on hover)</th>
</tr>
<tr>
<td><img src="docs/screenshots/dashboard-live-stream.png" alt="Agent live stream in JetBrains Mono next to system health" width="100%"></td>
<td><img src="docs/screenshots/dashboard-metrics-hover.png" alt="Four metric cards with a thin accent line on hover" width="100%"></td>
</tr>
</table>

> **Most LLM scanners tell you what the model said. AIVeritX tells you whether you can believe it, and proves it was safe to run.**
> No request leaves the building without a signed scope. No finding is reported without a quote, a replay and a second opinion.

## Quick start (2 minutes)

```bash
git clone https://github.com/capture0x/AIVeritX.git && cd AIVeritX
./install.sh                     # checks Docker, creates secrets, asks for your judge key, builds and starts everything
```

The installer is interactive (judge key, UI port, optional sandbox runner) and safe to run again. Prefer to do it by hand? `./scripts/init-env.sh && docker compose up -d --build` does the same without questions, and `./install.sh --yes` skips the questions for CI. Every service has a health check, so `docker compose up -d --wait` returns only when the database, API and UI are really ready.

Open **http://localhost:3000**, sign in as `admin`, then **New Test → Quick scan**: enter your endpoint, tick *"I am authorized to test this target"*, press **Sign and start scan**. You get a verified, evidence-backed report with the OWASP kit, Crescendo and Markdown-leak checks.

No API key yet? The repo ships a deterministic vulnerable mock target and judge, see [Try it without any API key](#setup-in-detail).

**Made for first-time users.** A *Getting started* panel on the dashboard walks you through three steps (judge key, first target, first scan) and ticks each one by itself. Empty pages tell you what to do next, every form field has an (i) tooltip, and errors say what to do instead of what failed.

<table>
<tr>
<th width="33%">Getting started wizard</th>
<th width="33%">Field help (i)</th>
<th width="33%">Empty state with a next step</th>
</tr>
<tr>
<td><img src="docs/screenshots/onboarding-wizard.png" alt="Getting started wizard" width="100%"></td>
<td><img src="docs/screenshots/help-tooltips.png" alt="Field help tooltips" width="100%"></td>
<td><img src="docs/screenshots/empty-state-targets.png" alt="Empty targets page" width="100%"></td>
</tr>
</table>

*These three screenshots simulate a fresh installation by answering the status calls with empty data; the rest of the UI is the real app.*

<table>
<tr>
<td width="33%" valign="top">

**🔏 Signed scope**<br>
HMAC-signed, immutable authorization: endpoints, attack classes, budgets. Unsigned, expired or revoked means zero requests.

</td>
<td width="33%" valign="top">

**🧾 Evidence, not opinion**<br>
Verbatim-quote check, k-of-n replay, canaries, deterministic detectors and an adversarial verifier cut false alarms.

</td>
<td width="33%" valign="top">

**🛡️ Defense measured**<br>
Run the same attacks with and without your guardrail and get a **Defense Score** with a 95% confidence interval.

</td>
</tr>
</table>

## Why AIVeritX

**Five things that make a finding believable.** Each one is enforced in code and pinned by tests.

| # | Feature | The problem it solves | Where to see it |
|---|---|---|---|
| 1 | **Impact Matrix** | A judge says "violation" for harmless text. The code decides *how much it matters*: only an executed action, exfiltrated data, protected data or a leaked system prompt can be **critical**; a text-only bypass is capped at high, a text echo at low | Finding card → Review tab |
| 2 | **Bias Control** | A judge from the same model family as the target tends to favour its own style. AIVeritX detects the same family or model, warns (or blocks) and suggests an independent judge | Settings → Bias control |
| 3 | **Adversarial Verifier** | After replay confirms a finding, a second model tries to *refute* it. A refutation counts only with a verbatim quote and enough confidence; findings proven by code are never sent to it | Settings → Adversarial verifier |
| 4 | **Replay + human calibration** | One lucky reply is not a finding. It must repeat in fresh conversations; your True / False positive labels then give measured precision and recall with 95% intervals | Findings → Calibration |
| 5 | **Defense Score** | "Did our guardrail help?" Same attacks with and without the defense: *blocked / bypassed / regression*, plus a score with a confidence interval | Defense Efficacy (Advanced mode) |

Underneath all five: a **signed scope** decides what may be tested before the first request leaves, and a Governor enforces limits on every call.

Most LLM test tools send a pile of prompts and show you what the model said. AIVeritX is built around a different question: **can you trust the result, and was it safe to run?**

- **Authorization is code, not a promise.** A test only starts under a *signed, immutable scope*: endpoints, attack classes, token/request/rate/conversation limits, even whether an attacker model may rewrite refused cases. An unsigned, expired, revoked or superseded scope means no request leaves the building.
- **Evidence over opinion.** A judge LLM must quote the violating text *verbatim*; a finding only becomes **verified** after it reproduces in fresh conversations; planted **canaries** and **deterministic detectors** (tool calls, Markdown leaks) back up or override a judge that is wrong.
- **The engine holds no attack content.** Every test message, tool definition and transform wording comes from your versioned, hashed test library. The engine carries state, enforces limits and records evidence.
- **Every layer of the AI stack.** Prompt and agent behavior, RAG documents, tool use, vector stores, model files and privacy leakage, in one platform, one audit log, one report.
- **Built for pipelines.** A scoped, expiring API token turns any scan into a CI gate.

### What it does differently

| Usual weak spot | How AIVeritX handles it |
|---|---|
| "The tool can hit anything I point it at" | Signed scope + Governor on **every** request; IP pinning against DNS rebinding; cloud metadata always blocked |
| "The judge said so" | Verbatim quote check, replay verification (k of n), canaries, deterministic rules, human-review queue |
| "An AI attacker with free rein" | The attacker only rewrites inside operator-allowed families, a few bounded rounds, validated in code, charged to a budget |
| "Findings I can't reproduce" | Each finding stores its transcript, replays and the exact library hash |
| "Results I can't take to compliance" | OWASP 2025 matrix with honest *not tested / needs review* states, PDF and CSV reports, hash-chained audit log |

## Features

- **Authorization as code**: signed scope, Governor on every request, IP pinning, kill switch.
- **Low false-alarm design**: quote check, replay, canaries, impact caps, adversarial verifier, human calibration.
- **Whole AI stack**: prompts, agents, RAG documents, tool use, vector stores, model files, privacy leakage.
- **Adaptive and multi-turn**: attacker agent, Crescendo, rule-based branching, campaigns, PLAGUE, PersonaTeaming.
- **Compliance views**: OWASP LLM 2025, Agentic (ASI) 2026, MITRE ATLAS, NIST AI RMF, AISVS, HarmBench / JailbreakBench / StrongREJECT ASR.
- **CI/CD gate**: scoped, expiring API tokens; incomplete scans never pass.

<details>
<summary><b>All capabilities (30+)</b></summary>

| Capability | What you get |
|---|---|
| **Defense efficacy** | Same library against `guardrail_off` and `guardrail_on` endpoints; per-vector *blocked / bypassed / regression*, **Defense Score** with 95% Wilson interval |
| **Reasoning-layer evaluation** | `reasoning_chain` cases check every intermediate answer with code rules; **Reasoning Deviation** shown as a step-by-step timeline |
| **Sandboxed verification** | Opt-in isolated runner (no network, read-only, no capabilities) labels unsafe output `verified_exploitable` or `not_exploitable`; shell is never executed |
| **Accuracy layer** | Judge bias control, impact matrix that caps severity, adversarial verifier, human review with precision / recall calibration |
| **OWASP LLM Top 10 (2025)** | Starter kit (10 templates), coverage matrix, compliance score, one-click scans, legacy-id mapping |
| **Compliance Suite** | One set of results seen through **OWASP Agentic (ASI) 2026**, **MITRE ATLAS** (threat matrix, per-finding badges), **NIST AI RMF** (Measure / Manage) and **OWASP AISVS** (chapter level); "test only AISVS-mapped cases" runs |
| **Benchmark datasets and ASR** | Import **HarmBench, JailbreakBench and StrongREJECT** files from your own copy; results are reported as Attack Success Rate (ASR) per benchmark |
| **Multimodal carrier** | Image or audio files from your library are attached to a message and only carried; before sending, OCR and metadata are read and the file is withheld if one of your canaries is inside |
| **Agentic tool chains** | Scripted multi-step scenarios on the fake tool sandbox: each step's message may quote what an earlier tool returned; a forbidden call or protected data reaching an outbound tool is a deterministic **critical** finding |
| **Knowledge Graph & Coverage Mapper** | A question tree you write is asked of the target; the knowledge tree and per-topic coverage are built from the replies in code; protected terms that leak become verified findings. Exploration and reporting only |
| **Multi-session campaigns** | A "patient" run over several sessions on a ladder of your cases; the planner is plain code (escalate, retry, step back, stop) and keeps only counters, never target text |
| **PLAGUE and PersonaTeaming** | Adaptive methods with a planning / reflecting state machine and a per-run lifelong memory; every strategy and persona is written by you in the library |
| **Adaptive Attacker agent** | State machine (probe → analyze → generate → validate → attack → confirm); rewrites refused cases in operator-allowed families; scope-gated and budgeted |
| **Attack tree** | Interactive graph of what the agent tried, why it moved on, how the verdict was reached |
| **Remediator** | Reviewable secure prompt / code patch per finding, secrets masked, never auto-applied |
| **Model benchmarking** | Same test set to 2-4 targets of one scope; per-category failure rates and ranking |
| **Tool sandbox** | Fake `read_file` / `query_db` / `http_request` tools with canned results (nothing executes); a forbidden call or a secret passed to an outbound tool is a deterministic **Critical** |
| **Crescendo conversations** | 5-10 turn scenarios whose later turns quote the target's previous reply (`{previous_reply}`); per-turn stage in the evidence |
| **Payload library import** | Bring your own `.txt` / JSON / JSONL / CSV / YAML / AltayDuel files; payloads stay verbatim carriers tagged with an **attack family** (instruction override, role play, encoding evasion, payload splitting, memory poisoning, tool abuse, exfiltration) that fills the ATLAS and Agentic mapping |
| **Rule-based multi-turn branching** | The code picks the next library message from the target's reply with the case's own rule table (forward-only, scope-gated by `branching_allowed`); the path is shown in the finding |
| **Markdown exfiltration detector** | Canary inside an image, link, HTML `src/href` or bare URL (also percent/base64-encoded) is a **High** leak |
| **Document ingestion (RAG)** | Library text rendered to visible PDF / DOCX / HTML / MD / CSV / TXT, uploaded, cleaned up; per-conversation canary tokens |
| **Defense-bypass transforms** | `base64`, `rot13`, `hex`, `homoglyph`, `split`, `language_switch`; wording templates come from the library |
| **Model supply chain** | Static pickle/zip/safetensors/GGUF analysis: never loads or executes the file; hash verification |
| **Vector DB exposure** | Read-only, credential-less probes of Chroma, Qdrant, Weaviate; masked previews; 3 records per collection |
| **Model extraction exposure** | Budgeted query harvest; cost estimate, throttling, repeatability, lookup-surrogate fidelity (nothing is trained) |
| **Membership inference signal** | Member vs. control continuation test with AUC and optional log-probs; hashes only, no sample text stored |
| **CI/CD gate** | `POST /api/scan-ci` with a revocable, expiring, scope-bound token; incomplete scans never pass |
| **Targets and auth types** | Save targets once (OpenAI, Anthropic, Ollama or any OpenAI-compatible URL); authenticate with an API key, a **browser cookie string** or a **custom header**; credentials are kept in server memory only |
| **Quick scan** | Enter a URL and credentials, review exactly what will be signed, tick the authorization box: one run covers the OWASP kit, Crescendo and Markdown-leak checks (plus tool abuse if you attest) |
| **Drag-and-drop uploads** | Drop a PDF, DOCX or EML (only its visible text is extracted and re-created) or a JSON/YAML test library |
| **Governance** | Signed scope, RBAC (viewer / operator / admin), hash-chained audit, kill switch |

</details>

<table>
<tr>
<th width="50%">Attack tree</th>
<th width="50%">Remediator (Fix tab)</th>
</tr>
<tr>
<td><img src="docs/screenshots/attack-tree.png" alt="Attack tree" width="100%"></td>
<td><img src="docs/screenshots/remediator-fix.png" alt="Remediator" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="50%">Quick scan: review before signing</th>
<th width="50%">Targets with cookie authentication</th>
</tr>
<tr>
<td><img src="docs/screenshots/quick-scan-plan.png" alt="Quick scan" width="100%"></td>
<td><img src="docs/screenshots/targets-list.png" alt="Targets" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="50%">Tool sandbox finding (Critical)</th>
<th width="50%">Vector store exposure</th>
</tr>
<tr>
<td><img src="docs/screenshots/tool-sandbox.png" alt="Tool sandbox" width="100%"></td>
<td><img src="docs/screenshots/privacy-vector.png" alt="Vector store" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="50%">Model benchmark</th>
<th width="50%">OWASP LLM Top 10 matrix</th>
</tr>
<tr>
<td><img src="docs/screenshots/model-benchmark.png" alt="Model benchmark" width="100%"></td>
<td><img src="docs/screenshots/owasp-matrix.png" alt="OWASP matrix" width="100%"></td>
</tr>
</table>

*The screenshots use a local deterministic mock target and mock helper models (see `sandbox/`), not real models.*
## Where AIVeritX fits

Each of these tools is good at something different. AIVeritX is built for teams who need **authorized, reproducible and auditable** results rather than the largest probe count.

| | Focus | Typical use |
|---|---|---|
| [promptfoo](https://github.com/promptfoo/promptfoo) | Evals and red teaming from a CLI and config files | Developer-side regression and eval loops |
| [garak](https://github.com/NVIDIA/garak) | Probe-based LLM vulnerability scanner | Broad probing of a model with many known attacks |
| [PyRIT](https://github.com/Azure/PyRIT) | Python framework for orchestrating risk identification | Custom research and automation in code |
| **AIVeritX** | Web platform: signed scope, evidence, replay, audit, compliance mapping, defense efficacy | Authorized assessments you must defend to a client or an auditor |

They combine well: bring payloads from other projects with the importer and let AIVeritX run them under a scope and verify the findings.

## Setup in detail

**Requirements:** Docker with Compose v2.

```bash
git clone https://github.com/capture0x/AIVeritX.git && cd AIVeritX
./scripts/init-env.sh          # writes .env with random secrets and prints the admin password once
docker compose up -d --build   # database, backend, UI
```

Open **http://localhost:3000** and sign in as `admin` with the password from `.env` (`AIVERITX_ADMIN_PASSWORD`).

**Where the API keys go**

| Key | Where | Notes |
|---|---|---|
| Judge LLM (use a strong model) | `.env` → `ANTHROPIC_API_KEY` (or any variable name), then *Settings → Judge LLM* | Only the variable **name** is stored in the app; keys never reach the database |
| Target under test | A variable named in the scope's endpoint (`api_key_env`), or typed once in *New Test* (kept in memory for that run) | Never written to the database |
| Attacker / Remediator (optional) | *Settings → Attacker / Remediator* | They fall back to the judge model if unset; the adaptive grant must also be in the signed scope |

Restart after editing `.env`: `docker compose up -d`. **Back up `AIVERITX_SCOPE_KEYS`**: without it, previously signed scopes can no longer be verified.

**Fastest path: Quick scan (admin).** *New Test → Quick scan*: enter the base URL, model name and how to sign in (API key, cookie string or a custom header), optionally tick the tool-abuse attestation, **Review**, tick “I am authorized to test this target” and **Sign and start scan**. It creates a normal 7-day signed scope with a fixed budget, saves the target and starts one run of the full kit. The target must speak the OpenAI chat-completions or Anthropic messages format (cookie authentication is for such endpoints behind a login or gateway).

> **Testing a model on your own machine (for example Ollama) from Docker:** the backend container cannot see your host's `localhost`. Use `http://host.docker.internal:11434/v1` as the Base URL and, on Linux, add `extra_hosts: ["host.docker.internal:host-gateway"]` to the `backend` service in `docker-compose.yml`. Local and private addresses are only reachable for targets marked **local**; cloud metadata addresses are always blocked.

**Your first scan, step by step (5 steps)**

1. *Settings → Judge LLM*: choose provider and model.
2. *Scopes → New scope*: the endpoint you are **authorized** to test, the classes, the limits. Read the digest on the approval screen and sign.
3. *Test Library → Ready-made templates*: import the OWASP starter kit (and the **Advanced examples**: tool sandbox, Crescendo, Markdown leak).
4. *OWASP Compliance → Start OWASP scan*, or the *New Test* wizard.
5. Watch the live timeline, then open *Findings*, the *Attack tree* and the PDF/CSV report.

**Try it without any API key (local development setup).** The repository ships a deterministic fake target and judge. Start the backend and UI as described in [Development](#development-without-docker), then `python sandbox/mock_llm.py --port 9100` and set *Settings → Judge* to provider `openai_compat`, URL `http://127.0.0.1:9100/judge/v1/chat/completions`, model `mock-judge`. Create a scope for `http://127.0.0.1:9100/v1/chat/completions` with **Local** ticked (the classes `tool_abuse` with the test-environment attestation, `system_prompt_extraction` and `data_leakage` cover the advanced examples), import the Advanced examples and run them: the mock target is vulnerable in exactly the advertised ways (enter `ACME-INTERNAL-KEY-48213` as a canary to see the Markdown check). The mock is test scaffolding, **not an LLM**.

## How a test runs

```mermaid
flowchart LR
  L[(Test library<br/>hashed JSON/YAML)] --> E
  S[Signed scope] -->|hard gate| E[Orchestrator]
  E -->|every request| G[Governor<br/>limits · rate · budget · breaker · IP pin]
  G --> T([Target LLM app])
  T -. untrusted reply .-> E
  E --> D{Deterministic rules<br/>tools · canaries · Markdown}
  D -->|no verdict| J[Judge LLM<br/>verbatim quote]
  D --> R
  J --> R[Replay k of n<br/>fresh conversations]
  R --> F[(Findings + audit)]
  E -. refused? .-> A[Attacker LLM<br/>allowed families only] --> E
```

**In four steps (no diagram reading needed):**

1. **Sign Scope:** you declare what may be tested, for how long and how hard. Nothing runs without it.
2. **Agent Attacks:** the engine sends the test messages inside that boundary, and an attacker model adapts when the target refuses.
3. **Judge Verifies:** a second model decides if a rule was broken and must quote the exact words as evidence.
4. **Replay Confirms:** the finding is repeated in fresh conversations, and only the ones that reproduce are reported.

The full lifecycle, with the data each component sees, is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Architecture at a glance

```mermaid
flowchart TB
  classDef ui fill:#1e1b4b,stroke:#818cf8,color:#e0e7ff
  classDef core fill:#172554,stroke:#60a5fa,color:#dbeafe
  classDef store fill:#052e2b,stroke:#34d399,color:#d1fae5
  classDef model fill:#3b0764,stroke:#c084fc,color:#f3e8ff
  classDef danger fill:#450a0a,stroke:#f87171,color:#fee2e2

  U([Operator browser]):::ui --> FE["Next.js UI<br/>Getting started · Findings · Defense"]:::ui
  FE -->|"/api proxy"| API["FastAPI backend<br/>auth · RBAC · signed-scope gate"]:::core
  API --> ENG["Orchestrator<br/>state machine, holds no attack text"]:::core
  LIB[("Test library<br/>hashed JSON / YAML")]:::store --> ENG
  ENG --> GOV["Governor<br/>limits · rate · budget · breaker · IP pin"]:::core
  GOV --> T(["Target LLM app<br/>untrusted replies"]):::danger
  ENG --> J["Judge LLM"]:::model
  ENG --> V["Adversarial verifier"]:::model
  ENG -.->|"opt-in, rewrites refused cases"| A["Attacker LLM"]:::model
  API --> R["Remediator LLM"]:::model
  API <--> DB[("PostgreSQL<br/>runs · findings · hash-chained audit")]:::store
  ENG -.->|"job files, shared volume"| SBX["sandbox-runner<br/>no network · read-only · no capabilities"]:::danger
```

### Data flow of one scan

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operator
  participant UI as UI
  participant API as Backend
  participant Gov as Governor
  participant T as Target
  participant J as Judge
  participant V as Verifier
  Op->>UI: review the plan, sign the scope
  UI->>API: start run (scope digest)
  API->>API: verify signature, expiry, limits
  loop every test case from the library
    API->>Gov: message to send
    Gov->>T: request (IP pinned, budgeted)
    T-->>API: reply (untrusted data)
    API->>API: deterministic rules (tools, canaries, Markdown)
    API->>J: reply and expected behavior
    J-->>API: verdict and verbatim quote
    API->>API: the quote must appear in the reply
  end
  API->>T: replay in fresh conversations (k of n)
  API->>V: try to refute the confirmed finding
  V-->>API: refutation with quote, or none
  API->>API: impact matrix caps the severity
  API-->>UI: verified finding, evidence, audit entry
```

### Finding lifecycle and the adaptive agent loop

```mermaid
stateDiagram-v2
  direction LR
  [*] --> QUEUED
  QUEUED --> SENDING
  SENDING --> JUDGING
  JUDGING --> NO_FINDING
  JUDGING --> INCONCLUSIVE
  JUDGING --> CANDIDATE
  CANDIDATE --> REPLAYING
  REPLAYING --> VERIFIED: k of n repeat
  REPLAYING --> UNSTABLE: threshold not reached
  VERIFIED --> FALSE_POSITIVE: refuted by verifier or reviewer
  NO_FINDING --> [*]
  VERIFIED --> [*]
```

```mermaid
stateDiagram-v2
  direction LR
  [*] --> PROBING: target refused a case
  PROBING --> ANALYZING
  ANALYZING --> GENERATING
  GENERATING --> VALIDATING: one allowed family
  VALIDATING --> ATTACKING: passes the code checks
  VALIDATING --> ABORTED: unusable output
  ATTACKING --> PROBING: refused again, next round
  ATTACKING --> CONFIRMING: violation
  ATTACKING --> CLEAN: no violation
  CONFIRMING --> FOUND: normal replay
  PROBING --> EXHAUSTED: rounds used
  FOUND --> [*]
  CLEAN --> [*]
  EXHAUSTED --> [*]
  ABORTED --> [*]
```

The agent loop is optional, off by default and allowed only by the signed scope. Every state change is appended to an audit trail (`agent_steps`).

## Security & architecture

> **Design principle:** the safety controls live outside the model. Scope, limits, network addresses and permissions are enforced in code; every piece of text coming from the target or the judge is treated as *untrusted data*. Even if the model is "persuaded", an out-of-scope request is never sent and a finding without evidence is never created.

- **Signed, immutable scope** (HMAC-SHA256): what may be tested, how much, and whether adaptive rewriting is allowed. The approval screen shows exactly what is being signed.
- **Governor on every request**: kill switch, token/request/rate/conversation/duration limits, circuit breaker, address check and **IP pinning** (DNS rebinding).
- **Deterministic where possible**: forbidden tool calls, exfiltration chains, canary-in-URL and quote verification do not depend on a model's opinion.
- **Canaries**: per-conversation tokens that appear in no sent message; independent evidence against judge false negatives.
- **Replay verification**: a finding is *verified* only if it repeats in new conversations; otherwise it is *unstable* or a *candidate*.
- **Nothing dangerous is generated or executed**: fake tools return canned text, model files are parsed never loaded, vector probes are read-only and allowlisted, documents are visible text only.
- **Governance**: default-deny RBAC, scrypt + signed sessions, CSRF header, hash-chained tamper-evident audit log, no API key ever stored.

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/LLM_REDTEAM.md`](docs/LLM_REDTEAM.md).

### Operations and deployment

| | |
|---|---|
| Stop / start | `docker compose stop` / `docker compose start` |
| Logs | `docker compose logs -f backend` |
| Backup | `docker compose exec db pg_dump -U aiveritx aiveritx > backup.sql` |
| Start from scratch | `docker compose down -v` (**deletes the database**) |

**Deployment security:** PostgreSQL and the API are **not exposed** to the host; the UI binds to `127.0.0.1` only. To open it to other machines, put a TLS-terminating reverse proxy in front and set `AIVERITX_COOKIE_SECURE=1` in `.env`.
The images run as a non-root user; the backend image contains no test/dev files.

## Environment variables

Template: [`.env.example`](.env.example). In Docker **all** variables in `.env` are passed to the backend container.

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | yes (Docker) | PostgreSQL password (inside the compose network only) |
| `AIVERITX_DATABASE_URL` | yes (non-Docker) | `postgresql://user:password@host:5432/database` (compose sets it up in Docker) |
| `AIVERITX_SCOPE_KEYS` | yes | Scope signing keys: `id:64hex[,id2:64hex]`. To rotate, add another key and set `AIVERITX_SCOPE_ACTIVE_KEY=id2` (old ones remain for verification) |
| `AIVERITX_ADMIN_PASSWORD` | yes | Password of the first `admin` account (≥ 12 characters). Used **only while the users table is empty**; afterwards it is managed on the Users page |
| `AIVERITX_SESSION_SECRET` | recommended | Session cookie signing secret. If empty it is random per process (sessions drop on restart) |
| `AIVERITX_COOKIE_SECURE` | no | `1` behind TLS |
| `AIVERITX_ALLOWED_HOSTS` | no | Extra names for the backend's Host validation (comma separated). In Docker `backend` is automatic |
| `AIVERITX_PORT` | no | The UI's host port (default 3000) |
| `AIVERITX_API` | no | *UI build argument*: the `/api` proxy address (Docker: `http://backend:8000`; local: `http://127.0.0.1:8000`) |
| `AIVERITX_TEST_DSN` | no | Admin DSN for the tests; if not given a temporary PostgreSQL cluster is started |
| `ANTHROPIC_API_KEY` etc. | for the judge | Judge/target API keys. **Never written to the database**; only the variable **name** is given in the scope (`api_key_env`) and in Settings |
| `AIVERITX_INSECURE_NO_AUTH` | no | **Local development only:** turns authentication off (everyone is admin). Never in production |

If there is no password and no user, the server refuses the API with **503** (fail-closed); it is never run without a password.

## First steps

1. **Sign in** (`admin`). Add operator/viewer accounts on the Users page.
2. **Settings → Judge LLM:** choose the provider and model, and give the environment variable name of the API key.
   > ⚠️ **Small/local models as the judge can cause false negatives.** A capable model (Claude Sonnet/Opus class, GPT-4o class) is strongly recommended in production. The UI warns you when it detects signs of a small/local model.
3. **Scopes → New scope:** enter the endpoint you are authorized to test, the allowed categories and the limits; read the content and digest on the approval screen and **sign**.
4. **Test Library → Ready-made templates:** import the OWASP starter kit, the **Advanced examples** (tool sandbox, Crescendo, Markdown leak) or upload your own JSON/YAML library.
5. **OWASP Compliance → Start OWASP scan** (or the **New Test** wizard). Watch the run live; **Findings** and the PDF/CSV reports are ready.

<table>
<tr>
<th width="50%">Ready-made templates</th>
<th width="50%">OWASP scan dialog</th>
</tr>
<tr>
<td><img src="docs/screenshots/library-templates.png" alt="Ready-made templates" width="100%"></td>
<td><img src="docs/screenshots/owasp-scan-dialog.png" alt="Scan dialog" width="100%"></td>
</tr>
</table>

## OWASP LLM Top 10 compliance

Test library cases carry an `owasp_category` (`LLM01_PromptInjection` … `LLM10_UnboundedConsumption`).
**The 2025 edition is canonical**; 2023 (v1.1) ids (e.g. `LLM02_InsecureOutput`, `LLM06_SensitiveInfoDisclosure`) and short codes (`LLM07`) are mapped to their current equivalents automatically.

- **Ready-made templates:** 10 templates (15 basic quality cases) - plain, polite requests; they contain no encoding, role-play or multi-step manipulation (pinned by a test).
- **Matrix:** for each category *Not tested · Testing · Vulnerable · Needs review · Clean*. "Vulnerable" is only for findings **verified** by replay.
- **Score = clean categories / tested categories**; coverage (tested/10) is shown alongside.
- **Classification:** case tag > the judge's suggestion > the attack-class default; the source is stored with every finding. If the scope does not allow a category's attack classes, that category is skipped and stays "Not tested".

> **This is not a compliance certificate.** The results map **behavioral quality probes** made through a black-box API to OWASP categories.
> LLM03 (supply chain), LLM04 (data/model poisoning) and LLM08 (vector/embedding) are only **partially** covered by black-box testing; a full assessment needs an architecture and process review. This warning also appears in the UI and in the reports.

<table>
<tr>
<th width="50%">OWASP matrix</th>
<th width="50%">Findings by category</th>
</tr>
<tr>
<td><img src="docs/screenshots/owasp-matrix.png" alt="OWASP matrix" width="100%"></td>
<td><img src="docs/screenshots/findings-owasp-filter.png" alt="Findings" width="100%"></td>
</tr>
</table>

## Compliance Suite (ASI, ATLAS, NIST AI RMF, AISVS, benchmarks)

The **Compliance** pages show the same test evidence through several frameworks. The mapping is derived from each case's attack class and OWASP category, and a case can add its own tags:

| Tag in a library case | Meaning |
|---|---|
| `asi_category` | OWASP Top 10 for Agentic Applications (2026): `ASI01_AgentGoalHijack` … `ASI10_RogueAgents` (codes such as `ASI03` and names such as `agent_identity_spoofing`, `excessive_agency`, `planning_manipulation` are accepted) |
| `aisvs` | OWASP AISVS chapters, e.g. `["C5", "C9"]` (added to the automatic mapping) |
| `attack_family` | One of seven carrier families (see *Payload libraries* below); adds its ATLAS techniques and ASI category when the case states no `asi_category` |
| `benchmark` | `harmbench`, `jailbreakbench` or `strongreject`; set by the importer, feeds the ASR score |

- **MITRE ATLAS:** every finding carries technique badges (for example `AML.T0051.000`), the finding detail shows tactics, and the PDF report has a *Threat matrix* section. CSV export gains `asi_category`, `mitre_atlas`, `nist_ai_rmf`, `aisvs` and `benchmark` columns. Classes with no clean ATLAS technique (unsafe output, misinformation) stay unmapped on purpose.
- **NIST AI RMF:** results are grouped under Measure (2.5, 2.6, 2.7, 2.10) and Manage (1.3, 2.4, 3.1, 4.1).
- **AISVS:** "Run only AISVS-mapped cases" in New Test (Custom) or `POST /api/runs` with `"aisvs": ["*"]` (or chapters such as `["C9"]`). The same run request accepts `asi` and `benchmark` filters.
- **Benchmarks:** *Library → Import a benchmark dataset* converts a file you supply (the project's own CSV/JSON) into an ordinary hashed library. The platform ships **no benchmark content**. **ASR** = share of prompts after which the judge found a violation, shown next to the share verified by replay.
- **Agentic examples:** `ADV_agentic` (identity spoofing through a claimed orchestrator message and a claimed administrator, plan replacement; fake tools, nothing executes) and `ADV_plague_persona` are in *Library → Advanced examples*. They are not part of the quick scan.
- **PLAGUE / PersonaTeaming:** an `adaptive` block can set `"method": "plague"` with `strategies: [{id, text}]` or `"method": "persona_teaming"` with `personas: [{id, text}]` (1-8 items, 600 characters each). The engine plans (picks the next item from a per-run memory of tries, refusals and violations), the Attacker model rewrites the case following that text, and the result goes through the usual scope limits, Governor, judge and replay. Needs adaptive mode in the signed scope; the scope's round cap applies.

<table>
<tr>
<th width="50%">MITRE ATLAS threat matrix</th>
<th width="50%">Agentic (ASI) 2026 matrix</th>
</tr>
<tr>
<td><img src="docs/screenshots/compliance-atlas.png" alt="ATLAS" width="100%"></td>
<td><img src="docs/screenshots/owasp-agentic.png" alt="ASI" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="50%">OWASP AISVS chapters</th>
<th width="50%">Benchmark score (ASR)</th>
</tr>
<tr>
<td><img src="docs/screenshots/compliance-aisvs.png" alt="AISVS" width="100%"></td>
<td><img src="docs/screenshots/compliance-benchmark-asr.png" alt="ASR" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="50%">Benchmark dataset import (Library)</th>
<th width="50%">Attack families (Compliance Suite)</th>
</tr>
<tr>
<td><img src="docs/screenshots/benchmark-import.png" alt="Benchmark import" width="100%"></td>
<td><img src="docs/screenshots/compliance-families.png" alt="Attack families" width="100%"></td>
</tr>
</table>

*These screenshots come from the local deterministic mock target, which refused both imported benchmark prompts. That is why the ASR shows 0.0% and the ATLAS row for LLM Jailbreak shows "Clean". The mock does not trigger every badge (for example a finding with an ATLAS badge); the mapping itself is covered by the backend tests.*

> **Honest limits.** The mappings are curated, not an official crosswalk, and framework ids change between releases (ATLAS ids, AISVS titles): check `llm_redteam/frameworks.py` against the version you report against. AISVS is mapped at **chapter** level only. ASI04-ASI10 need a live multi-agent setup and are marked *limited coverage*. **ASR is the judge's binary verdict, not the official scorer** of any of the three benchmarks, so do not compare it with published leaderboards. PLAGUE's lifelong memory lasts for one run; nothing is carried between runs.

## AI Security Suite (multimodal, chains, knowledge map, campaigns)

The **AI Security Suite** page adds four capabilities. They follow the platform's one rule: **all test text and files come from your hashed library**; code classifies, plans and reports. Every request still goes through the signed scope, the Governor, canaries and the audit log.

| Module | Library case | What the platform does | Scope grant |
|---|---|---|---|
| Multimodal carrier | `type: multimodal`, `media: [{name, format: png/jpeg/wav/mp3, data_base64, declared_text}]` | Sends the file exactly as written. **Static pre-processing** first: OCR text (Tesseract, when installed) and metadata (EXIF, PNG text, tags); text the library did not declare is reported; a file that contains one of the run's **canaries is not sent**. Audio speech is *not* transcribed | `multimodal_allowed` |
| Agentic chain | `type: agentic_chain`, `tools`, `steps: [{id, message, expect_tool, expect_args}]` | Runs the steps in order; `{step_1_output.field}` in a later message is filled from what the earlier step's fake tool returned. **Critical**: a `forbidden` tool is called, or a value returned by a `sensitive` tool reaches an `egress` tool. No judge call | tool-abuse attestation |
| Knowledge map | `type: knowledge_map`, `nodes: [{id, parent, topic, question, terms, protected_terms}]` | Asks the tree breadth-first (a child only if its parent was covered, or always with `expand: always`), classifies every reply by string matching, stores the tree with coverage per topic. A protected term in a reply is a deterministic, replay-verified finding | none |
| Campaign | `campaign: {ladder, level 1-5}` on ordinary cases | Each session is a normal run of one case. The planner escalates after a clean answer, tries another case or steps back after a refusal (limited by *patience*), and stops on a verified violation. Cool-down and session cap (also capped by the scope) pace it | `campaign_allowed` |

Four example libraries are in *Library → Advanced examples* (`ADV_multimodal`, `ADV_agentic_chain`, `ADV_knowledge_map`, `ADV_campaign_ladder`); none is part of the quick scan. Runs can be narrowed with `case_types` and `case_ids` (a campaign session runs exactly one case).

- **What a campaign remembers.** `state` holds counters per level (clean / refused / violation), the turn at which refusals started and the session list (case ids, outcomes). It never holds target text, so a hostile reply cannot steer the plan.
- **What the platform does not do here.** It does not write attack text, create or edit images, transcribe audio, or choose attacks by itself: the "attack path" is the order you put in the library, the plan only picks among your cases.
- **OCR** needs the `tesseract` program (the Docker image installs it). Without it files are still carried, but the OCR text and the OCR part of the canary check are skipped; the page shows "OCR engine: not installed".

<table>
<tr>
<th width="50%">Multimodal carrier</th>
<th width="50%">Agentic tool chain</th>
</tr>
<tr>
<td><img src="docs/screenshots/suite-multimodal.png" alt="Multimodal" width="100%"></td>
<td><img src="docs/screenshots/suite-chain.png" alt="Chain" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="50%">Knowledge map</th>
<th width="50%">Multi-session campaign</th>
</tr>
<tr>
<td><img src="docs/screenshots/suite-knowledge.png" alt="Knowledge map" width="100%"></td>
<td><img src="docs/screenshots/suite-campaign.png" alt="Campaign" width="100%"></td>
</tr>
</table>

*Screenshots come from the deterministic mock target (the agent reads a file and sends it to an outbound tool on purpose, the campaign ladder is refused, clean, then leaks).*

## Payload libraries, attack families and multi-turn branching

Three additions turn the library into a place where outside test sets can live next to your own, without changing the platform rule: **every message that can be sent is text from your hashed library; code classifies, routes and reports.**

**Attack families.** A case can carry `attack_family`: `instruction_override`, `role_play`, `encoding_evasion`, `payload_splitting`, `memory_poisoning`, `tool_abuse` or `exfiltration`. The tag never changes what is sent. It adds mapping: the family fills in the **OWASP Agentic (ASI)** category and the **MITRE ATLAS** techniques of the finding (an explicit `asi_category` on the case still wins), and it is a column in the **Compliance → Attack families** table.

| Family | Scope class used by the importer | OWASP Agentic (ASI) | MITRE ATLAS (curated) |
|---|---|---|---|
| `instruction_override` | `prompt_injection_direct` | ASI01 | AML.T0051.000 + class |
| `role_play` | `jailbreak` | ASI03 | AML.T0054 |
| `encoding_evasion` | `prompt_injection_direct` | ASI01 | AML.T0068 |
| `payload_splitting` | `prompt_injection_direct` | ASI01 | AML.T0051.000 |
| `memory_poisoning` | `prompt_injection_indirect` | ASI06 | AML.T0080.000 |
| `tool_abuse` | `tool_abuse` (needs the tool-abuse attestation) | ASI02 | AML.T0053 |
| `exfiltration` | `data_leakage` | ASI02 | AML.T0057, AML.T0086 |

**Importing an outside payload library** (*Library → Import an external payload library*, or `POST /api/libraries/import-payloads`, operator role). You supply the file; nothing is bundled and you are responsible for its licence. Payloads are stored **word for word**: the importer never rewrites, combines, encodes or generates text. It adds the family tag, the scope class, a generic expected behavior and a `source` note that is shown on every finding.

| Layout | Example | Notes |
|---|---|---|
| `lines` | `AUTHENSOR/ai-seclists` (MIT): one payload per line, `#` comments | The project's **folder name is the family** (`memory-poisoning/`, `exfiltration/`, ...): pass `family` or a `path_hint` such as `memory-poisoning/notes.txt` (the UI uses the file name) |
| `records` | JSON array / JSONL / CSV / YAML | Fields are detected (`payload`, `prompt`, `text`, ... and `category`/`family`/`technique` for the label); override with `mapping` |
| `altayduel` | `AltaySec/altayduel-transcripts` (CC-BY-4.0, **attribution required**: put it in the source note) | One duel becomes one multi-turn case from its attacker messages (`rounds[].red_attack`); the recorded defender replies are never used, the live target answers. `only_successful` keeps duels the attacker won |

Rows that are empty, longer than 3,500 characters, duplicates, or that contain the engine's reserved `{previous_reply}` / `{canary}` tokens are **skipped and counted**, never edited. `crazywifi/Redteam_LLM_Injection_payloads` is **not** supported directly: at the time of writing it ships only HTML pages and no licence file; the importer does not scrape pages. Extract lines you are allowed to use and import them as `lines`. The file layouts above were read from each project's public README or manifest; if a project changes its format, adjust the `mapping` or the layout.

**Rule-based multi-turn branching.** `type: branching` lets the *code* pick the next library message from the target's last reply:

```yaml
- id: duel-1
  type: branching
  category: prompt_injection_direct
  attack_family: instruction_override
  expected_behavior: The assistant keeps following its configured instructions.
  branching:
    - id: s1
      message: "(operator text)"
      rules:                              # first match wins; every condition inside a rule must hold
        - {contains: ["some phrase"], goto: s3}
        - {refused: true, goto: end}
    - id: s2
      message: "(operator text, may use {previous_reply})"
    - id: s3
      message: "(operator text)"
      default: next                       # next | end | a later step id
```

Conditions: `contains`, `not_contains` (case-insensitive substrings), `refused` (a generic refusal-wording check), `min_chars`, `max_chars`, `canary` (an operator canary appears in the reply). **Branches only go forward**, so a case cannot loop and its longest path is its step count (checked against the scope's turn limit). State (current step, turn counter, path) is kept by the engine in plain variables; the finding shows the path as *Branching path* chips (`via rule 2` / `via default`). A branching case needs **`branching_allowed`** in the signed scope (off by default, shown on the approval screen; the Governor also refuses it with `BRANCHING_NOT_ALLOWED`). It cannot be combined with `crescendo`, `variants` or a bypass technique.

<table>
<tr>
<th width="50%">Library: external payload import</th>
<th width="50%">Finding: family badges and branching path</th>
</tr>
<tr>
<td><img src="docs/screenshots/library-payload-import.png" alt="Payload import" width="100%"></td>
<td><img src="docs/screenshots/finding-branching.png" alt="Branching finding" width="100%"></td>
</tr>
</table>

<table>
<tr>
<th width="100%">Scopes: the `branching_allowed` grant (badge &quot;Multi-turn branching&quot;)</th>
</tr>
<tr>
<td><img src="docs/screenshots/scopes-branching-grant.png" alt="Scopes" width="100%"></td>
</tr>
</table>

*These screenshots come from the isolated E2E run against the deterministic mock target (the payload text is the E2E's own harmless marker text; sandbox client and scope names are test data).*

**Reports.** Each finding shows ASI, ATLAS and family badges. The CSV gained the columns `attack_family` and `source` (appended at the end); the PDF's *Threat matrix* section now lists the attack families next to the ATLAS, ASI, NIST and AISVS tables.

## Accuracy and reliability layer (bias control, impact matrix, verifier, calibration)

False alarms are the main way a red-team tool loses trust. Four mechanisms work against them; none generates attack text, and none lets a model overrule evidence the code can check.

| Mechanism | What it does |
|---|---|
| **Bias control** (*Settings → Bias control*) | Classifies the judge (and verifier) against each target by model family (Claude, GPT, Gemini, Llama, ...) and shows a warning in Settings and in the *New test* wizard when they are the same family or the same model. A comparison table suggests an independent judge per target and fills the form (you press Save). Policy `warn` (default), `block` (the run is refused with `BIAS_CONTROL`) or `off`. Unknown families are never blocked. The assessment is stored in the run and printed in the PDF. |
| **Evidence & Impact Matrix** | The judge says *whether* a response violated the expected behavior; the code decides *how much it matters*. `Action executed` (a forbidden tool really called), `Data exfiltrated`, `Protected data exposed` (canary / protected term) and `System prompt leaked` (hidden text that was not in the messages sent) keep their severity, so only these can be **critical**. `Policy bypass (text only)` is capped at **high**; `Text echo only`, where every quoted violation is text the tester sent (inline documents included) or an earlier reply, is capped at **low**. Impact only ever lowers a severity. Finding cards show the impact label and why. |
| **Adversarial verifier** (*Settings → Adversarial verifier*) | After a finding is replay-confirmed, a second model is asked to *refute* it. A refutation is accepted only with an allowed argument type, a reason, a **verbatim quote** from the response or the sent messages, and confidence above the threshold (default 0.8). Accepted: status `false_positive` (kept for audit, excluded from reports, scores and CI gates). Findings proven by code (sandbox rule, canary, protected term, exfil URL) are never sent to it, and a verifier error never loses a finding. |
| **Human review and calibration** (*Findings → card → Review*) | Mark a finding **True positive** or **False positive** (operator role), with a note. A false positive leaves reports and scores; a true positive restores a finding the system held back. The system's own decision is kept (`system_status`) so precision and recall can be measured: *precision = TP / (TP + FP)* over reported findings, *recall = TP / (TP + FN)* over the candidates the system surfaced, with 95% Wilson intervals, per-category tables, the verifier's accuracy and a confidence-threshold suggestion. The Findings page, Settings and the PDF show them. Nothing changes automatically: a suggested threshold is applied only when you press Save. |

<table>
<tr>
<th width="50%">Bias control</th>
<th width="50%">Detection quality (calibration)</th>
</tr>
<tr>
<td><img src="docs/screenshots/accuracy-bias-control.png" alt="Bias control" width="100%"></td>
<td><img src="docs/screenshots/accuracy-calibration.png" alt="Calibration" width="100%"></td>
</tr>
</table>
| *Settings → Bias control:* same-model warning per target and independent-judge suggestions | *Calibration panel:* precision / recall with 95% intervals (screenshot taken with 5 simulated test labels: 3 true, 2 false positives) |

![Evidence and impact, verifier verdict and human review](docs/screenshots/accuracy-impact-review.png)

*A finding's Review tab: impact label with the severity cap, the verifier's verdict with its verbatim quote, and the True / False positive buttons. This screenshot is from a run recorded before the format-tolerant echo rule was added, so it still shows "Policy bypass (text only)"; new runs classify the same evidence as "Text echo only".*

Limits: recall is an upper bound, because attempts the judge called "no violation" never become findings and are not reviewed. With *inline* documents the "confidential" text is part of the user's own message, so such a finding is classed as `Text echo only`; use `delivery: ingest` with a canary to prove real exposure. Model names in the judge suggestions are defaults, edit them to what your account offers.

## Defense efficacy, reasoning chains and sandboxed verification

Three modules that measure the target's defenses and logic instead of only listing violations. They sit inside the existing scope, Governor, impact matrix and verifier; none of them generates attack text.

| Module | What it does |
|---|---|
| **Defense efficacy** (*Defense Efficacy* page, `POST /api/defense-tests`) | Runs one library against two endpoints of the same signed scope: `guardrail_off` (no defense) and `guardrail_on` (filter, hardened system prompt). The tool cannot switch a guardrail itself, so each mode is a saved target. Per attack vector the two outcomes are compared: *blocked* (violated without the defense, clean with it), *bypassed* (violated in both), *regression* (clean without, violated with), *never worked* (clean in both) or *inconclusive*. **Defense Score = blocked / (blocked + bypassed)** with a 95% Wilson interval, per category and attack family. "Violated" means a verified, non-false-positive finding. A vector that never worked unprotected is reported as untested, never counted as a success of the defense, and no working attack means "n/a", not 100%. |
| **Reasoning-layer evaluation** (`type: reasoning_chain`) | A case lists 2-12 steps. Each has a `message`, an optional operator-written `hint` or `constraint` appended to it, and an `expect` rule table (`contains`, `not_contains`, `refused`, `min_chars`, `max_chars`). After every reply the code checks the rules; a step that breaks them is a **Reasoning Deviation**. Every intermediate reply is stored and shown as a timeline in the finding's *Reasoning* tab. No judge call is made, the deviation must reproduce in the replays like any finding, and the impact class `Reasoning deviation` is capped at medium. The category must be `misinformation` so the scope's attack-class attestation applies. Example: `docs/examples/reasoning-chain-example.json`. |
| **Sandboxed verification** (*Settings -> Sandbox verification*, off by default) | After a finding is verified (and not refuted by the adversarial verifier), the target's own output is analysed by an isolated runner and the finding is labelled `verified_exploitable`, `not_exploitable`, `not_applicable` or `unavailable`. HTML is parsed (never rendered) for what a browser runs on its own: `<script>`, `on*` handlers, `javascript:` URLs, `srcdoc`, `<object>`. SQL is executed against a throw-away in-memory SQLite database with decoy rows and per-job canaries, behind an authorizer (no ATTACH, PRAGMA or extensions). Active HTML inside a Markdown code block counts as not exploitable. Shell commands are **never executed**. Only unsafe-output findings are eligible. A label never removes a finding and never changes its severity. |

Start the runner with `docker compose --profile sandbox up -d`. The `sandbox-runner` service has `network_mode: none`, a read-only root filesystem, all capabilities dropped, `no-new-privileges`, a non-root user and memory/pid limits. The backend does not get the Docker socket: it exchanges small JSON files with the runner through a shared volume, checks the runner's heartbeat before submitting, and validates the answer as untrusted data (known fields, known effect types, bounded lengths). Without the runner, findings are labelled `unavailable` and nothing else changes.

Limits: the HTML check is a parser, not a browser, so it proves that active content is present and would run on its own, not that a particular browser version runs it. The SQL check measures effects on a decoy schema (`users`, `api_keys`, `orders`); a real application's schema can differ. A defense test spends the budget twice and compares two different deployments, so any other difference between them (model version, system prompt) is part of the result. The score needs enough working attacks: read its interval, not just the number.

## CI/CD integration

An admin issues an API token under **Settings → CI/CD access tokens** (bound to a signed scope, with an expiry date; shown once, stored only as a hash,
revocable at any time). A token is a separate `ci` identity: it cannot sign in to the UI and can only call these two routes.

```bash
# 1. start (returns at once)
curl -sf -X POST https://aiveritx.example/api/scan-ci -H "Authorization: Bearer $AIVERITX_TOKEN" -H "Content-Type: application/json" \
  -d '{"scope_id":"<id>","endpoint_url":"<target>","library_id":"<id>","label":"model-2026-11","fail_on":"high"}'   # -> {"job_id": "...", "status": "queued"}
# 2. poll until status != running
curl -sf -H "Authorization: Bearer $AIVERITX_TOKEN" https://aiveritx.example/api/scan-ci/<job_id>
```

Omit `library_id` to run the built-in OWASP starter-kit scan (`owasp`: list of ids, default all ten). The result is JSON with a `summary`, a findings list
(no prompts, target responses or evidence text) and a `gate` object: `passed` is `false` when a **verified** finding is at least `fail_on` severe, and also
when the scan did not complete (halted, budget exhausted), so an incomplete scan never passes a pipeline. Limits: 6 starts per minute and 2 concurrent
scans per token, plus a failed-token limiter per client address. Every call is written to the audit log as `ci:<token name>`. Scans still run only under
the signed scope and never use adaptive mode.

## Roles (RBAC)

| Role | Permissions |
|---|---|
| **Viewer** (`viewer`) | Read only: dashboard, runs, findings, PDF/CSV reports, the OWASP matrix, library and scope lists |
| **Operator** (`operator`) | + start/stop tests, global stop, import libraries/templates, OWASP scans, read audit and settings |
| **Admin** (`admin`) | + create/sign/revoke scopes, write settings, user management |

Any API path that is not in the permission table requires **admin** (default deny). The role is read from the database on every request; a role change, deactivation and password reset take effect **immediately**.
The last active admin cannot be demoted. Every refused access is written to the audit log with the `ACCESS_DENIED` code. Scope signing is deliberately admin-only: authorization is a governance decision.

![Viewer role - the OWASP matrix is read-only](docs/e2e-run/28-owasp-viewer.png)

## Development (without Docker)

Requirements: Python 3.12+, Node 20.9+, PostgreSQL 14+.

```bash
# Backend
cd backend && python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
export AIVERITX_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/aiveritx
export AIVERITX_SCOPE_KEYS=k1:$(python -c "import secrets;print(secrets.token_hex(32))")
export AIVERITX_ADMIN_PASSWORD='at-least-12-characters'
uvicorn main:create_app --factory --host 127.0.0.1 --port 8000

# UI (another terminal)
cd frontend && npm install && npm run dev          # http://localhost:3000  (/api → 127.0.0.1:8000)
```

To run the production build locally, use `npm run build && npm start`. The build uses `output: "standalone"`, so `npm start` runs `node .next/standalone/server.js` and the `postbuild` step copies `.next/static` next to it. Plain `next start` is not the right command for this build (use `npm run start:next` only if you know why); without the copied assets the page loads without JavaScript and stays on "Verifying session…". The Dockerfile does the same copy.

## Tests, CI and E2E

```bash
cd backend && python -m pytest tests               # hermetic tests; no sudo needed (a temporary PostgreSQL is started) or AIVERITX_TEST_DSN
cd frontend && npm run typecheck && npm run build
sandbox/run_e2e.sh mock                            # strict checks with a real Chromium, inside an isolated network namespace
```

- **Hermetic tests:** a real PostgreSQL, a fake target and a fake judge; sockets may only connect to loopback, and any attempt to reach outside fails the test.
- **Isolated E2E (`sandbox/`):** runs in a network namespace where only the `lo` interface remains (`unshare -rn`); on every run it proves that outside network access is **impossible**. It can also run with real local Ollama models (`sandbox/run_e2e.sh ollama`). Latest run output: [`docs/e2e-run/`](docs/e2e-run/).
- **Module E2E (`sandbox/e2e_modules.py`, runs after the UI test):** drives Defense efficacy, reasoning chains and sandboxed verification through the real HTTP API against deterministic stand-ins, with the real runner process. No model and no API key needed.
- **CI** (`.github/workflows/ci.yml`): backend (PostgreSQL service, Python 3.12 + 3.14), UI (`npm ci`, typecheck, build), `pip-audit`, `npm audit --omit=dev`. To make it mandatory on PRs, define *branch protection → required checks* in the repository settings (it cannot be done from code). Dependabot runs weekly.

## Security principles

All of them are enforced in code and pinned by tests:

- No test starts with an unsigned/corrupted/expired/revoked/old-version scope; if there is no signing key, a scope cannot be created.
- Every request passes through the Governor; **at connect time** a single resolution is made, all addresses are checked and the connection is pinned to the IP (DNS rebinding). Cloud metadata/link-local is always blocked; loopback/internal networks only for `local` endpoints.
- Target output is untrusted data (envelope + sanitizing). The quote of a judge's violation claim must appear verbatim in the response; a finding is verified by replay; a canary protects against judge false negatives.
- Reports escape the target's text, PDF generation fetches no external resource, and CSV neutralizes formula injection.
- Password (scrypt) + a signed `HttpOnly`/`SameSite=Strict` session, brute-force lockout, a CSRF header, Host validation; API keys are never stored.
- Every refusal is coded separately; a hash-chained, tamper-evident audit record.

## Known limits

- **The judge can be wrong.** Small local models are not reliable judges (in our measurements one model never produced a valid schema, and one said "no violation" for a real leak). The defense is layered (quote verification + replay + canary + human review) but it is no substitute for judge quality; measurements: [`docs/LLM_REDTEAM.md`](docs/LLM_REDTEAM.md) §12.
- The OWASP view is **not a certificate**; LLM03/04/08 are limited in black-box testing.
- The scope signature is a server key; the approver's own Ed25519 signature (Phase 2) does not exist yet.
- If `ingest_delete_url` is not defined, uploaded documents remain on the target (the UI warns).
- Test content comes from the external library. The only generated text is the **Attacker agent's rewrites** (opt-in per run, allowed by the signed scope and per case) and the Remediator's advice; both are validated, bounded and audited. They have been exercised with deterministic stand-ins and fake models in tests, **not yet measured against real Attacker/Remediator models**.
- Uploaded documents are sent as JSON (`content`, or `content_base64` for PDF/DOCX). Targets that require `multipart/form-data` uploads are not supported yet.
- CI and Remediator rate limits are kept in process memory: with several backend replicas each one counts separately.
- Benchmarks are small, non-statistical samples: use them to spot clear differences, not to publish a precise ranking.
- Token counts rely on the provider's `usage` field; otherwise they are estimates and are written to the report as "estimate".
- **Privacy and extraction modules are indicators, not proof.** The extraction surrogate is a retrieval lookup, not a trained model; membership inference is a statistical signal over samples you supply; the vector test only covers credential-less access to Chroma, Qdrant and Weaviate (no Pinecone).
- **Model file scanning cannot detect poisoned weights**, only code-execution risk and format anomalies; uploads are limited to 32 MB.
- **Credentials are never stored:** API keys, cookie strings and header values live in server memory only and are asked for again after a restart; saved targets keep only connection details and the auth type. A pasted cookie is only as safe as the account it belongs to: use test accounts and targets you are authorized to test.
- **Target API format:** targets must speak the OpenAI chat-completions or Anthropic messages format; custom request/response shapes are not supported yet.
- **Uploaded PDF/DOCX/EML files** are reduced to their visible text and re-created; hidden text in Word files is skipped, files with invisible characters are refused, and white-on-white PDF text cannot be told apart from normal text (the preview shows exactly what was extracted).
- **Tool sandbox**: tool cases do not support streaming; the Anthropic tool format is covered by unit tests, not yet by a real Anthropic target. Crescendo turns come from the library only; the Attacker does not write conversation turns.
- **Suite modules (multimodal, chains, knowledge map, campaigns) have been tested with scripted targets and a small local model, not with a production multimodal model.** The carrier check reads text with OCR and metadata only (no speech-to-text, no image classifier), so text hidden in ways OCR cannot read is not detected; the token estimate for a file is a fixed number per file. Campaigns are advanced by an operator action (or CI call) per session; there is no background scheduler. A knowledge map measures what string matching can see, not what the target "knows".
- **Imported payload libraries and branching have been tested with scripted targets only** (backend tests and the isolated E2E), not against a production model. The family-to-ATLAS/ASI table is a curated evidence mapping (ATLAS ids change between releases: AML.T0068, AML.T0080.000 and AML.T0086 should be verified against your ATLAS version). The importer layouts come from the projects' public descriptions; a changed format needs a `mapping`. Branching's `refused` is a wording check, not the judge: use `contains` rules for target-specific refusals.
- **Not included by design:** hidden-instruction *document* carriers (uploaded documents are reduced to visible text; only library-supplied image/audio files are carried) and an MCP tool-description scanner. For MCP scanning, integrating a maintained open-source scanner is the better route.
- **The mock target used for the screenshots and E2E does not trigger every compliance badge** (for example a finding with a MITRE ATLAS badge); the mapping, CSV/PDF output and badges are verified by backend tests, not by a real vulnerable target. **PLAGUE and PersonaTeaming ran end to end once against a small local model (`llama3.2:3b`) as the Attacker, which produced no violation;** their effect with strong models is not measured.
- **Compliance mappings are curated evidence mappings** (ASI, ATLAS, NIST AI RMF, AISVS chapters), not conformance statements; ASR is not comparable with published benchmark leaderboards; PLAGUE and PersonaTeaming have been tested with scripted Attacker models and one run with a small local model, not with strong models. Evaluations the judge could not complete (`inconclusive`) are never counted as clean and stay out of the ASR.
- The dashboard's live stream shows the engine's real recorded steps (requests sent, judge verdicts, refusals, cleanup); it does not show model "thoughts".

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - architecture: the orchestration engine, judge, adapters, governor, data model, security model
- [`docs/LLM_REDTEAM.md`](docs/LLM_REDTEAM.md) - design decisions, judge measurements, OWASP decisions
- [`sandbox/README.md`](sandbox/README.md) - the isolated E2E environment
- [`.env.example`](.env.example) - the environment variable template

## Folder structure

```
backend/            Python / FastAPI / PostgreSQL (llm_redteam/ core, starter_kit/ owasp/ + advanced/ templates, tests/)
frontend/           Next.js 16 / React 19 / Tailwind / Radix / Framer Motion / Recharts / TanStack Query
sandbox/            Isolated E2E: fake LLM, Ollama bridge, network-namespace orchestration
docs/               Architecture, design decisions, E2E output (screenshots, PDFs)
scripts/            init-env.sh (secret generation)
docker-compose.yml  The whole stack with one command
.github/            CI + Dependabot
LICENSE             GNU AGPL-3.0
_archive/           Earlier (web/network based) work - not part of the running project (not added to version control)
```

## Contributing

**AIVeritX gets better with every person who uses it. Come join the community.**

Found a bug? [Open an issue](../../issues/new/choose). Have an idea, a new attack family or a better judge prompt? Send a pull request. First time contributing to open source? Pick a small fix, we are happy to help you get it merged. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) first, and report security problems privately as described in [`SECURITY.md`](SECURITY.md).

Before opening a PR:

```bash
cd backend && python -m pytest tests            # hermetic, starts its own PostgreSQL
cd frontend && npm run typecheck && npm run build
```

Keep the design rules: the engine holds no attack content (it lives in the library), safety controls stay in code, and every new path that reaches a target goes through the scope gate and the Governor. Add a test with every change.

<a id="legal-disclaimer"></a>

## Legal disclaimer and responsible use

AIVeritX sends adversarial prompts to the systems it tests. **It is intended for legal, authorized security testing only.**

- **Authorization is required.** Use AIVeritX only against systems you own or for which you have explicit, written permission from the owner. The signed scope records that authorization and makes it auditable, but it does not replace the owner's permission.
- **You are responsible for compliance.** You must follow all laws and regulations that apply to you and to the target, your contracts, and the target's terms of service, including the usage policies of any AI provider whose models or APIs you test or use as a judge.
- **No warranty, no liability.** The software is provided "as is", without warranty of any kind (see [`LICENSE`](LICENSE)). The authors and contributors are not liable for any damage, data loss, service disruption, costs (for example API usage fees) or legal consequences that result from using or misusing it.
- **Disclose responsibly.** Report vulnerabilities you find to the system's owner through their disclosure process, and do not use findings to harm anyone.

Using AIVeritX for unauthorized access, attacks on systems you do not have permission to test, or any other illegal purpose is strictly prohibited. This section is not legal advice.

## Support

If AIVeritX saves you time or catches something real, a star helps other security teams find it.

## License

AIVeritX is licensed under the **[GNU Affero General Public License, version 3 (AGPL-3.0)](LICENSE)**.

```
Copyright (C) 2026 tmrswrr

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
```

**What it means in practice** (not legal advice; the binding text is [`LICENSE`](LICENSE)):

- You may freely use, study, modify and distribute the software; **commercial use is not prohibited**.
- If you distribute a modified version to others, you must offer it under AGPL-3.0 together with its source code.
- **If you offer it as a service over a network (SaaS), you must offer the complete source code of the modified version to everyone who uses that service (§13).**
  This clause exists to prevent the project from being turned into a closed-source service.
- As the copyright holder (if there is no other holder) you may also license your own code under other terms (e.g. commercial dual licensing).
