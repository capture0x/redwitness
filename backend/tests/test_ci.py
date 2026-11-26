"""Module 3: CI/CD integration - API tokens (`ci` identity), POST /api/scan-ci (async job) and GET /api/scan-ci/{job_id}."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from fakes import LEAK, openai_json
from llm_redteam import ci
from llm_redteam.store import Store
from test_rbac import H, world  # noqa: F401  (world is a fixture)

LEAKING = f"Sure, here is the key {LEAK}."
REFUSE = "Sorry, I cannot do that."



@pytest.fixture
def ciw(world, fresh_db):
    w = world
    w.store = Store(fresh_db)
    w.lineage = w.store.scope_lineage(w.sid)
    w.anon = TestClient(w.app)                                   # no cookie at all: what a pipeline looks like
    w.anon.__enter__()

    def make(name="gh-actions", lineages=None, ttl=30):
        r = w.admin.post("/api/ci-tokens", json={"name": name, "lineage_ids": lineages or [w.lineage], "ttl_days": ttl}, headers=H)
        assert r.status_code == 201, r.text
        return r.json()
    w.make = make
    w.tok = make()
    w.auth = lambda t=None: {"authorization": f"Bearer {(t or w.tok)['token']}"}
    w.scan = lambda t=None, **kw: w.anon.post("/api/scan-ci", json={"scope_id": w.sid, "endpoint_url": w.target.url, "library_id": w.lid, "replay_n": 1, "replay_k": 1} | kw, headers=w.auth(t))

    def finish(job_id, t=None, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            r = w.anon.get(f"/api/scan-ci/{job_id}", headers=w.auth(t)).json()
            if r["status"] != "running":
                return r
            time.sleep(0.05)
        raise AssertionError("scan did not finish")
    w.finish = finish
    yield w
    w.anon.__exit__(None, None, None)


def audit_actions(w):
    with w.store.conn() as c:
        return [(r["actor"], r["action"], json.loads(r["detail_json"])) for r in c.execute("SELECT actor, action, detail_json FROM audit ORDER BY seq").fetchall()]


# ============================================================ token primitives
def test_token_format_hash_and_bearer_parsing():
    t, h, prefix = ci.new_token()
    assert t.startswith("rlci_") and len(t) > 40 and h == ci.hash_token(t) and len(h) == 64 and t.startswith(prefix) and t != ci.new_token()[0]
    assert ci.bearer(f"Bearer {t}") == t and ci.bearer(f"bearer {t}") == t
    for bad in (None, "", "Basic abc", "Bearer ", "Bearer notatoken", f"Bearer {'rlci_' + 'x' * 300}"):
        assert ci.bearer(bad) is None


def test_rate_limiter_window():
    now = [0.0]
    rl = ci.RateLimiter(clock=lambda: now[0])
    assert [rl.hit("k", 3, 60) for _ in range(3)] == [0, 0, 0]
    assert rl.hit("k", 3, 60) > 0 and rl.hit("other", 3, 60) == 0
    now[0] = 61
    assert rl.hit("k", 3, 60) == 0


# ============================================================ token management (admin only, hash only at rest)
def test_token_is_shown_once_and_only_its_hash_is_stored(ciw):
    w = ciw
    plain = w.tok["token"]
    listed = w.admin.get("/api/ci-tokens").json()
    assert len(listed) == 1 and "token" not in listed[0] and listed[0]["prefix"] == plain[:11] and listed[0]["status"] == "active"
    assert plain not in json.dumps(listed)
    with w.store.conn() as c:
        row = c.execute("SELECT * FROM api_tokens").fetchone()
    assert row["token_hash"] == ci.hash_token(plain) and plain not in json.dumps(row, default=str)
    assert plain not in json.dumps(audit_actions(w))                          # never in the audit log either


@pytest.mark.parametrize("who", ["op", "viewer"])
def test_only_admins_manage_tokens(ciw, who):
    c = getattr(ciw, who)
    assert c.post("/api/ci-tokens", json={"name": "abc", "lineage_ids": [ciw.lineage]}, headers=H).status_code == 403
    assert c.get("/api/ci-tokens").status_code == 403
    assert c.post(f"/api/ci-tokens/{ciw.tok['id']}/revoke", headers=H).status_code == 403


def test_token_creation_validation(ciw):
    w = ciw
    post = lambda **kw: w.admin.post("/api/ci-tokens", json={"name": "abc", "lineage_ids": [w.lineage]} | kw, headers=H).status_code  # noqa: E731
    assert post(lineage_ids=["no-such-lineage"]) == 422 and post(lineage_ids=[]) == 422
    assert post(ttl_days=0) == 422 and post(ttl_days=366) == 422 and post(name="ab") == 422


def test_ci_identity_cannot_sign_in(ciw):
    r = ciw.anon.post("/api/auth/login", json={"username": "ci:gh-actions", "password": ciw.tok["token"]})
    assert r.status_code == 401


# ============================================================ authentication / authorization on the CI routes
def test_scan_ci_requires_a_valid_token(ciw):
    w = ciw
    body = {"scope_id": w.sid, "endpoint_url": w.target.url, "library_id": w.lid}
    for headers in ({}, {"authorization": "Bearer rlci_" + "a" * 43}, {"authorization": "Basic Zm9vOmJhcg=="}, {"authorization": "Bearer junk"}):
        assert w.anon.post("/api/scan-ci", json=body, headers=headers).status_code == 401
        assert w.anon.get("/api/scan-ci/x", headers=headers).status_code == 401
    assert ("ci:unknown", "ci.auth_failed") in [(a, b) for a, b, _ in audit_actions(w)]


def test_a_user_session_is_not_accepted_on_the_ci_routes(ciw):
    r = ciw.admin.post("/api/scan-ci", json={"scope_id": ciw.sid, "endpoint_url": ciw.target.url, "library_id": ciw.lid}, headers=H)
    assert r.status_code == 401


def test_a_ci_token_is_useless_anywhere_else(ciw):
    w = ciw
    for method, path in (("GET", "/api/runs"), ("GET", "/api/findings"), ("GET", "/api/system"), ("GET", "/api/audit"), ("GET", "/api/users"),
                         ("GET", "/api/ci-tokens"), ("POST", "/api/runs"), ("POST", "/api/kill"), ("GET", "/api/settings"), ("POST", "/api/scopes")):
        r = w.anon.request(method, path, headers=w.auth() | H)
        assert r.status_code == 401, (method, path, r.status_code)


def test_revoked_and_expired_tokens_stop_working(ciw):
    w = ciw
    assert w.scan().status_code == 202
    assert w.admin.post(f"/api/ci-tokens/{w.tok['id']}/revoke", headers=H).status_code == 200
    assert w.scan().status_code == 401 and w.anon.get("/api/scan-ci/x", headers=w.auth()).status_code == 401
    assert w.admin.post(f"/api/ci-tokens/{w.tok['id']}/revoke", headers=H).status_code == 404         # already revoked
    assert w.admin.get("/api/ci-tokens").json()[0]["status"] == "revoked"
    short = w.make("short-lived")
    with w.store.conn() as c:
        c.execute("UPDATE api_tokens SET expires_at=%s WHERE id=%s", (time.time() - 1, short["id"]))
    assert w.scan(short).status_code == 401
    assert [t for t in w.admin.get("/api/ci-tokens").json() if t["id"] == short["id"]][0]["status"] == "expired"


def test_token_is_limited_to_its_scope_lineages(ciw):
    w = ciw
    other = w.admin.post("/api/ci-tokens", json={"name": "other", "lineage_ids": [w.lineage]}, headers=H).json()
    with w.store.conn() as c:                                                   # narrow it to a lineage that is not the scope's
        c.execute("UPDATE api_tokens SET lineage_ids_json=%s WHERE id=%s", (json.dumps(["another-lineage"]), other["id"]))
    r = w.scan(other)
    assert r.status_code == 403
    assert w.scan(w.tok, scope_id="does-not-exist").status_code == 403           # same answer: no way to probe which scopes exist
    assert ("ci:other", "ci.scan.denied") in [(a, b) for a, b, _ in audit_actions(w)]


# ============================================================ asynchronous scans
def test_scan_is_asynchronous_and_the_result_is_pipeline_json(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(LEAKING))
    r = w.scan(fail_on="high", label="model-2026-11-17")
    assert r.status_code == 202
    j = r.json()
    assert set(j) == {"job_id", "status", "poll", "cases"} and j["status"] == "queued" and j["poll"] == f"/api/scan-ci/{j['job_id']}"
    res = w.finish(j["job_id"])
    assert res["status"] == "completed" and res["label"] == "model-2026-11-17" and res["job_id"] == j["job_id"]
    assert res["summary"]["verified"] == 1 and res["summary"]["total"] == 1
    f = res["findings"][0]
    assert {"id", "case_id", "category", "owasp", "severity", "status", "title"} == set(f) and f["status"] == "verified" and f["severity"] == "high"
    assert res["gate"] == {"fail_on": "high", "passed": False, "reason": "verified_findings", "blocking": [f["id"]]}
    assert LEAK not in json.dumps(res) and "message" not in json.dumps(res["findings"])      # no prompts/responses/evidence leave through CI output
    assert res["run_id"] and res["progress"]["requests"] >= 1


def test_clean_target_passes_the_gate_and_running_state_is_reported(ciw):
    w = ciw
    gate_open = []
    def slow(n, b, h):
        time.sleep(0.4)
        return 200, {}, openai_json(REFUSE)
    w.target.behavior = slow
    j = w.scan(fail_on="low").json()
    first = w.anon.get(f"/api/scan-ci/{j['job_id']}", headers=w.auth()).json()
    assert first["status"] == "running" and first["gate"]["passed"] is None and first["gate"]["reason"] == "running" and first["findings"] == []
    res = w.finish(j["job_id"])
    assert res["status"] == "completed" and res["gate"]["passed"] is True and res["summary"]["total"] == 0 and gate_open == []


def test_gate_threshold_only_counts_verified_findings_at_or_above_it(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(LEAKING))
    res = w.finish(w.scan(fail_on="critical").json()["job_id"])                  # the finding is "high": below the critical threshold
    assert res["summary"]["verified"] == 1 and res["gate"]["passed"] is True
    res = w.finish(w.scan().json()["job_id"])                                    # no fail_on: informational
    assert res["gate"] == {"fail_on": None, "passed": True, "reason": "no_gate_requested", "blocking": []}
    assert w.scan(fail_on="catastrophic").status_code == 422


def test_an_incomplete_scan_never_passes_the_gate(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(REFUSE))
    lim = {"max_requests_per_minute": 600, "max_total_tokens": 20}               # the token budget is exhausted almost at once
    from test_api import confirm, scope_body
    body = scope_body(w.target, limits=lim, name="tiny")
    prep = w.admin.post("/api/scopes/prepare", json=body, headers=H).json()
    sid = w.admin.post("/api/scopes", json=body | confirm(prep), headers=H).json()["id"]
    tok = w.make("tiny-token", [w.store.scope_lineage(sid)])
    j = w.anon.post("/api/scan-ci", json={"scope_id": sid, "endpoint_url": w.target.url, "library_id": w.lid, "fail_on": "low"}, headers=w.auth(tok)).json()
    res = w.finish(j["job_id"], tok)
    assert res["status"] != "completed" and res["gate"]["passed"] is False and res["gate"]["reason"].startswith("run_incomplete:")


def test_a_token_only_sees_its_own_jobs(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(REFUSE))
    mine = w.scan().json()["job_id"]
    other = w.make("other-pipeline")
    assert w.anon.get(f"/api/scan-ci/{mine}", headers=w.auth(other)).status_code == 404
    assert w.anon.get("/api/scan-ci/not-a-job", headers=w.auth()).status_code == 404
    assert w.anon.get(f"/api/scan-ci/{mine}", headers=w.auth()).status_code == 200
    w.finish(mine)


def test_scan_runs_are_normal_runs_under_the_signed_scope(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(REFUSE))
    res = w.finish(w.scan().json()["job_id"])
    run = w.admin.get(f"/api/runs/{res['run_id']}").json()
    assert run["config"]["started_by"] == "ci:gh-actions" and run["scope_id"] == w.sid
    # the hard gate still applies: a revoked scope cannot be scanned from CI
    assert w.admin.post(f"/api/scopes/{w.sid}/revoke", headers=H).status_code in (200, 204)
    r = w.scan()
    assert r.status_code == 409


def test_owasp_starter_kit_scan_from_ci(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(REFUSE))
    r = w.anon.post("/api/scan-ci", json={"scope_id": w.sid, "endpoint_url": w.target.url, "owasp": ["LLM07_SystemPromptLeakage"], "label": "owasp"}, headers=w.auth())
    assert r.status_code == 202 and r.json()["cases"] >= 1
    w.finish(r.json()["job_id"])


# ============================================================ rate limits and audit
def test_start_rate_limit_and_concurrency_limit(ciw):
    w = ciw
    r = w.scan(scope_id="nope")                                                  # rejected requests count too
    codes = [r.status_code] + [w.scan(scope_id="nope").status_code for _ in range(ci.START_PER_MINUTE)]
    assert codes[:ci.START_PER_MINUTE] == [403] * ci.START_PER_MINUTE and codes[-1] == 429
    limited = w.scan(scope_id="nope")
    assert limited.status_code == 429 and int(limited.headers["retry-after"]) >= 1
    other = w.make("second")                                                     # limits are per token
    assert w.scan(other, scope_id="nope").status_code == 403


def test_concurrent_scan_limit_per_token(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (time.sleep(0.6), (200, {}, openai_json(REFUSE)))[1]
    ids = [w.scan().json()["job_id"] for _ in range(ci.MAX_RUNNING_PER_TOKEN)]
    r = w.scan()
    assert r.status_code == 429 and r.json()["detail"]["reason"] == "RATE_LIMITED"
    for i in ids:
        w.finish(i)
    assert w.scan().status_code == 202


def test_read_rate_limit(ciw):
    w = ciw
    codes = {w.anon.get("/api/scan-ci/none", headers=w.auth()).status_code for _ in range(ci.READ_PER_MINUTE + 3)}
    assert codes == {404, 429}


def test_failed_token_attempts_are_rate_limited_per_client(ciw):
    w = ciw
    codes = [w.anon.get("/api/scan-ci/x", headers={"authorization": "Bearer rlci_" + "z" * 43}).status_code for _ in range(ci.BAD_AUTH_PER_MINUTE + 2)]
    assert codes[0] == 401 and codes[-1] == 429
    assert "ci.rate_limited" in [b for _, b, _ in audit_actions(w)]


def test_every_ci_action_is_audited_under_the_token_identity(ciw):
    w = ciw
    w.target.behavior = lambda n, b, h: (200, {}, openai_json(REFUSE))
    jid = w.scan(label="build-42").json()["job_id"]
    w.finish(jid)
    acts = audit_actions(w)
    mine = [(b, d) for a, b, d in acts if a == "ci:gh-actions"]
    names = [b for b, _ in mine]
    assert "ci.scan.start" in names and "ci.scan.read" in names
    start = dict(mine)["ci.scan.start"]
    assert start["label"] == "build-42" and start["job_id"] == jid and start["token_id"] == w.tok["id"]
    assert ("admin", "ci_token.create") in [(a, b) for a, b, _ in acts]
    assert w.store.audit_verify() is None
    assert w.tok["token"] not in json.dumps(acts)
