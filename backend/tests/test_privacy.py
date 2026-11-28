"""Feature: model extraction exposure, membership inference and read-only vector store exposure analyses."""
import contextlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from fakes import FakeTarget, openai_json
from llm_redteam import privacy
from llm_redteam.auth import Auth
from llm_redteam.store import Store
from llm_redteam.targets import TargetAdapter
from llm_redteam.vectorprobe import ALLOW, ProbeRefused, VectorProbe, mask_preview
from main import create_app
from test_api import RING, _plain_http, confirm, scope_body
from test_rbac import H, PW

CLASSES = ["model_extraction", "membership_inference", "vector_store_exposure"]
LIMITS = {"max_requests_per_minute": 600, "max_conversations": 100, "max_requests": 300}
COLL = "/api/v2/tenants/default_tenant/databases/default_database/collections"


def words(tag, n=20):
    return " ".join(f"{tag}{i}w" for i in range(n))


MEMBERS = [words(f"m{k}") for k in range(6)]
NON_MEMBERS = [words(f"n{k}") for k in range(6)]


def memorizing(n, body, h):
    prompt = body["messages"][-1]["content"]
    if "Continue the following text" in prompt:
        prefix = prompt.split("\n\n", 1)[1]
        for m in MEMBERS:
            if m.startswith(prefix):
                return 200, {}, openai_json(m[len(prefix):].strip(), 40, 20)
        return 200, {}, openai_json("I am not sure how that text continues.", 40, 10)
    return 200, {}, openai_json("Answer about: " + prompt, 10, 20)


def chroma_exposed(n, body, h):
    p, m = h[":path"].split("?")[0], h[":method"]
    if p.endswith("/heartbeat"):
        return 200, {}, {"nanosecond heartbeat": 1}
    if p == COLL:
        return 200, {}, [{"id": "c1", "name": "docs"}]
    if p.endswith("/count"):
        return 200, {"content-type": "application/json"}, b"42"
    if p.endswith("/get") and m == "POST":
        return 200, {}, {"documents": ["Mail bob@corp.com key sk-abcdefghijklmnop12345 end", "plain note"], "embeddings": [[0.11, 0.22, 0.33]]}
    return 404, {}, {}


def protected(n, body, h):
    return 401, {}, {"error": "unauthorized"}


@pytest.fixture
def pw(fresh_db):
    llm, vec = FakeTarget(), FakeTarget()
    llm.behavior = memorizing

    async def noop(s):
        pass
    app = create_app(fresh_db, RING, adapter_factory=lambda ep, key, stream: TargetAdapter(ep, key, stream=stream, sleep=noop, http=_plain_http(), max_retries=1),
                     vector_factory=lambda ep, gov: VectorProbe(ep, gov, http=_plain_http()), auth=Auth(PW))
    with contextlib.ExitStack() as st:
        w = type("W", (), {})()
        w.llm, w.vec, w.store = llm, vec, Store(fresh_db)
        w.admin, w.viewer, w.anon = (st.enter_context(TestClient(app)) for _ in range(3))
        assert w.admin.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
        assert w.admin.post("/api/users", json={"username": "viewer1", "password": "viewer1-password-99", "role": "viewer"}, headers=H).status_code == 201
        assert w.viewer.post("/api/auth/login", json={"username": "viewer1", "password": "viewer1-password-99"}).status_code == 200
        vec.behavior = chroma_exposed
        w.vurl = f"http://127.0.0.1:{vec.port}"

        def scope(classes=CLASSES, **lim):
            body = scope_body(llm, attack_classes=classes, limits=LIMITS | lim,
                              endpoints=[{"url": llm.url, "provider": "openai_compat", "model": "m", "local": True},
                                         {"url": w.vurl, "provider": "chroma", "model": "", "local": True}])
            prep = w.admin.post("/api/scopes/prepare", json=body, headers=H)
            assert prep.status_code == 200, prep.text
            r = w.admin.post("/api/scopes", json=body | confirm(prep.json()), headers=H)
            assert r.status_code == 201, r.text
            return r.json()["id"]

        def run(kind, sid=None, url=None, expect=202, **kw):
            sid = sid or scope()
            r = w.admin.post("/api/analyses", json={"kind": kind, "scope_id": sid, "endpoint_url": url or (w.vurl if kind == "vector" else llm.url)} | kw, headers=H)
            assert r.status_code == expect, r.text
            return r.json()

        def done(aid, timeout=30):
            end = time.time() + timeout
            while time.time() < end:
                d = w.admin.get(f"/api/analyses/{aid}").json()
                if d["status"] != "running":
                    return d
                time.sleep(0.05)
            raise AssertionError("analysis did not finish")
        w.scope, w.run, w.done = scope, run, done
        yield w
        llm.close()
        vec.close()


# ---------------------------------------------------------------- pure helpers
def test_scoring_helpers():
    assert privacy.f1(["a", "b"], ["a", "b"]) == 1.0 and privacy.f1(["a"], ["b"]) == 0.0 and privacy.f1([], ["a"]) == 0.0
    assert privacy.longest_run(list("abcde"), list("xbcdy")) == 3
    assert privacy.auc([1, 1], [0, 0]) == 1.0 and privacy.auc([0], [0]) == 0.5 and privacy.auc([], [1]) is None
    pairs = [(f"explain topic{i} please", f"answer {'alpha' if i % 2 else 'beta'} about topic{i}") for i in range(20)]
    s = privacy.surrogate_proxy(pairs)
    assert s["train"] == 14 and s["test"] == 6 and "not a trained model" in s["note"]
    assert privacy.surrogate_proxy(pairs[:5]) is None


def test_validation_limits():
    with pytest.raises(privacy.AnalysisError):
        privacy.validate_extraction(privacy.EXTRACTION_MAX_QUERIES + 1, 5000, [])
    with pytest.raises(privacy.AnalysisError):
        privacy.validate_extraction(30, privacy.EXTRACTION_MAX_TOKENS + 1, [])
    with pytest.raises(privacy.AnalysisError):
        privacy.validate_extraction(30, 5000, ["x\ny"])
    with pytest.raises(privacy.AnalysisError):
        privacy.validate_membership(MEMBERS[:3], NON_MEMBERS)
    with pytest.raises(privacy.AnalysisError):
        privacy.validate_membership(MEMBERS, ["too short"] * 6)


def test_mask_preview_hides_secrets_and_truncates():
    m, hit = mask_preview("mail bob@corp.com and sk-abcdefghijklmnop12345 call 4111 1111 1111 1111 " + "x" * 100)
    assert hit and "bob@corp.com" not in m and "sk-abc" not in m and "4111" not in m and len(m) <= 62


def test_vector_allowlist_refuses_writes():
    p = VectorProbe.__new__(VectorProbe)
    p.ep = type("E", (), {"provider": "chroma", "url": "http://x"})()
    p.gov = None
    import asyncio
    for method, path in (("DELETE", COLL + "/c1"), ("PUT", COLL), ("POST", COLL), ("POST", COLL + "/c1/delete"), ("POST", COLL + "/c1/add"),
                         ("GET", "/api/v2/auth/identity"), ("GET", COLL + "/../x")):
        with pytest.raises(ProbeRefused):
            asyncio.run(p._req(method, path))
    assert all(m in ("GET", "POST") for rules in ALLOW.values() for m, _ in rules)


# ---------------------------------------------------------------- extraction
def test_extraction_budgeted_and_stores_no_text(pw):
    pw.llm.behavior = lambda n, b, h: (200, {}, openai_json("Answer about: " + b["messages"][-1]["content"], 10, 20))
    d = pw.done(pw.run("extraction", queries=30, max_tokens=20000)["id"])
    r = d["result"]
    assert d["status"] == "completed" and r["pairs"] == 30 and r["tokens"]["total"] <= r["tokens"]["ceiling"]
    assert r["determinism"]["mean_f1"] == 1.0 and r["surrogate_proxy"] and r["est_tokens_for_10k_pairs"] == 10000 * 30
    assert r["risk"]["level"] in ("medium", "high") and r["queries_sent"] == 35
    assert "Answer about" not in json.dumps(d) and "Explain" not in json.dumps(d)
    assert len(pw.llm.calls) == 35 and all(c["body"]["max_tokens"] <= privacy.RESPONSE_CAP for c in pw.llm.calls)


def test_extraction_token_ceiling_stops_early(pw):
    pw.llm.behavior = lambda n, b, h: (200, {}, openai_json("ok", 300, 200))
    r = pw.done(pw.run("extraction", queries=30, max_tokens=1000)["id"])
    assert r["status"] == "halted" and r["result"]["stopped_reason"] == "ANALYSIS_TOKEN_CEILING" and r["result"]["pairs"] <= 3


def test_extraction_stops_when_target_throttles(pw):
    pw.llm.behavior = lambda n, b, h: (429, {"retry-after": "0"}, {"error": "slow down"})
    r = pw.done(pw.run("extraction")["id"])
    assert r["status"] == "halted" and r["result"]["stopped_reason"] == "TARGET_RATE_LIMITED" and r["result"]["risk"]["level"] == "low"
    assert len(pw.llm.calls) < 20


def test_hard_ceilings_cannot_be_raised(pw):
    sid = pw.scope()
    for kw in ({"queries": 101}, {"max_tokens": 60001}, {"queries": 1}):
        assert pw.run("extraction", sid, expect=422, **kw)


def test_scope_request_limit_still_applies(pw):
    sid = pw.scope(max_requests=4)
    d = pw.done(pw.run("extraction", sid)["id"])
    assert d["status"] == "halted" and d["result"]["stopped_reason"] == "REQUEST_LIMIT" and len(pw.llm.calls) == 4


# ---------------------------------------------------------------- membership
def test_membership_detects_memorized_samples(pw):
    d = pw.done(pw.run("membership", members=MEMBERS, non_members=NON_MEMBERS)["id"])
    r = d["result"]
    assert r["verbatim"]["auc"] == 1.0 and r["verbatim"]["members_reproduced_ge_80pct"] == 1.0 and r["risk"]["level"] == "high"
    blob = json.dumps(d)
    assert "m0w" not in blob and "n0w" not in blob                                  # no sample text stored
    assert r["per_sample"]["members"][0]["sha256"] and r["logprob"]["available"] is False


def test_membership_no_signal_when_nothing_is_memorized(pw):
    pw.llm.behavior = lambda n, b, h: (200, {}, openai_json("I am not sure how that text continues.", 40, 10))
    r = pw.done(pw.run("membership", members=MEMBERS, non_members=NON_MEMBERS)["id"])["result"]
    assert r["risk"]["level"] == "low" and r["verbatim"]["auc"] == 0.5


def test_membership_logprobs_opt_in(pw):
    def lp(n, b, h):
        out = openai_json("continuation text here", 10, 5)
        out["choices"][0]["logprobs"] = {"content": [{"logprob": -0.1}, {"logprob": -0.3}]}
        return 200, {}, out
    pw.llm.behavior = lp
    r = pw.done(pw.run("membership", members=MEMBERS, non_members=NON_MEMBERS, use_logprobs=True)["id"])["result"]
    assert r["logprob"]["available"] is True and all(c["body"].get("logprobs") for c in pw.llm.calls)
    pw.llm.calls.clear()
    pw.done(pw.run("membership", members=MEMBERS, non_members=NON_MEMBERS)["id"])
    assert not any("logprobs" in c["body"] for c in pw.llm.calls)


def test_membership_input_validation(pw):
    sid = pw.scope()
    assert pw.run("membership", sid, expect=422, members=MEMBERS[:2], non_members=NON_MEMBERS)
    assert pw.run("membership", sid, expect=422, members=MEMBERS, non_members=["short text"] * 6)


# ---------------------------------------------------------------- vector store
def test_vector_exposed_is_critical_masked_and_read_only(pw):
    d = pw.done(pw.run("vector")["id"])
    r = d["result"]
    codes = {f["code"] for f in r["findings"]}
    assert {"VECTOR_RECORDS_READABLE", "VECTOR_EMBEDDINGS_READABLE", "VECTOR_COLLECTIONS_LISTABLE", "VECTOR_SENSITIVE_PATTERN"} <= codes
    assert r["risk"]["level"] == "critical" and r["collections"][0]["count"] == 42 and r["collections"][0]["embedding_dims"] == 3
    blob = json.dumps(d)
    assert "bob@corp.com" not in blob and "sk-abcdefghijklmnop" not in blob and "0.11" not in blob
    methods = {(c["method"], c["path"].split("?")[0]) for c in pw.vec.calls}
    assert {m for m, _ in methods} <= {"GET", "POST"} and not any(p.endswith(("/add", "/delete", "/upsert")) for _, p in methods)
    assert all("authorization" not in {k.lower() for k in c["headers"]} for c in pw.vec.calls)        # credential-less on purpose
    assert next(c for c in pw.vec.calls if c["path"].endswith("/get"))["body"]["limit"] == 3


def test_vector_protected_is_low(pw):
    pw.vec.behavior = protected
    r = pw.done(pw.run("vector")["id"])["result"]
    assert r["risk"]["level"] == "low" and {f["code"] for f in r["findings"]} == {"VECTOR_PROTECTED"} and r["collections"] == []


def test_vector_respects_request_limit(pw):
    d = pw.done(pw.run("vector", pw.scope(max_requests=2))["id"])
    assert d["result"]["stopped_reason"] == "REQUEST_LIMIT" and len(pw.vec.calls) == 2


# ---------------------------------------------------------------- gates, roles, audit
def test_class_must_be_in_signed_scope(pw):
    sid = pw.scope(classes=["system_prompt_extraction"])
    for kind in ("extraction", "membership", "vector"):
        r = pw.admin.post("/api/analyses", json={"kind": kind, "scope_id": sid, "endpoint_url": pw.vurl if kind == "vector" else pw.llm.url}, headers=H)
        assert r.status_code == 409 and r.json()["detail"]["reason"] == "ATTACK_CLASS_NOT_ALLOWED"
    assert pw.llm.calls == [] and pw.vec.calls == []


def test_endpoint_kind_mismatch_and_unknown_endpoint(pw):
    sid = pw.scope()
    assert pw.run("vector", sid, url=pw.llm.url, expect=422)
    assert pw.run("extraction", sid, url=pw.vurl, expect=422)
    assert pw.admin.post("/api/analyses", json={"kind": "vector", "scope_id": sid, "endpoint_url": "http://127.0.0.1:9/"}, headers=H).status_code == 409
    assert pw.admin.post("/api/analyses", json={"kind": "nope", "scope_id": sid, "endpoint_url": pw.vurl}, headers=H).status_code == 422


def test_vector_endpoint_cannot_run_a_library(pw):
    sid = pw.scope()
    lid = pw.admin.post("/api/libraries", json={"content": json.dumps({"library": {"name": "l", "version": "1"}, "cases": [
        {"id": "a", "category": "system_prompt_extraction", "turns": ["hello there friend"], "expected_behavior": "x"}]})}, headers=H).json()["id"]
    r = pw.admin.post("/api/runs", json={"scope_id": sid, "endpoint_url": pw.vurl, "library_id": lid}, headers=H)
    assert r.status_code == 422 and "vector store" in r.text


def test_roles_and_audit(pw):
    aid = pw.run("vector")["id"]
    pw.done(aid)
    assert pw.viewer.get(f"/api/analyses/{aid}").status_code == 200 and pw.viewer.get("/api/analyses?kind=vector").json()[0]["id"] == aid
    assert pw.viewer.post("/api/analyses", json={"kind": "vector", "scope_id": "x", "endpoint_url": "y"}, headers=H).status_code == 403
    assert pw.anon.get("/api/analyses").status_code == 401 and pw.admin.get("/api/analyses/nope").status_code == 404
    with pw.store.conn() as c:
        acts = [r["action"] for r in c.execute("SELECT action FROM audit WHERE run_id=%s ORDER BY seq", (aid,)).fetchall()]
    assert acts[0] == "analysis.start" and acts[-1] == "analysis.finish" and "governor.allow" in acts
    assert pw.store.audit_verify() is None


def test_scope_validation_for_vector_providers(pw):
    body = scope_body(pw.llm, attack_classes=CLASSES, endpoints=[{"url": pw.vurl, "provider": "chroma", "model": "", "local": True, "ingest_url": "http://x/"}])
    assert pw.admin.post("/api/scopes/prepare", json=body, headers=H).status_code == 422
    body["endpoints"][0].pop("ingest_url")
    body["endpoints"][0]["provider"] = "pinecone"
    assert pw.admin.post("/api/scopes/prepare", json=body, headers=H).status_code == 422


# ---------------------------------------------------------------- qdrant / weaviate (direct, same Governor)
def _direct(provider, url, behavior_target):
    import asyncio
    import hashlib
    from datetime import datetime, timedelta, timezone

    from llm_redteam.governor import Governor
    from llm_redteam.scope import Endpoint, Limits, LLMScope
    now = datetime.now(timezone.utc)
    ep = Endpoint(url, provider, "", True)
    scope = LLMScope("t", "c", "a", hashlib.sha256(b"x").digest(), now, now + timedelta(days=1), [ep], ["vector_store_exposure"], Limits(max_requests_per_minute=600))
    scope.validate()
    return asyncio.run(VectorProbe(ep, Governor(scope), http=_plain_http()).run())


def test_qdrant_exposed(pw):
    def q(n, b, h):
        p, m = h[":path"].split("?")[0], h[":method"]
        if p == "/collections":
            return 200, {}, {"result": {"collections": [{"name": "kb"}]}}
        if p == "/collections/kb":
            return 200, {}, {"result": {"points_count": 7}}
        if p == "/collections/kb/points/scroll" and m == "POST":
            return 200, {}, {"result": {"points": [{"payload": {"text": "reach me at ann@corp.io"}, "vector": [0.1, 0.2]}]}}
        return 404, {}, {}
    pw.vec.behavior = q
    r = _direct("qdrant", pw.vurl, pw.vec)
    assert r["risk"]["level"] == "critical" and r["collections"][0]["count"] == 7 and r["collections"][0]["embedding_dims"] == 2
    assert "ann@corp.io" not in json.dumps(r) and {c["method"] for c in pw.vec.calls} <= {"GET", "POST"}


def test_weaviate_exposed_and_limit_param(pw):
    def wv(n, b, h):
        p = h[":path"].split("?")[0]
        if p == "/v1/meta":
            return 200, {}, {"version": "1"}
        if p == "/v1/schema":
            return 200, {}, {"classes": []}
        if p == "/v1/objects":
            return 200, {}, {"totalResults": 3, "objects": [{"properties": {"t": "hello"}, "vector": [0.1, 0.2, 0.3, 0.4]}]}
        return 404, {}, {}
    pw.vec.behavior = wv
    r = _direct("weaviate", pw.vurl, pw.vec)
    assert r["readable"] and r["collections"][0]["embedding_dims"] == 4
    assert any(c["path"] == "/v1/objects?limit=3" for c in pw.vec.calls)


def test_analyses_left_running_are_closed_on_restart(fresh_db):
    """A server restart loses the analysis task; the record must not stay 'running' forever."""
    from llm_redteam.store import Store
    s = Store(fresh_db)
    aid = s.create_analysis("vector", "scope-x", "http://127.0.0.1:1/", "admin", {})
    assert s.get_analysis(aid)["status"] == "running"
    create_app(fresh_db, RING, auth=Auth(insecure=True))                      # startup = what a restart does
    a = s.get_analysis(aid)
    assert a["status"] == "halted" and a["result"]["stopped_reason"] == "SERVER_RESTART" and a["finished_at"]


def test_a_failed_analysis_does_not_break_the_list(fresh_db):
    """finish_analysis(..., 'failed', {'risk': None}) is what the API stores on a crash; listing and reading it must still work."""
    s = Store(fresh_db)
    create_app(fresh_db, RING, auth=Auth(insecure=True))
    aid = s.create_analysis("extraction", "scope-x", "http://127.0.0.1:1/", "admin", {})
    s.finish_analysis(aid, "failed", {"error": "KeyError", "risk": None})
    assert s.get_analysis(aid)["risk"] is None and [a["status"] for a in s.list_analyses()] == ["failed"]
