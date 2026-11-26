"""CLEANUP of documents uploaded via ingest: adapter, Governor, engine, scope validation."""
import hashlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from fakes import LEAK, openai_json
from llm_redteam.governor import Denied, Governor
from llm_redteam.reasons import Reason
from llm_redteam.scope import Endpoint, Limits, LLMScope, ScopeInputError
from llm_redteam.targets import TargetAdapter, TargetError
from test_engine import Env, case, env, lib, play  # noqa: F401

NOW = datetime.now(timezone.utc)
DOCS = [{"name": "policy.md", "content": "Policy."}, {"name": "report attachment.txt", "content": "Report."}]


def ing_lib(**kw):
    return lib(case("i1", cat="prompt_injection_indirect", delivery="ingest", documents=DOCS, **kw))


def with_ingest(env, ex, delete="{base}/ingest/{name}"):
    base = env.target.url.replace("/v1/chat/completions", "")
    ep = Endpoint(env.target.url, "openai_compat", "m", local=True, ingest_url=base + "/ingest",
                  ingest_delete_url=delete.replace("{base}", base) if delete else None)
    env.gov.scope.endpoints = [ep]
    ex.ep = ep
    ex.adapter.ep = ep
    return ep


def tracker(env, fail_delete=False, delete_status=200):
    """Target server: tracks the document store. POST /ingest adds, DELETE removes."""
    store, log = {}, []

    def beh(n, body, h):
        path = h[":path"]
        if path == "/ingest":
            store[body["name"]] = body["content"]
            return 201, {}, {"ok": 1}
        if path.startswith("/ingest/") or path == "/ingest-del":
            return delete_status, {}, {"ok": 1}
        return 200, {}, openai_json("Selam")
    env.target.behavior = beh
    return store, log


# ---------------------------------------------------------------- scope
def scope_with(ingest, delete):
    return LLMScope(name="t", client="c", authorized_by="x", authorization_doc_sha256=hashlib.sha256(b"d").digest(),
                    valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=5),
                    endpoints=[Endpoint("https://api.example.com/v1/chat", "openai_compat", "m", ingest_url=ingest, ingest_delete_url=delete)],
                    attack_classes=["data_leakage"])


def test_scope_delete_url_validation_and_signed_content():
    scope_with("https://api.example.com/i", "https://api.example.com/i/{name}").validate()
    with pytest.raises(ScopeInputError, match="together with ingest_url"):
        scope_with(None, "https://api.example.com/i/{name}").validate()
    with pytest.raises(ScopeInputError, match="http"):
        scope_with("https://api.example.com/i", "ftp://x/y").validate()
    a = scope_with("https://api.example.com/i", None).digest()
    b = scope_with("https://api.example.com/i", "https://api.example.com/i/{name}").digest()
    assert a != b                                                         # the delete address is part of the signed content


# ---------------------------------------------------------------- adaptor
def adapter(target, delete):
    base = target.url.replace("/v1/chat/completions", "")

    async def sleep(s):
        pass
    ep = Endpoint(target.url, "openai_compat", "m", True, ingest_url=base + "/ingest", ingest_delete_url=delete.replace("{base}", base))
    return TargetAdapter(ep, "k", http=httpx.AsyncClient(follow_redirects=False), sleep=sleep, max_retries=2)


def test_adapter_delete_with_name_placeholder_encodes_the_name(run, target):
    target.behavior = lambda n, b, h: (200, {}, {})
    run(adapter(target, "{base}/ingest/{name}").delete_ingested("report attachment/special.txt"))
    c = target.calls[0]
    assert c["path"] == "/ingest/report%20attachment%2Fspecial.txt" and c["body"] == {}


def test_adapter_delete_without_placeholder_sends_name_in_body(run, target):
    target.behavior = lambda n, b, h: (204, {}, b"")
    run(adapter(target, "{base}/ingest-del").delete_ingested("policy.md"))
    assert target.calls[0]["path"] == "/ingest-del" and target.calls[0]["body"] == {"name": "policy.md"}


def test_adapter_delete_treats_404_as_already_gone_and_retries_5xx(run, target):
    target.behavior = lambda n, b, h: (404, {}, b"")
    run(adapter(target, "{base}/ingest/{name}").delete_ingested("x"))                    # not an error
    target.calls.clear()
    target.behavior = lambda n, b, h: (503, {}, b"") if n < 2 else (200, {}, {})
    run(adapter(target, "{base}/ingest/{name}").delete_ingested("x"))
    assert len(target.calls) == 3
    target.behavior = lambda n, b, h: (403, {}, b"")
    with pytest.raises(TargetError) as ei:
        run(adapter(target, "{base}/ingest/{name}").delete_ingested("x"))
    assert ei.value.kind == "auth"


def test_adapter_delete_requires_configuration(run, target):
    a = TargetAdapter(Endpoint(target.url, "openai_compat", "m", True, ingest_url="http://127.0.0.1:1/i"), "k", http=httpx.AsyncClient())
    with pytest.raises(TargetError):
        run(a.delete_ingested("x"))


# ---------------------------------------------------------------- Governor
def gov(**kw):
    ev = []
    ep = Endpoint("http://127.0.0.1:9/v1/chat", "openai_compat", "m", True, ingest_url="http://127.0.0.1:9/ingest",
                  ingest_delete_url=kw.pop("delete", "http://127.0.0.1:9/ingest/{name}"))
    sc = LLMScope(name="t", client="c", authorized_by="x", authorization_doc_sha256=hashlib.sha256(b"d").digest(),
                  valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=5), endpoints=[ep], attack_classes=["data_leakage"],
                  limits=Limits(**kw))
    return Governor(sc, lambda a, **k: ev.append((a, k.get("reason"), k.get("detail"))), resolver=lambda h, p: ["127.0.0.1"]), ev


URL = "http://127.0.0.1:9/v1/chat"


def test_cleanup_is_allowed_even_after_limits_are_exhausted_but_not_after_kill():
    g, ev = gov(max_requests=1)
    g.requests = 1                                                       # the request limit is full
    g.circuit = Reason.CIRCUIT_OPEN                                      # circuit breaker open
    g.authorize_cleanup(URL)                                             # it still cleans up: no document is LEFT on the target
    assert g.requests == 2 and ("governor.allow", None, {"endpoint": "http://127.0.0.1:9/ingest/{name}", "kind": "cleanup"}) in ev
    g.kill()
    with pytest.raises(Denied) as ei:
        g.authorize_cleanup(URL)
    assert ei.value.reason is Reason.KILLED                              # no network request is made when killed


def test_cleanup_denied_without_delete_url_unknown_endpoint_or_blocked_address():
    g, _ = gov(delete=None)
    with pytest.raises(Denied) as ei:
        g.authorize_cleanup(URL)
    assert ei.value.reason is Reason.ENDPOINT_NOT_AUTHORIZED
    g2, _ = gov()
    with pytest.raises(Denied):
        g2.authorize_cleanup("http://127.0.0.1:9/other")
    g2._resolver = lambda h, p: ["169.254.169.254"]
    with pytest.raises(Denied) as ei:
        g2.authorize_cleanup(URL)
    assert ei.value.reason is Reason.ENDPOINT_BLOCKED_ADDRESS


# ---------------------------------------------------------------- motor
def test_documents_are_deleted_after_each_conversation_including_replays(env, run):
    docs, _ = tracker(env)
    seen_deletes = []
    base = env.target.behavior

    def beh(n, b, h):
        if h[":path"].startswith("/ingest/") and h["authorization"]:
            seen_deletes.append(h[":path"])
        return base(n, b, h)
    env.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Sure {LEAK}")) if h[":path"] == "/v1/chat/completions" else beh(n, b, h)
    ex = env.build(ing_lib())
    with_ingest(env, ex)
    status, _ = run(ex.run())
    r = env.result()
    assert status == "completed" and r["findings"][0]["status"] == "verified"
    plays = 1 + 3                                                        # original + 3 replays
    assert len(seen_deletes) == 2 * plays and set(seen_deletes) == {"/ingest/policy.md", "/ingest/report%20attachment.txt"}
    outcomes = [a["outcome"] for a in r["attempts"]]
    assert outcomes.count("ingested") == 2 * plays and outcomes.count("cleaned") == 2 * plays
    cleaned = [a for a in r["attempts"] if a["outcome"] == "cleaned"]
    assert all(a["conversation_id"] == "cleanup" and a["prompt"].startswith("[document cleanup]") for a in cleaned)
    assert all(a["owasp_category"] for a in cleaned)


def test_cleanup_runs_even_when_the_conversation_fails(env, run):
    paths = []

    def beh(n, b, h):
        paths.append(h[":path"])
        if h[":path"] == "/v1/chat/completions":
            return 400, {}, b"bad request"                                 # the chat fails
        return 200, {}, {}
    env.target.behavior = beh
    ex = env.build(ing_lib())
    with_ingest(env, ex)
    run(ex.run())
    assert paths.count("/ingest/policy.md") == 1 and paths.count("/ingest/report%20attachment.txt") == 1       # deleted even though there was an error


def test_cleanup_runs_after_a_hard_limit_halts_the_run(env, run):
    docs, _ = tracker(env)
    ex = env.build(ing_lib(), max_requests=3)                           # 2 uploads + 1 chat = 3; then the limit
    with_ingest(env, ex)
    status, reason = run(ex.run())
    outcomes = [a["outcome"] for a in env.result()["attempts"]]
    assert outcomes.count("ingested") == outcomes.count("cleaned") == 2
    assert env.result()["requests"] >= 3


def test_failed_cleanup_is_recorded_and_audited_not_silent(env, run):
    docs, _ = tracker(env)
    base = env.target.behavior
    env.target.behavior = lambda n, b, h: (500, {}, b"") if h[":path"].startswith("/ingest/") else base(n, b, h)
    ex = env.build(ing_lib(), adapter_kw=dict(max_retries=0))
    with_ingest(env, ex)
    status, _ = run(ex.run())
    r = env.result()
    failed = [a for a in r["attempts"] if a["outcome"] == "cleanup_failed"]
    assert len(failed) == 2 and all(a["blocked_reason"] == "SERVER" and "[server]" in a["response"] for a in failed)
    with env.store.conn() as db:
        n = db.execute("SELECT count(*) AS n FROM audit WHERE action='ingest.cleanup_failed'").fetchone()["n"]
    assert n == 2 and status == "completed"


def test_missing_delete_url_warns_once_per_run_and_marks_attempts(env, run):
    tracker(env)
    ex = env.build(ing_lib())
    with_ingest(env, ex, delete=None)
    run(ex.run())
    r = env.result()
    skipped = [a for a in r["attempts"] if a["outcome"] == "cleanup_skipped"]
    assert len(skipped) == 2 and all(a["blocked_reason"] == "NOT_CONFIGURED" for a in skipped)
    with env.store.conn() as db:
        n = db.execute("SELECT count(*) AS n FROM audit WHERE action='ingest.cleanup_unconfigured'").fetchone()["n"]
    assert n == 1


def test_kill_skips_cleanup_and_records_why(env, run):
    docs, _ = tracker(env)
    base = env.target.behavior

    def beh(n, b, h):
        if h[":path"] == "/v1/chat/completions":
            env.gov.kill()
        return base(n, b, h)
    env.target.behavior = beh
    ex = env.build(ing_lib())
    with_ingest(env, ex)
    run(ex.run())
    r = env.result()
    failed = [a for a in r["attempts"] if a["outcome"] == "cleanup_failed"]
    assert len(failed) == 2 and all(a["blocked_reason"] == "KILLED" for a in failed)


def test_inline_delivery_needs_no_cleanup(env, run):
    tracker(env)
    ex = env.build(lib(case("d1", cat="prompt_injection_indirect", documents=DOCS)))                      # inline
    run(ex.run())
    assert not [a for a in env.result()["attempts"] if a["outcome"].startswith("clean")]
