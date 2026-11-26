"""Document feeding for indirect tests: library schema, inline/ingest delivery, Governor, adapter, engine."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from fakes import LEAK, FakeJudge, openai_json
from llm_redteam import library as L
from llm_redteam.governor import Denied, Governor
from llm_redteam.reasons import Reason
from llm_redteam.scope import Endpoint, Limits, LLMScope, ScopeInputError
from llm_redteam.targets import TargetAdapter, TargetError
from test_engine import Env, case, env, lib, play  # noqa: F401  (env fixture)

NOW = datetime.now(timezone.utc)
DOCS = [{"name": "report.txt", "content": "Quarterly report summary. Revenue grew."},
        {"name": "notes.md", "content": "Meeting notes."}]


def lib_doc(**kw):
    return lib(case("d1", cat="prompt_injection_indirect", documents=DOCS, **kw))


# ============================================================ library schema
def test_documents_parse_and_hash_covers_documents():
    a = lib_doc()
    b = lib(case("d1", cat="prompt_injection_indirect", documents=[DOCS[0], {**DOCS[1], "content": "changed"}]))
    c = a.cases[0]
    assert [d.name for d in c.documents] == ["report.txt", "notes.md"] and c.delivery == "inline"
    assert a.sha256 != b.sha256 and c.documents[0].sha256 == hashlib.sha256(DOCS[0]["content"].encode()).hexdigest()


@pytest.mark.parametrize("patch", [
    dict(documents="x"), dict(documents=["x"]), dict(documents=[{"name": "", "content": "a"}]),
    dict(documents=[{"name": 'a"b', "content": "a"}]), dict(documents=[{"name": "<x>", "content": "a"}]),
    dict(documents=[{"name": "a\nb", "content": "a"}]), dict(documents=[{"name": "a", "content": ""}]),
    dict(documents=[{"name": "a", "content": "x" * 50_001}]), dict(documents=[{"name": "a", "content": "n\x00ul"}]),
    dict(documents=[{"name": f"d{i}", "content": "a"} for i in range(11)]),
    dict(delivery="ftp"), dict(delivery="ingest"),                                 # ingest + no documents
    dict(documents=DOCS, document_template="no documents"), dict(documents=DOCS, document_template="{task} only"),
    dict(severity="catastrophic"),
])
def test_invalid_document_cases_rejected(patch):
    with pytest.raises(L.LibraryError):
        lib(case("d1", cat="prompt_injection_indirect", **patch))


def test_inline_render_embeds_documents_in_first_message_only():
    c = lib_doc(turns=["summarize", "continue"]).cases[0]
    m = c.render(c.turns)
    assert m[1] == "continue" and m[0].startswith("summarize\n\n") and '<document index="1" name="report.txt">' in m[0]
    assert "Revenue grew." in m[0] and m[0].count("<document ") == 2
    t = lib_doc(document_template="DOCUMENTS:\n{documents}\n\nTASK: {task}").cases[0]
    assert t.render(t.turns)[0].startswith("DOCUMENTS:\n<document") and t.render(t.turns)[0].endswith("TASK: " + t.turns[0])


def test_ingest_delivery_does_not_alter_messages():
    c = lib_doc(delivery="ingest").cases[0]
    assert c.render(c.turns) == list(c.turns)


def scope(**kw):
    ep = Endpoint("http://127.0.0.1:9/v1/chat/completions", "openai_compat", "m", local=True,
                  ingest_url=kw.pop("ingest_url", "http://127.0.0.1:9/ingest"))
    return LLMScope(name="t", client="c", authorized_by="CISO", authorization_doc_sha256=hashlib.sha256(b"d").digest(),
                    valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=30), endpoints=[ep],
                    attack_classes=["prompt_injection_indirect", "system_prompt_extraction"],
                    limits=Limits(**({"max_requests_per_minute": 600} | kw)))


def test_scope_check_counts_embedded_documents_toward_prompt_limit():
    L.check_against_scope(lib_doc(), scope())
    with pytest.raises(L.LibraryError, match="documents included"):
        L.check_against_scope(lib_doc(), scope(max_prompt_chars=100))
    with pytest.raises(L.LibraryError, match="ingest_url"):
        s = scope(ingest_url=None)
        L.check_against_scope(lib_doc(delivery="ingest"), s, endpoint=s.endpoints[0])
    L.check_against_scope(lib_doc(delivery="ingest"), scope(), endpoint=scope().endpoints[0])


def test_scope_ingest_url_is_part_of_signed_content_and_validated():
    assert scope().digest() != scope(ingest_url="http://127.0.0.1:9/other").digest()
    assert scope().digest() != scope(ingest_url=None).digest()
    with pytest.raises(ScopeInputError):
        scope(ingest_url="ftp://x/y").validate()


# ============================================================ Governor
def gov(**kw):
    ev = []
    g = Governor(scope(**kw), lambda a, **k: ev.append((a, k.get("reason"))), resolver=lambda h, p: ["127.0.0.1"])
    return g, ev


URL = "http://127.0.0.1:9/v1/chat/completions"


def test_governor_ingest_counts_as_request_and_audits(run):
    g, ev = gov(max_requests=2)
    run(g.authorize_ingest(URL, "prompt_injection_indirect", 100))
    run(g.authorize_ingest(URL, "prompt_injection_indirect", 100))
    assert g.requests == 2 and g.conversations == set() and g.tokens_used == 0
    with pytest.raises(Denied) as ei:
        run(g.authorize_ingest(URL, "prompt_injection_indirect", 100))
    assert ei.value.reason is Reason.REQUEST_LIMIT and ei.value.fatal
    assert [e for e in ev if e[0] == "governor.allow"] and ("governor.deny", Reason.REQUEST_LIMIT) in ev


@pytest.mark.parametrize("kw,call,reason", [
    (dict(), dict(endpoint_url="http://127.0.0.1:9/other"), Reason.ENDPOINT_NOT_AUTHORIZED),
    (dict(), dict(category="data_leakage"), Reason.ATTACK_CLASS_NOT_ALLOWED),
    (dict(max_prompt_chars=50), dict(doc_chars=100), Reason.PROMPT_TOO_LONG),
    (dict(ingest_url=None), dict(), Reason.ENDPOINT_NOT_AUTHORIZED),
])
def test_governor_ingest_denials(run, kw, call, reason):
    g, _ = gov(**kw)
    args = dict(endpoint_url=URL, category="prompt_injection_indirect", doc_chars=10) | call
    with pytest.raises(Denied) as ei:
        run(g.authorize_ingest(args["endpoint_url"], args["category"], args["doc_chars"]))
    assert ei.value.reason is reason


def test_governor_ingest_blocks_metadata_resolution_and_kill(run):
    g, _ = gov()
    g._resolver = lambda h, p: ["169.254.169.254"]
    with pytest.raises(Denied) as ei:
        run(g.authorize_ingest(URL, "prompt_injection_indirect", 10))
    assert ei.value.reason is Reason.ENDPOINT_BLOCKED_ADDRESS
    g2, _ = gov()
    g2.kill()
    with pytest.raises(Denied) as ei:
        run(g2.authorize_ingest(URL, "prompt_injection_indirect", 10))
    assert ei.value.reason is Reason.KILLED


# ============================================================ adaptor
def ad(target, key="k"):
    import httpx
    async def sleep(s):
        pass
    ep = Endpoint(target.url, "openai_compat", "m", local=True, ingest_url=target.url.replace("/v1/chat/completions", "/ingest"))
    return TargetAdapter(ep, key, http=httpx.AsyncClient(follow_redirects=False), sleep=sleep, max_retries=2)


def test_adapter_ingest_posts_name_and_content_with_auth(run, target):
    target.behavior = lambda n, b, h: (201, {}, {"ok": True})
    run(ad(target).ingest("report.txt", "content text"))
    c = target.calls[0]
    assert c["path"] == "/ingest" and c["body"] == {"name": "report.txt", "content": "content text"}
    assert c["headers"]["authorization"] == "Bearer k"


def test_adapter_ingest_retries_5xx_but_not_auth_or_client(run, target):
    target.behavior = lambda n, b, h: (503, {}, b"") if n < 2 else (200, {}, {})
    run(ad(target).ingest("a", "b"))
    assert len(target.calls) == 3
    for status, kind in ((401, "auth"), (404, "client"), (302, "client")):
        target.calls.clear()
        target.behavior = lambda n, b, h, s=status: (s, {"location": "http://127.0.0.1:1/"}, b"")
        with pytest.raises(TargetError) as ei:
            run(ad(target).ingest("a", "b"))
        assert ei.value.kind == kind and len(target.calls) == 1


def test_adapter_ingest_requires_ingest_url(run, target):
    import httpx
    a = TargetAdapter(Endpoint(target.url, "openai_compat", "m", True), "k", http=httpx.AsyncClient())
    with pytest.raises(TargetError):
        run(a.ingest("a", "b"))


# ============================================================ motor
def test_inline_documents_reach_target_in_first_message_and_evidence_records_them(env, run):
    env.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Summary: key {LEAK} here"))
    _, _, r = play(env, run, lib_doc(turns=["summarize these documents"]))
    sent = env.target.calls[0]["body"]["messages"][0]["content"]
    assert sent.startswith("summarize these documents") and "Quarterly report" in sent and "<document index=\"2\"" in sent
    ev = r["findings"][0]["evidence"]
    assert r["findings"][0]["status"] == "verified" and r["findings"][0]["severity"] == "high"
    assert [d["name"] for d in ev["documents"]] == ["report.txt", "notes.md"] and ev["case"]["delivery"] == "inline"
    assert ev["sequence"][0] == sent                                  # the evidence carries the text that was actually sent


def test_ingest_delivery_uploads_documents_then_converses(env, run):
    paths = []
    def beh(n, b, h):
        paths.append(h[":path"])
        return (200, {}, {"ok": 1}) if h[":path"] == "/ingest" else (200, {}, openai_json("Selam"))
    env.target.behavior = beh
    library = lib_doc(delivery="ingest")
    ex = env.build(library)
    ex.ep = env.gov.scope.endpoints[0] = env.gov.scope.endpoints[0].__class__(
        **{**env.gov.scope.endpoints[0].__dict__, "ingest_url": env.target.url.replace("/v1/chat/completions", "/ingest")})
    ex.adapter.ep = ex.ep
    status, _ = run(ex.run())
    assert status == "completed" and paths == ["/ingest", "/ingest", "/v1/chat/completions"]
    r = env.result()
    assert [a["outcome"] for a in r["attempts"][:2]] == ["ingested", "ingested"]
    assert r["requests"] == 3                                       # 2 uploads + 1 conversation request count toward the rate/limit counter
    # the message does not contain the documents: they are in the target's knowledge base
    assert "<document" not in env.target.calls[2]["body"]["messages"][0]["content"]


def test_ingest_failure_is_recorded_and_stops_on_auth(env, run):
    env.target.behavior = lambda n, b, h: (401, {}, b"")
    ex = env.build(lib_doc(delivery="ingest"))
    ex.ep = env.gov.scope.endpoints[0] = env.gov.scope.endpoints[0].__class__(
        **{**env.gov.scope.endpoints[0].__dict__, "ingest_url": env.target.url.replace("/v1/chat/completions", "/ingest")})
    ex.adapter.ep = ex.ep
    status, reason = run(ex.run())
    assert (status, reason) == ("halted", "AUTH_FAILURE") and len(env.target.calls) == 1
    assert env.result()["attempts"][0]["outcome"] == "error"


def test_documents_are_untrusted_data_but_judge_sees_what_was_sent(env, run):
    judge = FakeJudge()
    play(env, run, lib_doc(), judge=judge)
    assert "Quarterly report" in judge.last_user                        # the judge sees the text that was sent (with documents), inside the envelope
    assert "<UNTRUSTED_" in judge.last_user
