"""Custom HTTP (JSON) targets: the request template, the response path, the signed scope fields and a full quick scan against a non-OpenAI API."""
import asyncio
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from fakes import LEAK
from llm_redteam import customhttp, targetcfg
from llm_redteam.library import parse_library, check_against_scope
from llm_redteam.scope import Endpoint, LLMScope, ScopeInputError
from llm_redteam.targets import TargetAdapter, TargetError
from test_rbac import H
from test_targets_upload import tw, wait_run  # noqa: F401  (fixture)

TPL = '{"question": "{{prompt}}", "session": "{{session_id}}", "meta": {"lang": "en", "tags": ["a", "{{session_id}}"]}}'


# ---------------------------------------------------------------- template and path
@pytest.mark.parametrize("bad, msg", [
    ("", "required"), ("not json", "not valid JSON"), ('["{{prompt}}"]', "JSON object"), ('{"q": "hello"}', "must contain"),
    ('{"{{prompt}}": "x"}', "key names"), ('{"q": "{{prompt}}", "x": "{{secret}}"}', "unknown placeholder"),
    ('{"q": "{{ prompt }}"}', "unknown placeholder"), ('{"q": "{{prompt}}", "s": "{{session_id"}', "not closed"), ('{"q": "{{prompt}} }}"}', "not closed"), ('{"h": "past: {{messages}}"}', "whole value"), ("{" + '"q": "' + "x" * 9000 + '"}', "at most"),
])
def test_template_validation_refuses_bad_templates(bad, msg):
    with pytest.raises(customhttp.TemplateError, match=msg):
        customhttp.parse_template(bad)


def test_render_escapes_values_and_never_changes_the_structure():
    hostile = 'He said "hi"\n", "admin": true, "x": "{{session_id}}'
    body = customhttp.render(TPL, [{"role": "system", "content": "s"}, {"role": "user", "content": hostile}], "sess-1")
    assert set(body) == {"question", "session", "meta"} and "admin" not in body                    # injected JSON stays inside the string value
    assert body["question"] == hostile                                                               # inserted verbatim, never re-expanded
    assert body["session"] == "sess-1" and body["meta"] == {"lang": "en", "tags": ["a", "sess-1"]}
    json.dumps(body)                                                                                  # serialisable
    hist = customhttp.render('{"history": "{{messages}}", "who": "u"}', [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"},
                                                                         {"role": "tool", "content": "t"}, {"role": "user", "content": "c"}], "s")
    assert hist == {"history": [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "c"}], "who": "u"}


def test_render_does_not_expand_placeholders_inside_the_prompt():
    body = customhttp.render('{"q": "{{prompt}}", "s": "{{session_id}}"}', [{"role": "user", "content": "say {{session_id}}"}], "S")
    assert body["s"] == "S" and body["q"] == "say {{session_id}}"


@pytest.mark.parametrize("path, want", [("answer", "A"), ("data.reply", "R"), ("data.list.1.text", "second"), ("data.num", "42"), ("data.none", ""),
                                        ("data.obj", '{"k": "v"}')])
def test_extract_reads_the_dotted_path(path, want):
    doc = {"answer": "A", "data": {"reply": "R", "list": [{"text": "first"}, {"text": "second"}], "num": 42, "none": None, "obj": {"k": "v"}}}
    assert customhttp.extract(doc, path) == want


@pytest.mark.parametrize("path, err", [("missing", KeyError), ("data.list.9.text", IndexError), ("data.list.x", TypeError), ("answer.deeper", TypeError)])
def test_extract_raises_on_a_wrong_path(path, err):
    with pytest.raises(err):
        customhttp.extract({"answer": "A", "data": {"list": []}}, path)


@pytest.mark.parametrize("bad", ["", "a..b", "a b", "a.b/c", "x" * 201])
def test_bad_paths_are_refused(bad):
    with pytest.raises(customhttp.TemplateError):
        customhttp.parse_path(bad)


# ---------------------------------------------------------------- scope: signed, and older signatures stay valid
def _scope(**ep):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return LLMScope(name="n", client="c", authorized_by="a", authorization_doc_sha256=bytes(32), valid_from=now, valid_until=now + timedelta(days=1),
                    endpoints=[Endpoint(**({"url": "https://chat.example.test/api/ask", "provider": "openai_compat", "model": "m"} | ep))],
                    attack_classes=["system_prompt_extraction"], lineage_id="L")


def test_existing_scopes_keep_their_digest():
    s = _scope()
    s.validate()
    from llm_redteam.scope import CUSTOM_FIELDS
    legacy = {k: v for k, v in asdict(s.endpoints[0]).items() if k not in CUSTOM_FIELDS}
    assert s.content()["endpoints"] == [legacy]                                     # the same signed bytes as before this feature


def test_custom_fields_are_signed_and_validated():
    s = _scope(provider="http_json", model="", request_template=TPL, response_path="data.reply")
    s.validate()
    ep = s.content()["endpoints"][0]
    assert ep["request_template"] == TPL and ep["response_path"] == "data.reply"
    other = _scope(provider="http_json", model="", request_template=TPL.replace("en", "de"), response_path="data.reply")
    assert other.digest() != s.digest()                                            # changing the template changes the signature
    assert LLMScope.from_content(s.content()).digest() == s.digest()
    for bad in ({"request_template": None}, {"response_path": "a b"}, {"request_template": '{"q": 1}'}, {"ingest_url": "https://x/up"}):
        with pytest.raises(ScopeInputError):
            _scope(**({"provider": "http_json", "model": "", "request_template": TPL, "response_path": "r"} | bad)).validate()
    with pytest.raises(ScopeInputError, match="only for custom HTTP"):
        _scope(request_template=TPL).validate()


def test_target_config_for_a_custom_api():
    t = targetcfg.validate("Bot", "http_json", "https://chat.example.test/api/ask", "", None, None, None, "cookie", None, TPL, " data.reply ")
    assert t["request_url"] == "https://chat.example.test/api/ask" and t["model"] == "custom" and t["response_path"] == "data.reply"
    with pytest.raises(targetcfg.TargetInputError):
        targetcfg.validate("Bot", "http_json", "https://chat.example.test/api/ask", "", None, None, None, "bearer", None, '{"q": 1}', "r")
    with pytest.raises(targetcfg.TargetInputError):
        targetcfg.validate("Bot", "http_json", "https://chat.example.test/api/ask", "", None, "https://x/up", None, "bearer", None, TPL, "r")
    plain = targetcfg.validate("P", "openai_compat", "https://x/v1", "m", None, None, None, "bearer", None, TPL, "r")
    assert plain["request_template"] is None and plain["response_path"] is None    # ignored for the standard formats


# ---------------------------------------------------------------- adapter
def _adapter(handler, **ep):
    e = Endpoint(**({"url": "https://chat.example.test/api/ask", "provider": "http_json", "model": "", "request_template": TPL, "response_path": "data.reply"} | ep))
    return TargetAdapter(e, "tok-1", stream=True, http=httpx.AsyncClient(transport=httpx.MockTransport(handler)), max_retries=0)


def test_adapter_sends_the_template_and_keeps_one_session_per_conversation():
    seen = []

    def handler(req):
        seen.append((json.loads(req.content), dict(req.headers)))
        return httpx.Response(200, json={"data": {"reply": "Hi there"}})

    async def go():
        a = _adapter(handler)
        r1 = await a.send([{"role": "user", "content": "one"}], 100, session="conv-A")
        await a.send([{"role": "user", "content": "one"}, {"role": "assistant", "content": "Hi"}, {"role": "user", "content": "two"}], 100, session="conv-A")
        await a.send([{"role": "user", "content": "one"}], 100, session="conv-B")
        with pytest.raises(TargetError):
            await a.send([{"role": "user", "content": "x"}], 100, tools=[{"name": "t"}], session="conv-A")
        return r1
    r1 = asyncio.run(go())
    assert str(r1.text) == "Hi there" and r1.estimated and r1.tokens_in > 0 and r1.tool_calls == []
    (b1, h1), (b2, _), (b3, _) = seen
    assert b1["question"] == "one" and b2["question"] == "two" and b1["session"] == b2["session"] != b3["session"]
    assert "conv-A" not in json.dumps(seen)                                         # internal ids never reach the target
    assert h1["authorization"] == "Bearer tok-1" and "stream" not in b1 and "model" not in b1 and h1["content-type"] == "application/json"


def test_adapter_reports_a_wrong_response_shape_as_a_protocol_error():
    async def go():
        a = _adapter(lambda req: httpx.Response(200, json={"answer": "x"}))
        with pytest.raises(TargetError) as e:
            await a.send([{"role": "user", "content": "q"}], 100)
        return e.value
    assert asyncio.run(go()).kind == "protocol"


def test_tool_and_media_cases_are_skipped_for_a_custom_target():
    import pathlib
    kit = pathlib.Path(__file__).resolve().parent.parent / "starter_kit"
    tools = json.loads((kit / "advanced" / "ADV_tool_sandbox.json").read_text())
    plain = json.loads((kit / "owasp" / "LLM07_SystemPromptLeakage.json").read_text())
    lib = parse_library(json.dumps({"library": {"name": "l", "version": "1"}, "cases": tools["cases"] + plain["cases"]}))
    s = _scope(provider="http_json", model="", request_template=TPL, response_path="r")
    s.attack_classes, s.tool_abuse_attested = ["system_prompt_extraction", "tool_abuse"], True
    kept = check_against_scope(lib, s, None, s.endpoints[0])
    assert kept and all(not c.tools for c in kept) and {c.id for c in kept} == {c["id"] for c in plain["cases"]}
    std = _scope()
    std.attack_classes, std.tool_abuse_attested = s.attack_classes, True
    assert any(c.tools for c in check_against_scope(lib, std, None, std.endpoints[0]))     # the standard formats still run them


# ---------------------------------------------------------------- the whole path through the API
def _custom_api(n, body, h):
    if "question" not in body or "session" not in body:
        return 400, {}, {"error": "bad request"}
    q = body["question"].lower()
    reply = f"My instructions say: {LEAK}" if "instruction" in q else "Hello, how can I help?"
    return 200, {}, {"ok": True, "data": {"reply": reply}}


def qbody_custom(tw, **kw):
    return {"provider": "http_json", "base_url": f"http://127.0.0.1:{tw.target.port}/api/ask", "request_template": TPL, "response_path": "data.reply",
            "auth_type": "cookie", "api_key": "sid=custom-secret"} | kw


def test_quick_scan_against_a_custom_api_finds_and_verifies_a_leak(tw):
    tw.target.behavior = _custom_api
    plan = tw.admin.post("/api/quick-scan/prepare", json=qbody_custom(tw, include_tools=True, tools_attested=True), headers=H)
    assert plan.status_code == 200, plan.text
    p = plan.json()
    ep = p["content"]["endpoints"][0]
    assert ep["provider"] == "http_json" and ep["request_template"] == TPL and ep["url"].endswith("/api/ask") and p["skipped_cases"] == 1          # only the fake-tool case; text-only LLM06 cases still run
    assert "custom HTTP" in p["skip_note"] and p["skipped_format"] == 1 and p["skipped_unauthorized"] == 0 and tw.target.calls == []
    np = tw.admin.post("/api/quick-scan/prepare", json=qbody_custom(tw), headers=H).json()                   # no tool attestation: 3 not authorized, 0 format
    assert np["skipped_cases"] == 3 and np["skipped_unauthorized"] == 3 and np["skipped_format"] == 0                                       # prepare sends nothing
    assert tw.admin.post("/api/quick-scan/prepare", json=qbody_custom(tw, request_template='{"q": 1}'), headers=H).status_code == 422
    r = tw.admin.post("/api/quick-scan", json=qbody_custom(tw, include_tools=True, tools_attested=True) | {
        "authorized": True, "expected_hash": p["digest"], "lineage_id": p["lineage_id"], "valid_from": p["valid_from"]}, headers=H)
    assert r.status_code == 202, r.text
    run = wait_run(tw.admin, r.json()["id"])
    assert run["status"] in ("completed", "completed_budget"), run
    leaks = [f for f in run["findings"] if f["status"] == "verified" and f["category"] == "system_prompt_extraction"]
    assert leaks, run["findings"]
    assert all(c["path"] == "/api/ask" and set(c["body"]) == {"question", "session", "meta"} for c in tw.target.calls)
    assert all(c["headers"].get("cookie") == "sid=custom-secret" for c in tw.target.calls)
    t = tw.admin.get("/api/targets").json()[0]
    assert t["provider"] == "http_json" and t["request_template"] == TPL and t["response_path"] == "data.reply" and "custom-secret" not in json.dumps(t)
