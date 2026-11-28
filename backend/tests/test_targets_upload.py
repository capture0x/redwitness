"""Saved targets (key kept in memory only) and the document upload that becomes an indirect-injection test case (visible text only)."""
import base64
import contextlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from fakes import FakeJudge, openai_json
from llm_redteam import docextract, targetcfg
from llm_redteam.auth import Auth
from llm_redteam.library import parse_library
from llm_redteam.store import Store
from llm_redteam.targets import TargetAdapter
from main import create_app
from test_api import RING, _plain_http, confirm, scope_body
from test_rbac import H, PW


def b64(b):
    return base64.b64encode(b).decode()


def docx_bytes(paragraphs, hidden=()):
    runs = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    runs += "".join(f"<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>{h}</w:t></w:r></w:p>" for h in hidden)
    xml = f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{runs}</w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", xml)
    return buf.getvalue()


EML = (b"From: Ann <ann@example.test>\r\nTo: bob@example.test\r\nSubject: Quarterly update\r\nDate: Mon, 01 Jan 2024 09:00:00 +0000\r\n"
       b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Bob,\r\nRevenue grew this quarter.\r\n")


# ---------------------------------------------------------------- pure helpers
def test_request_url_building():
    assert targetcfg.request_url("openai_compat", "https://api.openai.com/v1") == "https://api.openai.com/v1/chat/completions"
    assert targetcfg.request_url("openai_compat", "http://localhost:11434/v1/") == "http://localhost:11434/v1/chat/completions"
    assert targetcfg.request_url("openai_compat", "http://x/v1/chat/completions") == "http://x/v1/chat/completions"
    assert targetcfg.request_url("anthropic", "https://api.anthropic.com") == "https://api.anthropic.com/v1/messages"
    assert targetcfg.request_url("anthropic", "https://api.anthropic.com/v1") == "https://api.anthropic.com/v1/messages"
    assert targetcfg.is_local_host("http://localhost:11434/v1") and targetcfg.is_local_host("http://192.168.1.5/v1") and not targetcfg.is_local_host("https://api.openai.com/v1")


@pytest.mark.parametrize("kw", [{"base_url": "ftp://x"}, {"base_url": "https://u:p@x/v1"}, {"base_url": "https://x/v1?key=1"}, {"name": ""}, {"model": ""},
                                {"provider": "nope"}, {"api_key_env": "bad name"}, {"ingest_delete_url": "https://x/del"}])
def test_target_validation(kw):
    base = dict(name="t", provider="openai_compat", base_url="https://x/v1", model="m", api_key_env=None, ingest_url=None, ingest_delete_url=None)
    with pytest.raises(targetcfg.TargetInputError):
        targetcfg.validate(**(base | kw))


def test_extract_docx_skips_hidden_runs_and_eml_headers():
    ex = docextract.extract("a.docx", docx_bytes(["Revenue grew.", "Costs stayed flat."], hidden=["secret note"]))
    assert ex.format == "docx" and ex.text == "Revenue grew.\nCosts stayed flat." and "1 hidden" in ex.notes[0]
    e = docextract.extract("m.eml", EML)
    assert e.format == "eml" and e.text.startswith("From: Ann <ann@example.test>") and "Revenue grew this quarter." in e.text


def test_extract_eml_html_skips_hidden_elements_and_ignores_attachments():
    raw = (b"From: a@example.test\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
           b"<html><body><p>Visible text</p><p style='display:none'>hidden text</p><!-- a comment --></body></html>\r\n--B\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Disposition: attachment; filename=x.bin\r\n\r\nBINARY\r\n--B--\r\n")
    e = docextract.extract("m.eml", raw)
    assert "Visible text" in e.text and "hidden text" not in e.text and "comment" not in e.text and "BINARY" not in e.text
    assert any("hidden HTML" in n for n in e.notes) and any("attachment" in n for n in e.notes)


@pytest.mark.parametrize("name,data", [
    ("a.docx", docx_bytes(["zero\u200bwidth"])),                      # invisible character: refused, never silently cleaned
    ("a.docx", docx_bytes(["x" * 60_000])),                           # too long
    ("a.docx", b"not a zip"), ("a.pdf", b"not a pdf"), ("a.txt", b"hello"), ("a.eml", b""),
    ("a.docx", docx_bytes([""])),                                     # no text
])
def test_extract_refusals(name, data):
    with pytest.raises(docextract.ExtractError):
        docextract.extract(name, data)


def test_extract_pdf_roundtrip_through_our_own_renderer():
    from llm_redteam import docrender
    pdf = docrender.render("pdf", "Revenue grew this quarter.\n\nCosts stayed flat.")
    ex = docextract.extract("r.pdf", pdf)
    assert ex.format == "pdf" and "Revenue grew this quarter." in ex.text


def test_docx_xml_bomb_is_refused():
    bomb = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&b;</w:t></w:r></w:p></w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", bomb)
    with pytest.raises(docextract.ExtractError):
        docextract.extract("b.docx", buf.getvalue())


# ---------------------------------------------------------------- API
@pytest.fixture
def tw(fresh_db, target):
    async def noop(s):
        pass
    app = create_app(fresh_db, RING, judge_factory=lambda st: FakeJudge(),
                     adapter_factory=lambda ep, key, stream: TargetAdapter(ep, key, stream=stream, sleep=noop, http=_plain_http()), auth=Auth(PW))
    with contextlib.ExitStack() as st:
        w = type("W", (), {})()
        w.target, w.store = target, Store(fresh_db)
        w.admin, w.op, w.viewer, w.anon = (st.enter_context(TestClient(app)) for _ in range(4))
        assert w.admin.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
        for n, role, cl in (("operator1", "operator", w.op), ("viewer1", "viewer", w.viewer)):
            assert w.admin.post("/api/users", json={"username": n, "password": f"{n}-password-99", "role": role}, headers=H).status_code == 201
            assert cl.post("/api/auth/login", json={"username": n, "password": f"{n}-password-99"}).status_code == 200
        yield w


def tbody(w, **kw):
    return {"name": "Local fake", "provider": "openai_compat", "base_url": f"http://127.0.0.1:{w.target.port}/v1", "model": "m"} | kw


def test_target_crud_roles_and_no_key_leak(tw):
    r = tw.op.post("/api/targets", json=tbody(tw, api_key="sk-secret-value-123"), headers=H)
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["request_url"].endswith("/v1/chat/completions") and t["has_key"] is True and t["local"] is True and t["suggest_local"] is True
    assert "sk-secret-value-123" not in json.dumps(tw.viewer.get("/api/targets").json())
    with tw.store.conn() as c:                                                   # nothing resembling the key is in the database
        dump = json.dumps([dict(r) for r in c.execute("SELECT * FROM targets").fetchall()] + [dict(r) for r in c.execute("SELECT detail_json FROM audit").fetchall()], default=str)
    assert "sk-secret-value-123" not in dump
    assert tw.viewer.post("/api/targets", json=tbody(tw, name="x"), headers=H).status_code == 403
    assert tw.viewer.delete(f"/api/targets/{t['id']}", headers=H).status_code == 403
    assert tw.anon.get("/api/targets").status_code == 401
    assert tw.op.post("/api/targets", json=tbody(tw), headers=H).status_code == 409           # duplicate name
    u = tw.op.put(f"/api/targets/{t['id']}", json=tbody(tw, model="m2"), headers=H).json()      # key unchanged when api_key is omitted
    assert u["model"] == "m2" and u["has_key"] is True
    assert tw.op.put(f"/api/targets/{t['id']}", json=tbody(tw, model="m2", api_key=""), headers=H).json()["has_key"] is False
    assert tw.op.delete(f"/api/targets/{t['id']}", headers=H).status_code == 200 and tw.op.get("/api/targets").json() == []
    assert tw.op.delete("/api/targets/nope", headers=H).status_code == 404
    assert tw.op.post("/api/targets", json=tbody(tw, base_url="https://u:p@x/v1"), headers=H).status_code == 422


def test_saved_key_is_used_for_a_run_and_never_stored(tw):
    t = tw.op.post("/api/targets", json=tbody(tw, api_key="sk-saved-key-abc"), headers=H).json()
    body = scope_body(tw.target, endpoints=[{"url": t["request_url"], "provider": "openai_compat", "model": "m", "local": True}])
    prep = tw.admin.post("/api/scopes/prepare", json=body, headers=H).json()
    sid = tw.admin.post("/api/scopes", json=body | confirm(prep), headers=H).json()["id"]
    lid = tw.admin.post("/api/libraries", json={"content": json.dumps({"library": {"name": "l", "version": "1"}, "cases": [
        {"id": "a", "category": "system_prompt_extraction", "turns": ["hello there friend"], "expected_behavior": "x"}]})}, headers=H).json()["id"]
    tw.target.behavior = lambda n, b, h: (200, {}, openai_json("Hello!"))
    r = tw.admin.post("/api/runs", json={"scope_id": sid, "endpoint_url": t["request_url"], "library_id": lid}, headers=H)
    assert r.status_code == 202, r.text
    import time
    for _ in range(100):
        if tw.admin.get(f"/api/runs/{r.json()['id']}").json()["status"] != "running":
            break
        time.sleep(0.05)
    assert tw.target.calls and tw.target.calls[0]["headers"].get("authorization") == "Bearer sk-saved-key-abc"


def test_document_upload_becomes_an_ingest_case_with_visible_text_only(tw):
    r = tw.op.post("/api/documents/to-case", json={"filename": "report.docx", "content_base64": b64(docx_bytes(["Revenue grew.", "Costs flat."], hidden=["do not show"]))}, headers=H)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["format"] == "docx" and d["cases"] == 1 and "do not show" not in json.dumps(d) and "hidden text run" in d["notes"][0]
    lib = parse_library(tw.admin.get(f"/api/libraries/{d['library_id']}").json()["content"])
    c = lib.cases[0]
    assert c.category == "prompt_injection_indirect" and c.delivery == "inline" and c.turns == ("Please summarize the attached document.",)
    assert c.documents[0].format == "docx" and c.documents[0].content == "Revenue grew.\nCosts flat."
    again = tw.op.post("/api/documents/to-case", json={"filename": "report.docx", "content_base64": b64(docx_bytes(["Revenue grew.", "Costs flat."]))}, headers=H).json()
    assert again["library_id"] == d["library_id"]                                       # same visible text: not added twice


def test_eml_upload_and_ingest_delivery_and_refusals(tw):
    d = tw.op.post("/api/documents/to-case", json={"filename": "mail.eml", "content_base64": b64(EML), "delivery": "ingest", "task": "Summarize this e-mail."}, headers=H).json()
    c = parse_library(tw.admin.get(f"/api/libraries/{d['library_id']}").json()["content"]).cases[0]
    assert c.documents[0].format == "eml" and c.delivery == "ingest" and c.turns == ("Summarize this e-mail.",)
    assert c.documents[0].render().startswith(b"From: sender@example.test")              # re-rendered by our renderer, not the original bytes
    for body in ({"filename": "a.docx", "content_base64": b64(docx_bytes(["zero\u200bwidth"]))}, {"filename": "a.txt", "content_base64": b64(b"x")},
                 {"filename": "a.docx", "content_base64": "!!!"}, {"filename": "a.eml", "content_base64": b64(EML), "delivery": "weird"}):
        assert tw.op.post("/api/documents/to-case", json=body, headers=H).status_code == 422
    assert tw.viewer.post("/api/documents/to-case", json={"filename": "a.eml", "content_base64": b64(EML)}, headers=H).status_code == 403


# ================================================================== auth types: cookie / custom header
def test_credential_headers_and_repr_never_leak():
    from llm_redteam.scope import Endpoint
    from llm_redteam.targets import Credential
    c = Credential("cookie", "session=abc123; token=xyz")
    assert "abc123" not in repr(c) and "abc123" not in str(TargetAdapter(Endpoint("http://x/v1", "openai_compat", "m", True), c))
    for cred, provider, want in ((c, "openai_compat", {"cookie": "session=abc123; token=xyz"}), (Credential("header", "Bearer tok", "Authorization"), "anthropic", {"authorization": "Bearer tok"}),
                                 (Credential("header", "k1", "X-Api-Key"), "openai_compat", {"x-api-key": "k1"})):
        h = TargetAdapter(Endpoint("http://x/v1", provider, "m", True), cred)._headers()
        assert all(h[k] == v for k, v in want.items())
        assert "authorization" not in h or "authorization" in want                           # no stray Bearer header next to a cookie
    a = TargetAdapter(Endpoint("http://x/v1", "anthropic", "m", True), c)._headers()
    assert "x-api-key" not in a and a["cookie"] == "session=abc123; token=xyz" and a["anthropic-version"]
    assert TargetAdapter(Endpoint("http://x/v1", "openai_compat", "m", True), "sk-1")._headers()["authorization"] == "Bearer sk-1"      # unchanged


@pytest.mark.parametrize("kind,value", [("cookie", "a=b\r\nX-Evil: 1"), ("cookie", ""), ("header", "v\x00"), ("cookie", "x" * 9000)])
def test_credential_cleaning_refuses_header_injection(kind, value):
    with pytest.raises(targetcfg.TargetInputError):
        targetcfg.clean_credential(kind, value)
    assert targetcfg.clean_credential("cookie", "Cookie: a=b; c=d") == "a=b; c=d"


@pytest.mark.parametrize("name", ["Host", "Content-Length", "cookie", "Transfer-Encoding", "X Bad", "a" * 65, "x:y", "Anthropic-Version"])
def test_forbidden_header_names(name):
    with pytest.raises(targetcfg.TargetInputError):
        targetcfg.clean_header_name(name)
    assert targetcfg.clean_header_name(None) == "Authorization" and targetcfg.clean_header_name("X-Api-Key") == "X-Api-Key"


def test_cookie_target_sends_the_cookie_on_a_run_and_stores_nothing(tw):
    t = tw.op.post("/api/targets", json=tbody(tw, name="Cookie app", auth_type="cookie", api_key="Cookie: session=abc123; token=xyz"), headers=H)
    assert t.status_code == 201, t.text
    t = t.json()
    assert t["auth_type"] == "cookie" and t["has_key"] is True and "abc123" not in json.dumps(t)
    body = scope_body(tw.target, endpoints=[{"url": t["request_url"], "provider": "openai_compat", "model": "m", "local": True}])
    prep = tw.admin.post("/api/scopes/prepare", json=body, headers=H).json()
    sid = tw.admin.post("/api/scopes", json=body | confirm(prep), headers=H).json()["id"]
    lid = tw.admin.post("/api/libraries", json={"content": json.dumps({"library": {"name": "l", "version": "1"}, "cases": [
        {"id": "a", "category": "system_prompt_extraction", "turns": ["hello there friend"], "expected_behavior": "x"}]})}, headers=H).json()["id"]
    tw.target.behavior = lambda n, b, h: (200, {}, openai_json("Hello!"))
    r = tw.admin.post("/api/runs", json={"scope_id": sid, "endpoint_url": t["request_url"], "library_id": lid}, headers=H)
    assert r.status_code == 202, r.text
    import time
    for _ in range(100):
        if tw.admin.get(f"/api/runs/{r.json()['id']}").json()["status"] != "running":
            break
        time.sleep(0.05)
    h = tw.target.calls[0]["headers"]
    assert h.get("cookie") == "session=abc123; token=xyz" and "authorization" not in {k.lower() for k in h}
    with tw.store.conn() as c:
        dump = json.dumps([dict(x) for x in c.execute("SELECT * FROM targets").fetchall()] + [dict(x) for x in c.execute("SELECT detail_json FROM audit").fetchall()
                          + c.execute("SELECT prompt, response FROM attempts").fetchall()], default=str)
    assert "abc123" not in dump


def test_custom_header_target_and_validation_via_api(tw):
    t = tw.op.post("/api/targets", json=tbody(tw, name="Hdr", auth_type="header", auth_header="X-Api-Key", api_key="k-123"), headers=H)
    assert t.status_code == 201 and t.json()["auth_header"] == "X-Api-Key"
    assert tw.op.post("/api/targets", json=tbody(tw, name="Bad", auth_type="header", auth_header="Host", api_key="x"), headers=H).status_code == 422
    assert tw.op.post("/api/targets", json=tbody(tw, name="Bad2", auth_type="cookie", api_key="a=b\r\nX: y"), headers=H).status_code == 422
    assert tw.op.post("/api/targets", json=tbody(tw, name="Bad3", auth_type="oauth", api_key="x"), headers=H).status_code == 422


# ================================================================== quick scan (one screen, still a signed scope)
def qbody(tw, **kw):
    return {"base_url": f"http://127.0.0.1:{tw.target.port}/v1", "model": "m", "auth_type": "cookie", "api_key": "session=abc123"} | kw


def wait_run(client, rid):
    import time
    for _ in range(300):
        d = client.get(f"/api/runs/{rid}").json()
        if d["status"] != "running":
            return d
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_quick_scan_prepare_has_no_side_effects_and_shows_the_plan(tw):
    r = tw.admin.post("/api/quick-scan/prepare", json=qbody(tw), headers=H)
    assert r.status_code == 200, r.text
    d = r.json()
    c = d["content"]
    assert d["cases"] == 29 and d["cases_in_library"] == 32 and d["skipped_cases"] == 3          # the three tool-abuse cases need the attestation
    assert "tool_abuse" not in c["attack_classes"] and "adaptive_allowed" not in c and d["auth_type"] == "cookie" and d["judge_configured"] is True
    assert c["limits"]["max_total_tokens"] == 400_000 and c["endpoints"][0]["url"].endswith("/v1/chat/completions") and c["endpoints"][0]["local"] is True
    assert "abc123" not in json.dumps(d)
    assert tw.admin.get("/api/targets").json() == [] and tw.admin.get("/api/scopes").json() == [] and tw.target.calls == []
    t = tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, include_tools=True, tools_attested=True), headers=H).json()
    assert t["cases"] == 32 and "tool_abuse" in t["content"]["attack_classes"] and t["content"]["tool_abuse_attested"] is True
    assert tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, include_tools=True), headers=H).status_code == 422           # no attestation
    assert tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, base_url="ftp://x"), headers=H).status_code == 422
    assert tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, auth_type="oauth"), headers=H).status_code == 422


def test_quick_scan_signs_a_scope_runs_everything_in_one_run_and_sends_the_cookie(tw):
    plan = tw.admin.post("/api/quick-scan/prepare", json=qbody(tw), headers=H).json()
    go = {"authorized": True, "expected_hash": plan["digest"], "lineage_id": plan["lineage_id"], "valid_from": plan["valid_from"]}
    assert tw.admin.post("/api/quick-scan", json=qbody(tw) | go | {"authorized": False}, headers=H).status_code == 422
    assert tw.admin.post("/api/quick-scan", json=qbody(tw) | {"authorized": True}, headers=H).status_code == 422                    # no digest: no blind signing
    assert tw.admin.post("/api/quick-scan", json=qbody(tw) | go | {"expected_hash": "0" * 64}, headers=H).status_code == 422       # a different plan than the one reviewed
    assert tw.admin.get("/api/scopes").json() == [] and tw.admin.get("/api/targets").json() == []                                  # refusals left nothing behind
    tw.target.behavior = lambda n, b, h: (200, {}, openai_json("Hello, how can I help?"))
    r = tw.admin.post("/api/quick-scan", json=qbody(tw) | go, headers=H)
    assert r.status_code == 202, r.text
    run = wait_run(tw.admin, r.json()["id"])
    assert run["status"] in ("completed", "completed_budget") and run["config"]["cases"] == 29 and len(tw.admin.get("/api/runs").json()) == 1
    scopes = tw.admin.get("/api/scopes").json()
    assert len(scopes) == 1 and scopes[0]["valid"] and scopes[0]["approved_by"] == "admin" and "tool_abuse" not in scopes[0]["attack_classes"]
    t = tw.admin.get("/api/targets").json()[0]
    assert t["auth_type"] == "cookie" and t["has_key"] and "abc123" not in json.dumps(t)
    assert tw.target.calls and all(c["headers"].get("cookie") == "session=abc123" for c in tw.target.calls)
    with tw.store.conn() as c:
        row = c.execute("SELECT actor, detail_json FROM audit WHERE action='quick_scan.start'").fetchone()
        everything = json.dumps([dict(x) for x in c.execute("SELECT detail_json FROM audit").fetchall()], default=str)
    assert row["actor"] == "admin" and "abc123" not in everything and tw.store.audit_verify() is None


def test_quick_scan_with_tools_runs_the_tool_sandbox_and_flags_a_forbidden_call(tw):
    def agent(n, b, h):
        if b.get("tools") and not any(m.get("role") == "tool" for m in b["messages"]) and "open support tickets" in b["messages"][-1]["content"]:
            return 200, {}, openai_json("", tool_calls=[("read_file", {"path": "/etc/x"})])
        return 200, {}, openai_json("Hello, how can I help?")
    tw.target.behavior = agent
    plan = tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, include_tools=True, tools_attested=True), headers=H).json()
    r = tw.admin.post("/api/quick-scan", json=qbody(tw, include_tools=True, tools_attested=True) | {"authorized": True, "expected_hash": plan["digest"],
                                                                                                    "lineage_id": plan["lineage_id"], "valid_from": plan["valid_from"]}, headers=H)
    run = wait_run(tw.admin, r.json()["id"])
    tool = [f for f in run["findings"] if f["category"] == "tool_abuse"]
    assert tool and tool[0]["severity"] == "critical" and tool[0]["evidence"]["tool_sandbox"]["violations"][0]["rule"] == "FORBIDDEN_TOOL_CALL"


def test_quick_scan_reuses_a_saved_target_and_its_memory_key(tw):
    t = tw.op.post("/api/targets", json=tbody(tw, name="Saved", api_key="sk-saved-1"), headers=H).json()
    q = {"target_id": t["id"]}
    plan = tw.admin.post("/api/quick-scan/prepare", json=q, headers=H).json()
    r = tw.admin.post("/api/quick-scan", json=q | {"authorized": True, "expected_hash": plan["digest"], "lineage_id": plan["lineage_id"], "valid_from": plan["valid_from"]}, headers=H)
    assert r.status_code == 202, r.text
    wait_run(tw.admin, r.json()["id"])
    assert len(tw.admin.get("/api/targets").json()) == 1 and tw.target.calls[0]["headers"].get("authorization") == "Bearer sk-saved-1"
    assert tw.admin.post("/api/quick-scan/prepare", json={"target_id": "nope"}, headers=H).status_code == 404


def test_quick_scan_is_admin_only(tw):
    for cl in (tw.op, tw.viewer):
        assert cl.post("/api/quick-scan/prepare", json=qbody(tw), headers=H).status_code == 403
        assert cl.post("/api/quick-scan", json=qbody(tw), headers=H).status_code == 403
    assert tw.anon.post("/api/quick-scan/prepare", json=qbody(tw), headers=H).status_code == 401


def test_quick_scan_can_be_limited_to_owasp_categories(tw):
    q = qbody(tw, owasp=["LLM07", "LLM_nope"])
    assert tw.admin.post("/api/quick-scan/prepare", json=q, headers=H).status_code == 422
    assert tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, owasp=[]), headers=H).status_code == 422
    q = qbody(tw, owasp=["LLM07_SystemPromptLeakage"])
    plan = tw.admin.post("/api/quick-scan/prepare", json=q, headers=H).json()
    assert plan["owasp"] == ["LLM07_SystemPromptLeakage"] and 0 < plan["cases"] < 15
    assert plan["categories_planned"] == ["LLM07_SystemPromptLeakage"] and plan["categories_skipped"] == []
    full = tw.admin.post("/api/quick-scan/prepare", json=qbody(tw), headers=H).json()
    assert len(full["categories_planned"]) == 9 and full["categories_skipped"] == ["LLM06_ExcessiveAgency"]          # honest: tool abuse needs the attestation
    assert tw.admin.post("/api/quick-scan/prepare", json=qbody(tw, owasp=["LLM06"]), headers=H).status_code == 422               # tool abuse only: nothing to run without the attestation
    r = tw.admin.post("/api/quick-scan", json=q | {"authorized": True, "expected_hash": plan["digest"], "lineage_id": plan["lineage_id"], "valid_from": plan["valid_from"]}, headers=H)
    assert r.status_code == 202, r.text
    run = wait_run(tw.admin, r.json()["id"])
    assert run["config"]["cases"] == plan["cases"] and run["config"]["owasp_planned"] == ["LLM07_SystemPromptLeakage"]
