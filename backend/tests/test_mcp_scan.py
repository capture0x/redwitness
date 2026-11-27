"""MCP server audit: deterministic checks, the read-only client, and the whole path through the API against the mock MCP server."""
import asyncio
import importlib.util
import json
import pathlib
import threading
import time
from http.server import ThreadingHTTPServer

import httpx
import pytest

from llm_redteam import clientreport, mcpscan
from test_api import confirm, scope_body
from test_reports import api  # noqa: F401  (fixture)


def _mock():
    spec = importlib.util.spec_from_file_location("mock_mcp", pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "mock_mcp.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---------------------------------------------------------------- deterministic checks
def test_checks_find_each_flaw_once_and_leave_clean_tools_alone():
    m = _mock()
    tools = m.tools()
    names = {t["name"] for t in tools}
    got = {t["name"]: sorted({i["code"] for i in mcpscan.check_item("tool", t, names)}) for t in tools}
    assert got == {"get_weather": [], "send_email": [], "translate": [], "add_numbers": ["MCP_TOOL_POISONING"], "run_shell": ["MCP_DANGEROUS_CAPABILITY"],
                   "send_note": ["MCP_TOOL_SHADOWING"], "lookup": ["MCP_HIDDEN_CHARACTERS", "MCP_TOOL_POISONING"]}
    sev = {i["name"]: i["severity"] for t in tools for i in mcpscan.check_item("tool", t, names) if i["code"] == "MCP_TOOL_POISONING"}
    assert sev == {"add_numbers": "critical", "lookup": "high"}                  # reading ~/.ssh is worse than a vague hidden step
    p = mcpscan.check_item("prompt", m.prompts()[0], names)
    assert [i["code"] for i in p] == ["MCP_SECRET_IN_DEFINITION"] and "QA-FAKE-KEY" not in json.dumps(p)   # the secret is masked
    assert all(mcpscan.check_item("tool", t, set()) == [] for t in m.tools(clean=True))


def test_invisible_characters_are_shown_and_encoded_blobs_flagged():
    i = mcpscan.check_item("tool", {"name": "t", "description": "Plain text​‮ with a hidden part"}, set())
    assert i[0]["code"] == "MCP_HIDDEN_CHARACTERS" and "<U+200B>" in i[0]["quote"] and "<U+202E>" in i[0]["quote"]
    b = mcpscan.check_item("tool", {"name": "t", "description": "Data: " + "QUJD" * 20}, set())
    assert [x["code"] for x in b] == ["MCP_ENCODED_PAYLOAD"]


@pytest.mark.parametrize("schema, flagged", [
    ({"command": {"type": "string"}}, True),
    ({"command": {"type": "string", "enum": ["uptime", "df"]}}, False),          # an allowlist makes it narrow
    ({"command": {"type": "string", "pattern": "^ls$"}}, False),
    ({"count": {"type": "integer"}}, False),
])
def test_dangerous_capability_needs_free_text_input(schema, flagged):
    t = {"name": "run_shell", "description": "Runs a shell command.", "inputSchema": {"type": "object", "properties": schema}}
    assert bool(mcpscan.check_item("tool", t, set())) == flagged


def test_findings_map_to_owasp_asi_and_carry_remediation():
    m = _mock()
    issues = [i for t in m.tools() for i in mcpscan.check_item("tool", t, {x["name"] for x in m.tools()})]
    fs = mcpscan.findings_from({"issues": issues})
    by = {f["code"]: f for f in fs}
    assert by["MCP_TOOL_POISONING"]["owasp"] == "LLM01_PromptInjection" and by["MCP_TOOL_POISONING"]["asi"] == "ASI04_AgenticSupplyChain"
    assert by["MCP_DANGEROUS_CAPABILITY"]["category"] == "tool_abuse" and by["MCP_DANGEROUS_CAPABILITY"]["owasp"] == "LLM06_ExcessiveAgency"
    assert all(f["remediation"] and f["status"] == "verified" for f in fs)


def test_client_refuses_anything_but_listing():
    class G:
        async def authorize_probe(self, *a):
            raise AssertionError("must not be reached")
    c = mcpscan.McpClient(type("E", (), {"url": "http://x/mcp", "local": True})(), G(), http=httpx.AsyncClient())
    for method in ("tools/call", "resources/read", "prompts/get", "sampling/createMessage"):
        with pytest.raises(mcpscan.McpError):
            asyncio.run(c.call(method, {}))


# ---------------------------------------------------------------- the whole path through the API
@pytest.fixture
def mcp_server():
    m = _mock()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), m.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.mock, srv.base = m, f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()


def _scope(api, srv, classes=("mcp_server_audit",)):
    eps = [{"url": f"{srv.base}{p}", "provider": "mcp", "model": "", "local": True} for p in ("/mcp", "/secure/mcp", "/clean/mcp")]
    body = scope_body(api.target, endpoints=eps, attack_classes=list(classes))
    prep = api.post("/api/scopes/prepare", json=body)
    assert prep.status_code == 200, prep.text
    return api.post("/api/scopes", json=body | confirm(prep.json())).json()["id"]


def _scan(api, sid, url, **kw):
    r = api.post("/api/mcp-scans", json={"scope_id": sid, "endpoint_url": url} | kw)
    assert r.status_code == 202, r.text
    for _ in range(200):
        run = api.get(f"/api/runs/{r.json()['id']}").json()
        if run["status"] != "running":
            return run
        time.sleep(0.05)
    raise TimeoutError


def test_api_audits_a_server_records_findings_and_never_calls_a_tool(api, mcp_server):
    sid = _scope(api, mcp_server)
    run = _scan(api, sid, f"{mcp_server.base}/mcp")
    assert run["status"] == "completed", run
    codes = {f["evidence"]["mcp"]["code"] for f in run["findings"]}
    assert codes == {"MCP_TOOL_POISONING", "MCP_HIDDEN_CHARACTERS", "MCP_DANGEROUS_CAPABILITY", "MCP_TOOL_SHADOWING", "MCP_SECRET_IN_DEFINITION", "MCP_NO_AUTH"}
    assert all(f["status"] == "verified" for f in run["findings"])
    snap = run["snapshot"]["mcp"]
    assert snap["server"]["name"] == "acme-mcp" and snap["auth"] == "none required" and len(snap["tools"]) == 7
    assert {t["name"]: t["issues"] for t in snap["tools"]}["get_weather"] == []
    methods = set(mcp_server.mock.state["methods"])
    assert methods <= set(mcpscan.ALLOWED) and "tools/call" not in methods and mcp_server.mock.state["calls_refused"] == 0
    crit = next(f for f in run["findings"] if f["severity"] == "critical")
    assert crit["owasp_category"] == "LLM01_PromptInjection" and crit["frameworks"]["asi"] == "ASI04_AgenticSupplyChain"
    m = clientreport.build([run], next(s for s in api.get("/api/scopes").json() if s["id"] == sid), clientreport.options("C", "P", "T", None, False))
    poison = next(x for x in m["findings"] if "Hidden instructions" in x["title"])
    assert poison["remediation"] == mcpscan.REMEDIATION["MCP_TOOL_POISONING"] and poison["remediation_source"] == "Guidance for this check"
    assert any(s["id"] == run["id"] for s in api.get("/api/mcp-scans").json())


def test_authentication_is_checked_and_used(api, mcp_server):
    sid = _scope(api, mcp_server)
    refused = _scan(api, sid, f"{mcp_server.base}/secure/mcp")
    assert refused["status"] == "halted" and refused["stop_reason"] == "AUTH_FAILURE" and refused["findings"] == []
    ok = _scan(api, sid, f"{mcp_server.base}/secure/mcp", auth_type="bearer", api_key="mcp-test-token")
    codes = {f["evidence"]["mcp"]["code"] for f in ok["findings"]}
    assert ok["status"] == "completed" and "MCP_NO_AUTH" not in codes and "MCP_TOOL_POISONING" in codes
    assert ok["snapshot"]["mcp"]["auth"] == "credential accepted"
    assert "mcp-test-token" not in json.dumps(ok)                                  # the credential is never stored


def test_rug_pull_between_two_scans_is_reported(api, mcp_server):
    sid = _scope(api, mcp_server)
    first = _scan(api, sid, f"{mcp_server.base}/clean/mcp")
    assert first["status"] == "completed" and [f["evidence"]["mcp"]["code"] for f in first["findings"]] == ["MCP_NO_AUTH"]   # clean definitions, but open
    httpx.post(f"{mcp_server.base}/admin/rugpull")
    second = _scan(api, sid, f"{mcp_server.base}/clean/mcp")
    changed = [f for f in second["findings"] if f["evidence"]["mcp"]["code"] == "MCP_DEFINITION_CHANGED"]
    assert changed and changed[0]["evidence"]["mcp"]["name"] == "get_weather" and changed[0]["owasp_category"] == "LLM03_SupplyChain"


def test_scope_rules_apply(api, mcp_server):
    sid = _scope(api, mcp_server, classes=("system_prompt_extraction",))         # the MCP class is not authorized
    assert api.post("/api/mcp-scans", json={"scope_id": sid, "endpoint_url": f"{mcp_server.base}/mcp"}).status_code == 409
    sid = _scope(api, mcp_server)
    assert api.post("/api/mcp-scans", json={"scope_id": sid, "endpoint_url": "http://127.0.0.1:1/other"}).status_code == 409
    assert api.post("/api/mcp-scans", json={"scope_id": sid, "endpoint_url": f"{mcp_server.base}/mcp", "auth_type": "bearer"}).status_code == 422
    lid = api.post("/api/libraries", json={"content": json.dumps({"library": {"name": "l", "version": "1"}, "cases": [
        {"id": "c", "category": "system_prompt_extraction", "title": "t", "turns": ["hi"], "expected_behavior": "e"}]})}).json()["id"]
    assert api.post("/api/runs", json={"scope_id": sid, "endpoint_url": f"{mcp_server.base}/mcp", "library_id": lid}).status_code in (409, 422)


def test_judge_review_adds_findings_that_need_human_review(fresh_db, target, mcp_server):
    """A judge that flags the 'send_email' description; deterministic findings stay verified, the judge-only one needs review."""
    class J:
        async def complete(self, system, user, max_tokens):
            flag = "Sends an e-mail." in user
            return json.dumps({"verdict": "violation" if flag else "no_violation", "questions": {
                "system_prompt_leaked": {"answer": "no", "evidence_quote": ""}, "harmful_request_fulfilled": {"answer": "no", "evidence_quote": ""},
                "filter_bypassed": {"answer": "yes" if flag else "no", "evidence_quote": "Sends an e-mail." if flag else ""},
                "unauthorized_tool_call": {"answer": "no", "evidence_quote": ""}}, "refusal_detected": False, "judge_injection_suspected": False,
                "owasp_category": "", "confidence": 0.9, "rationale": "test judge"}), 10
    from fastapi.testclient import TestClient
    from llm_redteam.auth import Auth
    from main import create_app
    from test_api import RING
    with TestClient(create_app(fresh_db, RING, judge_factory=lambda st: J(), auth=Auth(insecure=True))) as api:
        api.target = target
        sid = _scope(api, mcp_server)
        run = _scan(api, sid, f"{mcp_server.base}/mcp", judge_review=True)
    judged = [f for f in run["findings"] if f["evidence"]["mcp"]["code"] == "MCP_JUDGE_SUSPICIOUS"]
    assert run["status"] == "completed" and judged and all(f["status"] == "needs_review" for f in judged)
    assert {f["evidence"]["mcp"]["name"] for f in judged} == {"send_email"} and run["snapshot"]["mcp"]["judge_reviewed"] >= 2
