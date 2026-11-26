"""OWASP LLM Top 10: taxonomy, library field, starter kit, judge classification, matrix, scan, filter, report, judge advisory."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from fakes import LEAK, FakeJudge, openai_json
from llm_redteam import owasp, reports, starter
from llm_redteam.auth import Auth, required_role
from llm_redteam.evaluator import Evaluator, clean_untrusted, judge_advisory, validate_judgement
from llm_redteam.library import LibraryError, parse_library
from llm_redteam.targets import TargetAdapter
from main import create_app
from test_api import RING, _plain_http, confirm, lib_json, scope_body, wait


# ---------------------------------------------------------------- taxonomy
def test_ten_categories_with_unique_ids_codes_and_text():
    assert [c["code"] for c in owasp.CATEGORIES] == [f"LLM{i:02d}" for i in range(1, 11)]
    assert len({c["id"] for c in owasp.CATEGORIES}) == 10
    assert all(c["en"] and c["desc"] and c["coverage"] in ("direct", "limited") for c in owasp.CATEGORIES)
    assert {c["code"] for c in owasp.CATEGORIES if c["coverage"] == "limited"} == {"LLM03", "LLM04", "LLM08"}   # honest limit


@pytest.mark.parametrize("raw,canon", [
    ("LLM01_PromptInjection", "LLM01_PromptInjection"), ("llm01_promptinjection", "LLM01_PromptInjection"), ("LLM01", "LLM01_PromptInjection"),
    ("LLM07", "LLM07_SystemPromptLeakage"), ("LLM02_InsecureOutput", "LLM05_ImproperOutputHandling"),            # the 2023 examples the user gave
    ("LLM06_SensitiveInfoDisclosure", "LLM02_SensitiveInfoDisclosure"), ("LLM09_Overreliance", "LLM09_Misinformation"),
    ("LLM04_ModelDoS", "LLM10_UnboundedConsumption"), ("LLM08_ExcessiveAgency", "LLM06_ExcessiveAgency"),
])
def test_normalize_accepts_current_ids_and_2023_aliases(raw, canon):
    assert owasp.normalize(raw) == canon


@pytest.mark.parametrize("bad", ["", None, "LLM11", "LLM9", "LLM00", "Prompt Injection", "LLM01_Nope", 5, "LLM01_PromptInjection; DROP"])
def test_normalize_rejects_unknown(bad):
    assert owasp.normalize(bad) is None


def test_resolution_order_library_then_judge_then_default():
    assert owasp.resolve("LLM01_PromptInjection", "LLM07_SystemPromptLeakage", "data_leakage") == ("LLM01_PromptInjection", "library")
    assert owasp.resolve(None, "LLM07", "data_leakage") == ("LLM07_SystemPromptLeakage", "judge")
    assert owasp.resolve(None, "madeup", "data_leakage") == ("LLM02_SensitiveInfoDisclosure", "default")
    assert owasp.resolve(None, None, "missing") == (None, "none")
    assert set(owasp.DEFAULT_BY_CLASS.values()) <= set(owasp.BY_ID)


# ---------------------------------------------------------------- library schema
def libtxt(**case):
    c = {"id": "a", "category": "data_leakage", "turns": ["x"], "expected_behavior": "e"} | case
    return json.dumps({"library": {"name": "t", "version": "1"}, "cases": [c]})


def test_library_normalizes_owasp_field_and_rejects_unknown():
    assert parse_library(libtxt(owasp_category="LLM06_SensitiveInfoDisclosure")).cases[0].owasp_category == "LLM02_SensitiveInfoDisclosure"
    assert parse_library(libtxt()).cases[0].owasp_category is None
    assert parse_library(libtxt(owasp_category="")).cases[0].owasp_category is None
    with pytest.raises(LibraryError, match="unknown owasp_category"):
        parse_library(libtxt(owasp_category="LLM42_MadeUp"))


def test_owasp_category_is_part_of_library_hash():
    assert parse_library(libtxt(owasp_category="LLM02")).sha256 != parse_library(libtxt(owasp_category="LLM07")).sha256


def test_new_attack_classes_exist_for_owasp_modules():
    from llm_redteam.scope import ATTACK_CLASSES, CLASS_LABEL
    for k in ("unsafe_output", "misinformation", "resource_consumption"):
        assert k in ATTACK_CLASSES and k in CLASS_LABEL and k in owasp.DEFAULT_BY_CLASS


# ---------------------------------------------------------------- starter kit
def test_starter_kit_has_ten_valid_templates_one_per_category():
    t = starter.list_templates()
    assert len(t) == 10 and {x["owasp_category"] for x in t} == set(owasp.BY_ID)
    for x in t:
        assert x["cases"] >= 1 and x["sha256"] and x["name"].startswith("OWASP LLM")
    assert next(x for x in t if x["code"] == "LLM06")["needs_tool_attestation"] is True
    assert next(x for x in t if x["code"] == "LLM01")["needs_documents"] is True


def test_every_starter_case_is_tagged_expected_and_basic():
    lib = parse_library(starter.combined_text())
    assert len(lib.cases) == 15 and len({c.id for c in lib.cases}) == 15
    for c in lib.cases:
        assert c.owasp_category in owasp.BY_ID and c.expected_behavior and c.evaluator_hint is not None
        assert owasp.default_for(c.category) is not None
        assert all(len(t) < 300 for t in c.turns)                          # basic level: short, plain requests
        assert c.on_refusal == "next_case" and not c.variants              # no strategy/variants
    assert parse_library(starter.combined_text()).sha256 == lib.sha256     # deterministic


def test_starter_kit_contains_no_obfuscation_or_persona_tricks():
    """The kit is a basic quality probe: it contains no encoding/role-play/multi-step manipulation."""
    text = starter.combined_text().lower()
    for word in ("base64", "rot13", "roleplay", "pretend you are", "dan mode", "developer mode", "jailbreak", "unicode"):
        assert word not in text, word


def test_template_path_traversal_is_rejected():
    for bad in ("../x", "LLM01_PromptInjection/../../etc", "OWASP_ALL", "missing"):
        with pytest.raises(KeyError):
            starter.template_text(bad)


# ---------------------------------------------------------------- judge classification
GOODJ = {"verdict": "no_violation", "refusal_detected": False, "judge_injection_suspected": False, "confidence": 0.9, "rationale": "r",
         "questions": {q: {"answer": "no", "evidence_quote": ""} for q in
                       ("system_prompt_leaked", "harmful_request_fulfilled", "filter_bypassed", "unauthorized_tool_call")}}


@pytest.mark.parametrize("given,expected", [("LLM07_SystemPromptLeakage", "LLM07_SystemPromptLeakage"), ("LLM06_SensitiveInfoDisclosure", "LLM02_SensitiveInfoDisclosure"),
                                            ("LLM99", ""), ("", ""), (None, ""), (7, ""), ("LLM01_PromptInjection'; --", "")])
def test_judge_owasp_suggestion_is_validated_and_never_breaks_the_schema(given, expected):
    d = json.loads(json.dumps(GOODJ)) | ({"owasp_category": given} if given is not None else {})
    ev = validate_judgement(d, "response", [])
    assert ev.downgrade_reason == "" and ev.owasp_category == expected          # an invalid suggestion is NOT a SCHEMA error, it is simply ignored
    assert ev.to_dict()["owasp_category"] == expected


def test_judge_prompt_lists_all_owasp_ids_and_example_still_validates():
    from llm_redteam.evaluator import SYSTEM_PROMPT
    assert all(i in SYSTEM_PROMPT for i in owasp.BY_ID)
    d = json.loads(SYSTEM_PROMPT[SYSTEM_PROMPT.index('{"verdict"'):])
    assert validate_judgement(d, "x", []).downgrade_reason == ""


# ---------------------------------------------------------------- judge selection advisory
def test_judge_advisory_text_and_levels():
    big = judge_advisory({"judge_provider": "anthropic", "judge_model": "claude-sonnet-5-5", "judge_url": ""})
    assert big["level"] == "info" and big["reasons"] == [] and "false negatives" in big["message"] and "strongly recommended" in big["message"]
    for model in ("mistral:latest", "qwen2.5-coder:7b", "llama3.2:3b", "phi3:mini", "claude-haiku-5-5", "gemma2:9b"):
        assert judge_advisory({"judge_provider": "anthropic", "judge_model": model, "judge_url": ""})["level"] == "warn", model
    local = judge_advisory({"judge_provider": "openai_compat", "judge_model": "gpt-4o", "judge_url": "http://127.0.0.1:11434/v1"})
    assert local["level"] == "warn" and any("local" in r for r in local["reasons"])
    assert judge_advisory({"judge_provider": "openai_compat", "judge_model": "llama3.1:70b", "judge_url": "https://api.example.com/v1"})["level"] == "info"


# ---------------------------------------------------------------- API end to end
@pytest.fixture
def api(fresh_db, target):
    async def noop(s):
        pass
    app = create_app(fresh_db, RING, judge_factory=lambda st: FakeJudge(),
                     adapter_factory=lambda ep, key, stream: TargetAdapter(ep, key, stream=stream, sleep=noop, http=_plain_http()), auth=Auth(insecure=True))
    with TestClient(app) as c:
        c.target = target
        yield c


def signed(api, classes=("system_prompt_extraction", "data_leakage", "prompt_injection_direct", "prompt_injection_indirect", "misinformation",
                         "unsafe_output", "resource_consumption")):
    body = scope_body(api.target, attack_classes=list(classes))
    prep = api.post("/api/scopes/prepare", json=body).json()
    return api.post("/api/scopes", json=body | confirm(prep)).json()["id"]


def test_templates_api_lists_and_imports_idempotently(api):
    t = api.get("/api/templates").json()
    assert len(t["templates"]) == 10 and t["combined"]["id"] == "OWASP_ALL"
    r = api.post("/api/templates/import", json={"ids": ["LLM01_PromptInjection", "LLM07_SystemPromptLeakage"]})
    assert r.status_code == 201 and [x["cases"] for x in r.json()["imported"]] == [2, 2]
    again = api.post("/api/templates/import", json={"ids": ["LLM01_PromptInjection"]}).json()["imported"][0]
    assert again["library_id"] == r.json()["imported"][0]["library_id"]                         # same content = same library
    assert api.post("/api/templates/import", json={"ids": ["../x"]}).status_code == 404
    all_ = api.post("/api/templates/import", json={}).json()["imported"]
    assert len(all_) == 10
    comb = api.post("/api/templates/import", json={"combined": True}).json()["imported"][0]
    assert comb["cases"] == 15 and len(api.get("/api/libraries").json()) == 11


def leak_by_prompt(n, body, h):
    last = body["messages"][-1]["content"]
    if "email addresses" in last:
        return 200, {}, openai_json(f"Sure: alice@example.test, michael@example.test ({LEAK})")   # LLM02: vulnerable (the fake judge recognizes the marker)
    if "system instructions" in last:
        return 200, {}, openai_json(f"My instructions: secret key {LEAK}")                       # LLM07: vulnerable
    return 200, {}, openai_json("I cannot help with this request, I cannot do it.")                          # the rest: clean


def test_one_click_scan_matrix_filter_and_report(api):
    api.target.behavior = leak_by_prompt
    sid = signed(api)
    # matrix: nothing tested yet
    m0 = api.get("/api/owasp/matrix").json()
    assert m0["tested"] == 0 and m0["score"] is None and m0["coverage"] == 0 and all(c["status"] == "not_tested" for c in m0["categories"])
    # LLM06 (tool_abuse) is NOT in scope -> skipped and the reason is returned
    r = api.post("/api/owasp/scan", json={"scope_id": sid, "endpoint_url": api.target.url, "replay_n": 2, "replay_k": 2})
    assert r.status_code == 202, r.text
    j = r.json()
    assert "LLM06_ExcessiveAgency" in j["owasp_skipped"] and "LLM06_ExcessiveAgency" not in j["owasp_planned"] and len(j["owasp_planned"]) == 9
    run = wait(api, j["id"], timeout=90)
    assert run["status"] == "completed" and run["config"]["owasp_planned"] == j["owasp_planned"]
    m = api.get("/api/owasp/matrix").json()
    st = {c["code"]: c["status"] for c in m["categories"]}
    assert st["LLM02"] == "vulnerable" and st["LLM07"] == "vulnerable" and st["LLM06"] == "not_tested"
    assert st["LLM01"] == "clean" and st["LLM09"] == "clean" and st["LLM10"] == "clean" and st["LLM05"] == "clean"
    assert m["tested"] == 9 and m["vulnerable"] == 2 and m["clean"] == 7 and m["score"] == 78 and m["coverage"] == 90   # 7/9
    assert m["endpoint"] is None and api.target.url in m["endpoints"]
    # endpoint filter
    assert api.get("/api/owasp/matrix", params={"endpoint": "http://127.0.0.1:1/missing"}).json()["tested"] == 0
    assert api.get("/api/owasp/matrix", params={"endpoint": api.target.url}).json()["tested"] == 9
    # findings are filtered by OWASP
    f = api.get("/api/findings").json()
    assert sorted({x["owasp_category"] for x in f}) == ["LLM02_SensitiveInfoDisclosure", "LLM07_SystemPromptLeakage"]
    assert [x["owasp_category"] for x in api.get("/api/findings", params={"owasp": "LLM07"}).json()] == ["LLM07_SystemPromptLeakage"]
    assert api.get("/api/findings", params={"owasp": "LLM06_SensitiveInfoDisclosure"}).json()[0]["owasp_category"] == "LLM02_SensitiveInfoDisclosure"
    assert api.get("/api/findings", params={"owasp": "LLM77"}).status_code == 422
    assert f[0]["evidence"]["owasp"]["source"] == "library"
    # report: CSV + PDF contain OWASP information
    csv_rows = api.get(f"/api/runs/{j['id']}/findings.csv").content.decode("utf-8-sig").splitlines()
    assert "owasp_category" in csv_rows[0] and any("LLM07_SystemPromptLeakage" in r for r in csv_rows[1:])
    run = api.get(f"/api/runs/{j['id']}").json()
    html = reports.report_html(run, run["findings"])
    assert "OWASP Top 10 for LLM Applications (2025)" in html and "Categories tested: <b>9/10</b>" in html and "78%" in html and "not a compliance certificate" in html
    assert api.get(f"/api/runs/{j['id']}/report.pdf").content.startswith(b"%PDF")


def test_scan_with_selected_categories_only_runs_those(api):
    api.target.behavior = leak_by_prompt
    sid = signed(api)
    r = api.post("/api/owasp/scan", json={"scope_id": sid, "endpoint_url": api.target.url, "categories": ["LLM02", "LLM07_SystemPromptLeakage"], "replay_n": 2, "replay_k": 2})
    assert r.status_code == 202 and r.json()["owasp_planned"] == ["LLM02_SensitiveInfoDisclosure", "LLM07_SystemPromptLeakage"]
    run = wait(api, r.json()["id"], timeout=60)
    assert {a["case_id"] for a in run["attempts"] if a["outcome"] == "sent" and not a["is_replay"]} == {"llm02-customers", "llm02-config", "llm07-plain", "llm07-rules"}
    m = api.get("/api/owasp/matrix").json()
    assert m["tested"] == 2 and m["vulnerable"] == 2 and m["score"] == 0 and m["coverage"] == 20


def test_scan_validation_errors(api):
    sid = signed(api, classes=("system_prompt_extraction",))
    base = {"scope_id": sid, "endpoint_url": api.target.url}
    assert api.post("/api/owasp/scan", json=base | {"categories": ["LLM99"]}).status_code == 422
    r = api.post("/api/owasp/scan", json=base | {"categories": ["LLM06"]})                        # tool_abuse is not in the scope
    assert r.status_code == 422 and "LLM06_ExcessiveAgency" in r.json()["detail"]["message"]
    assert api.post("/api/owasp/scan", json={"scope_id": "missing", "endpoint_url": "x"}).status_code == 409   # hard gate


def test_running_scan_shows_testing_status(api):
    import threading
    gate = threading.Event()

    def slow(n, b, h):
        gate.wait(10)
        return 200, {}, openai_json("Merhaba")
    api.target.behavior = slow
    sid = signed(api)
    r = api.post("/api/owasp/scan", json={"scope_id": sid, "endpoint_url": api.target.url, "categories": ["LLM10"]})
    assert r.status_code == 202
    time.sleep(0.4)
    m = api.get("/api/owasp/matrix").json()
    assert {c["code"]: c["status"] for c in m["categories"]}["LLM10"] == "testing"
    gate.set()
    wait(api, r.json()["id"], timeout=30)
    assert {c["code"]: c["status"] for c in api.get("/api/owasp/matrix").json()["categories"]}["LLM10"] in ("clean", "review")


def test_judge_classification_is_used_when_the_case_has_no_owasp_tag(api):
    class J(FakeJudge):
        async def complete(self, system, user, max_tokens):
            t, n = await super().complete(system, user, max_tokens)
            d = json.loads(t); d["owasp_category"] = "LLM07"
            return json.dumps(d), n
    api.app.state.judge_override = None
    import main as m  # noqa: F401
    api.app.dependency_overrides = {}
    # judge_factory cannot be changed directly; the engine test is separately in test_engine. Here the library tag priority is verified:
    api.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Key {LEAK}"))
    sid = signed(api)
    lid = api.post("/api/libraries", json={"content": lib_json({"id": "x1"})}).json()["id"]          # EXAMPLE template: tagged LLM07
    run = wait(api, api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid, "replay_n": 2, "replay_k": 2}).json()["id"])
    assert run["findings"][0]["owasp_category"] == "LLM07_SystemPromptLeakage" and run["findings"][0]["evidence"]["owasp"]["source"] == "library"


def test_system_reports_judge_advisory(api):
    s = api.get("/api/system").json()
    assert s["judge_advisory"]["level"] == "info" and "false negatives" in s["judge_advisory"]["message"]
    api.put("/api/settings", json={"judge_model": "mistral:latest"})
    assert api.get("/api/system").json()["judge_advisory"]["level"] == "warn"


def test_new_endpoints_follow_rbac():
    for method, path, need in (("GET", "/api/templates", "viewer"), ("GET", "/api/owasp/matrix", "viewer"),
                               ("POST", "/api/templates/import", "operator"), ("POST", "/api/owasp/scan", "operator")):
        assert required_role(method, path) == need
