"""API: hard gate (no run with an unsigned scope), no blind signing, end-to-end run, refusal list."""
import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from fakes import LEAK, FakeJudge, openai_json
from llm_redteam.library import EXAMPLE_LIBRARY
from llm_redteam.auth import Auth
from llm_redteam.signing import Keyring
from llm_redteam.targets import TargetAdapter
from main import create_app

import httpx


def _plain_http():
    """The test target is on loopback; IP pinning is tested separately (test_components)."""
    return httpx.AsyncClient(follow_redirects=False)


RING = Keyring({"k1": bytes(range(32))}, "k1")
DOC = hashlib.sha256(b"authorization").hexdigest()


def lib_json(*cases):
    base = EXAMPLE_LIBRARY["cases"][0]
    return json.dumps({"library": EXAMPLE_LIBRARY["library"], "cases": [base | c for c in cases]})


@pytest.fixture
def api(fresh_db, target):
    async def noop(s):
        pass
    app = create_app(fresh_db, RING, judge_factory=lambda st: FakeJudge(),
                     adapter_factory=lambda ep, key, stream: TargetAdapter(ep, key, stream=stream, sleep=noop, http=_plain_http()),
                     auth=Auth(insecure=True))
    with TestClient(app) as c:
        c.target = target
        yield c


def scope_body(target, **kw):
    return {"name": "t", "client": "c", "authorized_by": "CISO", "authorization_doc_sha256": DOC, "valid_days": 30,
            "endpoints": [{"url": target.url, "provider": "openai_compat", "model": "m", "local": True}],
            "attack_classes": ["system_prompt_extraction"],
            "limits": {"max_requests_per_minute": 600}} | kw


def confirm(prep):
    """Fields the approval screen sends back: digest + pinned lineage and start date."""
    return {"expected_hash": prep["digest"], "lineage_id": prep["lineage_id"], "valid_from": prep["content"]["valid_from"]}


def sign(api, **kw):
    body = scope_body(api.target, **kw)
    prep = api.post("/api/scopes/prepare", json=body)
    assert prep.status_code == 200, prep.text
    r = api.post("/api/scopes", json=body | confirm(prep.json()))
    assert r.status_code == 201, r.text
    return r.json()["id"], prep.json()


def wait(api, run_id, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        r = api.get(f"/api/runs/{run_id}").json()
        if r["status"] != "running":
            return r
        time.sleep(0.05)
    raise AssertionError("the run did not finish")


def test_system_reports_missing_signing_key_and_judge(fresh_db):
    app = create_app(fresh_db, Keyring(), judge_factory=lambda s: None, auth=Auth(insecure=True))
    with TestClient(app) as c:
        s = c.get("/api/system").json()
        assert s["signing_key"] is False and s["judge_configured"] is False and len(s["warnings"]) == 3   # + the authentication-off warning


def test_blind_signing_is_refused(api):
    r = api.post("/api/scopes", json=scope_body(api.target))                         # no expected_hash
    assert r.status_code == 422 and "blind signing" in r.json()["detail"]["message"]
    prep = api.post("/api/scopes/prepare", json=scope_body(api.target)).json()
    r = api.post("/api/scopes", json=scope_body(api.target, attack_classes=["system_prompt_extraction", "jailbreak"])
                 | confirm(prep))
    assert r.status_code == 422 and "does not match" in r.json()["detail"]["message"]
    assert api.get("/api/scopes").json() == []


def test_signing_requires_the_start_date_shown_on_the_approval_screen(api):
    body = scope_body(api.target)
    prep = api.post("/api/scopes/prepare", json=body).json()
    c = confirm(prep)
    del c["valid_from"]
    r = api.post("/api/scopes", json=body | c)
    assert r.status_code == 422 and "valid_from" in r.json()["detail"]["message"]


def test_prepare_returns_full_signable_content(api):
    prep = api.post("/api/scopes/prepare", json=scope_body(api.target)).json()
    c = prep["content"]
    assert prep["version"] == 1 and prep["signing_available"] and len(prep["digest"]) == 64
    assert c["endpoints"][0]["url"] == api.target.url and c["limits"]["max_requests"] == 200
    assert c["attack_classes"] == ["system_prompt_extraction"] and c["valid_from"] < c["valid_until"]


def test_scope_without_signing_key_cannot_be_created(fresh_db, target):
    app = create_app(fresh_db, Keyring(), judge_factory=lambda s: FakeJudge(), auth=Auth(insecure=True))
    with TestClient(app) as c:
        body = scope_body(target)
        prep = c.post("/api/scopes/prepare", json=body).json()
        assert prep["signing_available"] is False
        r = c.post("/api/scopes", json=body | confirm(prep))
        assert r.status_code == 422 and "could not be signed" in r.json()["detail"]["message"]


def test_run_is_refused_without_valid_signed_scope(api):
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    base = {"scope_id": "missing", "endpoint_url": api.target.url, "library_id": lid}
    r = api.post("/api/runs", json=base)
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "SCOPE_NOT_FOUND" and r.json()["detail"]["message"]
    sid, _ = sign(api)
    store = api.app.state.store
    with store.conn() as c:                                                      # tamper
        c.execute("ALTER TABLE scopes DISABLE TRIGGER scopes_immutable")
        c.execute("UPDATE scopes SET signature = '\\x00'::bytea")
    r = api.post("/api/runs", json=base | {"scope_id": sid})
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "SCOPE_SIGNATURE_INVALID"
    assert api.get("/api/runs").json() == [] and api.target.calls == []
    codes = [a["reason_code"] for a in api.get("/api/audit?category=scope_state").json()]
    assert codes == ["SCOPE_SIGNATURE_INVALID", "SCOPE_NOT_FOUND"]


def test_run_refused_for_unauthorized_endpoint_unknown_library_and_missing_judge(api):
    sid, _ = sign(api)
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    r = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": "http://127.0.0.1:1/x", "library_id": lid})
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "ENDPOINT_NOT_AUTHORIZED"
    r = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": "missing"})
    assert r.status_code == 404
    r = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid,
                                    "categories": ["data_leakage"]})
    assert r.status_code == 422                                                   # category outside the scope


def test_end_to_end_verified_finding_via_api(api):
    api.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Sure, here is the key {LEAK}."))
    sid, _ = sign(api)
    lid = api.post("/api/libraries", json={"content": lib_json({"id": "k1"}, {"id": "k2"})}).json()["id"]
    r = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid,
                                    "api_key": "sk-test-secret", "replay_n": 2, "replay_k": 2})
    assert r.status_code == 202 and r.json()["cases"] == 2
    run = wait(api, r.json()["id"])
    assert run["status"] == "completed" and [f["status"] for f in run["findings"]] == ["verified", "verified"]
    assert run["requests"] == 6 and run["tokens_used"] > 0 and run["limits"]["max_requests"] == 200
    assert api.target.calls[0]["headers"]["authorization"] == "Bearer sk-test-secret"
    blob = json.dumps(run) + json.dumps(api.get("/api/audit").json()) + json.dumps(api.get("/api/findings").json())
    assert "sk-test-secret" not in blob                                           # the key is stored nowhere
    with api.app.state.store.conn() as c:
        dump = "".join(str(tuple(r.values())) for t in ("runs", "attempts", "findings", "audit", "scopes", "settings", "libraries")
                       for r in c.execute(f"SELECT * FROM {t}"))
    assert "sk-test-secret" not in dump
    st = api.get("/api/stats").json()
    assert st["findings_verified"] == 2 and st["verified_by_category"] == {"system_prompt_extraction": 2}
    assert api.get("/api/findings?status=verified").json()[0]["evidence"]["replay"]["violations"] == 2
    assert api.get("/api/system").json()["audit_chain_ok"] is True


def test_kill_switch_stops_live_run(api):
    import threading
    gate = threading.Event()
    def beh(n, b, h):
        gate.wait(5)
        return 200, {}, openai_json("Selam")
    api.target.behavior = beh
    sid, _ = sign(api)
    lid = api.post("/api/libraries", json={"content": lib_json(*[{"id": f"k{i}"} for i in range(5)])}).json()["id"]
    rid = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid}).json()["id"]
    time.sleep(0.3)
    assert api.post("/api/kill").json()["killed"] == 1
    gate.set()
    run = wait(api, rid)
    assert run["status"] == "halted" and run["stop_reason"] == "KILLED" and len(api.target.calls) == 1
    assert api.get("/api/audit?code=KILLED").json()


def test_library_import_validation_and_listing(api):
    r = api.post("/api/libraries", json={"content": "{"})
    assert r.status_code == 422
    r = api.post("/api/libraries", json={"content": json.dumps(EXAMPLE_LIBRARY)})
    assert r.status_code == 201
    again = api.post("/api/libraries", json={"content": json.dumps(EXAMPLE_LIBRARY)}).json()
    assert again["id"] == r.json()["id"] and len(api.get("/api/libraries").json()) == 1
    d = api.get(f"/api/libraries/{r.json()['id']}").json()
    assert d["case_list"][0]["id"] == "demo-001" and d["sha256"] == r.json()["sha256"]


def test_settings_validation_and_no_key_storage(api):
    assert api.get("/api/settings").json()["judge_model"] == "claude-sonnet-5-5"
    assert api.put("/api/settings", json={"judge_model": "another-model", "replay_n": 5}).json()["replay_n"] == 5
    assert api.put("/api/settings", json={"judge_api_key": "sk-xxx"}).status_code == 422
    assert api.put("/api/settings", json={"judge_api_key_env": "MY_KEY"}).status_code == 200
    assert api.put("/api/settings", json={"replay_n": 99}).status_code == 422
    assert api.put("/api/settings", json={"min_confidence": 7}).status_code == 422
    assert api.put("/api/settings", json={"unknown": 1}).status_code == 422


def test_reasons_and_audit_filtering_for_ui(api):
    reasons = api.get("/api/reasons").json()
    assert all(r["explanation"] and r["category_label"] for r in reasons) and {r["code"] for r in reasons} >= {"CIRCUIT_OPEN", "AUTH_FAILURE"}
    sid, _ = sign(api)
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    api.post("/api/runs", json={"scope_id": "missing", "endpoint_url": api.target.url, "library_id": lid})
    api.post("/api/runs", json={"scope_id": sid, "endpoint_url": "http://127.0.0.1:1/x", "library_id": lid})
    all_ = api.get("/api/audit").json()
    assert {a["reason_category"] for a in all_} == {"scope_state", "endpoint"}
    assert [a["reason_code"] for a in api.get("/api/audit?category=endpoint").json()] == ["ENDPOINT_NOT_AUTHORIZED"]
    assert api.get("/api/audit?code=SCOPE_NOT_FOUND").json()[0]["explanation"]


def test_scope_versions_and_revoke(api):
    sid, prep = sign(api)
    body = scope_body(api.target, attack_classes=["system_prompt_extraction", "data_leakage"]) | {"lineage_id": prep["lineage_id"]}
    p2 = api.post("/api/scopes/prepare", json=body).json()
    assert p2["version"] == 2
    assert api.post("/api/scopes", json=body | confirm(p2)).status_code == 201
    listed = {s["version"]: s for s in api.get("/api/scopes").json()}
    assert listed[1]["valid"] is False and listed[1]["invalid_reason"] == "SCOPE_SUPERSEDED" and listed[2]["valid"] is True
    assert api.post(f"/api/scopes/{listed[2]['id']}/revoke").status_code == 200
    assert api.post(f"/api/scopes/{listed[2]['id']}/revoke").status_code == 404


def test_canary_validation_and_only_count_is_stored(api):
    api.target.behavior = lambda n, b, h: (200, {}, openai_json("Hello, my key turns out to be SECRET-CANARY-777."))
    body = scope_body(api.target)
    prep = api.post("/api/scopes/prepare", json=body).json()
    sid = api.post("/api/scopes", json=body | confirm(prep)).json()["id"]
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    base = {"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid}
    for bad in (["short"], ["x" * 201], [f"canary-value-{i}" for i in range(11)]):
        assert api.post("/api/runs", json=base | {"canaries": bad}).status_code == 422
    r = api.post("/api/runs", json=base | {"canaries": ["SECRET-CANARY-777", "SECRET-CANARY-777", "  "]})
    assert r.status_code == 202
    run = wait(api, r.json()["id"])
    assert run["config"]["canaries"] == 1 and "SECRET-CANARY-777" not in json.dumps(run["config"])   # the values are not written to the config
    assert [f["status"] for f in run["findings"]] == ["needs_review"]


def test_live_feed_is_viewer_readable_and_lists_recent_attempts(api):
    """The dashboard's live activity feed: slim attempt events, newest first; idle -> the latest run's events with live=false."""
    assert api.get("/api/live").json() == {"live": False, "runs": 0, "events": []}
    api.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Sure, here is the key {LEAK}."))
    sid, _ = sign(api)
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    rid = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid, "replay_n": 1, "replay_k": 1}).json()["id"]
    wait(api, rid)
    feed = api.get("/api/live").json()
    assert feed["live"] is False and feed["events"]
    e = feed["events"][0]
    assert {"run_id", "seq", "at", "case_id", "outcome", "verdict", "confidence", "tokens"} <= set(e) and "prompt" not in e and "response" not in e
    assert all(feed["events"][i]["at"] >= feed["events"][i + 1]["at"] for i in range(len(feed["events"]) - 1))
    assert any(x["verdict"] == "violation" for x in feed["events"])
    ts = api.get("/api/stats").json()["timeseries"][0]
    assert ts["passed"] + ts["failed"] >= 1 and "failed" in ts


def test_live_feed_limit_and_all_runs_for_the_logs_page(api):
    """The Logs page asks for more rows across all runs; the limit is clamped and the payload stays slim."""
    assert api.get("/api/live?limit=5&all_runs=true").json() == {"live": False, "runs": 0, "events": []}
    api.target.behavior = lambda n, b, h: (200, {}, openai_json("Sorry, I cannot help with that."))
    sid, _ = sign(api)
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    rid = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid, "replay_n": 1, "replay_k": 1}).json()["id"]
    wait(api, rid)
    full = api.get("/api/live?all_runs=true&limit=500").json()["events"]
    assert full and len(api.get("/api/live?all_runs=true&limit=1").json()["events"]) == 1
    assert len(api.get("/api/live?limit=0").json()["events"]) == 1  # clamped to >= 1
    assert all("prompt" not in e and "response" not in e for e in full)
