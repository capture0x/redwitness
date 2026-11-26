"""Feature: multi-target benchmark (A/B): one test set, several targets, side-by-side OWASP failure rates and a ranking."""
import contextlib
import time

import pytest
from fastapi.testclient import TestClient

from fakes import LEAK, FakeJudge, FakeTarget, openai_json
from llm_redteam.auth import Auth
from llm_redteam.targets import TargetAdapter
from main import create_app
from test_api import RING, _plain_http, confirm, lib_json, scope_body
from test_rbac import H, PW

LEAKING = f"Sure, here is the key {LEAK}."
REFUSE = "Sorry, I cannot do that."


@pytest.fixture
def bw(fresh_db, target):
    """Two targets (A leaks, B refuses) inside ONE signed scope; admin + viewer."""
    b = FakeTarget()

    async def noop(s):
        pass
    app = create_app(fresh_db, RING, judge_factory=lambda st: FakeJudge(),
                     adapter_factory=lambda ep, key, stream: TargetAdapter(ep, key, stream=stream, sleep=noop, http=_plain_http()), auth=Auth(PW))
    with contextlib.ExitStack() as st:
        w = type("W", (), {})()
        w.a, w.b = target, b
        w.admin, w.viewer = st.enter_context(TestClient(app)), st.enter_context(TestClient(app))
        assert w.admin.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
        assert w.admin.post("/api/users", json={"username": "viewer1", "password": "viewer1-password-99", "role": "viewer"}, headers=H).status_code == 201
        assert w.viewer.post("/api/auth/login", json={"username": "viewer1", "password": "viewer1-password-99"}).status_code == 200
        target.behavior = lambda n, bd, h: (200, {}, openai_json(LEAKING))
        b.behavior = lambda n, bd, h: (200, {}, openai_json(REFUSE))
        body = scope_body(target, endpoints=[{"url": target.url, "provider": "openai_compat", "model": "model-a", "local": True},
                                             {"url": b.url, "provider": "openai_compat", "model": "model-b", "local": True}])
        w.body = body
        w.sid = w.admin.post("/api/scopes", json=body | confirm(w.admin.post("/api/scopes/prepare", json=body, headers=H).json()), headers=H).json()["id"]
        w.lid = w.admin.post("/api/libraries", json={"content": lib_json({"id": "k1"}, {"id": "k2"})}, headers=H).json()["id"]
        w.start = lambda **kw: w.admin.post("/api/benchmarks", json={"scope_id": w.sid, "endpoint_urls": [target.url, b.url], "library_id": w.lid, "replay_n": 1, "replay_k": 1, "label": "ab"} | kw, headers=H)

        def finish(bid, timeout=30):
            end = time.time() + timeout
            while time.time() < end:
                r = w.admin.get(f"/api/benchmarks/{bid}").json()
                if r["status"] != "running":
                    return r
                time.sleep(0.1)
            raise AssertionError("benchmark did not finish")
        w.finish = finish
        yield w
    b.close()


def test_same_test_set_goes_to_every_target_and_results_are_comparable(bw):
    r = bw.start()
    assert r.status_code == 202 and len(r.json()["runs"]) == 2
    res = bw.finish(r.json()["id"])
    assert res["status"] == "completed" and res["comparable"] is True and res["label"] == "ab"
    a, b = res["targets"]
    assert (a["model"], b["model"]) == ("model-a", "model-b")
    cats = res["categories"]
    assert cats == ["LLM07_SystemPromptLeakage"]
    assert a["tested"] == b["tested"] == 2                                       # k1 and k2 on both
    assert a["violations"] == 2 and a["fail_rate"] == 1.0 and a["categories"][cats[0]] == {"tested": 2, "violations": 2, "verified": 2, "fail_rate": 1.0}
    assert b["violations"] == 0 and b["fail_rate"] == 0.0 and b["verified"] == 0
    assert (b["rank"], a["rank"]) == (1, 2)                                      # the safer model ranks first
    assert len(bw.a.calls) > 0 and len(bw.b.calls) == 2                          # B only ever saw the two library cases (no replays: nothing to confirm)


def test_per_target_api_keys_reach_only_their_own_target(bw):
    res = bw.finish(bw.start(api_keys={bw.a.url: "key-for-a", bw.b.url: "key-for-b"}).json()["id"])
    assert res["status"] == "completed"
    auth = lambda t: {c["headers"].get("authorization") or c["headers"].get("x-api-key") for c in t.calls}  # noqa: E731
    assert auth(bw.a) == {"Bearer key-for-a"} and auth(bw.b) == {"Bearer key-for-b"}


def test_validation_and_all_or_nothing(bw):
    runs_before = len(bw.admin.get("/api/runs").json())
    assert bw.start(endpoint_urls=[bw.a.url]).status_code == 422                              # needs at least two
    assert bw.start(endpoint_urls=[bw.a.url, bw.a.url]).status_code == 422                    # duplicates collapse to one
    assert bw.start(endpoint_urls=[bw.a.url, "http://127.0.0.1:1/v1/chat/completions"]).status_code == 422   # not in the signed scope
    assert bw.start(endpoint_urls=[bw.a.url] * 5).status_code == 422
    assert bw.start(api_keys={"http://other": "k"}).status_code == 422
    assert bw.start(library_id="nope").status_code in (404, 422)
    assert bw.start(scope_id="nope").status_code == 409
    assert len(bw.admin.get("/api/runs").json()) == runs_before                               # nothing was started by any refused request


def test_roles(bw):
    bid = bw.start().json()["id"]
    assert bw.viewer.get("/api/benchmarks").status_code == 200 and bw.viewer.get(f"/api/benchmarks/{bid}").status_code == 200
    assert bw.viewer.post("/api/benchmarks", json={"scope_id": bw.sid, "endpoint_urls": [bw.a.url, bw.b.url]}, headers=H).status_code == 403
    assert bw.admin.get("/api/benchmarks/nope").status_code == 404
    listed = bw.viewer.get("/api/benchmarks").json()
    assert listed[0]["id"] == bid and listed[0]["targets"] == 2
    bw.finish(bid)


def test_incomplete_target_makes_the_comparison_partial(bw):
    body = bw.body | {"name": "tiny", "limits": {"max_requests_per_minute": 600, "max_total_tokens": 20}}
    sid = bw.admin.post("/api/scopes", json=body | confirm(bw.admin.post("/api/scopes/prepare", json=body, headers=H).json()), headers=H).json()["id"]
    bid = bw.start(scope_id=sid).json()["id"]
    res = bw.finish(bid)
    assert res["status"] == "partial" and res["comparable"] is False
    assert {t["status"] for t in res["targets"]} - {"completed"}


def test_owasp_starter_kit_benchmark_and_audit(bw):
    bw.b.behavior = bw.a.behavior = lambda n, bd, h: (200, {}, openai_json(REFUSE))
    r = bw.admin.post("/api/benchmarks", json={"scope_id": bw.sid, "endpoint_urls": [bw.a.url, bw.b.url], "owasp": ["LLM07_SystemPromptLeakage"]}, headers=H)
    assert r.status_code == 202
    res = bw.finish(r.json()["id"])
    assert res["label"] == "Benchmark" and all(t["fail_rate"] == 0 for t in res["targets"])


def test_a_target_that_only_errors_makes_the_comparison_partial(bw):
    bw.b.behavior = lambda n, bd, h: (200, {}, "not valid json at all")           # the adapter cannot read it: every attempt is an error
    res = bw.finish(bw.start().json()["id"])
    b = res["targets"][1]
    assert b["tested"] == 0 and b["fail_rate"] is None and res["status"] == "partial" and res["comparable"] is False
