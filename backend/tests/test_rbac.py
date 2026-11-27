"""RBAC: permission matrix (role x endpoint), immediate effect, last-admin protection, default deny, audit."""
import contextlib
import json

import pytest
from fastapi.testclient import TestClient

from fakes import LEAK, FakeJudge, openai_json
from llm_redteam.auth import Auth, required_role
from llm_redteam.signing import Keyring
from llm_redteam.targets import TargetAdapter
from main import create_app
from test_api import RING, _plain_http, confirm, lib_json, scope_body, wait

PW = "admin-password-123"
H = {"x-redwitness-csrf": "1"}


@pytest.fixture
def world(fresh_db, target):
    """One app, three separate clients (admin/operator/viewer), a signed scope and a library."""
    async def noop(s):
        pass
    app = create_app(fresh_db, RING, judge_factory=lambda st: FakeJudge(),
                     adapter_factory=lambda ep, key, stream: TargetAdapter(ep, key, stream=stream, sleep=noop, http=_plain_http()),
                     auth=Auth(PW))
    with contextlib.ExitStack() as stack:
        mk = lambda: stack.enter_context(TestClient(app))  # noqa: E731
        w = type("W", (), {})()
        w.app, w.target, w.admin, w.op, w.viewer = app, target, mk(), mk(), mk()
        assert w.admin.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
        for name, role in (("operator1", "operator"), ("viewer1", "viewer")):
            r = w.admin.post("/api/users", json={"username": name, "password": f"{name}-password-99", "role": role}, headers=H)
            assert r.status_code == 201, r.text
        for cl, name in ((w.op, "operator1"), (w.viewer, "viewer1")):
            assert cl.post("/api/auth/login", json={"username": name, "password": f"{name}-password-99"}).status_code == 200
        body = scope_body(target)
        prep = w.admin.post("/api/scopes/prepare", json=body, headers=H).json()
        w.sid = w.admin.post("/api/scopes", json=body | confirm(prep), headers=H).json()["id"]
        w.lid = w.op.post("/api/libraries", json={"content": lib_json({})}, headers=H).json()["id"]
        w.client_by_role = {"admin": w.admin, "operator": w.op, "viewer": w.viewer}
        yield w


# ---------------------------------------------------------------- permission table (pure)
@pytest.mark.parametrize("method,path,role", [
    ("GET", "/api/system", "viewer"), ("GET", "/api/stats", "viewer"), ("GET", "/api/runs", "viewer"),
    ("GET", "/api/runs/abc", "viewer"), ("GET", "/api/runs/abc/report.pdf", "viewer"), ("GET", "/api/findings.csv", "viewer"),
    ("GET", "/api/libraries", "viewer"), ("GET", "/api/scopes", "viewer"), ("POST", "/api/auth/password", "viewer"),
    ("GET", "/api/audit", "operator"), ("GET", "/api/settings", "operator"), ("POST", "/api/runs", "operator"),
    ("POST", "/api/runs/abc/stop", "operator"), ("POST", "/api/libraries", "operator"), ("POST", "/api/kill", "operator"),
    ("POST", "/api/scopes", "admin"), ("POST", "/api/scopes/prepare", "admin"), ("POST", "/api/scopes/x/revoke", "admin"),
    ("PUT", "/api/settings", "admin"), ("GET", "/api/users", "admin"), ("POST", "/api/users", "admin"),
    ("PATCH", "/api/users/x", "admin"), ("POST", "/api/users/x/password", "admin"),
])
def test_required_role_table(method, path, role):
    assert required_role(method, path) == role


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/a-new-endpoint"), ("DELETE", "/api/runs/abc"), ("PUT", "/api/runs"), ("GET", "/api/audit/"), ("GET", "/api/users/"),
    ("GET", "/api/runs/abc/stop"), ("POST", "/api/runs/abc/extra"), ("GET", "/api/runs/a/b"), ("PATCH", "/api/findings"),
    ("GET", "/API/system"), ("GET", "/api/system/"), ("GET", "/api/runs/../users"),
])
def test_default_deny_for_unlisted_routes(method, path):
    assert required_role(method, path) == "admin"


# ---------------------------------------------------------------- live matrix
ENDPOINTS = [  # (method, path, json, minimum role)
    ("GET", "/api/system", None, "viewer"), ("GET", "/api/meta", None, "viewer"), ("GET", "/api/reasons", None, "viewer"),
    ("GET", "/api/stats", None, "viewer"), ("GET", "/api/runs", None, "viewer"), ("GET", "/api/findings", None, "viewer"),
    ("GET", "/api/findings.csv", None, "viewer"), ("GET", "/api/libraries", None, "viewer"), ("GET", "/api/scopes", None, "viewer"),
    ("GET", "/api/audit", None, "operator"), ("GET", "/api/settings", None, "operator"),
    ("POST", "/api/libraries", {"content": "{"}, "operator"), ("POST", "/api/runs", {"scope_id": "x", "endpoint_url": "x", "library_id": "x"}, "operator"),
    ("POST", "/api/runs/missing/stop", None, "operator"),
    ("PUT", "/api/settings", {"replay_n": 3}, "admin"), ("POST", "/api/scopes/prepare", {}, "admin"), ("POST", "/api/scopes", {}, "admin"),
    ("POST", "/api/scopes/missing/revoke", None, "admin"), ("GET", "/api/users", None, "admin"),
    ("POST", "/api/users", {"username": "x", "password": "y", "role": "viewer"}, "admin"),
    ("PATCH", "/api/users/missing", {"active": False}, "admin"), ("POST", "/api/users/missing/password", {"password": "short"}, "admin"),
]
RANK = {"viewer": 0, "operator": 1, "admin": 2}


@pytest.mark.parametrize("method,path,body,need", ENDPOINTS, ids=[f"{m} {p}" for m, p, _, _ in ENDPOINTS])
def test_permission_matrix_live(world, method, path, body, need):
    for role, client in world.client_by_role.items():
        r = client.request(method, path, json=body, headers=H)
        if RANK[role] >= RANK[need]:
            assert r.status_code not in (401, 403), f"{role} {method} {path}: {r.status_code} {r.text[:120]}"
        else:
            assert r.status_code == 403 and r.json()["detail"]["reason"] == "ACCESS_DENIED", f"{role} {method} {path}: {r.status_code}"
            assert str(need and {"viewer": "Viewer", "operator": "Operator", "admin": "Admin"}[need]) in r.json()["detail"]["message"]


def test_denied_attempts_are_audited_with_code_actor_and_requirement(world):
    world.viewer.post("/api/runs", json={}, headers=H)
    world.op.put("/api/settings", json={"replay_n": 2}, headers=H)
    rows = world.admin.get("/api/audit?code=ACCESS_DENIED").json()
    got = {(r["actor"], r["detail"]["method"], r["detail"]["path"], r["detail"]["role"], r["detail"]["needs"]) for r in rows}
    assert {("viewer1", "POST", "/api/runs", "viewer", "operator"), ("operator1", "PUT", "/api/settings", "operator", "admin")} <= got
    assert all(r["reason_category"] == "control" and r["explanation"] for r in rows)
    assert world.viewer.get("/api/audit").status_code == 403                                   # a viewer cannot read the audit log


def test_unauthenticated_gets_401_not_403(world):
    with TestClient(world.app) as anon:
        assert anon.get("/api/runs").status_code == 401 and anon.post("/api/runs", json={}, headers=H).status_code == 401


# ---------------------------------------------------------------- workflows
def test_operator_runs_tests_viewer_reads_reports_nobody_below_admin_signs(world):
    world.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Sure, here is the key {LEAK}."))
    r = world.viewer.post("/api/runs", json={"scope_id": world.sid, "endpoint_url": world.target.url, "library_id": world.lid}, headers=H)
    assert r.status_code == 403 and world.target.calls == []                                   # a viewer cannot start a test
    r = world.op.post("/api/runs", json={"scope_id": world.sid, "endpoint_url": world.target.url, "library_id": world.lid,
                                         "replay_n": 2, "replay_k": 2}, headers=H)
    assert r.status_code == 202, r.text
    run = wait(world.op, r.json()["id"])
    assert run["status"] == "completed" and run["config"]["started_by"] == "operator1" and run["findings"][0]["status"] == "verified"
    for path in (f"/api/runs/{run['id']}/report.pdf", f"/api/runs/{run['id']}/findings.csv", "/api/findings.csv", f"/api/runs/{run['id']}"):
        assert world.viewer.get(path).status_code == 200, path                                  # a viewer reads reports
    assert world.viewer.post(f"/api/runs/{run['id']}/stop", headers=H).status_code == 403
    body = scope_body(world.target)
    assert world.op.post("/api/scopes/prepare", json=body, headers=H).status_code == 403       # an operator cannot sign a scope
    assert world.op.post(f"/api/scopes/{world.sid}/revoke", headers=H).status_code == 403
    assert world.admin.get("/api/scopes").json()[0]["approved_by"] == "admin"
    with world.app.state.store.conn() as db:
        actors = {r["action"]: r["actor"] for r in db.execute(
            "SELECT action, actor FROM audit WHERE action IN ('scope.create','library.import','report.export')")}
    assert actors["scope.create"] == "admin" and actors["library.import"] == "operator1" and actors["report.export"] == "viewer1"


def test_operator_kill_switch_is_allowed_and_attributed(world):
    r = world.op.post("/api/kill", headers=H)
    assert r.status_code == 200
    assert world.admin.get("/api/audit?code=KILLED").json()[0]["actor"] == "operator1"


# ---------------------------------------------------------------- user management
def test_user_creation_validation(world):
    a = world.admin
    assert a.post("/api/users", json={"username": "operator1", "password": "new-password-1234", "role": "viewer"}, headers=H).status_code == 409
    for bad, code in ((dict(username="ab", password="long-password-1234"), 422), (dict(username="Upper.Case", password="long-password-1234"), 422),
                      (dict(username="ok.user", password="short"), 422), (dict(username="ok.user", password="long-password-1234", role="root"), 422),
                      (dict(username="../x", password="long-password-1234"), 422), (dict(username="a" * 40, password="long-password-1234"), 422)):
        assert a.post("/api/users", json=bad, headers=H).status_code == code, bad
    ok = a.post("/api/users", json={"username": "ok.user", "password": "long-password-1234", "role": "operator"}, headers=H)
    assert ok.status_code == 201
    listing = a.get("/api/users").json()
    assert {u["username"] for u in listing} == {"admin", "operator1", "viewer1", "ok.user"}
    assert all("pw_hash" not in u and "password" not in json.dumps(u) for u in listing)        # the hash is never returned


def test_last_active_admin_cannot_be_demoted_or_disabled(world):
    a = world.admin
    assert a.patch("/api/users/admin", json={"role": "operator"}, headers=H).status_code == 409
    assert a.patch("/api/users/admin", json={"active": False}, headers=H).status_code == 409
    assert a.post("/api/users", json={"username": "admin2", "password": "second-admin-12", "role": "admin"}, headers=H).status_code == 201
    assert a.patch("/api/users/admin2", json={"active": False}, headers=H).status_code == 200      # the second one can be deactivated
    assert a.patch("/api/users/admin2", json={"active": True}, headers=H).status_code == 200
    assert a.patch("/api/users/admin", json={"role": "viewer"}, headers=H).status_code == 200       # there is another admin now
    assert world.admin.get("/api/users").status_code == 403                                         # and it is no longer an admin itself
    assert a.patch("/api/users/missing", json={"active": False}, headers=H).status_code == 403


def test_role_change_takes_effect_immediately_without_relogin(world):
    op = world.op
    assert op.get("/api/audit").status_code == 200
    assert world.admin.patch("/api/users/operator1", json={"role": "viewer"}, headers=H).status_code == 200
    assert op.get("/api/audit").status_code == 403 and op.get("/api/runs").status_code == 200       # same cookie, new role
    assert world.admin.patch("/api/users/operator1", json={"role": "operator"}, headers=H).status_code == 200
    assert op.get("/api/audit").status_code == 200


def test_deactivated_user_loses_session_and_cannot_login(world):
    assert world.viewer.get("/api/runs").status_code == 200
    assert world.admin.patch("/api/users/viewer1", json={"active": False}, headers=H).status_code == 200
    assert world.viewer.get("/api/runs").status_code == 401
    with TestClient(world.app) as c:
        assert c.post("/api/auth/login", json={"username": "viewer1", "password": "viewer1-password-99"}).status_code == 401
    assert world.admin.patch("/api/users/viewer1", json={"active": True}, headers=H).status_code == 200
    with TestClient(world.app) as c:
        assert c.post("/api/auth/login", json={"username": "viewer1", "password": "viewer1-password-99"}).status_code == 200


def test_admin_password_reset_invalidates_old_sessions(world):
    assert world.op.get("/api/runs").status_code == 200
    assert world.admin.post("/api/users/operator1/password", json={"password": "short"}, headers=H).status_code == 422
    assert world.admin.post("/api/users/operator1/password", json={"password": "reset-password-77"}, headers=H).status_code == 200
    assert world.op.get("/api/runs").status_code == 401
    with TestClient(world.app) as c:
        assert c.post("/api/auth/login", json={"username": "operator1", "password": "operator1-password-99"}).status_code == 401
        assert c.post("/api/auth/login", json={"username": "operator1", "password": "reset-password-77"}).status_code == 200


def test_own_password_change_requires_current_and_drops_sessions(world):
    v = world.viewer
    assert v.post("/api/auth/password", json={"current": "wrong", "new": "new-password-12345"}, headers=H).status_code == 403
    assert v.post("/api/auth/password", json={"current": "viewer1-password-99", "new": "short"}, headers=H).status_code == 422
    assert v.post("/api/auth/password", json={"current": "viewer1-password-99", "new": "new-password-12345"}, headers=H).json()["relogin"]
    assert v.get("/api/runs").status_code == 401
    with TestClient(world.app) as c:
        assert c.post("/api/auth/login", json={"username": "viewer1", "password": "new-password-12345"}).status_code == 200


def test_user_changes_are_audited_with_actor(world):
    world.admin.patch("/api/users/viewer1", json={"role": "operator"}, headers=H)
    world.admin.post("/api/users/viewer1/password", json={"password": "another-password-12345"}, headers=H)
    with world.app.state.store.conn() as db:
        rows = db.execute("SELECT action, actor, detail_json FROM audit WHERE action LIKE 'user.%' ORDER BY seq").fetchall()
    acts = [(r["action"], r["actor"]) for r in rows]
    assert ("user.create", "bootstrap") in acts or ("user.create", "admin") in acts
    assert ("user.update", "admin") in acts and ("user.password", "admin") in acts
    assert "another-password" not in "".join(r["detail_json"] for r in rows)                          # the password is never written to the audit log
    assert world.app.state.store.audit_verify() is None


def test_status_exposes_role_for_the_ui(world):
    for role, client in world.client_by_role.items():
        st = client.get("/api/auth/status").json()
        assert st["authenticated"] and st["user"]["role"] == role and set(st["roles"]) == {"viewer", "operator", "admin"}
