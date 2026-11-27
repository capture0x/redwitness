"""Authentication (session, lockout, CSRF, Host) - RBAC is separate: test_rbac.py."""
import pytest
from fastapi.testclient import TestClient

from fakes import FakeJudge
from llm_redteam.auth import Auth, hash_password, verify_password
from llm_redteam.signing import Keyring
from main import create_app

PW = "correct-password-123"
H = {"x-redwitness-csrf": "1"}
LOGIN = {"username": "admin", "password": PW}


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def make(fresh_db, auth):
    return create_app(fresh_db, Keyring({"k1": bytes(range(32))}, "k1"), judge_factory=lambda s: FakeJudge(), auth=auth)


def test_unconfigured_auth_fails_closed(fresh_db):
    with TestClient(make(fresh_db, Auth(None))) as c:
        r = c.get("/api/system")
        assert r.status_code == 503 and "REDWITNESS_ADMIN_PASSWORD" in r.json()["detail"]["message"]
        assert c.post("/api/auth/login", json=LOGIN).status_code == 503
        st = c.get("/api/auth/status").json()
        assert st["configured"] is False and st["authenticated"] is False and st["problem"]


def test_short_password_is_treated_as_unconfigured(fresh_db):
    with TestClient(make(fresh_db, Auth("short"))) as c:
        assert c.get("/api/system").status_code == 503
        assert "12" in c.get("/api/auth/status").json()["problem"]


def test_login_flow_and_cookie_flags(fresh_db):
    clock = Clock()
    with TestClient(make(fresh_db, Auth(PW, clock=clock))) as c:
        assert c.get("/api/system").status_code == 401
        assert c.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-xyz"}).status_code == 401
        r = c.post("/api/auth/login", json=LOGIN)
        assert r.status_code == 200 and r.json()["user"] == {"username": "admin", "role": "admin"}
        sc = r.headers["set-cookie"].lower()
        assert "httponly" in sc and "samesite=strict" in sc and "path=/" in sc and "rl_session=" in sc
        assert c.get("/api/system").status_code == 200
        st = c.get("/api/auth/status").json()
        assert st["authenticated"] is True and st["user"] == {"username": "admin", "role": "admin"}
        assert c.get("/api/system").headers["cache-control"] == "no-store"
        assert c.post("/api/auth/logout").status_code == 200
        c.cookies.clear()
        assert c.get("/api/system").status_code == 401


def test_session_expires_and_forged_tokens_are_rejected(fresh_db):
    clock = Clock()
    a = Auth(PW, ttl=60, clock=clock)
    with TestClient(make(fresh_db, a)) as c:
        c.post("/api/auth/login", json=LOGIN)
        assert c.get("/api/system").status_code == 200
        tok = c.cookies.get("rl_session")
        assert a.principal(tok).username == "admin"
        b64, _, sig = tok.partition(".")
        for forged in ("", "x", "x.y", b64 + ".", b64 + "." + "0" * 64, "A" + b64[1:] + "." + sig, sig + "." + b64):
            assert a.principal(forged) is None
        other = Auth(PW, secret=b"another-secret-key-another-secret-key")
        other.bind(a.users)
        assert other.principal(tok) is None                                  # a different server secret
        clock.t += 61
        assert c.get("/api/system").status_code == 401


def test_brute_force_lockout_is_per_user_and_recovers(fresh_db):
    clock = Clock()
    with TestClient(make(fresh_db, Auth(PW, clock=clock))) as c:
        for _ in range(5):
            assert c.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-xyz"}).status_code == 401
        r = c.post("/api/auth/login", json=LOGIN)                            # even the correct password is locked
        assert r.status_code == 429 and "try again in" in r.json()["detail"]["message"]
        assert c.post("/api/auth/login", json={"username": "someone-else", "password": "x"}).status_code == 401   # another user is not affected
        clock.t += 301
        assert c.post("/api/auth/login", json=LOGIN).status_code == 200
        with c.app.state.store.conn() as db:
            codes = [r["action"] for r in db.execute("SELECT action FROM audit WHERE action LIKE 'auth.%'")]
        assert codes.count("auth.failure") == 7 and "auth.login" in codes


def test_unknown_user_and_wrong_password_are_indistinguishable(fresh_db):
    with TestClient(make(fresh_db, Auth(PW))) as c:
        a = c.post("/api/auth/login", json={"username": "no-such-user", "password": "wrong-password-xyz"})
        b = c.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-xyz"})
        assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_csrf_header_required_for_mutations(fresh_db):
    with TestClient(make(fresh_db, Auth(PW))) as c:
        c.post("/api/auth/login", json=LOGIN)
        assert c.get("/api/settings").status_code == 200
        assert c.put("/api/settings", json={"replay_n": 4}).status_code == 403
        assert c.put("/api/settings", json={"replay_n": 4}, headers=H).status_code == 200
        assert c.post("/api/kill").status_code == 403 and c.post("/api/kill", headers=H).status_code == 200


def test_untrusted_host_is_rejected_before_authentication(fresh_db):
    with TestClient(make(fresh_db, Auth(PW))) as c:
        assert c.get("/api/system", headers={"host": "evil.example.com"}).status_code == 400
        assert c.post("/api/auth/login", json=LOGIN, headers={"host": "evil.example.com"}).status_code == 400
        assert c.get("/api/system", headers={"host": "localhost"}).status_code == 401
        c.post("/api/auth/login", json=LOGIN)
        assert c.get("/api/system", headers={"host": "localhost:3000"}).status_code == 200


def test_insecure_mode_is_explicit_and_reported(fresh_db):
    with TestClient(make(fresh_db, Auth(None, insecure=True))) as c:
        s = c.get("/api/system")
        assert s.status_code == 200 and any("OFF" in w for w in s.json()["warnings"])
        assert c.get("/api/auth/status").json()["insecure"] is True


def test_password_hashing_is_salted_and_verifies():
    h1, h2 = hash_password(PW), hash_password(PW)
    assert h1 != h2 and h1.startswith("scrypt$") and verify_password(PW, h1) and verify_password(PW, h2)
    for bad in ("", PW + "x", PW[:-1], PW.upper()):
        assert not verify_password(bad, h1)
    for broken in ("", "x", "scrypt$1$2", "md5$a$b$c$d$e"):
        assert not verify_password(PW, broken)


def test_bootstrap_password_only_creates_first_admin(fresh_db):
    with TestClient(make(fresh_db, Auth(PW))) as c:
        assert [u["username"] for u in c.app.state.store.list_users()] == ["admin"]
    with TestClient(make(fresh_db, Auth("completely-different-password-9"))) as c:           # ignored when a user already exists
        assert c.post("/api/auth/login", json={"username": "admin", "password": "completely-different-password-9"}).status_code == 401
        assert c.post("/api/auth/login", json=LOGIN).status_code == 200
