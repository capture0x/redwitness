"""
Authentication + role-based access control (RBAC).

Roles (increasing privilege):  viewer < operator < admin
  viewer   : read only - dashboard, runs, findings, PDF/CSV reports, library/scope lists
  operator : viewer + start/stop tests, import libraries, read audit records, global stop
  admin    : full control - create/sign/revoke scopes, settings, user management

Principles
- Default DENY: any API path that is not in the permission table requires admin.
- The role is NOT trusted from the session token; it is read from the database on every request: a role change/deactivation takes effect immediately.
- Changing the password invalidates old sessions (the token carries the password-change time).
- Password: scrypt (salted), constant-time comparison; an unknown user and a wrong password give the same message and a similar duration.
- Session: HMAC-signed, expiring, HttpOnly + SameSite=Strict cookie. Brute force: 5 failures per (client, user) -> 5 minute lock.
- CSRF: a custom header is required on state-changing requests. Host validation is in main.py.
- Fail-closed: if there are no users and no initial password is set, the API returns 503.
REDWITNESS_ADMIN_PASSWORD only creates the 'admin' user on FIRST start (when the users table is empty).
REDWITNESS_INSECURE_NO_AUTH=1 is for local development only (everyone counts as admin; a warning is shown on the status screen).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass

COOKIE = "rl_session"
CSRF_HEADER = "x-redwitness-csrf"
MIN_PASSWORD = 12
MAX_FAILURES, LOCK_SECONDS = 5, 300
ROLES = ("viewer", "operator", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
ROLE_LABEL = {"viewer": "Viewer", "operator": "Operator", "admin": "Admin"}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


class AuthError(Exception):
    def __init__(self, status: int, message: str, reason: str = "AUTH"):
        super().__init__(message)
        self.status, self.message, self.reason = status, message, reason


@dataclass(frozen=True)
class Principal:
    username: str
    role: str

    def can(self, need: str) -> bool:
        return RANK[self.role] >= RANK[need]


# ---------------------------------------------------------------- password
def validate_password(pw: str) -> None:
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD:
        raise AuthError(422, f"The password must be at least {MIN_PASSWORD} characters.", "WEAK_PASSWORD")
    if len(pw) > 256:
        raise AuthError(422, "The password is too long.", "WEAK_PASSWORD")


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(h) // 2)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:  # noqa: BLE001
        return False


_DUMMY = hash_password("timing-equalization-password")


def validate_username(u: str) -> None:
    if not isinstance(u, str) or not USERNAME_RE.match(u):
        raise AuthError(422, "The username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-'.", "BAD_USERNAME")


# ---------------------------------------------------------------- permission table (method, path pattern) -> minimum role
_ID = r"[^/]+"
PERMISSIONS: list[tuple[frozenset, "re.Pattern", str]] = [
    (frozenset({"GET"}), re.compile(p), "viewer") for p in (
        r"/api/system", r"/api/meta", r"/api/reasons", r"/api/stats", r"/api/live", r"/api/runs", rf"/api/runs/{_ID}",
        r"/api/findings", r"/api/findings\.csv", rf"/api/findings/{_ID}/remediation", r"/api/benchmarks", rf"/api/benchmarks/{_ID}", r"/api/model-scans", rf"/api/model-scans/{_ID}", r"/api/targets", r"/api/analyses", rf"/api/analyses/{_ID}", rf"/api/runs/{_ID}/report\.pdf", rf"/api/runs/{_ID}/findings\.csv",
        r"/api/libraries", rf"/api/libraries/{_ID}", r"/api/scopes", r"/api/templates", r"/api/owasp/matrix", r"/api/frameworks", r"/api/frameworks/stats", r"/api/calibration", r"/api/defense-tests", rf"/api/defense-tests/{_ID}", r"/api/knowledge-maps", r"/api/campaigns", rf"/api/campaigns/{_ID}", r"/api/mcp-scans", rf"/api/findings/{_ID}/retests", rf"/api/runs/{_ID}/compare")
] + [
    (frozenset({"GET"}), re.compile(r"/api/audit"), "operator"),
    (frozenset({"GET"}), re.compile(r"/api/settings"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/libraries"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/libraries/import-benchmark"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/libraries/import-payloads"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/templates/import"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/owasp/scan"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/runs"), "operator"),
    (frozenset({"POST"}), re.compile(rf"/api/runs/{_ID}/stop"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/kill"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/campaigns"), "operator"),
    (frozenset({"POST"}), re.compile(rf"/api/campaigns/{_ID}/(advance|stop)"), "operator"),
    (frozenset({"POST"}), re.compile(rf"/api/findings/{_ID}/remediation"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/benchmarks"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/model-scans"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/targets"), "operator"),
    (frozenset({"PUT", "DELETE"}), re.compile(rf"/api/targets/{_ID}"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/documents/to-case"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/analyses"), "operator"),
    (frozenset({"POST"}), re.compile(rf"/api/findings/{_ID}/review"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/defense-tests"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/mcp-scans"), "operator"),
    (frozenset({"POST"}), re.compile(rf"/api/findings/{_ID}/retest"), "operator"),
    (frozenset({"POST"}), re.compile(r"/api/bias/assess"), "viewer"),         # read-only computation
    (frozenset({"POST"}), re.compile(r"/api/client-report"), "viewer"),       # export only (like report.pdf); changes nothing
    (frozenset({"POST"}), re.compile(r"/api/auth/password"), "viewer"),       # own password
]
OPEN_PATHS = ("/api/auth/login", "/api/auth/status", "/api/auth/logout")


def required_role(method: str, path: str) -> str:
    """Minimum role. 'admin' if not in the table (default deny)."""
    for methods, pat, role in PERMISSIONS:
        if method in methods and pat.fullmatch(path):
            return role
    return "admin"


# ---------------------------------------------------------------- session manager
class Auth:
    """`users`: an object (Store) providing get_user(username) -> dict|None and count_users(). create_app wires it."""

    def __init__(self, password: str | None = None, secret: bytes | None = None, ttl: int = 8 * 3600,
                 insecure: bool = False, clock=time.time, users=None):
        self.bootstrap_password = password if password and len(password) >= MIN_PASSWORD else None
        self.short_password = bool(password) and len(password) < MIN_PASSWORD
        self._secret = secret or secrets.token_bytes(32)
        self.ttl, self.insecure, self._clock, self.users = ttl, insecure, clock, users
        self._fails: dict[str, list[float]] = {}

    @classmethod
    def from_env(cls, env=os.environ) -> "Auth":
        secret = env.get("REDWITNESS_SESSION_SECRET")
        return cls(env.get("REDWITNESS_ADMIN_PASSWORD"), secret.encode() if secret else None,
                   insecure=env.get("REDWITNESS_INSECURE_NO_AUTH") == "1")

    def bind(self, users) -> None:
        self.users = users

    @property
    def configured(self) -> bool:
        return bool(self.users and self.users.count_users() > 0) or self.bootstrap_password is not None

    # -------- token
    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, b"reconloop-session-v2" + payload, hashlib.sha256).hexdigest()

    def issue(self, user: dict) -> str:
        payload = json.dumps({"u": user["username"], "pc": user["pw_changed_at"], "exp": self._clock() + self.ttl,
                              "n": secrets.token_hex(8)}).encode()
        return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + self._sign(payload)   # unpadded: the cookie is not quoted

    def principal(self, token: str | None) -> Principal | None:
        """Valid token + active user + unchanged password -> Principal. The role ALWAYS comes from the database."""
        if self.insecure:
            return Principal("dev-insecure", "admin")
        if not token or "." not in token or self.users is None:
            return None
        b64, _, sig = token.partition(".")
        try:
            payload = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            if not hmac.compare_digest(sig, self._sign(payload)):
                return None
            d = json.loads(payload)
            if d["exp"] <= self._clock():
                return None
            u = self.users.get_user(d["u"])
        except Exception:  # noqa: BLE001
            return None
        if not u or not u["active"] or u["pw_changed_at"] != d["pc"]:
            return None
        return Principal(u["username"], u["role"])

    # -------- login
    def login(self, username: str, password: str, client: str) -> tuple[str, dict]:
        if not self.configured:
            raise AuthError(503, "Authentication is not configured: set REDWITNESS_ADMIN_PASSWORD (at least 12 characters); "
                                 "the server is never run without a password.")
        key, now = f"{client}|{username}", self._clock()
        recent = [t for t in self._fails.get(key, []) if now - t < LOCK_SECONDS]
        if len(recent) >= MAX_FAILURES:
            raise AuthError(429, f"Too many failed attempts; try again in {int(LOCK_SECONDS - (now - recent[0]))} s.")
        u = self.users.get_user(username) if self.users and isinstance(username, str) else None
        ok = verify_password(password, u["pw_hash"] if u else _DUMMY) and u is not None and u["active"]
        if not ok:
            self._fails[key] = recent + [now]
            raise AuthError(401, "Incorrect username or password.")        # it must not be possible to tell whether the user exists
        self._fails.pop(key, None)
        return self.issue(u), u

    def status(self, token: str | None) -> dict:
        p = self.principal(token)
        return {"configured": self.configured or self.insecure, "insecure": self.insecure, "authenticated": p is not None,
                "user": {"username": p.username, "role": p.role} if p else None,
                "problem": ("The password must be at least 12 characters." if self.short_password and not self.configured else
                            None if self.configured or self.insecure else "REDWITNESS_ADMIN_PASSWORD is not set.")}

    # -------- request check
    def check_request(self, method: str, path: str, token: str | None, csrf: str | None) -> Principal:
        if self.insecure:
            return Principal("dev-insecure", "admin")
        if not self.configured:
            raise AuthError(503, "Authentication is not configured: set REDWITNESS_ADMIN_PASSWORD (at least 12 characters); "
                                 "the server is never run without a password.")
        p = self.principal(token)
        if p is None:
            raise AuthError(401, "Sign-in required.")
        if method not in ("GET", "HEAD", "OPTIONS") and csrf != "1":
            raise AuthError(403, "CSRF protection: the request header is missing.")
        need = required_role(method, path)
        if not p.can(need):
            raise AuthError(403, f"This action requires the “{ROLE_LABEL[need]}” role (your role: {ROLE_LABEL[p.role]}).", "ACCESS_DENIED")
        return p
