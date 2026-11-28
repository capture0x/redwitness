"""
PostgreSQL store: signed scopes, runs, attempts, findings, settings and the hash-chained audit log.
`load_verified_scope` is the HARD gate for starting a run: signature/revocation/version/duration checks, no silent fallback.
"""
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row

from . import ci as ci_mod
from . import frameworks
from . import owasp as owasp_mod
from .risk import SEVERITIES, risk_score, severity_for

from .reasons import EXPLAIN, Reason, category
from .scope import LLMScope, ScopeInputError
from .signing import Keyring, SigningError, iso, sign, verify

GENESIS = "0" * 64

SCHEMA = """
SELECT pg_advisory_xact_lock(72160001);
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, role TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')), pw_hash TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE, created_at DOUBLE PRECISION NOT NULL, last_login DOUBLE PRECISION,
  pw_changed_at DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS scopes (
  id TEXT PRIMARY KEY, lineage_id TEXT NOT NULL, version INTEGER NOT NULL, content_json TEXT NOT NULL,
  digest TEXT NOT NULL, key_id TEXT NOT NULL, signature BYTEA NOT NULL, approved_by TEXT NOT NULL,
  approved_at TEXT NOT NULL, revoked_at TEXT, created_at DOUBLE PRECISION NOT NULL, UNIQUE(lineage_id, version));
CREATE TABLE IF NOT EXISTS libraries (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE,
  description TEXT, cases INTEGER NOT NULL, content TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, endpoint_url TEXT NOT NULL, config_json TEXT NOT NULL,
  status TEXT NOT NULL, stop_reason TEXT, created_at DOUBLE PRECISION NOT NULL, finished_at DOUBLE PRECISION,
  tokens_used BIGINT NOT NULL DEFAULT 0, requests INTEGER NOT NULL DEFAULT 0,
  conversations INTEGER NOT NULL DEFAULT 0, snapshot_json TEXT);
CREATE TABLE IF NOT EXISTS attempts (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, seq INTEGER NOT NULL, case_id TEXT NOT NULL, category TEXT NOT NULL,
  conversation_id TEXT NOT NULL, turn INTEGER NOT NULL, prompt TEXT NOT NULL, response TEXT, tool_calls_json TEXT,
  outcome TEXT NOT NULL, evaluation_json TEXT, blocked_reason TEXT, tokens INTEGER NOT NULL DEFAULT 0,
  is_replay INTEGER NOT NULL DEFAULT 0, created_at DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS attempts_run ON attempts(run_id, seq);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, case_id TEXT NOT NULL, category TEXT NOT NULL, status TEXT NOT NULL,
  title TEXT NOT NULL, evidence_json TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
ALTER TABLE attempts ADD COLUMN IF NOT EXISTS owasp_category TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owasp_category TEXT;
ALTER TABLE attempts ADD COLUMN IF NOT EXISTS tags_json TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tags_json TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS system_status TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_json TEXT;
CREATE TABLE IF NOT EXISTS finding_reviews (
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, verdict TEXT NOT NULL, note TEXT NOT NULL, reviewer TEXT NOT NULL, at DOUBLE PRECISION NOT NULL,
  system_status TEXT NOT NULL, snapshot_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS finding_reviews_f ON finding_reviews(finding_id, at);
CREATE INDEX IF NOT EXISTS attempts_owasp ON attempts(owasp_category, run_id);
CREATE INDEX IF NOT EXISTS findings_owasp ON findings(owasp_category);
CREATE TABLE IF NOT EXISTS defense_tests (
  id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, library_id TEXT NOT NULL, off_run_id TEXT NOT NULL, on_run_id TEXT NOT NULL,
  config_json TEXT NOT NULL, created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  seq BIGSERIAL PRIMARY KEY, at TEXT NOT NULL, run_id TEXT, actor TEXT NOT NULL,
  action TEXT NOT NULL, reason_code TEXT, reason_category TEXT, detail_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_steps (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, seq INTEGER NOT NULL, case_id TEXT NOT NULL, round INTEGER NOT NULL,
  state TEXT NOT NULL, detail_json TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS agent_steps_run ON agent_steps(run_id, seq);
CREATE TABLE IF NOT EXISTS knowledge_maps (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, case_id TEXT NOT NULL, category TEXT NOT NULL, tree_json TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS knowledge_maps_run ON knowledge_maps(run_id, created_at);
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, scope_id TEXT NOT NULL, endpoint_url TEXT NOT NULL, library_id TEXT NOT NULL, ladder TEXT NOT NULL,
  status TEXT NOT NULL, cooldown_seconds INTEGER NOT NULL, max_sessions INTEGER NOT NULL, patience INTEGER NOT NULL, state_json TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, updated_at DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS campaigns_created ON campaigns(created_at);
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, lineage_ids_json TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL,
  revoked_at DOUBLE PRECISION, revoked_by TEXT, last_used_at DOUBLE PRECISION);
CREATE TABLE IF NOT EXISTS ci_jobs (
  job_id TEXT PRIMARY KEY, token_id TEXT NOT NULL, run_id TEXT NOT NULL, label TEXT, fail_on TEXT, created_at DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS remediations (
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, kind TEXT NOT NULL, model TEXT NOT NULL, created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
  input_sha256 TEXT NOT NULL, tokens INTEGER NOT NULL, result_json TEXT NOT NULL, had_system_prompt BOOLEAN NOT NULL DEFAULT FALSE);
CREATE INDEX IF NOT EXISTS remediations_finding ON remediations(finding_id, created_at);
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, provider TEXT NOT NULL, base_url TEXT NOT NULL, request_url TEXT NOT NULL, model TEXT NOT NULL,
  api_key_env TEXT, local BOOLEAN NOT NULL DEFAULT FALSE, ingest_url TEXT, ingest_delete_url TEXT, created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS auth_type TEXT NOT NULL DEFAULT 'bearer';
ALTER TABLE targets ADD COLUMN IF NOT EXISTS auth_header TEXT;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS request_template TEXT;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS response_path TEXT;
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, scope_id TEXT NOT NULL, endpoint_url TEXT NOT NULL, status TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, finished_at DOUBLE PRECISION, params_json TEXT NOT NULL, result_json TEXT);
CREATE INDEX IF NOT EXISTS analyses_created ON analyses(created_at);
CREATE TABLE IF NOT EXISTS model_scans (
  id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, size BIGINT NOT NULL, format TEXT NOT NULL, verdict TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, result_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS model_scans_created ON model_scans(created_at);
CREATE TABLE IF NOT EXISTS benchmarks (
  id TEXT PRIMARY KEY, label TEXT NOT NULL, scope_id TEXT NOT NULL, library_id TEXT NOT NULL, created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
  targets_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_reason ON audit(reason_category, reason_code);

CREATE OR REPLACE FUNCTION rl_forbid() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN RAISE EXCEPTION '% is append-only/undeletable: % is forbidden', TG_TABLE_NAME, TG_OP USING ERRCODE = 'restrict_violation'; END $f$;
CREATE OR REPLACE FUNCTION rl_scopes_guard() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
  IF OLD.revoked_at IS NOT NULL OR (to_jsonb(NEW) - 'revoked_at') <> (to_jsonb(OLD) - 'revoked_at') THEN
    RAISE EXCEPTION 'scope is immutable; create a new version' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $f$;
DROP TRIGGER IF EXISTS audit_no_update ON audit;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit FOR EACH ROW EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS audit_no_delete ON audit;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit FOR EACH ROW EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS agent_steps_no_update ON agent_steps;
CREATE TRIGGER agent_steps_no_update BEFORE UPDATE ON agent_steps FOR EACH ROW EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS agent_steps_no_delete ON agent_steps;
CREATE TRIGGER agent_steps_no_delete BEFORE DELETE ON agent_steps FOR EACH ROW EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS scopes_no_delete ON scopes;
CREATE TRIGGER scopes_no_delete BEFORE DELETE ON scopes FOR EACH ROW EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS scopes_no_truncate ON scopes;
CREATE TRIGGER scopes_no_truncate BEFORE TRUNCATE ON scopes FOR EACH STATEMENT EXECUTE FUNCTION rl_forbid();
DROP TRIGGER IF EXISTS scopes_immutable ON scopes;
CREATE TRIGGER scopes_immutable BEFORE UPDATE ON scopes FOR EACH ROW EXECUTE FUNCTION rl_scopes_guard();
"""


class ScopeGateError(Exception):
    def __init__(self, reason: Reason, message: str):
        super().__init__(message)
        self.reason, self.message = reason, message


def library_benchmarks():
    from .library import BENCHMARKS
    return BENCHMARKS


class Store:
    """PostgreSQL store. `dsn`: postgresql://user:password@host:5432/database"""

    def __init__(self, dsn: str):
        if not dsn or not str(dsn).startswith(("postgresql://", "postgres://")):
            raise ValueError("a PostgreSQL DSN is required (REDWITNESS_DATABASE_URL=postgresql://...)")
        self.dsn = str(dsn)
        with self.conn() as c, c.transaction():
            c.execute(SCHEMA)

    @contextmanager
    def conn(self):
        c = psycopg.connect(self.dsn, autocommit=True, row_factory=dict_row)
        try:
            yield c
        finally:
            c.close()

    # ------------------------------------------------------------ users (RBAC)
    def count_users(self) -> int:
        with self.conn() as c:
            return c.execute("SELECT count(*) AS n FROM users").fetchone()["n"]

    def get_user(self, username: str) -> dict | None:
        with self.conn() as c:
            return c.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()

    def list_users(self) -> list[dict]:
        with self.conn() as c:
            return c.execute("SELECT username, role, active, created_at, last_login FROM users ORDER BY created_at").fetchall()

    def create_user(self, username: str, role: str, pw_hash: str, actor: str = "system") -> None:
        now = time.time()
        with self.conn() as c:
            try:
                c.execute("INSERT INTO users (username, role, pw_hash, created_at, pw_changed_at) VALUES (%s,%s,%s,%s,%s)",
                          (username, role, pw_hash, now, now))
            except psycopg.errors.UniqueViolation:
                raise ValueError("This username already exists.") from None
        self.audit("user.create", actor=actor, detail={"username": username, "role": role})

    def _admins_left(self, c, excluding: str) -> int:
        return c.execute("SELECT count(*) AS n FROM users WHERE role='admin' AND active AND username<>%s", (excluding,)).fetchone()["n"]

    def update_user(self, username: str, *, role: str | None = None, active: bool | None = None, actor: str = "system") -> dict:
        """The last active admin can never be removed/demoted/deactivated."""
        with self.conn() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(72160004)")
            u = c.execute("SELECT * FROM users WHERE username=%s", (username,)).fetchone()
            if not u:
                raise LookupError("User not found.")
            new_role, new_active = role or u["role"], u["active"] if active is None else active
            if u["role"] == "admin" and u["active"] and (new_role != "admin" or not new_active) and self._admins_left(c, username) == 0:
                raise ValueError("The last active admin cannot be demoted or deactivated.")
            c.execute("UPDATE users SET role=%s, active=%s WHERE username=%s", (new_role, new_active, username))
        self.audit("user.update", actor=actor, detail={"username": username, "role": new_role, "active": new_active,
                                                       "was_role": u["role"], "was_active": u["active"]})
        return self.get_user(username)

    def set_password(self, username: str, pw_hash: str, actor: str = "system") -> None:
        with self.conn() as c:
            n = c.execute("UPDATE users SET pw_hash=%s, pw_changed_at=%s WHERE username=%s", (pw_hash, time.time(), username)).rowcount
        if not n:
            raise LookupError("User not found.")
        self.audit("user.password", actor=actor, detail={"username": username})

    def touch_login(self, username: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE users SET last_login=%s WHERE username=%s", (time.time(), username))

    # ------------------------------------------------------------ audit (hash-chained)
    @staticmethod
    def _row_hash(prev, at, run_id, actor, action, code, cat, detail_json) -> str:
        return hashlib.sha256("\x1f".join([prev, at, run_id or "", actor, action, code or "", cat or "",
                                           detail_json]).encode()).hexdigest()

    def audit(self, action: str, *, run_id=None, actor="system", reason: Reason | None = None, detail=None):
        detail_json = json.dumps(detail or {}, sort_keys=True, ensure_ascii=False, default=str)
        code = reason.value if reason else None
        cat = category(reason) if reason else None
        at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        with self.conn() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(72160002)")          # serialize the chain order
            row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = self._row_hash(prev, at, run_id, actor, action, code, cat, detail_json)
            c.execute("INSERT INTO audit (at, run_id, actor, action, reason_code, reason_category, detail_json,"
                      " prev_hash, hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (at, run_id, actor, action, code, cat, detail_json, prev, h))

    def audit_verify(self) -> int | None:
        """The seq of the first corrupted row; None if the chain is intact."""
        prev = GENESIS
        with self.conn() as c:
            for r in c.execute("SELECT * FROM audit ORDER BY seq"):
                if r["prev_hash"] != prev or r["hash"] != self._row_hash(
                        prev, r["at"], r["run_id"], r["actor"], r["action"], r["reason_code"],
                        r["reason_category"], r["detail_json"]):
                    return r["seq"]
                prev = r["hash"]
        return None

    def audit_list(self, category=None, code=None, run_id=None, limit=200) -> list[dict]:
        q, a = "SELECT * FROM audit WHERE reason_code IS NOT NULL", []
        for col, v in (("reason_category", category), ("reason_code", code), ("run_id", run_id)):
            if v:
                q += f" AND {col} = %s"
                a.append(v)
        with self.conn() as c:
            rows = c.execute(q + " ORDER BY seq DESC LIMIT %s", (*a, limit)).fetchall()
        out = []
        for d in rows:
            d["detail"] = json.loads(d.pop("detail_json"))
            d["explanation"] = EXPLAIN.get(Reason(d["reason_code"]), "")
            out.append(d)
        return out

    # ------------------------------------------------------------ scopes
    @staticmethod
    def _assign_version(c, scope: LLMScope):
        """Generates a lineage_id for a new scope (version 1); bumps the version within an existing lineage."""
        if not scope.lineage_id:
            scope.lineage_id = str(uuid.uuid4())
        else:
            try:
                uuid.UUID(scope.lineage_id)
            except ValueError:
                raise ScopeInputError("lineage_id must be a valid uuid") from None
        m = c.execute("SELECT max(version) AS m FROM scopes WHERE lineage_id=%s", (scope.lineage_id,)).fetchone()["m"]
        scope.version = (m or 0) + 1

    def prepare_scope(self, scope: LLMScope) -> str:
        """For the approval screen: PINS the lineage_id and version and returns the digest to be signed. Writes nothing.
        The digest shown on screen must equal the digest of the content saved with create_scope(expected_hash=...)."""
        scope.validate()
        with self.conn() as c:
            self._assign_version(c, scope)
        return scope.digest().hex()

    def create_scope(self, scope: LLMScope, approver: str, keyring: Keyring, *,
                     expected_hash: str | None = None, now: datetime | None = None) -> str:
        """Validates, signs, writes. expected_hash: the digest the approver saw on screen; if it differs, nothing is signed."""
        now = now or datetime.now(timezone.utc)
        scope.validate()
        with self.conn() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(72160003)")
            self._assign_version(c, scope)
            digest = scope.digest()
            if expected_hash is not None and digest.hex() != expected_hash.lower():
                raise ScopeInputError("the approved digest does not match the content to be saved; refresh the preview")
            try:
                key_id, sig = sign(keyring, digest, approver, now)
            except SigningError as e:
                raise ScopeInputError(f"the scope could not be signed: {e}") from None
            sid = str(uuid.uuid4())
            c.execute("INSERT INTO scopes (id, lineage_id, version, content_json, digest, key_id, signature,"
                      " approved_by, approved_at, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (sid, scope.lineage_id, scope.version, scope.canonical().decode(), digest.hex(),
                       key_id, sig, approver, iso(now), time.time()))
        self.audit("scope.create", actor=approver,
                   detail={"scope_id": sid, "lineage_id": scope.lineage_id, "version": scope.version, "digest": digest.hex()})
        return sid

    def revoke_scope(self, scope_id: str, actor: str) -> bool:
        with self.conn() as c:
            n = c.execute("UPDATE scopes SET revoked_at=%s WHERE id=%s AND revoked_at IS NULL",
                          (iso(datetime.now(timezone.utc)), scope_id)).rowcount
        if n:
            self.audit("scope.revoke", actor=actor, detail={"scope_id": scope_id})
        return bool(n)

    def load_verified_scope(self, scope_id: str, keyring: Keyring, now: datetime | None = None) -> LLMScope:
        """HARD GATE. Order: exists -> signature -> revoked -> old version -> duration. Signature first: a tampered row is never trusted."""
        now = now or datetime.now(timezone.utc)

        def fail(reason: Reason, extra: str = ""):
            raise ScopeGateError(reason, EXPLAIN[reason] + (f" ({extra})" if extra else ""))

        with self.conn() as c:
            r = c.execute("SELECT * FROM scopes WHERE id=%s", (str(scope_id),)).fetchone()
            if r is None:
                fail(Reason.SCOPE_NOT_FOUND)
            newest = c.execute("SELECT max(version) AS m FROM scopes WHERE lineage_id=%s", (r["lineage_id"],)).fetchone()["m"]
        try:
            content = json.loads(r["content_json"])
            scope = LLMScope.from_content(content)
            digest = scope.digest()                                    # RECOMPUTE from the row
        except Exception:  # noqa: BLE001
            fail(Reason.SCOPE_SIGNATURE_INVALID, "the content could not be read")
        if digest.hex() != r["digest"] or content["lineage_id"] != r["lineage_id"] or content["version"] != r["version"]:
            fail(Reason.SCOPE_SIGNATURE_INVALID, "the content changed after signing")
        try:
            verify(keyring, r["key_id"], bytes(r["signature"]), digest, r["approved_by"],
                   datetime.fromisoformat(r["approved_at"]))
        except (SigningError, ValueError) as e:
            fail(Reason.SCOPE_SIGNATURE_INVALID, str(e))
        if r["revoked_at"]:
            fail(Reason.SCOPE_REVOKED)
        if newest != r["version"]:
            fail(Reason.SCOPE_SUPERSEDED, f"the current version is v{newest}, this one is v{r['version']}")
        if not (scope.valid_from <= now < scope.valid_until):
            fail(Reason.SCOPE_EXPIRED, f"{iso(scope.valid_from)[:16]} - {iso(scope.valid_until)[:16]} UTC")
        return scope

    def list_scopes(self, keyring: Keyring) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM scopes ORDER BY created_at DESC").fetchall()
        out = []
        for m in rows:
            content = json.loads(m["content_json"])
            try:
                self.load_verified_scope(m["id"], keyring)
                valid, reason, msg = True, None, ""
            except ScopeGateError as e:
                valid, reason, msg = False, e.reason.value, e.message
            out.append({"id": m["id"], "lineage_id": content["lineage_id"], "name": content["name"], "client": content["client"], "version": m["version"],
                        "valid_from": content["valid_from"], "valid_until": content["valid_until"],
                        "endpoints": content["endpoints"], "attack_classes": content["attack_classes"],
                        "limits": content["limits"], "tool_abuse_attested": content["tool_abuse_attested"],
                        "adaptive_allowed": content.get("adaptive_allowed", False), "max_adaptive_rounds": content.get("max_adaptive_rounds", 3),
                        "multimodal_allowed": content.get("multimodal_allowed", False), "campaign_allowed": content.get("campaign_allowed", False),
                        "max_campaign_sessions": content.get("max_campaign_sessions", 5), "branching_allowed": content.get("branching_allowed", False),
                        "digest": m["digest"], "approved_by": m["approved_by"], "approved_at": m["approved_at"],
                        "revoked_at": m["revoked_at"], "valid": valid, "invalid_reason": reason, "invalid_message": msg})
        return out

    # ------------------------------------------------------------ libraries and settings
    def save_library(self, name, version, sha256, description, cases, content: str, actor: str = "system") -> str:
        with self.conn() as c:
            row = c.execute("SELECT id FROM libraries WHERE sha256=%s", (sha256,)).fetchone()
            if row:
                return row["id"]
            lid = str(uuid.uuid4())
            c.execute("INSERT INTO libraries VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                      (lid, name, version, sha256, description, cases, content, time.time()))
        self.audit("library.import", actor=actor, detail={"library_id": lid, "name": name, "version": version, "sha256": sha256})
        return lid

    def get_library(self, lid: str) -> dict | None:
        with self.conn() as c:
            return c.execute("SELECT * FROM libraries WHERE id=%s", (lid,)).fetchone()

    def list_libraries(self) -> list[dict]:
        with self.conn() as c:
            return c.execute("SELECT id, name, version, sha256, description, cases, created_at FROM libraries"
                             " ORDER BY created_at DESC").fetchall()

    def get_settings(self) -> dict:
        with self.conn() as c:
            return {r["key"]: json.loads(r["value_json"]) for r in c.execute("SELECT * FROM settings")}

    def set_setting(self, key: str, value, actor: str = "system"):
        with self.conn() as c:
            c.execute("INSERT INTO settings VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value_json=EXCLUDED.value_json",
                      (key, json.dumps(value)))
        self.audit("settings.update", actor=actor, detail={"key": key})

    # ------------------------------------------------------------ runs / attempts / findings
    def create_run(self, scope_id: str, endpoint_url: str, config: dict) -> str:
        rid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO runs (id, scope_id, endpoint_url, config_json, status, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                      (rid, scope_id, endpoint_url, json.dumps(config), "running", time.time()))
        return rid

    def update_run(self, rid: str, **cols):
        if cols:
            with self.conn() as c:
                c.execute(f"UPDATE runs SET {', '.join(k + '=%s' for k in cols)} WHERE id=%s", (*cols.values(), rid))

    def finish_run(self, rid: str, status: str, reason: str | None, snapshot: dict | None = None):
        self.update_run(rid, status=status, stop_reason=reason, finished_at=time.time(),
                        snapshot_json=json.dumps(snapshot or {}))

    def add_attempt(self, run_id: str, **f) -> str:
        aid = str(uuid.uuid4())
        with self.conn() as c:
            seq = c.execute("SELECT coalesce(max(seq),0)+1 AS s FROM attempts WHERE run_id=%s", (run_id,)).fetchone()["s"]
            c.execute("INSERT INTO attempts (id, run_id, seq, case_id, category, conversation_id, turn, prompt, response,"
                      " tool_calls_json, outcome, evaluation_json, blocked_reason, tokens, is_replay, created_at, owasp_category, tags_json)"
                      " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (aid, run_id, seq, f["case_id"], f["category"], f["conversation_id"], f.get("turn", 0), f["prompt"],
                       f.get("response"), json.dumps(f.get("tool_calls") or []), f["outcome"],
                       json.dumps(f["evaluation"]) if f.get("evaluation") else None, f.get("blocked_reason"),
                       f.get("tokens", 0), int(f.get("is_replay", False)), time.time(), f.get("owasp_category"),
                       json.dumps(f["tags"]) if f.get("tags") else None))
        return aid

    def add_agent_step(self, run_id: str, case_id: str, round_: int, state: str, detail: dict | None = None) -> None:
        """Append-only trace of the Attacker agent's state machine (the data behind the attack-tree view)."""
        with self.conn() as c:
            seq = c.execute("SELECT coalesce(max(seq),0)+1 AS s FROM agent_steps WHERE run_id=%s", (run_id,)).fetchone()["s"]
            c.execute("INSERT INTO agent_steps (id, run_id, seq, case_id, round, state, detail_json, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                      (str(uuid.uuid4()), run_id, seq, case_id, round_, state, json.dumps(detail or {}, ensure_ascii=False), time.time()))

    # ------------------------------------------------------------ knowledge maps (exploration results)
    def add_knowledge_map(self, run_id: str, case_id: str, category: str, tree: dict) -> str:
        mid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO knowledge_maps (id, run_id, case_id, category, tree_json, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                      (mid, run_id, case_id, category, json.dumps(tree, ensure_ascii=False), time.time()))
        return mid

    def list_knowledge_maps(self, run_id: str | None = None, limit: int = 50) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT k.*, r.scope_id, r.endpoint_url FROM knowledge_maps k LEFT JOIN runs r ON r.id=k.run_id"
                             + (" WHERE k.run_id=%s" if run_id else "") + " ORDER BY k.created_at DESC LIMIT %s",
                             (run_id, limit) if run_id else (limit,)).fetchall()
        return [{"id": r["id"], "run_id": r["run_id"], "case_id": r["case_id"], "category": r["category"], "endpoint_url": r.get("endpoint_url"),
                 "created_at": r["created_at"], "tree": json.loads(r["tree_json"])} for r in rows]

    # ------------------------------------------------------------ multi-session campaigns
    def add_campaign(self, name, scope_id, endpoint_url, library_id, ladder, cooldown, max_sessions, patience, state: dict, actor: str) -> dict:
        cid, now = str(uuid.uuid4()), time.time()
        with self.conn() as c:
            c.execute("INSERT INTO campaigns (id, name, scope_id, endpoint_url, library_id, ladder, status, cooldown_seconds, max_sessions, patience, state_json, created_by, created_at, updated_at)"
                      " VALUES (%s,%s,%s,%s,%s,%s,'active',%s,%s,%s,%s,%s,%s,%s)",
                      (cid, name, scope_id, endpoint_url, library_id, ladder, cooldown, max_sessions, patience, json.dumps(state), actor, now, now))
        self.audit("campaign.create", actor=actor, detail={"campaign": cid, "ladder": ladder, "max_sessions": max_sessions, "cooldown_seconds": cooldown})
        return self.get_campaign(cid)

    @staticmethod
    def _campaign(r: dict) -> dict:
        return {k: r[k] for k in ("id", "name", "scope_id", "endpoint_url", "library_id", "ladder", "status", "cooldown_seconds", "max_sessions", "patience", "created_by", "created_at", "updated_at")} \
            | {"state": json.loads(r["state_json"])}

    def get_campaign(self, cid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM campaigns WHERE id=%s", (cid,)).fetchone()
        return self._campaign(r) if r else None

    def list_campaigns(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
        return [self._campaign(r) for r in rows]

    def save_campaign(self, cid: str, state: dict, status: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE campaigns SET state_json=%s, status=%s, updated_at=%s WHERE id=%s", (json.dumps(state), status, time.time(), cid))

    # ------------------------------------------------------------ defense efficacy tests (two linked runs)
    def create_defense_test(self, scope_id: str, library_id: str, off_run_id: str, on_run_id: str, config: dict, by: str) -> str:
        did = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO defense_tests (id, scope_id, library_id, off_run_id, on_run_id, config_json, created_by, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                      (did, scope_id, library_id, off_run_id, on_run_id, json.dumps(config), by, time.time()))
        self.audit("defense.create", actor=by, detail={"defense_test_id": did, "off_run_id": off_run_id, "on_run_id": on_run_id})
        return did

    def get_defense_test(self, did: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM defense_tests WHERE id=%s", (did,)).fetchone()
        return r | {"config": json.loads(r["config_json"])} if r else None

    def list_defense_tests(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM defense_tests ORDER BY created_at DESC").fetchall()
        return [r | {"config": json.loads(r["config_json"])} for r in rows]

    def run_attempt_rows(self, run_id: str) -> list[dict]:
        with self.conn() as c:
            return c.execute("SELECT case_id, category, outcome, is_replay FROM attempts WHERE run_id=%s", (run_id,)).fetchall()

    def agent_steps(self, run_id: str, case_id: str | None = None) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT seq, case_id, round, state, detail_json, created_at FROM agent_steps WHERE run_id=%s"
                             + (" AND case_id=%s" if case_id else "") + " ORDER BY seq", (run_id, case_id) if case_id else (run_id,)).fetchall()
        return [{"seq": r["seq"], "case_id": r["case_id"], "round": r["round"], "state": r["state"],
                 "detail": json.loads(r["detail_json"]), "at": r["created_at"]} for r in rows]

    # ------------------------------------------------------------ CI tokens and jobs
    def create_token(self, name: str, lineage_ids: list[str], created_by: str, ttl_days: int) -> tuple[dict, str]:
        plain, h, prefix = ci_mod.new_token()
        tid, now = str(uuid.uuid4()), time.time()
        with self.conn() as c:
            c.execute("INSERT INTO api_tokens (id, name, token_hash, prefix, lineage_ids_json, created_by, created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                      (tid, name, h, prefix, json.dumps(sorted(set(lineage_ids))), created_by, now, now + ttl_days * 86400))
        self.audit("ci_token.create", actor=created_by, detail={"token_id": tid, "name": name, "prefix": prefix, "lineages": sorted(set(lineage_ids)), "ttl_days": ttl_days})
        return self._token_view(self._token_row(tid)), plain

    def _token_row(self, tid: str) -> dict:
        with self.conn() as c:
            return c.execute("SELECT * FROM api_tokens WHERE id=%s", (tid,)).fetchone()

    @staticmethod
    def _token_view(r: dict) -> dict:
        now = time.time()
        return {"id": r["id"], "name": r["name"], "prefix": r["prefix"], "lineage_ids": json.loads(r["lineage_ids_json"]), "created_by": r["created_by"],
                "created_at": r["created_at"], "expires_at": r["expires_at"], "revoked_at": r["revoked_at"], "last_used_at": r["last_used_at"],
                "status": "revoked" if r["revoked_at"] else "expired" if r["expires_at"] <= now else "active"}

    def list_tokens(self) -> list[dict]:
        with self.conn() as c:
            return [self._token_view(r) for r in c.execute("SELECT * FROM api_tokens ORDER BY created_at DESC").fetchall()]

    def revoke_token(self, tid: str, by: str) -> bool:
        with self.conn() as c:
            r = c.execute("UPDATE api_tokens SET revoked_at=%s, revoked_by=%s WHERE id=%s AND revoked_at IS NULL RETURNING id", (time.time(), by, tid)).fetchone()
        if r:
            self.audit("ci_token.revoke", actor=by, detail={"token_id": tid})
        return bool(r)

    def resolve_token(self, plain: str) -> dict | None:
        """The token row when it exists, is not revoked and not expired (and records the use); otherwise None."""
        with self.conn() as c:
            r = c.execute("SELECT * FROM api_tokens WHERE token_hash=%s", (ci_mod.hash_token(plain),)).fetchone()
            if not r or r["revoked_at"] is not None or r["expires_at"] <= time.time():
                return None
            c.execute("UPDATE api_tokens SET last_used_at=%s WHERE id=%s", (time.time(), r["id"]))
        return self._token_view(r)

    def list_scope_lineages(self) -> list[dict]:
        with self.conn() as c:
            return c.execute("SELECT DISTINCT lineage_id FROM scopes").fetchall()

    def scope_lineage(self, scope_id: str) -> str | None:
        with self.conn() as c:
            r = c.execute("SELECT lineage_id FROM scopes WHERE id=%s", (scope_id,)).fetchone()
        return r["lineage_id"] if r else None

    def add_ci_job(self, token_id: str, run_id: str, label: str, fail_on: str | None) -> str:
        jid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO ci_jobs (job_id, token_id, run_id, label, fail_on, created_at) VALUES (%s,%s,%s,%s,%s,%s)", (jid, token_id, run_id, label, fail_on, time.time()))
        return jid

    def get_ci_job(self, job_id: str, token_id: str) -> dict | None:
        with self.conn() as c:
            return c.execute("SELECT * FROM ci_jobs WHERE job_id=%s AND token_id=%s", (job_id, token_id)).fetchone()

    def count_running_ci_jobs(self, token_id: str) -> int:
        with self.conn() as c:
            return c.execute("SELECT count(*) AS n FROM ci_jobs j JOIN runs r ON r.id=j.run_id WHERE j.token_id=%s AND r.status='running'", (token_id,)).fetchone()["n"]

    def add_finding(self, run_id: str, case_id: str, category_: str, status: str, title: str, evidence: dict,
                    owasp_category: str | None = None, tags: dict | None = None) -> str:
        fid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO findings (id, run_id, case_id, category, status, title, evidence_json, created_at, owasp_category, tags_json, system_status)"
                      " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (fid, run_id, case_id, category_, status, title, json.dumps(evidence, ensure_ascii=False), time.time(), owasp_category,
                       json.dumps(tags) if tags else None, status))
        self.audit("finding.create", run_id=run_id, detail={"finding_id": fid, "status": status, "case_id": case_id})
        return fid

    @staticmethod
    def _finding(r: dict) -> dict:
        ev = json.loads(r.pop("evidence_json"))
        tags = json.loads(r.pop("tags_json", None) or "{}")
        review = json.loads(r.pop("review_json", None) or "null")
        system_status = r.pop("system_status", None) or r["status"]
        fw = frameworks.resolve(owasp=r.get("owasp_category"), attack_class=r["category"], asi=tags.get("asi"), aisvs=tags.get("aisvs"), family=tags.get("family"))
        return r | {"evidence": ev, "severity": severity_for(r["category"], (ev.get("case") or {}).get("severity")),
                    "frameworks": fw, "benchmark": tags.get("benchmark"), "system_status": system_status, "review": review,
                    "impact": ev.get("impact"), "verifier": ev.get("verifier"), "sandbox": ev.get("sandbox"),
                    "reasoning": ev.get("reasoning")}

    def review_finding(self, fid: str, verdict: str, note: str, reviewer: str) -> dict | None:
        """Human review: true_positive | false_positive | clear. The finding's status follows the human (the system's own decision stays in
        `system_status` and in the review history, which is what calibration measures)."""
        with self.conn() as c:
            r = c.execute("SELECT * FROM findings WHERE id=%s FOR UPDATE", (fid,)).fetchone()
            if not r:
                return None
            sys_status = r["system_status"] or r["status"]
            ev = json.loads(r["evidence_json"])
            if verdict == "clear":
                new_status, review = sys_status, None
            else:
                new_status = "verified" if verdict == "true_positive" else "false_positive"
                e = ev.get("evaluation") or {}
                snap = {"judge_verdict": e.get("verdict"), "judge_confidence": e.get("confidence"), "impact": (ev.get("impact") or {}).get("impact"),
                        "verifier": (ev.get("verifier") or {}).get("outcome"), "category": r["category"], "case_id": r["case_id"], "model": ev.get("model")}
                review = {"verdict": verdict, "note": note[:1000], "reviewer": reviewer, "at": time.time(), "system_status": sys_status}
                c.execute("INSERT INTO finding_reviews (id, finding_id, verdict, note, reviewer, at, system_status, snapshot_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                          (str(uuid.uuid4()), fid, verdict, note[:1000], reviewer, review["at"], sys_status, json.dumps(snap)))
            c.execute("UPDATE findings SET status=%s, system_status=%s, review_json=%s WHERE id=%s",
                      (new_status, sys_status, json.dumps(review) if review else None, fid))
        self.audit("finding.review", actor=reviewer, detail={"finding_id": fid, "verdict": verdict, "system_status": sys_status, "status": new_status})
        return self.get_finding(fid)

    def review_rows(self) -> list[dict]:
        """The latest human label per finding, with what the system had decided and the judge's confidence at the time."""
        with self.conn() as c:
            rows = c.execute("""SELECT DISTINCT ON (finding_id) finding_id, verdict, system_status, at, snapshot_json
                                 FROM finding_reviews ORDER BY finding_id, at DESC""").fetchall()
        out = []
        for r in rows:
            f = self.get_finding(r["finding_id"])
            if f and f.get("review"):                      # a cleared review is not a label
                out.append({"finding_id": r["finding_id"], "human": r["verdict"], "system_status": r["system_status"], "at": r["at"], **json.loads(r["snapshot_json"])})
        return out

    def get_finding(self, fid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM findings WHERE id=%s", (fid,)).fetchone()
        return self._finding(r) if r else None

    def add_remediation(self, finding_id: str, kind: str, model: str, by: str, input_sha: str, tokens: int, result: dict, had_system_prompt: bool) -> dict:
        rid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO remediations (id, finding_id, kind, model, created_by, created_at, input_sha256, tokens, result_json, had_system_prompt)"
                      " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (rid, finding_id, kind, model, by, time.time(), input_sha, tokens, json.dumps(result, ensure_ascii=False), had_system_prompt))
        self.audit("remediation.generate", actor=by, detail={"remediation_id": rid, "finding_id": finding_id, "model": model, "kind": kind, "tokens": tokens,
                                                              "input_sha256": input_sha, "had_system_prompt": had_system_prompt})
        return self.latest_remediation(finding_id)

    def latest_remediation(self, finding_id: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM remediations WHERE finding_id=%s ORDER BY created_at DESC LIMIT 1", (finding_id,)).fetchone()
        return None if not r else {"id": r["id"], "finding_id": finding_id, "kind": r["kind"], "model": r["model"], "created_by": r["created_by"], "created_at": r["created_at"],
                                   "tokens": r["tokens"], "had_system_prompt": r["had_system_prompt"], "result": json.loads(r["result_json"])}

    # ------------------------------------------------------------ saved targets (connection details only; the API key is never stored)
    def add_target(self, t: dict, local: bool, by: str, key_set: bool) -> dict:
        tid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO targets (id, name, provider, base_url, request_url, model, api_key_env, local, ingest_url, ingest_delete_url, created_by, created_at, auth_type, auth_header, request_template, response_path)"
                      " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (tid, t["name"], t["provider"], t["base_url"], t["request_url"], t["model"], t["api_key_env"], local, t["ingest_url"], t["ingest_delete_url"], by, time.time(),
                       t["auth_type"], t["auth_header"], t.get("request_template"), t.get("response_path")))
        self.audit("target.create", actor=by, detail={"target_id": tid, "name": t["name"], "request_url": t["request_url"], "provider": t["provider"], "auth_type": t["auth_type"], "key_set": key_set})
        return self.get_target(tid)

    def update_target(self, tid: str, t: dict, local: bool, by: str, key_changed: bool) -> dict | None:
        with self.conn() as c:
            n = c.execute("UPDATE targets SET name=%s, provider=%s, base_url=%s, request_url=%s, model=%s, api_key_env=%s, local=%s, ingest_url=%s, ingest_delete_url=%s, auth_type=%s, auth_header=%s, request_template=%s, response_path=%s WHERE id=%s",
                          (t["name"], t["provider"], t["base_url"], t["request_url"], t["model"], t["api_key_env"], local, t["ingest_url"], t["ingest_delete_url"], t["auth_type"], t["auth_header"],
                           t.get("request_template"), t.get("response_path"), tid)).rowcount
        if not n:
            return None
        self.audit("target.update", actor=by, detail={"target_id": tid, "name": t["name"], "request_url": t["request_url"], "key_changed": key_changed})
        return self.get_target(tid)

    def delete_target(self, tid: str, by: str) -> bool:
        with self.conn() as c:
            row = c.execute("DELETE FROM targets WHERE id=%s RETURNING name, request_url", (tid,)).fetchone()
        if row:
            self.audit("target.delete", actor=by, detail={"target_id": tid, "name": row["name"], "request_url": row["request_url"]})
        return bool(row)

    def get_target(self, tid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM targets WHERE id=%s", (tid,)).fetchone()
        return dict(r) if r else None

    def list_targets(self) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()]

    # ------------------------------------------------------------ privacy / extraction / vector store analyses (results hold no prompts, responses or record text)
    def create_analysis(self, kind: str, scope_id: str, endpoint_url: str, by: str, params: dict) -> str:
        aid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO analyses (id, kind, scope_id, endpoint_url, status, created_by, created_at, params_json) VALUES (%s,%s,%s,%s,'running',%s,%s,%s)",
                      (aid, kind, scope_id, endpoint_url, by, time.time(), json.dumps(params, ensure_ascii=False)))
        self.audit("analysis.start", actor=by, run_id=aid, detail={"kind": kind, "scope_id": scope_id, "endpoint": endpoint_url, "params": params})
        return aid

    def finish_analysis(self, aid: str, status: str, result: dict) -> None:
        with self.conn() as c:
            c.execute("UPDATE analyses SET status=%s, finished_at=%s, result_json=%s WHERE id=%s", (status, time.time(), json.dumps(result, ensure_ascii=False), aid))
        risk = (result.get("risk") or {}).get("level")
        self.audit("analysis.finish", run_id=aid, detail={"status": status, "risk": risk, "stopped_reason": result.get("stopped_reason")})

    def get_analysis(self, aid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM analyses WHERE id=%s", (aid,)).fetchone()
        return None if not r else self._analysis(r, full=True)

    def list_analyses(self, kind: str | None = None, limit: int = 100) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM analyses WHERE (%s::text IS NULL OR kind=%s) ORDER BY created_at DESC LIMIT %s", (kind, kind, limit)).fetchall()
        return [self._analysis(r, full=False) for r in rows]

    @staticmethod
    def _analysis(r, full: bool) -> dict:
        res = json.loads(r["result_json"]) if r["result_json"] else None
        d = {"id": r["id"], "kind": r["kind"], "scope_id": r["scope_id"], "endpoint_url": r["endpoint_url"], "status": r["status"], "created_by": r["created_by"],
             "created_at": r["created_at"], "finished_at": r["finished_at"], "params": json.loads(r["params_json"]),
             "risk": ((res or {}).get("risk") or {}).get("level")}           # a failed or interrupted analysis stores risk = None
        if full:
            d["result"] = res
        return d

    # ------------------------------------------------------------ model file scans (static supply-chain analysis; the file itself is never stored)
    def add_model_scan(self, result: dict, by: str) -> dict:
        sid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO model_scans (id, filename, sha256, size, format, verdict, created_by, created_at, result_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (sid, result["filename"], result["sha256"], result["size"], result["format"], result["verdict"], by, time.time(), json.dumps(result, ensure_ascii=False)))
        self.audit("model_scan.create", actor=by, detail={"scan_id": sid, "filename": result["filename"], "sha256": result["sha256"], "format": result["format"], "verdict": result["verdict"]})
        return self.get_model_scan(sid)

    def get_model_scan(self, sid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM model_scans WHERE id=%s", (sid,)).fetchone()
        return None if not r else {"id": r["id"], "created_by": r["created_by"], "created_at": r["created_at"], **json.loads(r["result_json"])}

    def list_model_scans(self, limit: int = 100) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT id, filename, sha256, size, format, verdict, created_by, created_at FROM model_scans ORDER BY created_at DESC LIMIT %s", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ model benchmarking (several targets, one test set)
    def add_benchmark(self, label: str, scope_id: str, library_id: str, by: str, targets: list[dict]) -> str:
        bid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO benchmarks (id, label, scope_id, library_id, created_by, created_at, targets_json) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                      (bid, label, scope_id, library_id, by, time.time(), json.dumps(targets)))
        self.audit("benchmark.start", actor=by, detail={"benchmark_id": bid, "label": label, "scope_id": scope_id, "library_id": library_id, "targets": [t["endpoint_url"] for t in targets]})
        return bid

    def list_benchmarks(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM benchmarks ORDER BY created_at DESC").fetchall()
        return [{"id": r["id"], "label": r["label"], "created_at": r["created_at"], "created_by": r["created_by"], "targets": len(json.loads(r["targets_json"]))} for r in rows]

    def benchmark_result(self, bid: str) -> dict | None:
        """Per target and per OWASP category: evaluated tests (first conversations only, replays excluded), violations and verified findings."""
        with self.conn() as c:
            b = c.execute("SELECT * FROM benchmarks WHERE id=%s", (bid,)).fetchone()
        if not b:
            return None
        targets = []
        for t in json.loads(b["targets_json"]):
            run = self.get_run(t["run_id"])
            cats: dict[str, dict] = {}
            cases = set()
            for a in run["attempts"]:
                if a["is_replay"] or not a["outcome"].startswith("judged:"):
                    continue
                cid = a["owasp_category"] or "unclassified"
                d = cats.setdefault(cid, {"tested": 0, "violations": 0, "verified": 0})
                d["tested"] += 1
                d["violations"] += a["outcome"] == "judged:violation"
                cases.add(a["case_id"])
            for f in run["findings"]:
                if f["status"] == "verified":
                    cats.setdefault(f["owasp_category"] or "unclassified", {"tested": 0, "violations": 0, "verified": 0})["verified"] += 1
            for d in cats.values():
                d["fail_rate"] = round(d["violations"] / d["tested"], 4) if d["tested"] else None
            tested, viol = sum(d["tested"] for d in cats.values()), sum(d["violations"] for d in cats.values())
            targets.append({"endpoint_url": t["endpoint_url"], "model": t["model"], "run_id": t["run_id"], "status": run["status"], "stop_reason": run["stop_reason"],
                            "tokens": run["tokens_used"], "requests": run["requests"], "tested": tested, "violations": viol,
                            "verified": sum(d["verified"] for d in cats.values()), "fail_rate": round(viol / tested, 4) if tested else None,
                            "categories": cats, "case_ids": sorted(cases)})
        running = any(t["status"] == "running" for t in targets)
        same_cases = len({tuple(t["case_ids"]) for t in targets}) == 1
        complete = all(t["status"] == "completed" and t["tested"] > 0 for t in targets)       # a target that answered nothing is not "complete"
        order = sorted(range(len(targets)), key=lambda i: (targets[i]["verified"], targets[i]["fail_rate"] if targets[i]["fail_rate"] is not None else 2, targets[i]["tokens"]))
        for rank, i in enumerate(order, 1):
            targets[i]["rank"] = rank
        for t in targets:
            t.pop("case_ids")
        cat_ids = [c["id"] for c in owasp_mod.CATEGORIES if any(c["id"] in t["categories"] for t in targets)]
        return {"id": b["id"], "label": b["label"], "created_at": b["created_at"], "created_by": b["created_by"], "scope_id": b["scope_id"], "library_id": b["library_id"],
                "status": "running" if running else "completed" if complete else "partial", "comparable": same_cases and complete,
                "categories": cat_ids, "targets": targets}

    def get_run(self, rid: str) -> dict | None:
        with self.conn() as c:
            run = c.execute("SELECT * FROM runs WHERE id=%s", (rid,)).fetchone()
            if run is None:
                return None
            run["config"] = json.loads(run.pop("config_json"))
            run["snapshot"] = json.loads(run.pop("snapshot_json") or "{}")
            run["attempts"] = [a | {"tool_calls": json.loads(a["tool_calls_json"] or "[]"),
                                    "evaluation": json.loads(a["evaluation_json"]) if a["evaluation_json"] else None}
                               for a in c.execute("SELECT * FROM attempts WHERE run_id=%s ORDER BY seq", (rid,))]
            run["findings"] = [self._finding(f) for f in c.execute(
                "SELECT * FROM findings WHERE run_id=%s ORDER BY created_at", (rid,))]
        return run

    def list_runs(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("""SELECT r.*, (SELECT count(*) FROM findings f WHERE f.run_id=r.id AND f.status='verified') AS verified,
                (SELECT count(*) FROM findings f WHERE f.run_id=r.id) AS findings FROM runs r ORDER BY created_at DESC""").fetchall()
        return [r | {"config": json.loads(r["config_json"])} for r in rows]

    def list_findings(self, status=None, category_=None, run_id=None, owasp=None) -> list[dict]:
        q, a = "SELECT * FROM findings WHERE TRUE", []
        owasp = owasp_mod.normalize(owasp) if owasp else None
        for col, v in (("status", status), ("category", category_), ("run_id", run_id), ("owasp_category", owasp)):
            if v:
                q += f" AND {col}=%s"
                a.append(v)
        with self.conn() as c:
            rows = c.execute(q + " ORDER BY created_at DESC", a).fetchall()
        return [self._finding(r) for r in rows]

    # ------------------------------------------------------------ frameworks: ASI / ATLAS / NIST AI RMF / AISVS / benchmark ASR
    def _framework_runs(self, endpoint: str | None, run_id: str | None) -> list[str]:
        with self.conn() as c:
            if run_id:
                return [r["id"] for r in c.execute("SELECT id FROM runs WHERE id=%s", (run_id,))]
            q, a = "SELECT DISTINCT ON (endpoint_url) id FROM runs", []
            if endpoint:
                q, a = q + " WHERE endpoint_url=%s", [endpoint]
            return [r["id"] for r in c.execute(q + " ORDER BY endpoint_url, created_at DESC", a)]

    def framework_stats(self, endpoint: str | None = None, run_id: str | None = None) -> dict:
        """Per framework area (ASI / NIST AI RMF / AISVS / ATLAS / benchmark ASR) for the LATEST run per endpoint, or for one run."""
        runs = self._framework_runs(endpoint, run_id)
        atts, fnds = [], []
        if runs:
            with self.conn() as c:
                atts = c.execute("SELECT category, owasp_category, outcome, tags_json, is_replay FROM attempts WHERE run_id = ANY(%s)", (runs,)).fetchall()
                fnds = c.execute("SELECT category, owasp_category, status, tags_json FROM findings WHERE run_id = ANY(%s)", (runs,)).fetchall()
        return {"runs": runs, **frameworks.stats(atts, fnds, library_benchmarks())}

    # ------------------------------------------------------------ OWASP LLM Top 10 compliance matrix
    STATUS_ORDER = ("vulnerable", "review", "testing", "clean", "not_tested")

    def owasp_endpoints(self) -> list[str]:
        with self.conn() as c:
            return [r["endpoint_url"] for r in c.execute("SELECT DISTINCT endpoint_url FROM runs ORDER BY endpoint_url")]

    def owasp_matrix(self, endpoint: str | None = None) -> dict:
        """
        For each category, (optionally) per endpoint, the status according to the LATEST run THAT COVERS THAT CATEGORY:
          testing    : a run covering the category is running right now
          not_tested : there is no evaluated (first, non-replay) attempt for the category
          vulnerable : that run has a verified finding
          review     : there is an unverified finding (candidate/unstable/review) or an inconclusive evaluation
          clean      : the evaluations only say 'no violation'
        Score = clean / (number of tested categories). NOT a certificate; coverage (tested/10) is shown alongside.
        """
        ep_sql, ep_args = ("AND r.endpoint_url = %s", [endpoint]) if endpoint else ("", [])
        out = []
        with self.conn() as c:
            for cat in owasp_mod.CATEGORIES:
                cid = cat["id"]
                running = c.execute(
                    "SELECT r.id FROM runs r WHERE r.status='running' " + ep_sql + " AND (r.config_json::jsonb -> 'owasp_planned') ? %s LIMIT 1",
                    (*ep_args, cid)).fetchone()
                last = c.execute(
                    "SELECT r.id, r.created_at, r.endpoint_url FROM runs r JOIN attempts a ON a.run_id = r.id "
                    "WHERE a.owasp_category = %s AND a.is_replay = 0 AND a.outcome LIKE 'judged:%%' " + ep_sql +
                    " ORDER BY r.created_at DESC LIMIT 1", (cid, *ep_args)).fetchone()
                counts = {"clean": 0, "violation": 0, "inconclusive": 0, "verified": 0, "review": 0}
                if last:
                    for r in c.execute("SELECT outcome, count(*) AS n FROM attempts WHERE run_id=%s AND owasp_category=%s AND is_replay=0 "
                                       "AND outcome LIKE 'judged:%%' GROUP BY outcome", (last["id"], cid)):
                        counts[{"judged:no_violation": "clean", "judged:violation": "violation", "judged:inconclusive": "inconclusive"}[r["outcome"]]] = r["n"]
                    for r in c.execute("SELECT status, count(*) AS n FROM findings WHERE run_id=%s AND owasp_category=%s GROUP BY status",
                                       (last["id"], cid)):
                        counts["verified" if r["status"] == "verified" else "review"] += r["n"]
                if running:
                    status = "testing"
                elif not last:
                    status = "not_tested"
                elif counts["verified"]:
                    status = "vulnerable"
                elif counts["review"] or counts["violation"] or counts["inconclusive"]:
                    status = "review"
                else:
                    status = "clean"
                out.append({**cat, "status": status, "counts": counts, "last_run_id": last["id"] if last else None,
                            "last_run_at": last["created_at"] if last else None, "endpoint": last["endpoint_url"] if last else None})
        tested = [x for x in out if x["status"] in ("clean", "vulnerable", "review")]
        clean = sum(1 for x in tested if x["status"] == "clean")
        return {"categories": out, "endpoint": endpoint, "tested": len(tested), "total": len(out), "clean": clean,
                "vulnerable": sum(1 for x in out if x["status"] == "vulnerable"), "review": sum(1 for x in out if x["status"] == "review"),
                "score": round(100 * clean / len(tested)) if tested else None,
                "coverage": round(100 * len(tested) / len(out)), "endpoints": self.owasp_endpoints(),
                "edition": "OWASP Top 10 for LLM Applications 2025"}

    def stats(self) -> dict:
        with self.conn() as c:
            one = lambda q: list(c.execute(q).fetchone().values())[0]  # noqa: E731
            verified = [self._finding(r) for r in c.execute("SELECT * FROM findings WHERE status='verified'")]
            by_cat: dict[str, int] = {}
            sev: dict[str, int] = {s: 0 for s in SEVERITIES}
            for f in verified:
                by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
                sev[f["severity"]] += 1
            judged = {r["outcome"]: r["n"] for r in c.execute(
                "SELECT outcome, count(*) AS n FROM attempts WHERE is_replay=0 AND outcome LIKE 'judged:%' GROUP BY outcome")}
            series = c.execute("""WITH d AS (SELECT id, tokens_used,
                        to_char(to_timestamp(created_at), 'YYYY-MM-DD') AS day FROM runs)
                    SELECT d.day AS day, coalesce(sum(d.tokens_used),0)::bigint AS tokens, count(*)::int AS runs,
                        (SELECT count(*) FROM findings f JOIN d d2 ON d2.id=f.run_id
                          WHERE f.status='verified' AND d2.day=d.day)::int AS verified,
                        (SELECT count(*) FROM attempts a JOIN d d3 ON d3.id=a.run_id
                          WHERE a.is_replay=0 AND a.outcome='judged:no_violation' AND d3.day=d.day)::int AS passed,
                        (SELECT count(*) FROM attempts a JOIN d d4 ON d4.id=a.run_id
                          WHERE a.is_replay=0 AND a.outcome='judged:violation' AND d4.day=d.day)::int AS failed
                    FROM d GROUP BY d.day ORDER BY d.day""").fetchall()
            total_judged = sum(judged.values())
            score = risk_score(sev)
            return {"runs": one("SELECT count(*) FROM runs"),
                    "attempts": one("SELECT count(*) FROM attempts WHERE is_replay=0"),
                    "tokens": int(one("SELECT coalesce(sum(tokens_used),0) FROM runs")),
                    "findings_verified": len(verified),
                    "findings_total": one("SELECT count(*) FROM findings"),
                    "verified_by_category": by_cat, "severity_counts": sev, "risk_score": score,
                    "judged": total_judged, "passed": judged.get("judged:no_violation", 0),
                    "failed": judged.get("judged:violation", 0), "inconclusive": judged.get("judged:inconclusive", 0),
                    "pass_rate": round(judged.get("judged:no_violation", 0) / total_judged, 3) if total_judged else None,
                    "timeseries": series,
                    "running": one("SELECT count(*) FROM runs WHERE status='running'")}

    def live_events(self, limit: int = 40, all_runs: bool = False) -> dict:
        """Recent attempt records for the live activity feed: of the running runs, or (when idle) of the latest run."""
        with self.conn() as c:
            running = c.execute("SELECT id FROM runs WHERE status='running' ORDER BY created_at").fetchall()
            ids = [r["id"] for r in running]
            live = bool(ids)
            if all_runs:
                ids = [r["id"] for r in c.execute("SELECT id FROM runs").fetchall()]
            elif not ids:
                last = c.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
                ids = [last["id"]] if last else []
            rows = c.execute(
                "SELECT a.run_id, a.seq, a.case_id, a.category, a.turn, a.outcome, a.blocked_reason, a.tokens, a.is_replay, a.created_at,"
                " a.evaluation_json, a.owasp_category FROM attempts a WHERE a.run_id = ANY(%s) ORDER BY a.created_at DESC, a.seq DESC LIMIT %s",
                (ids, limit)).fetchall() if ids else []
        events = []
        for r in rows:
            ev = json.loads(r["evaluation_json"]) if r["evaluation_json"] else None
            events.append({"run_id": r["run_id"], "seq": r["seq"], "at": r["created_at"], "case_id": r["case_id"], "turn": r["turn"],
                           "outcome": r["outcome"], "blocked_reason": r["blocked_reason"], "tokens": r["tokens"], "replay": bool(r["is_replay"]),
                           "verdict": (ev or {}).get("verdict"), "confidence": (ev or {}).get("confidence"),
                           "owasp": r["owasp_category"]})
        return {"live": live, "runs": len(running) if live else 0, "events": events}

    def orphan_analyses_stopped(self) -> int:
        """Closes analyses (extraction, membership, vector) left in 'running' when the server restarted; their task is gone."""
        with self.conn() as c:
            return c.execute("UPDATE analyses SET status='halted', finished_at=%s, result_json=%s WHERE status='running'",
                             (time.time(), json.dumps({"stopped_reason": "SERVER_RESTART", "risk": None}))).rowcount

    def orphan_runs_stopped(self) -> int:
        """Closes orphaned runs left in 'running' when the server restarted."""
        with self.conn() as c:
            return c.execute("UPDATE runs SET status='stopped', stop_reason='SERVER_RESTART', finished_at=%s"
                             " WHERE status='running'", (time.time(),)).rowcount
