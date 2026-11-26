"""
Sandbox runner. Runs in a container with NO network, a read-only root filesystem, no capabilities and a non-root user (see docker-compose.yml).
It talks to the backend only through a shared job directory: the backend writes in/<id>.json, the runner writes out/<id>.json. Python standard library only.

Everything in a job is untrusted model output. Nothing is ever passed to a shell or `eval`. Two analyses exist:
  html  the text is parsed (never rendered) to find what a browser would run on its own: <script>, on* handlers, javascript: URLs, srcdoc, <object>/<embed>
  sql   the statements run against a throw-away in-memory SQLite database holding decoy rows and per-job canary values; an authorizer records and
        restricts every action (no ATTACH, no PRAGMA, no extension loading, no file access)
The result states what happened; the backend decides what it means.
"""
import hashlib
import json
import os
import re
import resource
import signal
import sqlite3
import sys
import time
from html.parser import HTMLParser

JOBS = os.environ.get("RUNNER_JOBS", "/jobs")
POLL = 0.5
MAX_PAYLOAD = 20_000
JOB_SECONDS = 5
ID_RE = re.compile(r"^[0-9a-f-]{36}$")
KINDS = ("html", "sql")
ACTIVE_URL = re.compile(r"^\s*(javascript|vbscript|data\s*:\s*text/html)", re.I)


class _Html(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.effects, self._in_script = [], False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "script":
            self._in_script = True
            src = dict(attrs).get("src")
            self.effects.append({"type": "script_element", "detail": f"<script src={src[:120]!r}>" if src else "inline <script>"})
        for k, v in attrs:
            k = (k or "").lower()
            if k.startswith("on") and len(k) > 2 and v:
                self.effects.append({"type": "event_handler", "detail": f"<{t} {k}=...>"})
            elif k in ("href", "src", "action", "formaction", "data", "xlink:href") and v and ACTIVE_URL.match(v):
                self.effects.append({"type": "active_url", "detail": f"<{t} {k}={v[:80]!r}>"})
            elif k == "srcdoc" and v:
                self.effects.append({"type": "srcdoc", "detail": f"<{t} srcdoc=...>"})
        if t in ("object", "embed", "iframe") and t != "iframe":
            self.effects.append({"type": "embedded_content", "detail": f"<{t}>"})
        if t == "meta" and (dict(attrs).get("http-equiv") or "").lower() == "refresh" and ACTIVE_URL.search(dict(attrs).get("content") or ""):
            self.effects.append({"type": "active_url", "detail": "<meta refresh> to an active URL"})

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self._in_script = False


def run_html(payload: str, _canary: str) -> dict:
    p = _Html()
    p.feed(payload)
    p.close()
    seen, effects = set(), []
    for e in p.effects:
        k = (e["type"], e["detail"])
        if k not in seen:
            seen.add(k)
            effects.append(e)
    return {"method": "html_parse", "exploitable": bool(effects), "effects": effects[:20], "error": None}


DENY = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA}
ALLOWED_FUNCS = {"count", "sum", "avg", "min", "max", "lower", "upper", "length", "substr", "coalesce", "ifnull", "abs", "round", "group_concat", "typeof",
                 "like", "glob", "hex", "replace", "trim", "instr", "random", "printf", "total", "nullif", "iif"}
WRITE_ACTIONS = {sqlite3.SQLITE_INSERT: "insert", sqlite3.SQLITE_UPDATE: "update", sqlite3.SQLITE_DELETE: "delete", sqlite3.SQLITE_DROP_TABLE: "drop_table",
                 sqlite3.SQLITE_DROP_INDEX: "drop_index", sqlite3.SQLITE_ALTER_TABLE: "alter_table", sqlite3.SQLITE_CREATE_TABLE: "create_table"}
SENSITIVE = {"users": ("password_hash", "secret"), "api_keys": ("token",)}


def _decoy(canary: str):
    db = sqlite3.connect(":memory:")
    db.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password_hash TEXT, secret TEXT);
                        CREATE TABLE api_keys (id INTEGER PRIMARY KEY, owner TEXT, token TEXT);
                        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL);""")
    db.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [(1, "alice", "alice@example.test", "h-" + canary[:8], canary + "-A"),
                                                              (2, "bob", "bob@example.test", "h-" + canary[8:16], canary + "-B")])
    db.executemany("INSERT INTO api_keys VALUES (?,?,?)", [(1, "alice", canary + "-K1"), (2, "bob", canary + "-K2")])
    db.executemany("INSERT INTO orders VALUES (?,?,?)", [(1, 1, 10.0), (2, 2, 20.0), (3, 1, 5.5)])
    db.commit()
    return db


def _snapshot(db) -> str:
    h = hashlib.sha256()
    for t in ("users", "api_keys", "orders"):
        try:
            for r in db.execute(f"SELECT * FROM {t} ORDER BY 1"):
                h.update(repr(r).encode())
        except sqlite3.Error:
            h.update(b"<missing:" + t.encode() + b">")
    return h.hexdigest()


def run_sql(payload: str, canary: str) -> dict:
    db = _decoy(canary)
    before = _snapshot(db)
    writes, reads, blocked = set(), set(), []

    def auth(action, a1, a2, _db, _src):
        if action == sqlite3.SQLITE_FUNCTION and str(a2 or "").lower() not in ALLOWED_FUNCS:
            blocked.append(f"function {a2}")
            return sqlite3.SQLITE_DENY
        if action in DENY:
            blocked.append({sqlite3.SQLITE_ATTACH: "ATTACH", sqlite3.SQLITE_DETACH: "DETACH", sqlite3.SQLITE_PRAGMA: "PRAGMA"}.get(action, "restricted action"))
            return sqlite3.SQLITE_DENY
        if action in WRITE_ACTIONS:
            if not str(a1 or "").startswith("sqlite_"):
                writes.add(f"{WRITE_ACTIONS[action]} {a1 or ''}".strip())
        if action == sqlite3.SQLITE_READ and a1 in SENSITIVE and a2 in SENSITIVE[a1]:
            reads.add(f"{a1}.{a2}")
        return sqlite3.SQLITE_OK

    ops = {"n": 0}

    def progress():
        ops["n"] += 1
        return 1 if ops["n"] > 2000 else 0

    db.set_authorizer(auth)
    db.set_progress_handler(progress, 1000)
    err, leaked = None, False
    try:
        cur = db.cursor()
        for stmt in [s for s in re.split(r";\s*(?:\n|$)", payload) if s.strip()][:20]:
            cur.execute(stmt)
            for row in cur.fetchmany(200):
                if any(canary in str(v) for v in row):
                    leaked = True
    except sqlite3.Error as e:
        err = f"{type(e).__name__}: {str(e)[:120]}"
    db.set_authorizer(None)                                           # the final snapshot must not be recorded as the model's reads
    changed = _snapshot(db) != before
    effects = []
    if leaked:
        effects.append({"type": "data_read", "detail": "a statement returned protected decoy values (" + ", ".join(sorted(reads)) + ")"})
    if changed:
        effects.append({"type": "data_changed", "detail": "the decoy database differs after the statements (" + ", ".join(sorted(writes)) + ")"})
    if blocked:
        effects.append({"type": "blocked_attempt", "detail": "the sandbox refused: " + ", ".join(sorted(set(blocked))[:5])})
    return {"method": "sqlite_decoy", "exploitable": leaked or changed, "effects": effects, "error": err}


def process(job: dict) -> dict:
    kind, payload = job.get("kind"), job.get("payload")
    if kind not in KINDS or not isinstance(payload, str) or len(payload) > MAX_PAYLOAD or "\x00" in payload:
        return {"method": None, "exploitable": False, "effects": [], "error": "invalid job"}
    canary = "RLSBX" + hashlib.sha256(str(job.get("id")).encode()).hexdigest()[:16].upper()
    return (run_html if kind == "html" else run_sql)(payload, canary)


class _Timeout(Exception):
    pass


def _alarm(_sig, _frm):
    raise _Timeout()


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    signal.signal(signal.SIGALRM, _alarm)
    inbox, outbox = os.path.join(JOBS, "in"), os.path.join(JOBS, "out")
    print("runner ready", flush=True)
    alive = os.path.join(outbox, ".alive")
    done: set[str] = set()                                               # a job that cannot be deleted must still run only once
    while True:
        try:
            with open(alive, "w") as f:                                   # heartbeat: the backend only submits jobs while this is fresh
                f.write(str(time.time()))
        except OSError:
            pass
        try:
            names = sorted(n for n in os.listdir(inbox) if n.endswith(".json"))
        except OSError:
            names = []
        for n in names:
            jid, path = n[:-5], os.path.join(inbox, n)
            if not ID_RE.match(jid) or jid in done:
                continue
            done.add(jid)
            t0 = time.time()
            try:
                with open(path, encoding="utf-8") as f:
                    job = json.load(f)
                job["id"] = jid
                signal.alarm(JOB_SECONDS)
                try:
                    res = process(job)
                finally:
                    signal.alarm(0)
            except _Timeout:
                res = {"method": None, "exploitable": False, "effects": [], "error": "timeout"}
            except Exception as e:  # noqa: BLE001
                res = {"method": None, "exploitable": False, "effects": [], "error": type(e).__name__}
            res |= {"id": jid, "ms": int((time.time() - t0) * 1000)}
            tmp = os.path.join(outbox, jid + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(res, f)
            os.replace(tmp, os.path.join(outbox, jid + ".json"))
            try:
                os.remove(path)
            except OSError:
                pass
        time.sleep(POLL)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":                # used by tests: process a single job file and print the result
        print(json.dumps(process(json.load(open(sys.argv[2])))))
    else:
        main()
