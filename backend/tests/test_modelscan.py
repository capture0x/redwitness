import io
import json
import pickle
import struct
import zipfile

import pytest

from llm_redteam import modelscan as m


class _Evil:
    def __reduce__(self):
        import os
        return (os.system, ("echo should-never-run",))


def test_malicious_pickle_detected_without_executing(tmp_path):
    blob = pickle.dumps(_Evil())
    r = m.scan_bytes("model.pkl", blob)
    assert r.verdict == "unsafe"
    assert any(f.code == "PICKLE_CALLS_DANGEROUS" for f in r.findings)
    assert any(i.endswith(".system") for i in r.imports)


def test_protocols_0_to_5_detected():
    for proto in range(0, 6):
        r = m.scan_bytes("a.pkl", pickle.dumps(_Evil(), protocol=proto))
        assert r.verdict == "unsafe", proto


def test_plain_data_pickle_is_clean():
    r = m.scan_bytes("a.pkl", pickle.dumps({"w": [1.0, 2.0], "n": "x"}))
    assert r.verdict == "clean" and r.imports == []


def test_torch_zip_with_evil_pickle():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(_Evil(), protocol=2))
        z.writestr("archive/version", "3")
    r = m.scan_bytes("model.pt", buf.getvalue())
    assert r.format == "zip-pickle" and r.verdict == "unsafe"
    assert r.findings[0].location.endswith("data.pkl") or any(f.location.endswith("data.pkl") for f in r.findings)


def test_zip_slip_and_executable_flagged():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.py", "print(1)")
    r = m.scan_bytes("m.bin", buf.getvalue())
    codes = {f.code for f in r.findings}
    assert {"ZIP_PATH_TRAVERSAL", "ARCHIVE_EXECUTABLE"} <= codes and r.verdict == "unsafe"


def test_safetensors_ok_and_bad():
    hdr = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    good = struct.pack("<Q", len(hdr)) + hdr + b"\0\0\0\0"
    assert m.scan_bytes("a.safetensors", good).verdict == "clean"
    bad = struct.pack("<Q", 10**12) + b"x" * 20
    assert m.scan_bytes("a.safetensors", bad).verdict == "unsafe"
    trailing = good + b"EXTRA"
    assert m.scan_bytes("a.safetensors", trailing).verdict == "suspicious"


def test_hash_mismatch_is_unsafe():
    blob = pickle.dumps([1])
    assert m.scan_bytes("a.pkl", blob, "0" * 64).verdict == "unsafe"
    import hashlib
    assert m.scan_bytes("a.pkl", blob, hashlib.sha256(blob).hexdigest()).hash_match is True


def test_unknown_global_is_suspicious_and_garbage_unsupported():
    blob = pickle.dumps(__import__("fractions").Fraction(1, 3))
    assert m.scan_bytes("a.pkl", blob).verdict == "suspicious"
    assert m.scan_bytes("a.txt", b"hello").verdict == "unsupported"


def test_limits_and_caveat_always_present():
    with pytest.raises(m.ScanError):
        m.scan_bytes("a.pkl", b"")
    with pytest.raises(m.ScanError):
        m.scan_bytes("a.pkl", b"x" * (m.MAX_BYTES + 1))
    assert any("poisoned" in s for s in m.scan_bytes("a.pkl", pickle.dumps(1)).limits)


def test_truncated_pickle_not_clean():
    r = m.scan_bytes("a.pkl", pickle.dumps(_Evil())[:-3])
    assert r.verdict in ("unsafe", "suspicious")


# ------------------------------------------------------------------ API
import base64
import contextlib
import hashlib

from fastapi.testclient import TestClient

from llm_redteam.auth import Auth
from llm_redteam.store import Store
from main import create_app
from test_api import RING
from test_rbac import H, PW


@pytest.fixture
def api(fresh_db):
    app = create_app(fresh_db, RING, auth=Auth(PW))
    with contextlib.ExitStack() as st:
        w = type("W", (), {})()
        w.admin, w.viewer, w.anon = (st.enter_context(TestClient(app)) for _ in range(3))
        assert w.admin.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
        assert w.admin.post("/api/users", json={"username": "viewer1", "password": "viewer1-password-99", "role": "viewer"}, headers=H).status_code == 201
        assert w.viewer.post("/api/auth/login", json={"username": "viewer1", "password": "viewer1-password-99"}).status_code == 200
        w.store = Store(fresh_db)
        yield w


def b64(b):
    return base64.b64encode(b).decode()


def test_api_scan_store_audit_and_roles(api):
    blob = pickle.dumps(_Evil())
    r = api.admin.post("/api/model-scans", json={"filename": "evil.pkl", "content_base64": b64(blob)}, headers=H)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["verdict"] == "unsafe" and d["sha256"] == hashlib.sha256(blob).hexdigest() and "content_base64" not in json.dumps(d)
    assert api.viewer.get(f"/api/model-scans/{d['id']}").json()["verdict"] == "unsafe"
    assert api.viewer.get("/api/model-scans").json()[0]["id"] == d["id"]
    assert api.viewer.post("/api/model-scans", json={"filename": "a", "content_base64": b64(blob)}, headers=H).status_code == 403
    assert api.anon.get("/api/model-scans").status_code == 401
    assert api.admin.get("/api/model-scans/nope").status_code == 404
    with api.store.conn() as c:
        row = c.execute("SELECT actor, detail_json FROM audit WHERE action='model_scan.create'").fetchone()
    assert row["actor"] == "admin" and json.loads(row["detail_json"])["verdict"] == "unsafe"


def test_api_rejects_bad_input(api):
    assert api.admin.post("/api/model-scans", json={"filename": "a.pkl", "content_base64": "!!!notb64"}, headers=H).status_code == 422
    assert api.admin.post("/api/model-scans", json={"filename": "a.pkl", "content_base64": b64(b"x"), "expected_sha256": "zz"}, headers=H).status_code == 422
