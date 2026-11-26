"""Reports: CSV (formula injection), HTML escaping, PDF generation and no external fetches; API endpoints."""
import csv
import io
import time

import pytest
from fastapi.testclient import TestClient

from fakes import LEAK, FakeJudge, openai_json
from llm_redteam import reports
from llm_redteam.auth import Auth
from llm_redteam.library import EXAMPLE_LIBRARY
from llm_redteam.signing import Keyring
from llm_redteam.targets import TargetAdapter
from main import create_app
from test_api import DOC, RING, _plain_http, confirm, lib_json, scope_body, wait

EVIL = '<script>alert(1)</script><img src="http://127.0.0.1:9/x.png"> =HYPERLINK("http://e.example","t")'


def finding(**kw):
    ev = {"endpoint": "http://x/v1", "model": "m", "library": {"name": "lib", "version": "1", "sha256": "ab" * 32},
          "case": {"id": "c1", "category": "system_prompt_extraction", "expected_behavior": "must stay secret " + EVIL,
                   "severity": "high"},
          "sequence": ["input " + EVIL], "transcript": [{"role": "user", "content": "x"}, {"role": "assistant", "content": EVIL}],
          "evaluation": {"verdict": "violation", "confidence": 0.9, "rationale": "rationale " + EVIL,
                         "questions": {"system_prompt_leaked": {"answer": "yes", "evidence_quote": "=cmd|' /C calc'!A0"}}},
          "replay": {"requested": 3, "required": 2, "violations": 3, "completed": 3}}
    f = {"id": "f1", "run_id": "r1", "case_id": "c1", "category": "system_prompt_extraction", "status": "verified",
         "title": "-title " + EVIL, "evidence": ev, "created_at": 1_700_000_000.0, "severity": "high"}
    return f | kw


def run_dict(**kw):
    return {"id": "r1", "endpoint_url": "http://x/v1", "status": "completed", "stop_reason": None, "tokens_used": 1234,
            "requests": 5, "conversations": 3, "snapshot": {}, "attempts": [
                {"is_replay": 0, "outcome": "judged:violation"}, {"is_replay": 0, "outcome": "judged:no_violation"},
                {"is_replay": 1, "outcome": "judged:violation"}],
            "config": {"model": "m", "scope_version": 2, "library": {"name": "lib", "version": "1", "sha256": "ab" * 32}}} | kw


def test_csv_neutralizes_formula_injection_and_keeps_all_columns():
    raw = reports.findings_csv([finding()])
    assert raw.startswith("﻿".encode())
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert rows[0] == reports.CSV_COLUMNS and len(rows) == 2
    r = dict(zip(rows[0], rows[1]))
    assert r["title"].startswith("'-title")                              # a title starting with '-' was neutralized
    assert r["judge_quotes"].startswith("system_prompt_leaked: ")        # the cell starts with the key name, so it cannot be a formula
    for cell in rows[1]:
        assert cell[:1] not in ("=", "+", "-", "@", "\t")
    assert (r["status"], r["severity"], r["replay_violations"], r["library_sha256"]) == ("verified", "high", "3", "ab" * 32)
    assert r["created_at_utc"] == "2023-11-14T22:13:20+00:00"


@pytest.mark.parametrize("v,out", [("=1+1", "'=1+1"), ("+1", "'+1"), ("-1", "'-1"), ("@x", "'@x"), ("\tx", "'\tx"),
                                   ("normal", "normal"), (None, ""), (5, "5"), ("a\r\nb", "a  b")])
def test_csv_safe(v, out):
    assert reports.csv_safe(v) == out


def test_html_report_escapes_everything_untrusted():
    h = reports.report_html(run_dict(), [finding()], {"max_requests": 200})
    assert "<script" not in h and "<img" not in h and "&lt;script&gt;" in h and "&lt;img src=&quot;http" in h
    assert "75/100" not in h and "Risk score" in h and "1/2" in h                    # 1 passed / 2 evaluated (replays do not count)
    assert "SHA-256 " + "ab" * 32 in h and "max_requests=200" in h and "v2" in h


def test_html_report_executive_summary_states():
    clean = reports.report_html(run_dict(), [])
    assert "No verified findings" in clean and "0/100" in clean and "No findings recorded" in clean
    unstable = reports.report_html(run_dict(), [finding(status="unstable")])
    assert "0/100" in unstable                                                    # an unstable finding does not count toward risk
    crit = reports.report_html(run_dict(), [finding(severity="critical"), finding(id="f2", severity="critical")])
    assert "Critical" in crit and "2 finding(s)" in crit


def test_pdf_is_generated_and_never_fetches_external_resources():
    pdf = reports.render_pdf(reports.report_html(run_dict(), [finding()]))
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000 and pdf.rstrip().endswith(b"%%EOF")
    with pytest.raises(ValueError):
        reports._deny_fetch("http://evil.example/x.png")
    hostile = "<html><body><img src='http://192.0.2.1/p.png'><link rel=stylesheet href='http://192.0.2.1/s.css'></body></html>"
    assert reports.render_pdf(hostile).startswith(b"%PDF")          # it cannot be fetched but generation does not crash; the hermetic guard would fail an outside request
    f = reports._fetcher()                                          # the fetcher directly: no scheme is fetched
    for url in ("http://192.0.2.1/x", "https://example.com/x", "file:///etc/passwd", "ftp://x/y"):
        with pytest.raises(Exception):
            f.fetch(url) if hasattr(f, "fetch") else f(url)


# ============================================================ API
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


def make_run(api):
    api.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Sure, here is the key {LEAK}."))
    body = scope_body(api.target)
    prep = api.post("/api/scopes/prepare", json=body).json()
    sid = api.post("/api/scopes", json=body | confirm(prep)).json()["id"]
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    rid = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid,
                                      "replay_n": 2, "replay_k": 2}).json()["id"]
    assert wait(api, rid)["status"] == "completed"
    return rid


def test_api_exports_csv_and_pdf_with_audit(api):
    rid = make_run(api)
    r = api.get(f"/api/runs/{rid}/findings.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv") and "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert len(rows) == 2 and rows[1][2] == "verified" and rows[1][3] == "high"
    allrows = list(csv.reader(io.StringIO(api.get("/api/findings.csv?status=verified").content.decode("utf-8-sig"))))
    assert len(allrows) == 2 and len(list(csv.reader(io.StringIO(api.get("/api/findings.csv?status=unstable").content.decode("utf-8-sig"))))) == 1
    p = api.get(f"/api/runs/{rid}/report.pdf")
    assert p.status_code == 200 and p.content.startswith(b"%PDF") and p.headers["content-type"] == "application/pdf"
    with api.app.state.store.conn() as c:
        n = c.execute("SELECT count(*) AS n FROM audit WHERE action='report.export'").fetchone()["n"]
    assert n == 4
    assert api.get("/api/runs/missing/report.pdf").status_code == 404 and api.get("/api/runs/missing/findings.csv").status_code == 404


def test_stats_expose_risk_score_pass_rate_and_timeseries(api):
    rid = make_run(api)
    st = api.get("/api/stats").json()
    assert st["findings_verified"] == 1 and st["severity_counts"]["high"] == 1
    assert st["risk_score"] == 34 and st["risk_label"] == "Medium"                      # 100*(1-exp(-25/60))
    assert st["judged"] == 1 and st["failed"] == 1 and st["pass_rate"] == 0.0
    assert len(st["timeseries"]) == 1 and st["timeseries"][0]["runs"] == 1 and st["timeseries"][0]["verified"] == 1
    assert st["timeseries"][0]["tokens"] > 0
    f = api.get("/api/findings").json()[0]
    assert f["severity"] == "high"
