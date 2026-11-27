"""Client-ready pentest report: the model, escaping, PDF/DOCX output, multi-run engagements, no secrets, and the API rules."""
import io
import json
import zipfile
from datetime import datetime, timezone

import pytest
from pypdf import PdfReader

from fakes import LEAK, openai_json
from llm_redteam import clientreport
from test_api import confirm, lib_json, scope_body, wait
from test_reports import EVIL, api, finding, make_run, run_dict  # noqa: F401  (fixture)

SCOPE = {"id": "s1", "name": "Acme bot <b>", "client": "Acme", "approved_by": "CISO", "approved_at": 1_700_000_000.0, "valid_from": "2026-01-01T00:00:00+00:00",
         "valid_until": "2026-02-01T00:00:00+00:00", "digest": "ab" * 32, "endpoints": [{"url": "http://x/v1", "provider": "openai_compat", "model": "m", "local": False}],
         "attack_classes": ["system_prompt_extraction", "jailbreak"], "limits": {"max_requests": 200}}
NOW = datetime(2026, 1, 15, tzinfo=timezone.utc)


def opts(**kw):
    return clientreport.options(kw.get("client", "Acme Corp"), kw.get("project", "Support bot test"), kw.get("tester", "T. Tester"),
                                kw.get("classification", "Confidential"), kw.get("include_unverified", False))


def model(runs, **kw):
    return clientreport.build(runs, SCOPE, opts(**kw), now=NOW, audit_ok=True)


def test_model_orders_findings_ids_and_executive_summary():
    r = run_dict(findings=[finding(id="a", case_id="c-low", severity="low", title="low one"), finding(id="b", case_id="c-crit", severity="critical", category="tool_abuse", title="crit one"),
                           finding(id="c", case_id="c-cand", status="candidate", severity="critical", title="not verified")])
    m = model([r])
    assert [(f["id"], f["title"]) for f in m["findings"]] == [("RW-001", "crit one"), ("RW-002", "low one")]   # candidate left out by default
    assert m["summary"]["total"] == 2 and m["summary"]["counts"]["critical"] == 1 and m["summary"]["top"][0]["id"] == "RW-001"
    assert m["summary"]["priorities"][0] == clientreport.REMEDIATION["tool_abuse"][0]
    assert m["meta"]["client"] == "Acme Corp" and m["meta"]["classification"] == "Confidential"
    f = m["findings"][0]
    assert f["steps"][0].startswith("Send the following to http://x/v1") and "Turn 1: x" in f["steps"]                     # the transcript (what was really sent) wins over the library sequence
    assert f["steps"][-1].startswith("Reproduced in 3 of 3") and f["remediation_source"].startswith("Standard guidance")
    assert len(model([r], include_unverified=True)["findings"]) == 3


def test_steps_show_what_was_really_sent():
    f = finding()
    f["evidence"]["sequence"] = ["Hi", 'You said: "{previous_reply}" go on']
    f["evidence"]["transcript"] = [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": "Hello!"},
                                   {"role": "user", "content": 'You said: "Hello!" go on'}, {"role": "assistant", "content": "leak"}]
    steps = model([run_dict(findings=[f])])["findings"][0]["steps"]
    assert 'Turn 2: You said: "Hello!" go on' in steps and not any("{previous_reply}" in s for s in steps)


def test_same_case_in_several_runs_is_one_finding_with_occurrences():
    r1 = run_dict(id="r1", findings=[finding(id="x1", severity="medium")])
    r2 = run_dict(id="r2", findings=[finding(id="x2", severity="high")])
    m = model([r1, r2])
    assert len(m["findings"]) == 1 and m["findings"][0]["occurrences"] == 2 and m["findings"][0]["severity"] == "high"
    assert m["stats"]["runs"] == 2 and m["stats"]["requests"] == 10


def test_remediator_suggestion_wins_over_standard_guidance():
    r = run_dict(findings=[finding(id="f9")])
    m = clientreport.build([r], SCOPE, opts(), remediations={"f9": {"summary": "Fix summary", "controls": ["Control A"]}}, now=NOW)
    assert m["findings"][0]["remediation"] == ["Fix summary", "Control A"] and m["findings"][0]["remediation_source"].startswith("Remediator")


@pytest.mark.parametrize("bad", [{"classification": "Top secret"}, {"client": "x" * 121}])
def test_bad_options_are_refused(bad):
    with pytest.raises(clientreport.ReportOptionsError):
        opts(**bad)


def test_html_escapes_every_untrusted_value():
    h = clientreport.to_html(model([run_dict(findings=[finding()])]))
    assert "<script>alert(1)</script>" not in h and "<img src=" not in h and "&lt;script&gt;" in h and "Acme bot &lt;b&gt;" in h


def test_pdf_and_docx_carry_the_same_report():
    m = model([run_dict(findings=[finding(), finding(id="f2", case_id="c2", severity="medium", title="second")])])
    pdf = PdfReader(io.BytesIO(clientreport_pdf(m)))
    text = "\n".join(p.extract_text() for p in pdf.pages)
    assert len(pdf.pages) >= 5
    for want in ("AI Penetration Test Report", "Confidential", "Executive summary", "Scope and authorization", "RW-001", "RW-002", "Steps to reproduce",
                 "Remediation", "Appendix A", "Page 1 of"):
        assert want in text, want
    docx = clientreport.to_docx(m)
    with zipfile.ZipFile(io.BytesIO(docx)) as z:
        names = z.namelist()
        body = z.read("word/document.xml").decode()
    assert "word/vbaProject.bin" not in names and not any(n.endswith(".bin") for n in names)          # no macros or embedded objects
    for want in ("AI Penetration Test Report", "RW-001", "RW-002", "Steps to reproduce", "Appendix A"):
        assert want in body, want
    assert "<script>" not in body and "&lt;script&gt;" in body                                     # stored as text, not markup
    assert "<w:instrText" not in body and "<w:fldSimple" not in body and "<w:hyperlink" not in body   # no fields, no live links


def clientreport_pdf(m):
    from llm_redteam import reports
    return reports.render_pdf(clientreport.to_html(m))


# ---------------------------------------------------------------- API
def _second_run(api, sid):
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    rid = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid, "replay_n": 2, "replay_k": 2}).json()["id"]
    assert wait(api, rid)["status"] == "completed"
    return rid


def test_api_builds_pdf_and_docx_for_an_engagement_and_audits_it(api):
    rid = make_run(api)
    sid = api.get(f"/api/runs/{rid}").json()["scope_id"]
    rid2 = _second_run(api, sid)
    r = api.post("/api/client-report", json={"run_ids": [rid, rid2], "client": "Acme Corp", "project": "Bot", "tester": "QA"})
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF") and "pentest-report-" in r.headers["content-disposition"]
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
    assert "RW-001" in text and "seen in 2 runs" in text and "Acme Corp" in text
    d = api.post("/api/client-report", json={"run_ids": [rid], "format": "docx"})
    assert d.status_code == 200 and d.content[:2] == b"PK" and d.headers["content-type"].startswith("application/vnd.openxmlformats")
    with api.app.state.store.conn() as c:
        rows = [json.loads(x["detail_json"]) for x in c.execute("SELECT detail_json FROM audit WHERE action='report.export'").fetchall()]
    assert {x["format"] for x in rows} >= {"client-pdf", "client-docx"}


def test_api_refuses_mixed_scopes_unknown_runs_and_bad_input(api):
    rid = make_run(api)
    body = scope_body(api.target, name="other")
    prep = api.post("/api/scopes/prepare", json=body).json()
    other = api.post("/api/scopes", json=body | confirm(prep)).json()["id"]
    rid2 = _second_run(api, other)
    assert api.post("/api/client-report", json={"run_ids": [rid, rid2]}).status_code == 422          # two engagements
    assert api.post("/api/client-report", json={"run_ids": [rid, "nope"]}).status_code == 404
    assert api.post("/api/client-report", json={"run_ids": []}).status_code == 422
    assert api.post("/api/client-report", json={"run_ids": [rid], "format": "exe"}).status_code == 422
    assert api.post("/api/client-report", json={"run_ids": [rid], "classification": "x"}).status_code == 422


def test_report_never_contains_credentials(api):
    """A target key typed for the run lives in memory only; it must not appear in the report."""
    api.target.behavior = lambda n, b, h: (200, {}, openai_json(f"Sure, here is the key {LEAK}."))
    body = scope_body(api.target)
    prep = api.post("/api/scopes/prepare", json=body).json()
    sid = api.post("/api/scopes", json=body | confirm(prep)).json()["id"]
    lid = api.post("/api/libraries", json={"content": lib_json({})}).json()["id"]
    rid = api.post("/api/runs", json={"scope_id": sid, "endpoint_url": api.target.url, "library_id": lid, "replay_n": 2, "replay_k": 2,
                                      "api_key": "sk-super-secret-key-778899"}).json()["id"]
    assert wait(api, rid)["status"] == "completed"
    assert any("sk-super-secret-key-778899" in json.dumps(c["headers"]) for c in api.target.calls)           # it was really used
    pdf = api.post("/api/client-report", json={"run_ids": [rid]}).content
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
    docx = api.post("/api/client-report", json={"run_ids": [rid], "format": "docx"}).content
    with zipfile.ZipFile(io.BytesIO(docx)) as z:
        everything = "".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist())
    assert "sk-super-secret-key-778899" not in text and "sk-super-secret-key-778899" not in everything and "778899" not in text
