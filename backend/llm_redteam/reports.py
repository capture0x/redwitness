"""
Report generation: CSV (findings list) and PDF (executive summary + technical detail).
The report contains UNTRUSTED text that came from the target:
  - every value is escaped before it enters HTML (no tag/script/image injection),
  - no external resource is fetched while the PDF is generated (url_fetcher refuses everything),
  - formula injection in CSV (cells starting with =,+,-,@) is neutralized.
"""
import csv
import html
import io
from datetime import datetime, timezone

from . import frameworks
from . import owasp as owasp_mod
from .library import BENCHMARKS
from .reasons import EXPLAIN, Reason
from .risk import SEVERITY_LABEL, risk_label, risk_score
from .scope import CLASS_LABEL

STATUS_LABEL = {"verified": "Verified", "unstable": "Unstable", "candidate": "Candidate", "needs_review": "Needs review", "false_positive": "False positive"}
CSV_COLUMNS = ["finding_id", "run_id", "status", "severity", "category", "owasp_category", "case_id", "title", "endpoint", "model",
               "library", "library_version", "library_sha256", "replay_violations", "replay_required",
               "replay_completed", "judge_verdict", "judge_confidence", "judge_quotes", "created_at_utc",
               "asi_category", "mitre_atlas", "nist_ai_rmf", "aisvs", "benchmark", "attack_family", "source", "impact", "system_status", "human_review", "verifier", "sandbox", "reasoning_deviation"]


def csv_safe(v) -> str:
    s = "" if v is None else str(v).replace("\r", " ").replace("\n", " ")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t") else s


def _quotes(ev: dict) -> str:
    q = ((ev.get("evaluation") or {}).get("questions") or {})
    return " | ".join(f"{k}: {v.get('evidence_quote', '')}" for k, v in q.items() if v.get("answer") == "yes")


def findings_csv(findings: list[dict], include_false_positives: bool = False) -> bytes:
    """False positives (refuted by the adversarial verifier or a human) are left out unless asked for explicitly."""
    findings = [f for f in findings if include_false_positives or f["status"] != "false_positive"]
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for f in findings:
        ev, rp, e = f.get("evidence") or {}, (f.get("evidence") or {}).get("replay") or {}, (f.get("evidence") or {}).get("evaluation") or {}
        lib = ev.get("library") or {}
        w.writerow([csv_safe(x) for x in (
            f["id"], f["run_id"], f["status"], f["severity"], f["category"], f.get("owasp_category") or "", f["case_id"], f["title"], ev.get("endpoint"),
            ev.get("model"), lib.get("name"), lib.get("version"), lib.get("sha256"), rp.get("violations"), rp.get("required"),
            rp.get("completed"), e.get("verdict"), e.get("confidence"), _quotes(ev),
            datetime.fromtimestamp(f["created_at"], timezone.utc).isoformat(timespec="seconds"),
            (f.get("frameworks") or {}).get("asi") or "",
            "; ".join(t["id"] for t in (f.get("frameworks") or {}).get("atlas", [])),
            "; ".join(n["id"] for n in (f.get("frameworks") or {}).get("nist", [])),
            "; ".join((f.get("frameworks") or {}).get("aisvs", [])), f.get("benchmark") or "",
            (f.get("frameworks") or {}).get("family") or "", (ev.get("case") or {}).get("source") or "",
            (ev.get("impact") or {}).get("impact") or "", f.get("system_status") or f["status"], (f.get("review") or {}).get("verdict") or "",
            (ev.get("verifier") or {}).get("outcome") or "", (ev.get("sandbox") or {}).get("status") or "",
            (ev.get("reasoning") or {}).get("first_deviation") or "")])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")           # BOM: Excel opens non-ASCII characters correctly


# ------------------------------------------------------------------ PDF
CSS = """
@page { size: A4; margin: 18mm 15mm; @bottom-right { content: "Page " counter(page) " / " counter(pages); font-size: 8pt; color: #666; } }
body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt; color: #1a1d24; }
h1 { font-size: 20pt; margin: 0 0 2mm; } h2 { font-size: 13pt; border-bottom: 1px solid #ccd; padding-bottom: 1mm; margin-top: 8mm; }
h3 { font-size: 10.5pt; margin: 4mm 0 1mm; } .muted { color: #667; font-size: 8.5pt; }
table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #d5d8e0; padding: 1.5mm 2mm; text-align: left; vertical-align: top; }
th { background: #f0f2f7; } .kpi { display: inline-block; width: 31%; border: 1px solid #d5d8e0; border-radius: 2mm; padding: 2mm; margin-right: 1.5%; }
.kpi b { font-size: 16pt; display: block; } .sev { color: #fff; padding: 0.5mm 2mm; border-radius: 1.5mm; font-size: 8pt; }
.sev-critical { background: #b91c1c; } .sev-high { background: #ea580c; } .sev-medium { background: #ca8a04; }
.sev-low { background: #2563eb; } .sev-info { background: #64748b; }
pre { white-space: pre-wrap; word-break: break-word; background: #f6f7fa; border: 1px solid #e1e4ec; padding: 1.5mm; font-size: 8pt; }
.finding { page-break-inside: avoid; border: 1px solid #d5d8e0; border-radius: 2mm; padding: 2.5mm; margin: 3mm 0; }
"""


def e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _sev_counts(findings):
    c: dict[str, int] = {}
    for f in findings:
        if f["status"] == "verified":
            c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


OWASP_STATUS_LABEL = {"vulnerable": "Vulnerable", "review": "Needs review", "clean": "Clean", "not_tested": "Not tested"}


def owasp_summary(run: dict, findings: list[dict]) -> list[dict]:
    """OWASP summary for a single run (pure; no DB)."""
    rows = []
    for cat in owasp_mod.CATEGORIES:
        cid = cat["id"]
        att = [a for a in run.get("attempts", []) if a.get("owasp_category") == cid and not a["is_replay"] and a["outcome"].startswith("judged:")]
        fs = [f for f in findings if f.get("owasp_category") == cid]
        if not att:
            status = "not_tested"
        elif any(f["status"] == "verified" for f in fs):
            status = "vulnerable"
        elif fs or any(a["outcome"] != "judged:no_violation" for a in att):
            status = "review"
        else:
            status = "clean"
        rows.append({**cat, "status": status, "tests": len(att)})
    return rows


def suite_html(run: dict, findings: list[dict]) -> str:
    """Evidence of the suite modules in one run: multimodal carrier files, agentic chains, knowledge maps. Empty when the run used none of them."""
    out: list[str] = []
    mm = [(f, (f.get("evidence") or {}).get("multimodal")) for f in findings if (f.get("evidence") or {}).get("multimodal")]
    if mm:
        out.append("<h2>Multimodal carrier</h2><p class='muted'>The files below are exactly what the library holds; they were only carried. Static pre-processing read them before sending "
                   "(OCR and metadata; audio speech is not transcribed).</p><table><tr><th>Finding</th><th>File</th><th>SHA-256</th><th>OCR</th><th>Text the library did not declare</th></tr>")
        for f, m in mm:
            pre = {x["name"]: x for x in m["preflight"]["files"]}
            for fl in m["files"]:
                p = pre.get(fl["name"], {})
                out.append(f"<tr><td>{e(f['case_id'])}</td><td>{e(fl['name'])} ({e(fl['format'])})</td><td>{e(fl['sha256'][:16])}…</td><td>{e(p.get('ocr_status', p.get('speech', '-')))}</td>"
                           f"<td>{'yes' if p.get('carries_undeclared_text') else 'no'}</td></tr>")
        out.append("</table>")
    ch = [(f, (f.get("evidence") or {}).get("agentic_chain")) for f in findings if (f.get("evidence") or {}).get("agentic_chain")]
    if ch:
        out.append("<h2>Agentic tool chains</h2><table><tr><th>Finding</th><th>Severity</th><th>Tool path</th><th>Rule</th></tr>")
        for f, c in ch:
            rules = ", ".join(v["rule"] for v in ((f.get("evidence") or {}).get("tool_sandbox") or {}).get("violations", [])) or "-"
            out.append(f"<tr><td>{e(f['case_id'])}</td><td>{e(f.get('severity', ''))}</td><td>{e(' → '.join(c['path']) or '(no tool call)')}</td><td>{e(rules)}</td></tr>")
        out.append("</table>")
    for km in run.get("knowledge_maps", []):
        s = km["tree"]["summary"]
        out.append(f"<h2>Knowledge map - {e(km['case_id'])}</h2><p>Questions asked: <b>{s['asked']}/{s['nodes']}</b> · covered: <b>{s['covered']}</b> · not covered: <b>{s['uncovered']}</b> · "
                   f"nodes that exposed a protected term: <b>{s['exposed_nodes']}</b>" + (f" · term coverage: <b>{s['coverage']:.0%}</b>" if s["coverage"] is not None else "") + "</p>"
                   "<table><tr><th>Topic</th><th>Asked</th><th>Covered</th><th>Terms found</th><th>Exposed</th></tr>" +
                   "".join(f"<tr><td>{e(x['topic'])}</td><td>{x['asked']}/{x['nodes']}</td><td>{x['covered']}</td><td>{x['found']}/{x['terms']}</td><td>{x['exposed']}</td></tr>" for x in km["tree"]["topics"]) +
                   "</table><p class='muted'>Exploration and reporting only: questions and terms come from the library; classification is string matching in code.</p>")
    return "".join(out)


def threat_matrix_html(run: dict, findings: list[dict]) -> str:
    """MITRE ATLAS threat matrix + OWASP Agentic / NIST AI RMF / AISVS / benchmark summary for one run (pure)."""
    st = frameworks.stats(run.get("attempts", []), findings, BENCHMARKS)
    lbl = {**OWASP_STATUS_LABEL}
    out = ["<h2>Threat matrix (MITRE ATLAS)</h2>"]
    rows = [t for t in st["atlas"] if t["tested"]]
    if rows:
        out.append("<table><tr><th>Tactic</th><th>Technique</th><th>Evaluations</th><th>Violations</th><th>Verified</th><th>Status</th></tr>" + "".join(
            f"<tr><td>{e(', '.join(x['name'] + ' (' + x['id'] + ')' for x in t['tactics']))}</td><td>{e(t['id'])} {e(t['name'])}</td>"
            f"<td>{t['tested']}</td><td>{t['violations']}</td><td>{t['verified']}</td><td>{e(lbl[t['status']])}</td></tr>" for t in rows) + "</table>")
    else:
        out.append("<p class='muted'>No evaluated case maps to an ATLAS technique in this run.</p>")
    fam = [r for r in st["families"] if r["tested"]]
    if fam:
        out.append("<h3>Attack families (carrier taxonomy) and the framework areas they evidence</h3><table><tr><th>Family</th><th>OWASP Agentic (ASI)</th>"
                   "<th>MITRE ATLAS techniques</th><th>Evaluations</th><th>Violations</th><th>Verified</th><th>Status</th></tr>" + "".join(
            f"<tr><td>{e(r['en'])}</td><td>{e(r['asi'].split('_')[0])}</td><td>{e('; '.join(t['id'] + ' ' + t['name'] for t in r['atlas']))}</td>"
            f"<td>{r['tested']}</td><td>{r['violations']}</td><td>{r['verified']}</td><td>{e(lbl[r['status']])}</td></tr>" for r in fam) + "</table>")
    for key, title, label in (("asi", "OWASP Agentic (ASI) 2026", "en"), ("nist", "NIST AI RMF (Measure / Manage)", "en"), ("aisvs", "OWASP AISVS (chapter level)", "en")):
        sub = [r for r in st[key] if r["tested"]]
        if sub:
            out.append(f"<h3>{e(title)}</h3><table><tr><th>Area</th><th>Title</th><th>Evaluations</th><th>Violations</th><th>Verified</th><th>Status</th></tr>" + "".join(
                f"<tr><td>{e(r.get('code') or r['id'])}</td><td>{e(r[label])}</td><td>{r['tested']}</td><td>{r['violations']}</td><td>{r['verified']}</td>"
                f"<td>{e(lbl[r['status']])}</td></tr>" for r in sub) + "</table>")
    bs = [b for b in st["benchmarks"] if b["evaluated"]]
    if bs:
        out.append("<h3>Benchmark score (Attack Success Rate)</h3><table><tr><th>Benchmark</th><th>Evaluated</th><th>Violations</th><th>ASR</th><th>Verified ASR</th></tr>" + "".join(
            f"<tr><td>{e(b['name'])}</td><td>{b['evaluated']}</td><td>{b['violations']}</td><td>{b['asr']:.1%}</td><td>{b['asr_verified']:.1%}</td></tr>" for b in bs) + "</table>"
            "<p class='muted'>ASR = share of benchmark prompts after which the judge found a violation (lower is better). It is a binary judge-based rate, "
            "not the official scorer of the benchmark, so it is not comparable with published leaderboard numbers.</p>")
    out.append("<p class='muted'>Mappings are curated and show which framework areas a finding is evidence for; they are not a conformance certificate. "
               "ATLAS ids and AISVS chapter titles change between releases: verify them against the version you report against.</p>")
    return "".join(out)


def quality_html(run: dict, removed: list[dict], calibration: dict | None) -> str:
    """Evaluator independence + false-positive handling + measured precision/recall (from human review). Pure."""
    cfg = run.get("config") or {}
    out = ["<h2>Evaluation quality and independence</h2><table>"]
    b = (cfg.get("bias") or {}).get("assessments") or []
    out.append(f"<tr><th>Judge</th><td>{e(cfg.get('judge_provider'))} · {e(cfg.get('judge_model'))}</td></tr>")
    vf = cfg.get("verifier") or {}
    out.append(f"<tr><th>Adversarial verifier</th><td>{'on · ' + e(vf.get('model')) if vf.get('enabled') else 'off'}</td></tr>")
    sb = cfg.get("sandbox") or {}
    out.append(f"<tr><th>Sandbox verification</th><td>{('on' + ('' if sb.get('runner_up') else ' (runner was not reachable at start)')) if sb.get('enabled') else 'off'}</td></tr>")
    if (cfg.get("defense") or {}).get("mode"):
        out.append(f"<tr><th>Defense test mode</th><td>{e(cfg['defense']['mode'])}</td></tr>")
    for a in b:
        out.append(f"<tr><th>Independence ({e(a.get('role'))})</th><td>{e(a.get('level'))} - {e(a.get('message'))}</td></tr>")
    if not b:
        out.append("<tr><th>Independence</th><td class='muted'>not recorded for this run</td></tr>")
    fp_v = sum(1 for f in removed if (f.get("review") or {}).get("verdict") != "false_positive")
    out.append(f"<tr><th>Removed as false positives</th><td>{len(removed)} (adversarial verifier: {fp_v}, human review: {len(removed) - fp_v}). "
               "They are kept in the database for audit and are not part of this report's findings, score or counts.</td></tr></table>")
    c = calibration or {}
    if c.get("reviewed"):
        pc, rc = c.get("precision_ci"), c.get("recall_ci")
        ci = lambda x: f" (95% CI {x[0]:.0%}-{x[1]:.0%})" if x else ""
        pct = lambda v: "n/a" if v is None else f"{v:.0%}"
        out.append("<h3>Measured detection quality (human-reviewed findings, all runs)</h3><table>"
                   f"<tr><th>Reviewed</th><td>{c['reviewed']}</td><th>True / false positives reported</th><td>{c['tp']} / {c['fp']}</td></tr>"
                   f"<tr><th>Precision</th><td>{pct(c['precision'])}{e(ci(pc))}</td><th>Recall (reviewed candidates)</th><td>{pct(c['recall'])}{e(ci(rc))}</td></tr></table>"
                   f"<p class='muted'>{e(c.get('note'))}</p>")
    else:
        out.append("<p class='muted'>No human-reviewed findings yet, so precision and recall have not been measured. "
                   "Mark findings as true or false positive on the Findings page to calibrate.</p>")
    return "".join(out)


def report_html(run: dict, findings: list[dict], limits: dict | None = None, now: datetime | None = None, calibration: dict | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    removed = [f for f in findings if f["status"] == "false_positive"]
    findings = [f for f in findings if f["status"] != "false_positive"]
    cfg = run.get("config") or {}
    lib = cfg.get("library") or {}
    sev = _sev_counts(findings)
    score = risk_score(sev)
    verified = [f for f in findings if f["status"] == "verified"]
    judged = [a for a in run.get("attempts", []) if not a["is_replay"] and a["outcome"].startswith("judged:")]
    passed = sum(1 for a in judged if a["outcome"] == "judged:no_violation")
    stop = EXPLAIN.get(Reason(run["stop_reason"])) if run.get("stop_reason") in Reason._value2member_map_ else None

    def sev_badge(s):
        return f'<span class="sev sev-{e(s)}">{e(SEVERITY_LABEL.get(s, s))}</span>'

    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><style>{CSS}</style></head><body>",
             "<h1>LLM Security &amp; Quality Test Report</h1>",
             f"<div class='muted'>Generated: {e(now.strftime('%Y-%m-%d %H:%M UTC'))} · Run: {e(run['id'])}</div>",
             "<h2>Executive summary</h2>",
             f"<div class='kpi'><b>{score}/100</b>Risk score · {e(risk_label(score))}</div>"
             f"<div class='kpi'><b>{len(verified)}</b>Verified findings</div>"
             f"<div class='kpi'><b>{passed}/{len(judged)}</b>Cases passed</div>",
             "<p>" + ("No verified findings: in the evaluated cases the target did not deviate from the expected safe behavior."
                      if not verified else
                      f"{len(verified)} finding(s) were verified by replaying in new conversations. Highest severity: "
                      f"<b>{e(SEVERITY_LABEL[max(sev, key=lambda s: ['info','low','medium','high','critical'].index(s))])}</b>.") + "</p>",
             "<table><tr><th>Severity</th><th>Verified findings</th></tr>" +
             "".join(f"<tr><td>{sev_badge(s)}</td><td>{sev.get(s, 0)}</td></tr>" for s in ("critical", "high", "medium", "low", "info")) +
             "</table>",
             "<h2>Test scope and run information</h2><table>",
             f"<tr><th>Target endpoint</th><td>{e(run.get('endpoint_url'))}</td></tr>",
             f"<tr><th>Model</th><td>{e(cfg.get('model'))}</td></tr>",
             f"<tr><th>Test library</th><td>{e(lib.get('name'))} v{e(lib.get('version'))}<br><span class='muted'>SHA-256 {e(lib.get('sha256'))}</span></td></tr>",
             f"<tr><th>Scope version</th><td>v{e(cfg.get('scope_version'))}</td></tr>",
             f"<tr><th>Status</th><td>{e(run['status'])}{(' - ' + e(run['stop_reason'])) if run.get('stop_reason') else ''}"
             f"{('<br><span class=muted>' + e(stop) + '</span>') if stop else ''}</td></tr>",
             f"<tr><th>Usage</th><td>{e(run.get('tokens_used'))} tokens · {e(run.get('requests'))} requests · {e(run.get('conversations'))} conversations</td></tr>"]
    if limits:
        parts.append("<tr><th>Applied limits</th><td>" + e(", ".join(f"{k}={v}" for k, v in limits.items())) + "</td></tr>")
    parts.append("</table>")
    ow = owasp_summary(run, findings)
    tested = [r for r in ow if r["status"] != "not_tested"]
    clean = sum(1 for r in tested if r["status"] == "clean")
    parts.append("<h2>OWASP Top 10 for LLM Applications (2025) - summary</h2>")
    parts.append(f"<p>Categories tested: <b>{len(tested)}/10</b> · clean: <b>{clean}</b>"
                 + (f" · compliance score (tested categories only): <b>{round(100 * clean / len(tested))}%</b>" if tested else "") + "</p>")
    parts.append("<table><tr><th>Code</th><th>Category</th><th>Status</th><th>Evaluations</th></tr>" +
                 "".join(f"<tr><td>{e(r['code'])}</td><td>{e(r['en'])}</td><td>{e(OWASP_STATUS_LABEL[r['status']])}</td>"
                         f"<td>{r['tests']}</td></tr>" for r in ow) + "</table>")
    parts.append("<p class='muted'>This summary maps behavioral quality probes made through a black-box API to OWASP categories; it is not a compliance "
                 "certificate. LLM03, LLM04 and LLM08 are only covered in a limited way by black-box testing.</p>")
    parts.append(quality_html(run, removed, calibration))
    parts.append(threat_matrix_html(run, findings))
    parts.append(suite_html(run, findings))
    parts.append(f"<h2>Findings ({len(findings)})</h2>")
    if not findings:
        parts.append("<p class='muted'>No findings recorded.</p>")
    for f in findings:
        ev = f.get("evidence") or {}
        ee = ev.get("evaluation") or {}
        rp = ev.get("replay") or {}
        parts.append(
            f"<div class='finding'><h3>{sev_badge(f['severity'])} {e(f['title'])} "
            f"<span class='muted'>· {e(STATUS_LABEL.get(f['status'], f['status']))} · {e(CLASS_LABEL.get(f['category'], f['category']))} · {e(f['case_id'])}</span></h3>"
            + (f"<div><b>{e((ev.get('impact') or {}).get('label'))}</b> <span class='muted'>- {e('; '.join((ev.get('impact') or {}).get('reasons', [])))}"
               + (f" (severity capped from {e(ev['impact'].get('severity_before_cap'))})" if (ev.get('impact') or {}).get('capped') else "") + "</span></div>" if ev.get("impact") else "") +
            (f"<div class='muted'>Adversarial verifier: {e((ev.get('verifier') or {}).get('outcome'))}"
             f"{(' - ' + e((ev.get('verifier') or {}).get('reason'))) if (ev.get('verifier') or {}).get('reason') else ''}</div>" if ev.get("verifier") else "") +
            (f"<div class='muted'>Sandbox verification: <b>{e((ev.get('sandbox') or {}).get('status'))}</b> - {e((ev.get('sandbox') or {}).get('note'))}</div>" if ev.get("sandbox") else "") +
            (f"<div class='muted'>Reasoning: {e(len((ev.get('reasoning') or {}).get('deviations', [])))} deviating step(s) of {e((ev.get('reasoning') or {}).get('total'))}; first at {e((ev.get('reasoning') or {}).get('first_deviation'))}</div>" if ev.get("reasoning") else "") +
            (f"<div class='muted'>Human review: {e((f.get('review') or {}).get('verdict'))} by {e((f.get('review') or {}).get('reviewer'))}</div>" if f.get("review") else "") +
            f"<div class='muted'>Expected safe behavior</div><div>{e((ev.get('case') or {}).get('expected_behavior'))}</div>"
            "<div class='muted' style='margin-top:2mm'>Test input sent</div>" +
            "".join(f"<pre>{e(m)}</pre>" for m in ev.get("sequence", [])) +
            "<div class='muted'>Target response (untrusted data)</div>"
            f"<pre>{e(next((m['content'] for m in reversed(ev.get('transcript') or []) if m.get('role') == 'assistant'), ''))}</pre>"
            f"<div class='muted'>Judge verdict: <b>{e(ee.get('verdict'))}</b> · confidence {e(ee.get('confidence'))}</div>"
            f"<div>{e(ee.get('rationale'))}</div>" +
            (f"<div class='muted'>Evidence quotes:</div><pre>{e(_quotes(ev))}</pre>" if _quotes(ev) else "") +
            (f"<div class='muted'>Replay: {e(rp.get('violations'))}/{e(rp.get('completed'))} repeats violated "
             f"(required {e(rp.get('required'))}/{e(rp.get('requested'))}).</div>" if rp else "") + "</div>")
    parts.append("<h2>Method and limits</h2><p class='muted'>The test content comes from an external library; responses are "
                 "evaluated by a judge LLM. A judge verdict is only accepted if the quote supporting the claim appears verbatim in the target response; a finding counts as "
                 "“verified” if it repeats in new conversations. An LLM judge can be wrong; “candidate” and “unstable” findings need human review. "
                 "Token counts rely on the provider's report, otherwise they are estimates.</p></body></html>")
    return "".join(parts)


def _deny_fetch(url, *a, **k):
    raise ValueError(f"report generation fetches no external resource: {url[:80]}")


def _fetcher():
    """A fetcher that allows no external resource. WeasyPrint >= 68: URLFetcher class (empty protocol list = everything forbidden);
    a plain function in older versions."""
    try:
        from weasyprint.urls import URLFetcher
        return URLFetcher(allowed_protocols=[], allow_redirects=False)
    except ImportError:
        return _deny_fetch


def render_pdf(html_text: str) -> bytes:
    from weasyprint import HTML
    return HTML(string=html_text, url_fetcher=_fetcher()).write_pdf()
