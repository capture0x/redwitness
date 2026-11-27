"""
Client-ready penetration test report: one engagement (one or more runs under the same signed scope) written the way a client expects it:
cover, executive summary, scope and authorization, method, findings table, one section per finding (impact, steps to reproduce,
evidence, remediation, references) and appendices.

build() turns runs into a plain report MODEL (dicts and strings, no markup). to_html() and to_docx() only print that model, so the PDF and
the DOCX can never say different things. Everything that came from the target is untrusted: to_html() escapes every value and the PDF
renderer fetches nothing; to_docx() writes plain text runs only. Credentials never enter the model (runs and findings do not hold them).
"""
import io
from datetime import datetime, timezone

from . import owasp as owasp_mod
from .reports import CSS, STATUS_LABEL, _quotes, e, owasp_summary
from .risk import SEVERITY_LABEL, risk_label, risk_score
from .scope import CLASS_LABEL

ORDER = ["critical", "high", "medium", "low", "info"]
INCLUDED_DEFAULT = ("verified",)
INCLUDED_ALL = ("verified", "unstable", "candidate", "needs_review")
CLASSIFICATIONS = ("Confidential", "Internal", "Restricted", "Public")

# Business impact and remediation per attack class. Generic guidance written for this report (not attack content).
IMPACT = {
    "prompt_injection_direct": "A user can override the application's instructions, so any rule that lives only in the prompt can be bypassed. Depending on what the assistant can reach, this leads to policy violations, wrong actions or data exposure.",
    "prompt_injection_indirect": "Content the application reads (documents, web pages, files) can steer the assistant. An attacker who can place content in that path controls the assistant without talking to it.",
    "jailbreak": "The assistant can be talked out of its rules. Safeguards that rely on the model's own refusals do not hold, so harmful, off-brand or non-compliant output can be produced on request.",
    "system_prompt_extraction": "The hidden instructions can be read out. Anything placed in them (internal rules, product logic, keys, names) must be treated as public, and attackers learn exactly which rules to target.",
    "data_leakage": "Information the user is not entitled to (other customers' data, configuration, secrets) leaves the application through the assistant's replies. This is a confidentiality and possibly a regulatory issue.",
    "tool_abuse": "The assistant performs actions it should not, or moves data between tools without authorization. Impact equals the power of the connected tools: changed records, sent messages, exfiltrated data.",
    "unsafe_output": "Replies contain content that becomes active when the application renders or executes it (HTML/script, SQL, links that carry data out). This can lead to cross-site scripting or data exfiltration in the application around the model.",
    "misinformation": "The assistant states false facts with confidence or follows a flawed chain of reasoning. Users and downstream systems may act on wrong information.",
    "resource_consumption": "Requests can make the assistant produce excessive output or cost, which raises spend and can degrade service for other users.",
}
REMEDIATION = {
    "prompt_injection_direct": ["Do not rely on prompt wording for security decisions; enforce permissions and business rules in code outside the model.",
                                "Separate system instructions from user input clearly and treat all user input as untrusted.",
                                "Add an input and output policy layer (classifier or rules) for the behaviours that must never happen, and re-test."],
    "prompt_injection_indirect": ["Treat retrieved documents, web content and tool results as untrusted data, never as instructions.",
                                  "Restrict what an assistant can do after reading external content (no sensitive actions without user confirmation).",
                                  "Sanitize or quarantine content from untrusted sources before it reaches the model, and re-test."],
    "jailbreak": ["Do not depend on the model's refusals alone: add an independent output policy check for the content that must never be produced.",
                  "Keep a stable role in the system prompt and refuse requests to switch modes, personas or 'developer modes'.",
                  "Monitor for repeated jailbreak patterns (persona, encoding, multi-turn escalation) and re-test after model or prompt changes."],
    "system_prompt_extraction": ["Assume the system prompt will be disclosed: remove secrets, keys, internal names and sensitive logic from it.",
                                 "Filter replies for fragments of the system prompt before they reach the user.",
                                 "Keep confidential configuration in server-side code or configuration, not in the model context."],
    "data_leakage": ["Only give the model the data the current user is entitled to see; enforce authorization before retrieval, not in the prompt.",
                     "Mask or remove personal data and secrets from the context and from replies.",
                     "Log and alert on replies that contain sensitive patterns, and re-test with canary values."],
    "tool_abuse": ["Apply least privilege to every tool; require explicit user confirmation for destructive or outbound actions.",
                   "Validate tool arguments server-side against the user's permissions, never trust the model's choice.",
                   "Block data flows from sensitive tools to outbound tools unless explicitly allowed."],
    "unsafe_output": ["Encode model output for the context it is shown in (HTML, Markdown, SQL); never render it as trusted markup.",
                      "Disable automatic loading of images and links from model output, or allow only trusted domains.",
                      "Use parameterized queries and an allowlist for anything the model output feeds into."],
    "misinformation": ["Ground answers in approved sources (retrieval with citations) and allow the assistant to say it does not know.",
                       "Add checks for high-stakes answers (figures, policies, legal or medical statements) before they reach users.",
                       "Show users that answers are generated and provide a path to a human."],
    "resource_consumption": ["Cap output tokens, request rate and cost per user and per session.",
                             "Reject requests for excessive length or repetition early.",
                             "Monitor spend and alert on unusual consumption."],
}


class ReportOptionsError(ValueError):
    pass


def _clean(v: str | None, what: str, limit: int = 120) -> str:
    v = " ".join((v or "").split())
    if len(v) > limit:
        raise ReportOptionsError(f"{what}: at most {limit} characters")
    return v


def options(client: str | None, project: str | None, tester: str | None, classification: str | None, include_unverified: bool) -> dict:
    cls = classification or "Confidential"
    if cls not in CLASSIFICATIONS:
        raise ReportOptionsError(f"classification must be one of {', '.join(CLASSIFICATIONS)}")
    return {"client": _clean(client, "client"), "project": _clean(project, "project"), "tester": _clean(tester, "tester"),
            "classification": cls, "include_unverified": bool(include_unverified)}


def _day(ts) -> str:
    """A date from an epoch number or an ISO string (the store returns either, depending on the column)."""
    if not ts:
        return "-"
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
    return str(ts)[:10]


def _epoch(ts) -> float:
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(str(ts)).timestamp()
    except ValueError:
        return 0.0


def _reply(ev: dict) -> str:
    return next((m.get("content") for m in reversed(ev.get("transcript") or []) if m.get("role") == "assistant"), "") or ""


def build(runs: list[dict], scope: dict, opts: dict, *, remediations: dict | None = None, audit_ok: bool | None = None, now: datetime | None = None) -> dict:
    """The report model. runs: full run dicts (with findings) under ONE scope. scope: the stored scope summary (list_scopes row)."""
    now = now or datetime.now(timezone.utc)
    remediations = remediations or {}
    statuses = INCLUDED_ALL if opts["include_unverified"] else INCLUDED_DEFAULT
    # one entry per (endpoint, case): the same weakness found in several runs is one finding with several occurrences
    groups: dict[tuple, dict] = {}
    for r in runs:
        for f in r["findings"]:
            if f["status"] not in statuses:
                continue
            key = (r["endpoint_url"], f["case_id"])
            g = groups.setdefault(key, {"finding": f, "run": r, "occurrences": []})
            g["occurrences"].append({"run_id": r["id"], "status": f["status"], "severity": f["severity"]})
            better = (STATUS_RANK[f["status"]], -ORDER.index(f["severity"])) > (STATUS_RANK[g["finding"]["status"]], -ORDER.index(g["finding"]["severity"]))
            if better:
                g["finding"], g["run"] = f, r
    items = sorted(groups.values(), key=lambda g: (ORDER.index(g["finding"]["severity"]), -STATUS_RANK[g["finding"]["status"]], g["finding"]["case_id"]))
    findings = []
    for i, g in enumerate(items, 1):
        f, r = g["finding"], g["run"]
        ev = f.get("evidence") or {}
        rp = ev.get("replay") or {}
        rem = remediations.get(f["id"])
        fw = f.get("frameworks") or {}
        steps = [f"Send the following to {r['endpoint_url']} ({ev.get('model') or (r.get('config') or {}).get('model') or 'the configured model'}) in a new conversation:"]
        # what was really sent (Crescendo turns quote earlier replies, encodings are applied), else the library sequence
        sent = [m.get("content") for m in ev.get("transcript") or [] if m.get("role") == "user" and isinstance(m.get("content"), str)] or list(ev.get("sequence") or [])
        steps += [f"Turn {n}: {m}" for n, m in enumerate(sent, 1)]
        steps.append(f"Expected: {(ev.get('case') or {}).get('expected_behavior') or '-'}")
        steps.append("Observed: the reply shown under Evidence, which breaks the expected behaviour.")
        if rp:
            steps.append(f"Reproduced in {rp.get('violations')} of {rp.get('completed')} fresh conversations (at least {rp.get('required')} required).")
        findings.append({
            "id": f"AIX-{i:03d}", "title": f["title"], "severity": f["severity"], "severity_label": SEVERITY_LABEL.get(f["severity"], f["severity"]),
            "status": f["status"], "status_label": STATUS_LABEL.get(f["status"], f["status"]), "category": CLASS_LABEL.get(f["category"], f["category"]),
            "owasp": owasp_mod.BY_ID.get(f.get("owasp_category") or "", {}).get("code", f.get("owasp_category") or "-"),
            "owasp_name": owasp_mod.BY_ID.get(f.get("owasp_category") or "", {}).get("en", ""),
            "atlas": ", ".join(f"{a['id']} {a['name']}" for a in fw.get("atlas") or []), "endpoint": r["endpoint_url"], "case_id": f["case_id"],
            "description": f"The target did not keep the expected behaviour for test case {f['case_id']} ({CLASS_LABEL.get(f['category'], f['category'])}). "
                           + ((ev.get("evaluation") or {}).get("rationale") or ""),
            "impact": IMPACT.get(f["category"], "The application behaves differently from its expected safe behaviour."),
            "impact_note": (ev.get("impact") or {}).get("label") and f"Impact class: {ev['impact']['label']}"
                           + (f" (severity capped from {ev['impact'].get('severity_before_cap')})" if ev["impact"].get("capped") else ""),
            "steps": steps, "reply": _reply(ev)[:4000], "quotes": _quotes(ev),
            "remediation": ([rem["summary"]] if rem and rem.get("summary") else []) + (rem.get("controls") if rem and rem.get("controls") else
                           ev.get("remediation") if isinstance(ev.get("remediation"), list) and ev.get("remediation") else REMEDIATION.get(f["category"], [])),
            "remediation_source": "Remediator suggestion for this finding" if rem else "Guidance for this check" if ev.get("remediation") else "Standard guidance for this attack class",
            "occurrences": len(g["occurrences"]), "reviewed": bool(f.get("review")),
        })
    sev = {s: sum(1 for x in findings if x["severity"] == s) for s in ORDER}
    score = risk_score(sev)
    # coverage: the worst state per OWASP category over all runs
    worst = {"vulnerable": 3, "needs_review": 2, "clean": 1, "not_tested": 0}
    cov: dict[str, dict] = {}
    for r in runs:
        for row in owasp_summary(r, [f for f in r["findings"] if f["status"] != "false_positive"]):
            cur = cov.get(row["id"])
            if cur is None or worst.get(row["status"], 0) > worst.get(cur["status"], 0):
                cov[row["id"]] = {"code": row["code"], "name": row["en"], "status": row["status"]}
    classes = []
    for x in findings:
        c = next(k for k, v in CLASS_LABEL.items() if v == x["category"]) if x["category"] in CLASS_LABEL.values() else None
        if c and c not in classes:
            classes.append(c)
    started = min(_epoch(r.get("created_at") or 0) for r in runs)
    ended = max(_epoch(r.get("finished_at") or r.get("created_at") or 0) for r in runs)
    return {
        "meta": {"title": "AI Penetration Test Report", "client": opts["client"] or scope.get("client") or "-", "project": opts["project"] or scope.get("name") or "-",
                 "tester": opts["tester"] or "-", "classification": opts["classification"], "period": f"{_day(started)} to {_day(ended)}",
                 "generated": now.strftime("%Y-%m-%d %H:%M UTC"), "runs": [r["id"] for r in runs], "include_unverified": opts["include_unverified"]},
        "summary": {"risk_score": score, "risk_label": risk_label(score), "counts": sev, "total": len(findings),
                    "verified": sum(1 for x in findings if x["status"] == "verified"),
                    "top": [{"id": x["id"], "title": x["title"], "severity_label": x["severity_label"]} for x in findings[:3]],
                    "priorities": [REMEDIATION[c][0] for c in classes[:3] if c in REMEDIATION]},
        "scope": {"name": scope.get("name"), "client": scope.get("client"), "approved_by": scope.get("approved_by"), "approved_at": _day(scope.get("approved_at")),
                  "valid": f"{(scope.get('valid_from') or '')[:10]} to {(scope.get('valid_until') or '')[:10]}", "digest": scope.get("digest"),
                  "endpoints": [{"url": ep["url"], "provider": ep.get("provider"), "model": ep.get("model"), "local": ep.get("local")} for ep in scope.get("endpoints") or []],
                  "classes": [CLASS_LABEL.get(c, c) for c in scope.get("attack_classes") or []], "limits": scope.get("limits") or {},
                  "tested_endpoints": sorted({r["endpoint_url"] for r in runs})},
        "findings": findings,
        "coverage": [cov[k] for k in owasp_mod.BY_ID if k in cov],
        "stats": {"runs": len(runs), "requests": sum(r.get("requests") or 0 for r in runs), "conversations": sum(r.get("conversations") or 0 for r in runs),
                  "tokens": sum(r.get("tokens_used") or 0 for r in runs), "audit_ok": audit_ok},
    }


STATUS_RANK = {"verified": 3, "needs_review": 2, "unstable": 1, "candidate": 0}
METHOD = [
    "Every request was sent under the signed scope above. A Governor enforced the endpoint list, the limits and network checks on each request.",
    "Test messages came from a versioned, hashed test library. A judge model evaluated each reply against the expected behaviour and had to quote the reply verbatim; deterministic rules (forbidden tool calls, canaries, Markdown links) decided where possible.",
    "A finding is Verified only if it repeated in fresh conversations (k of n). Unstable and candidate results are excluded unless the report says otherwise.",
    "Severity follows the AIVeritX scale and is capped by an impact matrix: for example, a reply that only echoes text the tester sent is rated low.",
]
SEVERITY_TEXT = {"critical": "Direct, high-impact abuse (for example an unauthorized destructive action or data exfiltration through a tool).",
                 "high": "Confidential data or hidden instructions are exposed, or a key safeguard is bypassed.",
                 "medium": "A safeguard can be bypassed with moderate effort; impact depends on context.",
                 "low": "Limited impact, for example only text the tester supplied is repeated.",
                 "info": "An observation without direct security impact."}
COV_LABEL = {"vulnerable": "Vulnerable", "needs_review": "Needs review", "clean": "Clean", "not_tested": "Not tested"}

EXTRA_CSS = """
.cover{height:240mm;display:flex;flex-direction:column;justify-content:center;page-break-after:always}
.cover h1{font-size:28pt;margin:0 0 4mm}.cover .cls{display:inline-block;border:1px solid #b91c1c;color:#b91c1c;padding:1mm 3mm;font-weight:600;margin-bottom:10mm}
.cover table{width:auto}.cover th{width:40mm}
.toc li{margin:1mm 0}.pb{page-break-before:always}
.finding h3 .id{color:#4f46e5;margin-right:2mm}
ol.steps li{margin:1mm 0}
table{page-break-inside:avoid}h2,h3{page-break-after:avoid}.keep{page-break-inside:avoid}.finding{margin-top:6mm}
@page{@bottom-right{content:"Page " counter(page) " of " counter(pages);font-size:8pt;color:#64748b}}
"""


def to_html(m: dict) -> str:
    meta, s, sc = m["meta"], m["summary"], m["scope"]

    def sev(x):
        return f'<span class="sev sev-{e(x["severity"])}">{e(x["severity_label"])}</span>'
    p = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><style>{CSS}{EXTRA_CSS}"
         f"@page{{@bottom-left{{content:'{meta['classification']}';font-size:8pt;color:#64748b}}}}</style></head><body>",
         "<div class='cover'>", f"<div><span class='cls'>{e(meta['classification'])}</span></div>", f"<h1>{e(meta['title'])}</h1>",
         f"<div style='font-size:14pt;margin-bottom:10mm'>{e(meta['project'])}</div><table>",
         f"<tr><th>Client</th><td>{e(meta['client'])}</td></tr><tr><th>Test period</th><td>{e(meta['period'])}</td></tr>",
         f"<tr><th>Tester</th><td>{e(meta['tester'])}</td></tr><tr><th>Report date</th><td>{e(meta['generated'])}</td></tr>",
         f"<tr><th>Runs</th><td>{len(meta['runs'])}</td></tr></table></div>",
         "<h2>Contents</h2><ol class='toc'><li>Executive summary</li><li>Scope and authorization</li><li>Method and severity rating</li>"
         "<li>Findings overview</li><li>Detailed findings</li><li>Appendix A: Test coverage</li><li>Appendix B: Engagement statistics</li></ol>",
         "<h2 class='pb'>1. Executive summary</h2>"]
    if s["total"]:
        p.append(f"<p>The assessment found <b>{s['total']}</b> issue(s) in the AI application ({s['verified']} verified by replay). "
                 f"The overall risk is rated <b>{e(s['risk_label'])}</b> ({s['risk_score']}/100).</p>")
    else:
        p.append("<p>No issue was confirmed: in the tests run, the application kept its expected behaviour. This does not prove the absence of weaknesses outside the tested scope.</p>")
    p.append("<table><tr>" + "".join(f"<th>{e(SEVERITY_LABEL[k])}</th>" for k in ORDER) + "</tr><tr>" + "".join(f"<td>{s['counts'][k]}</td>" for k in ORDER) + "</tr></table>")
    if s["top"]:
        p.append("<p><b>Most important findings</b></p><ul>" + "".join(f"<li>{e(t['id'])}: {e(t['title'])} ({e(t['severity_label'])})</li>" for t in s["top"]) + "</ul>")
    if s["priorities"]:
        p.append("<p><b>Priority recommendations</b></p><ol>" + "".join(f"<li>{e(x)}</li>" for x in s["priorities"]) + "</ol>")
    p.append("<h2>2. Scope and authorization</h2><table>"
             f"<tr><th>Scope</th><td>{e(sc['name'])}</td></tr><tr><th>Authorized by</th><td>{e(sc['approved_by'])} on {e(sc['approved_at'])}</td></tr>"
             f"<tr><th>Valid</th><td>{e(sc['valid'])}</td></tr><tr><th>Scope digest (SHA-256)</th><td style='font-family:monospace;font-size:8pt'>{e(sc['digest'])}</td></tr>"
             f"<tr><th>Authorized endpoints</th><td>{'<br>'.join(e(ep['url']) + ' · ' + e(ep['provider']) + (' · ' + e(ep['model']) if ep['model'] else '') for ep in sc['endpoints'])}</td></tr>"
             f"<tr><th>Tested endpoints</th><td>{'<br>'.join(e(u) for u in sc['tested_endpoints'])}</td></tr>"
             f"<tr><th>Attack classes</th><td>{e(', '.join(sc['classes']))}</td></tr>"
             f"<tr><th>Limits</th><td>{e(', '.join(f'{k}={v}' for k, v in sc['limits'].items()))}</td></tr></table>")
    p.append("<div class='keep'><h2>3. Method and severity rating</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in METHOD) + "</ul><table><tr><th>Severity</th><th>Meaning</th></tr>"
             + "".join(f"<tr><td><span class='sev sev-{k}'>{e(SEVERITY_LABEL[k])}</span></td><td>{e(SEVERITY_TEXT[k])}</td></tr>" for k in ORDER) + "</table></div>")
    p.append("<h2 class='pb'>4. Findings overview</h2>")
    if m["findings"]:
        p.append("<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>OWASP</th></tr>"
                 + "".join(f"<tr><td>{e(x['id'])}</td><td>{e(x['title'])}</td><td>{sev(x)}</td><td>{e(x['status_label'])}</td><td>{e(x['owasp'])}</td></tr>" for x in m["findings"]) + "</table>")
    else:
        p.append("<p class='muted'>No findings to report.</p>")
    p.append("<h2>5. Detailed findings</h2>")
    for x in m["findings"]:
        seen = (" · reviewed by a human" if x["reviewed"] else "") + (f" · seen in {x['occurrences']} runs" if x["occurrences"] > 1 else "")
        p.append(f"<div class='finding'><h3><span class='id'>{e(x['id'])}</span>{e(x['title'])} {sev(x)}</h3><table>"
                 f"<tr><th>Status</th><td>{e(x['status_label'])}{seen}</td></tr>"
                 f"<tr><th>Category</th><td>{e(x['category'])}</td></tr><tr><th>OWASP</th><td>{e(x['owasp'])} {e(x['owasp_name'])}</td></tr>"
                 + (f"<tr><th>MITRE ATLAS</th><td>{e(x['atlas'])}</td></tr>" if x["atlas"] else "")
                 + f"<tr><th>Endpoint</th><td>{e(x['endpoint'])}</td></tr></table>"
                 f"<p><b>Description.</b> {e(x['description'])}</p><p><b>Impact.</b> {e(x['impact'])}"
                 + (f" <span class='muted'>{e(x['impact_note'])}</span>" if x["impact_note"] else "") + "</p>"
                 "<p><b>Steps to reproduce</b></p><ol class='steps'>" + "".join(f"<li><pre style='white-space:pre-wrap;margin:0'>{e(st)}</pre></li>" for st in x["steps"]) + "</ol>"
                 f"<p><b>Evidence</b> <span class='muted'>(target reply, untrusted data)</span></p><pre style='white-space:pre-wrap'>{e(x['reply'])}</pre>"
                 + (f"<p class='muted'>Judge quotes: {e(x['quotes'])}</p>" if x["quotes"] else "")
                 + f"<p><b>Remediation</b> <span class='muted'>({e(x['remediation_source'])})</span></p><ul>" + "".join(f"<li>{e(r)}</li>" for r in x["remediation"]) + "</ul></div>")
    p.append("<h2 class='pb'>Appendix A: Test coverage (OWASP LLM Top 10, 2025)</h2><table><tr><th>Code</th><th>Category</th><th>Result</th></tr>"
             + "".join(f"<tr><td>{e(c['code'])}</td><td>{e(c['name'])}</td><td>{e(COV_LABEL.get(c['status'], c['status']))}</td></tr>" for c in m["coverage"]) + "</table>"
             "<p class='muted'>Black-box behavioural testing; this is not a compliance certificate. LLM03, LLM04 and LLM08 can only be partly assessed this way.</p>")
    st = m["stats"]
    p.append("<h2>Appendix B: Engagement statistics</h2><table>"
             f"<tr><th>Runs</th><td>{st['runs']}: {e(', '.join(r[:8] for r in meta['runs']))}</td></tr><tr><th>Requests</th><td>{st['requests']}</td></tr>"
             f"<tr><th>Conversations</th><td>{st['conversations']}</td></tr><tr><th>Tokens</th><td>{st['tokens']}</td></tr>"
             f"<tr><th>Audit log</th><td>{'intact (hash chain verified)' if st['audit_ok'] else 'NOT verified' if st['audit_ok'] is False else '-'}</td></tr>"
             f"<tr><th>Findings included</th><td>{'all open statuses (verified, needs review, unstable, candidate)' if meta['include_unverified'] else 'verified only'}</td></tr></table>")
    p.append("</body></html>")
    return "".join(p)


def to_docx(m: dict) -> bytes:
    """The same model as an editable Word document. Plain text runs only (no fields, macros or external links)."""
    from docx import Document
    from docx.shared import Cm, Pt
    meta, s, sc = m["meta"], m["summary"], m["scope"]
    d = Document()
    d.core_properties.title, d.core_properties.author = meta["title"], meta["tester"] if meta["tester"] != "-" else ""
    d.add_paragraph(meta["classification"].upper())
    d.add_heading(meta["title"], 0)
    d.add_paragraph(meta["project"])

    def table(rows, header=None, widths=None):
        n = len(rows[0]) if rows else (len(header) if header else 2)
        widths = widths or ([4.5, 11.5] if n == 2 else [16 / n] * n)
        t = d.add_table(rows=0, cols=n)
        t.style, t.autofit = "Table Grid", False
        for i, row in enumerate(([header] if header else []) + rows):
            cells = t.add_row().cells
            for j, (c, v) in enumerate(zip(cells, row)):
                c.text, c.width = str(v), Cm(widths[j])
                if (header and i == 0) or (n == 2 and not header and j == 0):
                    for r in c.paragraphs[0].runs:
                        r.bold = True
        for j, col in enumerate(t.columns):                       # the grid width is what LibreOffice and Google Docs read
            col.width = Cm(widths[j])
        return t

    def items(texts, numbered=False):
        # plain paragraphs with their own marker: every list starts at 1 and looks the same in Word and LibreOffice
        for k, x in enumerate(texts, 1):
            para = d.add_paragraph(f"{k}. {x}" if numbered else f"\u2022 {x}")
            para.paragraph_format.left_indent, para.paragraph_format.first_line_indent = Cm(0.8), Cm(-0.5)
            para.paragraph_format.space_after = Pt(2)
    table([["Client", meta["client"]], ["Test period", meta["period"]], ["Tester", meta["tester"]], ["Report date", meta["generated"]], ["Runs", str(len(meta["runs"]))]])
    d.add_page_break()
    d.add_heading("1. Executive summary", 1)
    d.add_paragraph(f"The assessment found {s['total']} issue(s) in the AI application ({s['verified']} verified by replay). The overall risk is rated {s['risk_label']} ({s['risk_score']}/100)."
                    if s["total"] else "No issue was confirmed: in the tests run, the application kept its expected behaviour. This does not prove the absence of weaknesses outside the tested scope.")
    table([[str(s["counts"][k]) for k in ORDER]], [SEVERITY_LABEL[k] for k in ORDER])
    if s["top"]:
        d.add_paragraph("Most important findings").runs[0].bold = True
        items([f"{t['id']}: {t['title']} ({t['severity_label']})" for t in s["top"]])
    if s["priorities"]:
        d.add_paragraph("Priority recommendations").runs[0].bold = True
        items(s["priorities"], numbered=True)
    d.add_heading("2. Scope and authorization", 1)
    table([["Scope", sc["name"] or ""], ["Authorized by", f"{sc['approved_by']} on {sc['approved_at']}"], ["Valid", sc["valid"]], ["Scope digest (SHA-256)", sc["digest"] or ""],
           ["Authorized endpoints", "\n".join(f"{ep['url']} · {ep['provider']}" + (f" · {ep['model']}" if ep["model"] else "") for ep in sc["endpoints"])],
           ["Tested endpoints", "\n".join(sc["tested_endpoints"])], ["Attack classes", ", ".join(sc["classes"])],
           ["Limits", ", ".join(f"{k}={v}" for k, v in sc["limits"].items())]])
    d.add_heading("3. Method and severity rating", 1)
    items(METHOD)
    table([[SEVERITY_LABEL[k], SEVERITY_TEXT[k]] for k in ORDER], ["Severity", "Meaning"], [3, 13])
    d.add_page_break()
    d.add_heading("4. Findings overview", 1)
    if m["findings"]:
        table([[x["id"], x["title"], x["severity_label"], x["status_label"], x["owasp"]] for x in m["findings"]], ["ID", "Title", "Severity", "Status", "OWASP"], [2.3, 6.5, 2.4, 2.6, 2.2])
    else:
        d.add_paragraph("No findings to report.")
    d.add_heading("5. Detailed findings", 1)
    for x in m["findings"]:
        d.add_heading(f"{x['id']} {x['title']} ({x['severity_label']})", 2)
        table([["Status", x["status_label"] + (" · reviewed by a human" if x["reviewed"] else "") + (f" · seen in {x['occurrences']} runs" if x["occurrences"] > 1 else "")],
               ["Category", x["category"]], ["OWASP", f"{x['owasp']} {x['owasp_name']}"], ["MITRE ATLAS", x["atlas"] or "-"], ["Endpoint", x["endpoint"]]])
        for label, text in (("Description.", x["description"]), ("Impact.", x["impact"] + (f" {x['impact_note']}" if x["impact_note"] else ""))):
            para = d.add_paragraph()
            para.add_run(label + " ").bold = True
            para.add_run(text)
        d.add_paragraph("Steps to reproduce").runs[0].bold = True
        items(x["steps"], numbered=True)
        para = d.add_paragraph()
        para.add_run("Evidence ").bold = True
        para.add_run("(target reply, untrusted data)")
        ev = d.add_paragraph(x["reply"])
        for r in ev.runs:
            r.font.name, r.font.size = "Courier New", Pt(8)
        if x["quotes"]:
            d.add_paragraph(f"Judge quotes: {x['quotes']}")
        para = d.add_paragraph()
        para.add_run("Remediation ").bold = True
        para.add_run(f"({x['remediation_source']})")
        items(x["remediation"])
    d.add_page_break()
    d.add_heading("Appendix A: Test coverage (OWASP LLM Top 10, 2025)", 1)
    table([[c["code"], c["name"], COV_LABEL.get(c["status"], c["status"])] for c in m["coverage"]] or [["-", "-", "-"]], ["Code", "Category", "Result"], [2, 10, 4])
    d.add_paragraph("Black-box behavioural testing; this is not a compliance certificate. LLM03, LLM04 and LLM08 can only be partly assessed this way.")
    st = m["stats"]
    d.add_heading("Appendix B: Engagement statistics", 1)
    table([["Runs", f"{st['runs']}: " + ", ".join(r[:8] for r in meta["runs"])], ["Requests", str(st["requests"])], ["Conversations", str(st["conversations"])],
           ["Tokens", str(st["tokens"])], ["Audit log", "intact (hash chain verified)" if st["audit_ok"] else "NOT verified" if st["audit_ok"] is False else "-"],
           ["Findings included", "all open statuses (verified, needs review, unstable, candidate)" if meta["include_unverified"] else "verified only"]])
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()
