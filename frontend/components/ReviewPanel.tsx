"use client";
import { useState } from "react";
import { CheckCircle2, Scale, ShieldQuestion, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useMe } from "@/lib/me";

export const IMPACT_TONE: Record<string, any> = { action_executed: "critical", data_exfiltrated: "critical", data_exposed: "high", system_prompt_leaked: "high", reasoning_deviation: "amber", policy_bypass: "amber", text_echo: "neutral" };
export const SANDBOX: Record<string, [string, any]> = { verified_exploitable: ["Verified exploitable", "red"], not_exploitable: ["Not exploitable", "green"], not_applicable: ["Sandbox: not applicable", "neutral"], unavailable: ["Sandbox unavailable", "neutral"] };
const VERIFIER: Record<string, [string, any]> = { refuted: ["Refuted by verifier", "amber"], upheld: ["Verifier: upheld", "green"], skipped: ["Proven deterministically", "blue"], invalid: ["Verifier: no answer", "neutral"] };

/** Evidence & impact, the adversarial verifier's opinion, and the human True/False-positive label (the feedback loop that calibrates the platform). */
export default function ReviewPanel({ f, onChange }: { f: any; onChange?: () => void }) {
  const { can } = useMe();
  const [note, setNote] = useState(""), [busy, setBusy] = useState(false), [err, setErr] = useState("");
  const ev = f.evidence || {}, imp = ev.impact, ver = ev.verifier, rv = f.review;
  const send = async (verdict: string) => {
    setBusy(true); setErr("");
    try { await api(`/findings/${f.id}/review`, { method: "POST", body: JSON.stringify({ verdict, note }) }); setNote(""); onChange?.(); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-4" data-testid="review-panel">
      <div><div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">Evidence &amp; impact</div>
        {imp ? <div className="space-y-1.5 text-sm text-slate-300"><div className="flex flex-wrap items-center gap-2"><Badge tone={IMPACT_TONE[imp.impact]} data-testid="impact-label">{imp.label}</Badge>
          {imp.capped && <span className="text-xs text-amber-300" data-testid="impact-capped">severity capped from {imp.severity_before_cap} to {ev.case?.severity} because the evidence is {imp.label.toLowerCase()}</span>}</div>
          <ul className="list-disc space-y-0.5 pl-5 text-xs text-slate-400">{imp.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}</ul>
          <p className="text-[11px] text-slate-500">Critical is only possible when the target really acted (forbidden tool call, data leaving through an outbound tool) or protected data / hidden instructions appeared that were not part of what was sent.</p></div>
          : <p className="text-sm text-slate-500">No impact classification for this record.</p>}</div>
      <div><div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">Adversarial verifier (devil&apos;s advocate)</div>
        {ver ? <div className="space-y-1 text-sm text-slate-300"><Badge tone={VERIFIER[ver.outcome]?.[1]} data-testid="verifier-outcome">{VERIFIER[ver.outcome]?.[0] || ver.outcome}</Badge>
          {ver.reason && <p className="text-xs text-slate-400">{ver.argument !== "none" && <b className="text-slate-300">{String(ver.argument).replace(/_/g, " ")}: </b>}{ver.reason}</p>}
          {ver.quote && <p className="text-xs text-slate-500">quote: “{ver.quote}”</p>}{ver.note && <p className="text-xs text-slate-500">{ver.note}</p>}</div>
          : <p className="text-sm text-slate-500">Not run for this finding (not replay-confirmed, or the verifier is switched off).</p>}</div>
      {ev.sandbox && <div><div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">Sandboxed verification</div>
        <div className="space-y-1 text-sm text-slate-300" data-testid="sandbox-panel"><Badge tone={SANDBOX[ev.sandbox.status]?.[1]} data-testid="sandbox-status">{SANDBOX[ev.sandbox.status]?.[0] || ev.sandbox.status}</Badge>
          <p className="text-xs text-slate-400">{ev.sandbox.note}</p>
          {ev.sandbox.checks?.map((c: any, i: number) => <p key={i} className="text-xs text-slate-500">{c.kind}{c.fenced ? " (inside a code block)" : ""} · {c.method} · {c.exploitable ? "harmful effect" : "no harmful effect"}{c.effects?.length ? `: ${c.effects.map((e: any) => e.detail).join("; ")}` : ""}</p>)}
          <p className="text-[11px] text-slate-500">Isolation: {ev.sandbox.isolation}. A sandbox label never removes a finding or changes its severity.</p></div></div>}
      <div><div className="mb-1 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-slate-500"><Scale className="h-3.5 w-3.5" />Human review</div>
        <p className="mb-2 text-xs text-slate-500">System decision: <b className="text-slate-300">{String(f.system_status || f.status).replace(/_/g, " ")}</b>.{rv && <> Your label: <b className="text-slate-200">{rv.verdict.replace(/_/g, " ")}</b> by {rv.reviewer}{rv.note ? ` - “${rv.note}”` : ""}.</>}</p>
        {can("operator") ? <div className="flex flex-wrap items-center gap-2">
          <Input className="max-w-xs" placeholder="Optional note" maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => send("true_positive")} data-testid="review-tp"><CheckCircle2 className="h-4 w-4 text-emerald-300" />True positive</Button>
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => send("false_positive")} data-testid="review-fp"><XCircle className="h-4 w-4 text-rose-300" />False positive</Button>
          {rv && <Button size="sm" variant="ghost" disabled={busy} onClick={() => send("clear")} data-testid="review-clear"><ShieldQuestion className="h-4 w-4" />Clear label</Button>}</div>
          : <p className="text-xs text-slate-500">Only operators and admins can label findings.</p>}
        {err && <p className="mt-1 text-xs text-rose-300">{err}</p>}
        <p className="mt-2 text-[11px] text-slate-500">A false positive leaves reports, scores and CI gates but stays in the database for audit; labels feed the precision/recall measurement.</p></div>
    </div>
  );
}
