"use client";
import { useEffect, useState } from "react";
import { ShieldHalf } from "lucide-react";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { api, fmtDate, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";

const RESULT: Record<string, [string, any, string]> = {
  blocked: ["Blocked by the defense", "green", "violated without the defense, clean with it"],
  bypassed: ["Bypassed", "red", "violated in both"],
  regression: ["Regression", "amber", "clean without the defense, violated with it"],
  not_triggered: ["Never worked", "neutral", "clean in both: the defense is untested for this vector"],
  inconclusive: ["Inconclusive", "blue", "an error, a limit or an unconfirmed finding in either run"],
};
const STATE_TONE: Record<string, any> = { violated: "red", clean: "green", uncertain: "amber", unknown: "neutral" };
const pct = (v: number | null | undefined) => (v == null ? "n/a" : `${v}%`);

function Score({ d }: { d: any }) {
  const tone = d.score == null ? "text-slate-400" : d.score >= 80 ? "text-emerald-300" : d.score >= 50 ? "text-amber-300" : "text-rose-300";
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-black/20 p-5" data-testid="defense-score">
      <div className="text-[11px] uppercase tracking-wider text-slate-500">Defense Score</div>
      <div className={`mt-1 text-4xl font-semibold ${tone}`}>{pct(d.score)}</div>
      <div className="text-xs text-slate-500">{d.ci ? `95% CI ${d.ci[0]}-${d.ci[1]}% · ` : ""}{d.n} attack(s) worked without the defense</div>
    </div>
  );
}

function Result({ id }: { id: string }) {
  const { data: t } = usePoll<any>(() => api(`/defense-tests/${id}`), 4000, [id]);
  if (!t) return <Skeleton className="h-40" />;
  if (!t.complete) return <Card className="p-5 text-sm text-slate-400" data-testid="defense-running">Running: guardrail_off is {t.off_status}, guardrail_on is {t.on_status}. The score appears when both runs have finished.</Card>;
  const r = t.result;
  return (
    <div className="space-y-4" data-testid="defense-result">
      <div className="grid gap-3 sm:grid-cols-4">
        <Score d={r.defense} />
        {(["blocked", "bypassed", "regression"] as const).map((k) => (
          <div key={k} className="rounded-2xl border border-white/[0.08] bg-black/20 p-5"><div className="text-[11px] uppercase tracking-wider text-slate-500">{RESULT[k][0]}</div><div className="mt-1 text-3xl font-semibold text-white">{r.counts[k]}</div><div className="text-xs text-slate-500">{RESULT[k][2]}</div></div>
        ))}
      </div>
      <p className="text-[11px] leading-relaxed text-slate-500">{r.note} {r.counts.not_triggered} vector(s) never worked and {r.counts.inconclusive} were inconclusive; both are reported, not counted in the score.</p>
      <Card><CardHeader><CardTitle>Attack vectors</CardTitle></CardHeader><CardContent>
        <div className="overflow-x-auto"><table className="w-full text-left text-xs" data-testid="defense-vectors"><thead className="text-slate-500"><tr><th className="py-1.5 pr-3">Vector</th><th className="pr-3">Category</th><th className="pr-3">guardrail_off</th><th className="pr-3">guardrail_on</th><th>Result</th></tr></thead>
          <tbody>{r.vectors.map((v: any) => (
            <tr key={v.case_id} className="border-t border-white/[0.06]"><td className="py-1.5 pr-3 font-mono text-slate-300">{v.case_id}</td><td className="pr-3 text-slate-400">{v.category}{v.family ? ` · ${v.family}` : ""}</td>
              <td className="pr-3"><Badge tone={STATE_TONE[v.off]}>{v.off}</Badge></td><td className="pr-3"><Badge tone={STATE_TONE[v.on]}>{v.on}</Badge></td><td><Badge tone={RESULT[v.result][1]} title={RESULT[v.result][2]}>{RESULT[v.result][0]}</Badge></td></tr>))}</tbody></table></div>
      </CardContent></Card>
      {r.by_category.length > 0 && <Card><CardHeader><CardTitle>By category</CardTitle></CardHeader><CardContent>
        <table className="w-full text-left text-xs"><thead className="text-slate-500"><tr><th className="py-1.5">Category</th><th>Vectors</th><th>Blocked</th><th>Bypassed</th><th>Regression</th><th>Score</th></tr></thead>
          <tbody>{r.by_category.map((c: any) => <tr key={c.category} className="border-t border-white/[0.06] text-slate-300"><td className="py-1.5">{c.category}</td><td>{c.vectors}</td><td>{c.blocked}</td><td>{c.bypassed}</td><td>{c.regression}</td><td>{pct(c.score)}</td></tr>)}</tbody></table>
      </CardContent></Card>}
    </div>
  );
}

export default function Defense() {
  const { can } = useMe();
  const { data: scopes } = usePoll(() => api("/scopes"), 0);
  const { data: libs } = usePoll(() => api("/libraries"), 0);
  const { data: tests, reload } = usePoll<any[]>(() => api("/defense-tests"), 4000);
  const valid = (scopes || []).filter((s: any) => s.valid);
  const [f, setF] = useState({ scopeId: "", libId: "", off: "", on: "", offKey: "", onKey: "" });
  const [sel, setSel] = useState<string | null>(null);
  const [err, setErr] = useState(""), [busy, setBusy] = useState(false);
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));
  const scope = valid.find((s: any) => s.id === f.scopeId);
  const eps = (scope?.endpoints || []).filter((e: any) => !["chroma", "qdrant", "weaviate"].includes(e.provider));
  useEffect(() => { if (!f.scopeId && valid[0]) set("scopeId", valid[0].id); }, [valid.length]); // eslint-disable-line
  useEffect(() => { if (!f.libId && libs?.[0]) set("libId", libs[0].id); }, [libs?.length]); // eslint-disable-line
  useEffect(() => { if (eps.length >= 2 && (!eps.some((e: any) => e.url === f.off) || !eps.some((e: any) => e.url === f.on))) setF((p) => ({ ...p, off: eps[0].url, on: eps[1].url })); }, [f.scopeId, eps.length]); // eslint-disable-line
  const start = async () => {
    setErr(""); setBusy(true);
    try {
      const r = await api("/defense-tests", { method: "POST", body: JSON.stringify({ scope_id: f.scopeId, library_id: f.libId, off_endpoint_url: f.off, on_endpoint_url: f.on, off_api_key: f.offKey || null, on_api_key: f.onKey || null }) });
      setSel(r.id); set("offKey", ""); set("onKey", ""); reload();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <>
      <PageHeader title="Defense efficacy" sub="Run the same test library against an unprotected and a protected version of an application, then measure how many working attacks the defense stopped." />
      {can("operator") && (
        <Card className="mb-5" data-testid="defense-form"><CardHeader><div><CardTitle>New defense test</CardTitle><CardDescription>Pick two endpoints of the same signed scope: <b>guardrail_off</b> (no filter, plain system prompt) and <b>guardrail_on</b> (the filter or hardened prompt). The tool cannot switch a guardrail itself, so each mode is a saved target.</CardDescription></div><ShieldHalf className="h-4 w-4 text-slate-500" /></CardHeader>
          <CardContent className="space-y-4">
            {valid.length === 0 ? <Notice tone="red">No signed scope. Create and sign one on the Scopes page.</Notice> : eps.length < 2 ? <Notice tone="amber">The selected scope authorizes fewer than two endpoints. Add the protected and the unprotected endpoint to a scope version.</Notice> : null}
            <div className="grid gap-4 sm:grid-cols-2">
              <div><Label>Scope (signed)</Label><NativeSelect value={f.scopeId} onChange={(e) => set("scopeId", e.target.value)}>{valid.map((s: any) => <option key={s.id} value={s.id}>{s.name} · v{s.version}</option>)}</NativeSelect></div>
              <div><Label>Test library</Label><NativeSelect value={f.libId} onChange={(e) => set("libId", e.target.value)}>{libs?.map((l: any) => <option key={l.id} value={l.id}>{l.name} v{l.version} - {l.cases} cases</option>)}</NativeSelect></div>
              <div><Label>guardrail_off endpoint</Label><NativeSelect data-testid="defense-off" value={f.off} onChange={(e) => set("off", e.target.value)}>{eps.map((e: any) => <option key={e.url} value={e.url}>{e.model} - {e.url}</option>)}</NativeSelect>
                <Input type="password" autoComplete="off" className="mt-2" value={f.offKey} onChange={(e) => set("offKey", e.target.value)} placeholder="API key (optional, memory only)" /></div>
              <div><Label>guardrail_on endpoint</Label><NativeSelect data-testid="defense-on" value={f.on} onChange={(e) => set("on", e.target.value)}>{eps.map((e: any) => <option key={e.url} value={e.url}>{e.model} - {e.url}</option>)}</NativeSelect>
                <Input type="password" autoComplete="off" className="mt-2" value={f.onKey} onChange={(e) => set("onKey", e.target.value)} placeholder="API key (optional, memory only)" /></div>
            </div>
            {err && <Notice tone="red">{err}</Notice>}
            <div className="flex items-center gap-3"><Button data-testid="defense-start" disabled={busy || !f.scopeId || !f.libId || !f.off || !f.on || f.off === f.on} onClick={start}>Start defense test</Button><Hint>Both runs go through the same scope limits, Governor and verification. Budget is spent twice.</Hint></div>
          </CardContent></Card>)}
      <div className="grid gap-5 lg:grid-cols-[320px_1fr]">
        <div className="space-y-2" data-testid="defense-list">
          {!tests ? <Skeleton className="h-24" /> : tests.length === 0 ? <Card className="p-5 text-sm text-slate-500">No defense tests yet.</Card> : tests.map((t) => (
            <button key={t.id} onClick={() => setSel(t.id)} className={`w-full rounded-2xl border p-4 text-left transition ${sel === t.id ? "border-indigo-400/40 bg-indigo-500/[0.08]" : "border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.04]"}`}>
              <div className="flex items-center justify-between gap-2"><span className="text-xs text-slate-400">{fmtDate(t.created_at)}</span>{t.complete ? <Badge tone={t.defense?.score == null ? "neutral" : t.defense.score >= 80 ? "green" : t.defense.score >= 50 ? "amber" : "red"}>{pct(t.defense?.score)}</Badge> : <Badge tone="blue">running</Badge>}</div>
              <div className="mt-1 truncate text-xs text-slate-300">{t.config.cases} case(s) · {t.created_by}</div>
            </button>))}
        </div>
        <div>{sel ? <Result id={sel} /> : <Card className="p-8 text-center text-sm text-slate-500">Select a defense test to see its Defense Score.</Card>}</div>
      </div>
    </>
  );
}
