"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import { ArrowRight, FileImage, GitBranch, Layers3, Map as MapIcon, Play, Square, Waypoints } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import PageHeader from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, NativeSelect, Textarea } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

const NODE_TONE: Record<string, { tone: any; label: string; dot: string }> = {
  covered: { tone: "green", label: "Covered", dot: "bg-emerald-400" },
  uncovered: { tone: "amber", label: "Not covered", dot: "bg-amber-400" },
  exposed: { tone: "red", label: "Exposed a protected term", dot: "bg-rose-400" },
  empty: { tone: "neutral", label: "Empty reply", dot: "bg-slate-400" },
  error: { tone: "red", label: "Error", dot: "bg-rose-400" },
  skipped: { tone: "neutral", label: "Not asked", dot: "bg-slate-600" },
};
const OUTCOME_TONE: Record<string, any> = { clean: "green", refused: "amber", violation: "red", unverified: "blue", error: "neutral" };
const pct = (v: number | null | undefined) => (v === null || v === undefined ? "-" : `${Math.round(v * 100)}%`);

function Explain({ icon: Icon, title, children }: { icon: any; title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4 flex gap-3 rounded-2xl border border-white/10 bg-white/[0.03] p-4">
      <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-violet-500/15 text-violet-300"><Icon className="h-4.5 w-4.5" /></div>
      <div><div className="text-sm font-semibold text-white">{title}</div><p className="mt-1 max-w-3xl text-xs leading-relaxed text-slate-400">{children}</p></div>
    </div>
  );
}

const Empty = ({ children }: { children: React.ReactNode }) => <div className="rounded-2xl border border-dashed border-white/10 p-8 text-center text-sm text-slate-500">{children}</div>;

// ------------------------------------------------------------------ multimodal
function Multimodal({ findings, sys }: { findings: any[]; sys: any }) {
  const rows = findings.filter((f) => f.evidence?.multimodal);
  return (
    <>
      <Explain icon={FileImage} title="Multimodal carrier">
        An image or audio file written into the test library is attached to a message. The platform only carries it: before sending, it reads what the file really contains (OCR text, metadata) and refuses to send it if one of your canary values is inside.
        Audio speech is not transcribed. The signed scope must allow files (<code>multimodal_allowed</code>).
      </Explain>
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
        <Badge tone={sys?.ocr_available ? "green" : "amber"} data-testid="ocr-status">OCR engine: {sys?.ocr_available ? "available" : "not installed (images are still sent; OCR text and the canary text check are skipped)"}</Badge>
        <Link href="/library" className="text-indigo-300 hover:text-indigo-200">Import the multimodal example from the Test Library →</Link>
      </div>
      {rows.length === 0 ? <Empty>No finding came from a multimodal case yet. Import “Multimodal carrier” in the Test Library, allow files in a scope and run it.</Empty> : (
        <div className="grid gap-3 lg:grid-cols-2">{rows.map((f) => (
          <Card key={f.id}><CardContent className="p-5">
            <div className="flex flex-wrap items-center gap-2"><Badge tone={f.severity === "critical" ? "red" : "amber"}>{f.severity}</Badge><Badge tone="neutral">{f.status}</Badge></div>
            <div className="mt-2 text-sm font-semibold text-white">{f.title}</div>
            <div className="mt-3 space-y-2">{f.evidence.multimodal.preflight.files.map((fl: any) => (
              <div key={fl.name} className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs">
                <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-slate-200">{fl.name}</span><span className="text-slate-500">{fl.format} · {fl.bytes} bytes</span>
                  {fl.kind === "image" ? <Badge tone={fl.ocr_status === "ok" ? "green" : "amber"}>OCR {fl.ocr_status}</Badge> : <Badge tone="amber">speech not transcribed</Badge>}
                  {fl.carries_undeclared_text && <Badge tone="amber">undeclared text</Badge>}</div>
                {fl.ocr_text && <pre className="mt-2 max-h-24 overflow-auto whitespace-pre-wrap text-slate-400">{fl.ocr_text}</pre>}
              </div>))}</div>
            <Link href={`/runs/${f.run_id}`} className="mt-3 inline-flex items-center gap-1 text-xs text-indigo-300 hover:text-indigo-200">Open the run <ArrowRight className="h-3 w-3" /></Link>
          </CardContent></Card>))}</div>)}
    </>
  );
}

// ------------------------------------------------------------------ agent chains
function Chains({ findings }: { findings: any[] }) {
  const rows = findings.filter((f) => f.evidence?.agentic_chain);
  return (
    <>
      <Explain icon={GitBranch} title="Agentic tool chains">
        A scripted scenario with fake tools (nothing is executed). Every step's message comes from the library and may quote what an earlier step's tool returned. A call to a forbidden tool, or protected data reaching an outbound (egress) tool, is a critical finding decided in code, without a judge.
      </Explain>
      {rows.length === 0 ? <Empty>No finding came from an agentic chain yet. Import “Agentic tool chain” in the Test Library; the scope needs tool abuse and the test-environment attestation.</Empty> : (
        <div className="space-y-3">{rows.map((f) => {
          const c = f.evidence.agentic_chain, v = f.evidence.tool_sandbox?.violations || [];
          return (
            <Card key={f.id}><CardContent className="p-5">
              <div className="flex flex-wrap items-center gap-2"><Badge tone={f.severity === "critical" ? "red" : "amber"}>{f.severity}</Badge><Badge tone="neutral">{f.status}</Badge>{v.map((x: any, i: number) => <Badge key={i} tone="red">{x.rule}</Badge>)}</div>
              <div className="mt-2 text-sm font-semibold text-white">{f.title}</div>
              <div className="mt-3 flex flex-wrap items-center gap-2 font-mono text-xs" data-testid="chain-path">
                {c.steps.map((s: any, i: number) => (
                  <span key={s.id} className="flex items-center gap-2">{i > 0 && <ArrowRight className="h-3.5 w-3.5 text-slate-600" />}
                    <span className="rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1.5"><span className="text-slate-500">{s.id}</span>{" "}
                      {s.called.length ? s.called.map((n: string) => <b key={n} className={cn("mr-1", c.forbidden_tools.includes(n) ? "text-rose-300" : c.egress_tools.includes(n) ? "text-orange-300" : "text-slate-200")}>{n}</b>) : <i className="text-slate-500">no tool</i>}</span></span>))}
              </div>
              {v.map((x: any, i: number) => <div key={i} className="mt-3 rounded-xl border border-red-400/20 bg-red-500/[0.07] p-3 text-xs text-slate-300">{x.detail}</div>)}
              <Link href={`/runs/${f.run_id}`} className="mt-3 inline-flex items-center gap-1 text-xs text-indigo-300 hover:text-indigo-200">Open the run <ArrowRight className="h-3 w-3" /></Link>
            </CardContent></Card>);
        })}</div>)}
    </>
  );
}

// ------------------------------------------------------------------ knowledge map
function TreeNode({ n, depth }: { n: any; depth: number }) {
  const st = NODE_TONE[n.status] || NODE_TONE.skipped;
  return (
    <div data-testid={`kn-${n.id}`}>
      <div className="flex items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] px-3 py-2.5" style={{ marginLeft: depth * 22 }}>
        <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", st.dot)} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><span className="text-sm text-slate-100">{n.question}</span><Badge tone={st.tone}>{st.label}</Badge><Badge tone="neutral">{n.topic}</Badge></div>
          {(n.found.length > 0 || n.missing.length > 0 || n.exposed.length > 0) && (
            <div className="mt-1.5 flex flex-wrap gap-1.5 text-[11px]">
              {n.found.map((t: string) => <span key={t} className="rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-emerald-300">✓ {t}</span>)}
              {n.missing.map((t: string) => <span key={t} className="rounded-md bg-white/[0.05] px-1.5 py-0.5 text-slate-500">✗ {t}</span>)}
              {n.exposed.map((t: string) => <span key={t} className="rounded-md bg-rose-500/15 px-1.5 py-0.5 text-rose-300">exposed: {t}</span>)}</div>)}
          {n.excerpt && <div className="mt-1.5 line-clamp-2 text-xs text-slate-500">{n.excerpt}</div>}
        </div>
      </div>
      <div className="mt-1.5 space-y-1.5">{n.children.map((c: any) => <TreeNode key={c.id} n={c} depth={depth + 1} />)}</div>
    </div>
  );
}

function Knowledge({ maps }: { maps: any[] }) {
  const [sel, setSel] = useState<string>("");
  const cur = maps.find((m) => m.id === sel) || maps[0];
  const s = cur?.tree.summary;
  return (
    <>
      <Explain icon={MapIcon} title="Knowledge Graph & Coverage Mapper">
        Exploration and reporting, not attack generation. A tree of questions you wrote in the library is asked of the target; the tree you see here is built from its replies by string matching in code: which topics it knows, and whether any protected value leaked.
        A child question is asked only when its parent was covered.
      </Explain>
      {maps.length === 0 ? <Empty>No knowledge map yet. Import “Knowledge map” in the Test Library and run it.</Empty> : (
        <div className="space-y-4">
          <div className="max-w-xl"><NativeSelect value={cur.id} onChange={(e) => setSel(e.target.value)} data-testid="kn-select">
            {maps.map((m) => <option key={m.id} value={m.id}>{m.case_id} · {new Date(m.created_at * 1000).toLocaleString()}</option>)}</NativeSelect></div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {[["Questions asked", `${s.asked}/${s.nodes}`], ["Covered", s.covered], ["Not covered", s.uncovered], ["Protected terms exposed", s.exposed_terms], ["Term coverage", pct(s.coverage)]].map(([k, v]) => (
              <div key={k as string} className="glass rounded-2xl p-4"><div className="text-[11px] uppercase tracking-wider text-slate-500">{k}</div><div className={cn("mt-1 text-2xl font-semibold tabular-nums text-white", k === "Protected terms exposed" && s.exposed_terms ? "text-rose-300" : "")} data-testid={`kn-kpi-${(k as string).split(" ")[0].toLowerCase()}`}>{v}</div></div>))}
          </div>
          <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
            <div className="space-y-1.5" data-testid="kn-tree">{cur.tree.roots.map((r: any) => <TreeNode key={r.id} n={r} depth={0} />)}</div>
            <Card className="h-fit"><CardHeader><CardTitle>Coverage by topic</CardTitle><CardDescription>Expected terms the target mentioned.</CardDescription></CardHeader>
              <CardContent className="space-y-3">{cur.tree.topics.map((t: any) => (
                <div key={t.topic}><div className="flex justify-between text-xs text-slate-300"><span>{t.topic}</span><span className="tabular-nums text-slate-500">{t.found}/{t.terms} terms · {t.asked}/{t.nodes} asked</span></div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className={cn("h-full rounded-full", t.exposed ? "bg-rose-400" : "bg-emerald-400")} style={{ width: `${t.terms ? (100 * t.found) / t.terms : 0}%` }} /></div></div>))}
                <p className="pt-2 text-[11px] text-slate-500">{cur.tree.note}</p></CardContent></Card>
          </div>
        </div>)}
    </>
  );
}

// ------------------------------------------------------------------ campaigns
function Campaigns({ scopes, libs }: { scopes: any[]; libs: any[] }) {
  const { can } = useMe();
  const { data: camps, reload: refresh } = usePoll(() => api("/campaigns"), 3000);
  const allowed = scopes.filter((s) => s.valid && s.campaign_allowed);
  const [f, setF] = useState({ name: "", scope_id: "", endpoint_url: "", library_id: "", ladder: "", cooldown_seconds: 0, max_sessions: 5, patience: 2 });
  const [ladders, setLadders] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [run, setRun] = useState({ api_key: "", canaries: "", reference: "" });
  const scope = scopes.find((s) => s.id === f.scope_id);
  const pickLib = async (id: string) => {
    setF({ ...f, library_id: id, ladder: "" }); setLadders([]);
    if (!id) return;
    try { const l = await api(`/libraries/${id}`); setLadders([...new Set<string>((l.case_list || []).filter((c: any) => c.campaign).map((c: any) => c.campaign.ladder))]); } catch { /* ignore */ }
  };
  const create = async () => {
    setErr(null);
    try { await api("/campaigns", { method: "POST", body: JSON.stringify(f) }); setF({ ...f, name: "" }); refresh?.(); } catch (e: any) { setErr(e.message); }
  };
  const advance = async (id: string) => {
    setErr(null); setNote(null);
    try {
      const r = await api(`/campaigns/${id}/advance`, { method: "POST", body: JSON.stringify({ api_key: run.api_key || null, canaries: run.canaries.split("\n").map((x) => x.trim()).filter(Boolean), reference: run.reference }) });
      setNote(r.finished ? `Finished: ${r.reason}` : `Session ${r.seq} started: case ${r.case_id} (level ${r.level}) - ${r.why}`); refresh?.();
    } catch (e: any) { setErr(e.message); }
  };
  const stop = async (id: string) => { try { await api(`/campaigns/${id}/stop`, { method: "POST" }); refresh?.(); } catch (e: any) { setErr(e.message); } };
  return (
    <>
      <Explain icon={Waypoints} title="Long-horizon multi-session campaigns">
        A patient run over several sessions. The library holds a ladder of cases (level 1 gentlest … 5 strongest). Each session is an ordinary governed run of one case; between sessions the planner (plain code) escalates after a clean answer, tries another case or steps back after a refusal, and stops on a verified violation.
        Only counters and library ids are kept as state; the target's text never steers the plan. A cool-down and a session cap (also capped by the signed scope) pace it.
      </Explain>
      {err && <div className="mb-3 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200" data-testid="camp-error">{err}</div>}
      {note && <div className="mb-3 rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-3 text-sm text-emerald-200" data-testid="camp-note">{note}</div>}
      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <Card className="h-fit"><CardHeader><CardTitle>New campaign</CardTitle><CardDescription>{allowed.length ? "Choose a scope that allows campaigns." : "No valid scope allows campaigns yet: create a scope version with “Allow multi-session campaigns”."}</CardDescription></CardHeader>
          <CardContent className="space-y-3">
            <div><Label>Name</Label><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} data-testid="camp-name" /></div>
            <div><Label>Scope</Label><NativeSelect value={f.scope_id} onChange={(e) => setF({ ...f, scope_id: e.target.value, endpoint_url: "" })} data-testid="camp-scope"><option value="">-</option>{allowed.map((s) => <option key={s.id} value={s.id}>{s.name} v{s.version}</option>)}</NativeSelect></div>
            <div><Label>Endpoint</Label><NativeSelect value={f.endpoint_url} onChange={(e) => setF({ ...f, endpoint_url: e.target.value })} data-testid="camp-endpoint"><option value="">-</option>{scope?.endpoints?.map((e: any) => <option key={e.url} value={e.url}>{e.url}</option>)}</NativeSelect></div>
            <div><Label>Library</Label><NativeSelect value={f.library_id} onChange={(e) => pickLib(e.target.value)} data-testid="camp-library"><option value="">-</option>{libs.map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}</NativeSelect></div>
            <div><Label>Ladder</Label><NativeSelect value={f.ladder} onChange={(e) => setF({ ...f, ladder: e.target.value })} data-testid="camp-ladder"><option value="">-</option>{ladders.map((l) => <option key={l} value={l}>{l}</option>)}</NativeSelect></div>
            <div className="grid grid-cols-3 gap-2">
              <div><Label>Cool-down (s)</Label><Input type="number" min={0} value={f.cooldown_seconds} onChange={(e) => setF({ ...f, cooldown_seconds: Math.max(0, +e.target.value || 0) })} /></div>
              <div><Label>Sessions</Label><Input type="number" min={1} max={10} value={f.max_sessions} onChange={(e) => setF({ ...f, max_sessions: Math.min(10, Math.max(1, +e.target.value || 1)) })} /></div>
              <div><Label>Patience</Label><Input type="number" min={0} max={5} value={f.patience} onChange={(e) => setF({ ...f, patience: Math.min(5, Math.max(0, +e.target.value || 0)) })} /></div></div>
            <Button onClick={create} disabled={!can("operator") || !f.name || !f.scope_id || !f.endpoint_url || !f.library_id || !f.ladder} data-testid="camp-create"><Layers3 className="h-4 w-4" />Create campaign</Button>
            <div className="border-t border-white/10 pt-3"><div className="mb-2 text-xs font-medium text-slate-300">Used when a session starts</div>
              <Label>API key (kept in memory only)</Label><Input type="password" autoComplete="off" value={run.api_key} onChange={(e) => setRun({ ...run, api_key: e.target.value })} />
              <Label className="mt-2">Canaries (one per line)</Label><Textarea rows={2} value={run.canaries} onChange={(e) => setRun({ ...run, canaries: e.target.value })} /></div>
          </CardContent></Card>
        <div className="space-y-4">{(camps || []).length === 0 ? <Empty>No campaign yet.</Empty> : (camps || []).map((c: any) => {
          const st = c.state, left = c.max_sessions - c.sessions_done;
          return (
            <Card key={c.id} data-testid={`camp-${c.id}`}><CardContent className="p-5">
              <div className="flex flex-wrap items-center gap-2"><span className="text-[15px] font-semibold text-white">{c.name}</span>
                <Badge tone={c.status === "active" ? "blue" : c.status === "finished" ? (st.finished === "found" ? "red" : "green") : "neutral"}>{c.status === "finished" ? `finished: ${st.finished}` : c.status}</Badge>
                {c.running && <Badge tone="amber">session running</Badge>}<Badge tone="neutral">ladder {c.ladder}</Badge><Badge tone="neutral">{c.sessions_done}/{c.max_sessions} sessions</Badge>
                {c.cooldown_seconds > 0 && <Badge tone="neutral">cool-down {c.cooldown_seconds}s</Badge>}</div>
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div><div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">Defence profile (counters)</div>
                  <table className="w-full text-xs"><thead className="text-slate-500"><tr><th className="text-left font-medium">Level</th><th className="text-right font-medium">Sessions</th><th className="text-right font-medium">Refused</th><th className="text-right font-medium">Clean</th><th className="text-right font-medium">Violation</th></tr></thead>
                    <tbody>{c.profile.levels.map((l: any) => <tr key={l.level} className={cn("border-t border-white/[0.06]", l.level === st.level && "text-white")}><td className="py-1.5">{l.level}{l.level === st.level && c.status === "active" ? " ◀" : ""}</td><td className="text-right tabular-nums">{l.sessions}</td><td className="text-right tabular-nums">{l.refused} <span className="text-slate-500">({pct(l.refusal_rate)})</span></td><td className="text-right tabular-nums">{l.clean}</td><td className={cn("text-right tabular-nums", l.violation && "text-rose-300")}>{l.violation}</td></tr>)}</tbody></table>
                  {c.profile.mean_refusal_turn !== null && <div className="mt-2 text-[11px] text-slate-500">Refusals start around turn {c.profile.mean_refusal_turn} on average.</div>}</div>
                <div><div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">Sessions</div>
                  <ol className="space-y-1.5">{st.sessions.map((s: any) => (
                    <li key={s.seq} className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[0.07] px-3 py-1.5 text-xs"><span className="text-slate-500">#{s.seq}</span><span className="font-mono text-slate-200">{s.case_id}</span><span className="text-slate-500">level {s.level}</span><Badge tone={OUTCOME_TONE[s.outcome]}>{s.outcome}</Badge>
                      <Link href={`/runs/${s.run_id}`} className="ml-auto text-indigo-300 hover:text-indigo-200">run →</Link><span className="basis-full text-[11px] text-slate-500">{s.why}</span></li>))}
                    {st.pending && <li className="flex items-center gap-2 rounded-lg border border-amber-400/30 bg-amber-500/[0.06] px-3 py-1.5 text-xs text-amber-200"><span>#{st.pending.seq}</span><span className="font-mono">{st.pending.case_id}</span><span>running…</span><Link href={`/runs/${st.pending.run_id}`} className="ml-auto text-indigo-300">run →</Link></li>}
                    {st.sessions.length === 0 && !st.pending && <li className="text-xs text-slate-500">No session yet.</li>}</ol></div>
              </div>
              {c.status === "active" && <div className="mt-4 flex items-center gap-2">
                <Button size="sm" onClick={() => advance(c.id)} disabled={!can("operator") || c.running || left <= 0} data-testid={`camp-advance-${c.id}`}><Play className="h-3.5 w-3.5" />Run next session</Button>
                <Button size="sm" variant="outline" onClick={() => stop(c.id)} disabled={!can("operator")}><Square className="h-3.5 w-3.5" />Stop</Button></div>}
            </CardContent></Card>);
        })}</div>
      </div>
    </>
  );
}

export default function SuitePage() {
  const { data: findings } = usePoll(() => api("/findings"), 6000);
  const { data: maps } = usePoll(() => api("/knowledge-maps"), 6000);
  const { data: scopes } = usePoll(() => api("/scopes"), 8000);
  const { data: libs } = usePoll(() => api("/libraries"), 8000);
  const { data: sys } = usePoll(() => api("/system"), 15000);
  const f = useMemo(() => findings || [], [findings]);
  const nMM = f.filter((x: any) => x.evidence?.multimodal).length, nCh = f.filter((x: any) => x.evidence?.agentic_chain).length;
  return (
    <>
      <PageHeader title="AI Security Suite" sub="Carry files, script tool chains, map what a target knows and run patient multi-session campaigns. Every step uses the signed scope, the Governor, canaries and the audit log; all test text comes from your library." />
      <Tabs defaultValue="multimodal">
        <TabsList className="mb-4 flex-wrap">
          <TabsTrigger value="multimodal" data-testid="tab-multimodal">Multimodal{nMM ? ` (${nMM})` : ""}</TabsTrigger>
          <TabsTrigger value="chains" data-testid="tab-chains">Agent chains{nCh ? ` (${nCh})` : ""}</TabsTrigger>
          <TabsTrigger value="knowledge" data-testid="tab-knowledge">Knowledge map{maps?.length ? ` (${maps.length})` : ""}</TabsTrigger>
          <TabsTrigger value="campaigns" data-testid="tab-campaigns">Campaigns</TabsTrigger>
        </TabsList>
        <TabsContent value="multimodal"><Multimodal findings={f} sys={sys} /></TabsContent>
        <TabsContent value="chains"><Chains findings={f} /></TabsContent>
        <TabsContent value="knowledge"><Knowledge maps={maps || []} /></TabsContent>
        <TabsContent value="campaigns"><Campaigns scopes={scopes || []} libs={libs || []} /></TabsContent>
      </Tabs>
    </>
  );
}
