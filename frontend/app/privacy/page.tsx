"use client";
import { useEffect, useMemo, useState } from "react";
import { Database, Fingerprint, Layers, Play } from "lucide-react";
import PageHeader from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, NativeSelect, Textarea, Hint } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/misc";
import { api, fmtDate, fmtNum, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import { useQueryClient } from "@tanstack/react-query";

const VEC = ["chroma", "qdrant", "weaviate"];
const KINDS: Record<string, { label: string; cls: string; icon: any; blurb: string }> = {
  extraction: { label: "Model extraction", cls: "model_extraction", icon: Layers, blurb: "Sends a small, capped set of neutral questions and measures how cheaply an outsider could collect imitation data: tokens per pair, throttling, repeatability and how well a trivial lookup surrogate already imitates the target. Nothing is trained." },
  membership: { label: "Membership inference", cls: "membership_inference", icon: Fingerprint, blurb: "Gives the target the first half of texts you suspect were in its training data (and control texts that were not) and measures how often it reproduces the second half. A statistical signal, not proof." },
  vector: { label: "Vector store exposure", cls: "vector_store_exposure", icon: Database, blurb: "Read-only, credential-less probes of a vector database (Chroma, Qdrant, Weaviate): can a stranger list collections, read records or read embeddings? Samples at most 3 records per collection; previews are masked; nothing is written." },
};
const TONE: Record<string, any> = { critical: "critical", high: "high", medium: "medium", low: "green", unknown: "neutral" };
const lines = (t: string) => t.split(/\n\s*\n/).map((x) => x.trim()).filter(Boolean);

function Result({ a }: { a: any }) {
  const r = a.result;
  if (!r) return <Card className="p-5 text-sm text-slate-400">{a.status === "running" ? "Running…" : "No result."}</Card>;
  return (
    <Card className="space-y-4 p-5" data-testid="analysis-result">
      <div className="flex flex-wrap items-center gap-3"><div className="font-medium text-white">{KINDS[a.kind]?.label}</div>
        {r.risk && <Badge tone={TONE[r.risk.level]}>{r.risk.level} risk</Badge>}<Badge>{a.status}</Badge>
        {r.stopped_reason && <Badge tone="amber">stopped: {r.stopped_reason}</Badge>}</div>
      {a.kind !== "vector" && r.risk?.reasons?.map((x: string) => <div key={x} className="text-sm text-slate-300">{x}</div>)}
      {a.kind === "extraction" && r.tokens && <div className="grid gap-3 md:grid-cols-4">
        <Stat k="Answers collected" v={`${r.pairs} / ${r.queries_planned}`} /><Stat k="Tokens used" v={`${fmtNum(r.tokens.total)} / ${fmtNum(r.tokens.ceiling)}`} />
        <Stat k="Est. tokens for 10,000 pairs" v={r.est_tokens_for_10k_pairs ? fmtNum(r.est_tokens_for_10k_pairs) : "-"} /><Stat k="Repeatability (F1)" v={r.determinism?.mean_f1 ?? "-"} />
        {r.surrogate_proxy && <><Stat k="Lookup surrogate F1" v={r.surrogate_proxy.mean_f1} /><Stat k="Random baseline F1" v={r.surrogate_proxy.baseline_f1} /></>}<Stat k="Throttled" v={r.throttled} /></div>}
      {a.kind === "membership" && r.verbatim && <div className="grid gap-3 md:grid-cols-4">
        <Stat k="Members reproduced (avg)" v={r.verbatim.members_mean ?? "-"} /><Stat k="Controls reproduced (avg)" v={r.verbatim.non_members_mean ?? "-"} />
        <Stat k="Separation (AUC)" v={r.verbatim.auc ?? "-"} /><Stat k="Log-prob AUC" v={r.logprob?.available ? r.logprob.auc : "not returned by target"} /></div>}
      {a.kind === "vector" && <div className="space-y-2">
        {r.findings.map((f: any) => <div key={f.code} className="flex items-start gap-3 rounded-lg border border-white/5 bg-white/[0.02] p-3 text-sm"><Badge tone={f.severity === "info" ? "info" : f.severity}>{f.severity}</Badge><div><div className="text-slate-200">{f.message}</div><div className="text-xs text-slate-500">{f.code}</div></div></div>)}
        {r.collections.map((c: any) => <div key={c.name} className="rounded-lg bg-black/30 p-3 text-xs"><div className="font-mono text-slate-200">{c.name} · {c.count ?? "?"} records{c.embedding_dims ? ` · ${c.embedding_dims}-dim embeddings readable` : ""}</div>
          {c.previews.map((p: string, i: number) => <div key={i} className="mt-1 font-mono text-slate-500">{p}</div>)}</div>)}</div>}
      <ul className="list-disc space-y-1 pl-5 text-xs text-amber-200/80">{r.caveats?.map((c: string) => <li key={c}>{c}</li>)}</ul>
    </Card>);
}
const Stat = ({ k, v }: { k: string; v: any }) => <div className="rounded-xl bg-white/[0.03] p-3"><div className="text-[11px] uppercase tracking-wider text-slate-500">{k}</div><div className="mt-1 text-lg font-semibold text-white">{String(v)}</div></div>;

export default function Privacy() {
  const { can } = useMe();
  const qc = useQueryClient();
  const { data: scopes } = usePoll(() => api("/scopes"), 0);
  const { data: list } = usePoll(() => api("/analyses"), 3000);
  const [tab, setTab] = useState("extraction");
  const [f, setF] = useState<any>({ scopeId: "", endpoint: "", apiKey: "", queries: 30, maxTokens: 20000, topics: "", members: "", nonMembers: "", logprobs: false });
  const [sel, setSel] = useState<string | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const set = (k: string, v: any) => setF((p: any) => ({ ...p, [k]: v }));
  const k = KINDS[tab];
  const valid = (scopes || []).filter((s: any) => s.valid && s.attack_classes.includes(k.cls));
  const scope = valid.find((s: any) => s.id === f.scopeId);
  const eps = useMemo(() => (scope?.endpoints || []).filter((e: any) => (tab === "vector") === VEC.includes(e.provider)), [scope, tab]);
  useEffect(() => { setF((p: any) => ({ ...p, scopeId: valid[0]?.id || "" })); setErr(""); }, [tab, scopes]); // eslint-disable-line
  useEffect(() => { set("endpoint", eps[0]?.url || ""); }, [f.scopeId, tab, eps.length]); // eslint-disable-line
  const { data: detail } = usePoll(() => (sel ? api(`/analyses/${sel}`) : Promise.resolve(null)), sel ? 2000 : 0, [sel]);

  async function start() {
    setErr(""); setBusy(true);
    try {
      const body: any = { kind: tab, scope_id: f.scopeId, endpoint_url: f.endpoint, api_key: f.apiKey || null };
      if (tab === "extraction") Object.assign(body, { queries: Number(f.queries), max_tokens: Number(f.maxTokens), topics: f.topics.split("\n").map((x: string) => x.trim()).filter(Boolean) });
      if (tab === "membership") Object.assign(body, { members: lines(f.members), non_members: lines(f.nonMembers), use_logprobs: f.logprobs });
      const r = await api("/analyses", { method: "POST", body: JSON.stringify(body) });
      setSel(r.id); qc.invalidateQueries({ queryKey: ["poll"] });
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title="Privacy & Extraction" sub="Budgeted extraction exposure, membership inference and read-only vector store exposure, all inside a signed scope and under the Governor's limits." />
      <Tabs value={tab} onValueChange={setTab}><TabsList>{Object.entries(KINDS).map(([id, x]) => <TabsTrigger key={id} value={id}><x.icon className="mr-1.5 inline h-3.5 w-3.5" />{x.label}</TabsTrigger>)}</TabsList>
        <TabsContent value={tab}>
          <Card className="space-y-4 p-5">
            <p className="text-sm text-slate-400">{k.blurb}</p>
            {scopes && valid.length === 0 && <div className="rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100" data-testid="no-scope">No valid signed scope grants “{k.cls}”. Create a new scope version that includes this class{tab === "vector" ? " and a vector store endpoint (chroma, qdrant or weaviate)" : ""}.</div>}
            {can("operator") && valid.length > 0 && <>
              <div className="grid gap-3 md:grid-cols-2">
                <div><Label>Signed scope</Label><NativeSelect value={f.scopeId} onChange={(e) => set("scopeId", e.target.value)}>{valid.map((s: any) => <option key={s.id} value={s.id}>{s.name} · v{s.version}</option>)}</NativeSelect></div>
                <div><Label>Endpoint</Label><NativeSelect value={f.endpoint} onChange={(e) => set("endpoint", e.target.value)}>{eps.map((e: any) => <option key={e.url} value={e.url}>{e.provider} - {e.url}</option>)}</NativeSelect></div>
                {tab !== "vector" && <div className="md:col-span-2"><Label>API key (optional; otherwise the scope's environment variable is used)</Label><Input type="password" autoComplete="off" value={f.apiKey} onChange={(e) => set("apiKey", e.target.value)} /></div>}
              </div>
              {tab === "extraction" && <div className="grid gap-3 md:grid-cols-3">
                <div><Label>Queries (5-100)</Label><Input type="number" min={5} max={100} value={f.queries} onChange={(e) => set("queries", e.target.value)} /></div>
                <div><Label>Token ceiling (1,000-60,000)</Label><Input type="number" min={1000} max={60000} value={f.maxTokens} onChange={(e) => set("maxTokens", e.target.value)} /></div>
                <div className="md:col-span-3"><Label>Topics (optional, one per line)</Label><Textarea rows={3} value={f.topics} onChange={(e) => set("topics", e.target.value)} placeholder="Leave empty to use neutral general topics" /></div></div>}
              {tab === "membership" && <div className="grid gap-3 md:grid-cols-2">
                <div><Label>Member candidates (5-40 texts, separated by a blank line)</Label><Textarea rows={8} value={f.members} onChange={(e) => set("members", e.target.value)} /></div>
                <div><Label>Control texts that were NOT in training (same style and length)</Label><Textarea rows={8} value={f.nonMembers} onChange={(e) => set("nonMembers", e.target.value)} /></div>
                <label className="flex items-center gap-2 text-xs text-slate-400 md:col-span-2"><input type="checkbox" checked={f.logprobs} onChange={(e) => set("logprobs", e.target.checked)} />Ask the target for token log-probabilities (OpenAI-compatible endpoints only; ignored if unsupported)</label>
                <Hint>Each text needs at least 12 words. Texts are sent to the authorized target; only their SHA-256 hashes and scores are stored.</Hint></div>}
              {err && <div className="text-sm text-red-400" role="alert">{err}</div>}
              <Button onClick={start} disabled={busy || !f.endpoint} data-testid="start-analysis"><Play className="h-4 w-4" />{busy ? "Starting…" : "Start"}</Button>
            </>}
          </Card>
        </TabsContent></Tabs>
      {detail && <div className="mt-5"><Result a={detail} /></div>}
      <div className="mb-2 mt-6 text-xs uppercase tracking-wide text-slate-500">Previous analyses</div>
      {!list ? <Skeleton className="h-20" /> : list.length === 0 ? <Card className="py-8 text-center text-sm text-slate-500">None yet.</Card> :
        <div className="grid gap-2">{list.map((a: any) => <button key={a.id} onClick={() => setSel(a.id)} className="text-left"><Card className="surface-hover flex flex-wrap items-center gap-3 p-4 text-sm">
          <span className="font-medium text-white">{KINDS[a.kind]?.label}</span>{a.risk && <Badge tone={TONE[a.risk]}>{a.risk}</Badge>}<Badge>{a.status}</Badge>
          <span className="font-mono text-xs text-slate-500">{a.endpoint_url}</span><span className="ml-auto text-xs text-slate-500">{fmtDate(a.created_at)} · {a.created_by}</span></Card></button>)}</div>}
    </>
  );
}
