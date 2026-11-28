"use client";
import { isTemplated } from "@/lib/targets";
import CustomHttpFields from "@/components/CustomHttpFields";
import { useEffect, useRef, useState } from "react";
import { CheckCircle2, FileCheck2, Fingerprint, Plus, ShieldAlert, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { api, fmtDate, sha256Hex, usePoll } from "@/lib/api";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { Check_ } from "@/components/ui/misc";
import { Item, Stagger } from "@/components/motion";
import { useMe } from "@/lib/me";

const EP = { url: "", provider: "openai_compat", model: "", local: false, api_key_env: "", ingest_url: "", ingest_delete_url: "", request_template: "", response_path: "", done_path: "", token_url: "" };
const EMPTY = { name: "", client: "", authorized_by: "", authorization_doc_sha256: "", valid_days: 30, endpoints: [EP], attack_classes: [] as string[], tool_abuse_attested: false, adaptive_allowed: false, max_adaptive_rounds: 3, multimodal_allowed: false, campaign_allowed: false, branching_allowed: false, max_campaign_sessions: 5, limits: null as any };

export default function Scopes() {
  const { data: scopes, reload } = usePoll(() => api("/scopes"), 5000);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const { data: saved } = usePoll(() => api("/targets"), 0);
  const { can, me } = useMe();
  const [f, setF] = useState<any>(EMPTY);
  const [form, setForm] = useState(false);
  const [prep, setPrep] = useState<any>(null);
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const limits = f.limits || meta?.limit_defaults || {};
  const body = () => ({ ...f, limits, endpoints: f.endpoints.map((e: any) => ({ ...e, api_key_env: e.api_key_env || null, ingest_url: e.ingest_url || null, ingest_delete_url: e.ingest_delete_url || null,
    request_template: isTemplated(e.provider) ? e.request_template : null, response_path: isTemplated(e.provider) ? (e.response_path || "").trim() : null,
    done_path: e.provider === "ws_json" ? (e.done_path || "").trim() || null : null, token_url: (e.token_url || "").trim() || null })) });
  const set = (k: string, v: any) => setF({ ...f, [k]: v });
  const setEp = (i: number, k: string, v: any) => set("endpoints", f.endpoints.map((e: any, j: number) => (j === i ? { ...e, [k]: v } : e)));
  const prefilled = useRef(false);
  const fromTarget = (i: number, id: string) => {
    const t = (saved || []).find((x: any) => x.id === id);
    if (!t) return;
    set("endpoints", f.endpoints.map((e: any, j: number) => (j === i ? { ...e, url: t.request_url, provider: t.provider, model: t.model, local: t.local, api_key_env: t.api_key_env || "", ingest_url: t.ingest_url || "", ingest_delete_url: t.ingest_delete_url || "", request_template: t.request_template || "", response_path: t.response_path || "", done_path: t.done_path || "", token_url: t.token_url || "" } : e)));
  };
  useEffect(() => {                                                         // /scopes?target=<id> (from the Targets page): open the form with that target filled in
    const id = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("target") : null;
    const t = id && saved && !prefilled.current ? saved.find((x: any) => x.id === id) : null;
    if (t && can("admin")) { prefilled.current = true; setF({ ...EMPTY, name: `${t.name} scope`, endpoints: [{ url: t.request_url, provider: t.provider, model: t.model, local: t.local, api_key_env: t.api_key_env || "", ingest_url: t.ingest_url || "", ingest_delete_url: t.ingest_delete_url || "", request_template: t.request_template || "", response_path: t.response_path || "", done_path: t.done_path || "", token_url: t.token_url || "" }] }); setForm(true); }
  }, [saved, me]); // eslint-disable-line
  const onDoc = async (file?: File) => { if (file) set("authorization_doc_sha256", await sha256Hex(await file.arrayBuffer())); };
  const preview = async () => { setErr(null); setOk(null); setAck(false); try { setPrep(await api("/scopes/prepare", { method: "POST", body: JSON.stringify(body()) })); } catch (e: any) { setErr(e.message); } };
  const sign = async () => {
    setErr(null);
    try {
      // The values SHOWN on the approval screen are sent back: digest, lineage and start date.
      await api("/scopes", { method: "POST", body: JSON.stringify({ ...body(), expected_hash: prep.digest, lineage_id: prep.lineage_id, valid_from: prep.content.valid_from }) });
      setOk("Scope signed and saved."); setPrep(null); setForm(false); setF(EMPTY); reload();
    } catch (e: any) { setErr(e.message); setPrep(null); }
  };

  return (
    <>
      <PageHeader title="Scopes" sub="A limited, signed authorization of an LLM target. No test runs without a signed scope." right={!form && can("admin") && <Button onClick={() => { setForm(true); setOk(null); }}><Plus className="h-4 w-4" />New scope</Button>} />
      {err && <Notice tone="red">{err}</Notice>}{ok && <Notice tone="green">{ok}</Notice>}
      {form && (
        <Card className="mb-8"><CardHeader><div><CardTitle>New scope</CardTitle><CardDescription>The preview step shows the entire content that will be signed</CardDescription></div><Button variant="ghost" size="sm" onClick={() => setForm(false)}>Cancel</Button></CardHeader>
          <CardContent className="space-y-6">
            <div className="grid gap-4 md:grid-cols-3">
              <div><Label help="A short name for this permission, for example Support bot staging, Q4 test.">Name</Label><Input value={f.name} onChange={(e) => set("name", e.target.value)} /></div>
              <div><Label help="Who owns the system under test.">Client / organization</Label><Input value={f.client} onChange={(e) => set("client", e.target.value)} /></div>
              <div><Label help="The person who gave permission to test. This name is written into the audit log.">Authorized by</Label><Input value={f.authorized_by} onChange={(e) => set("authorized_by", e.target.value)} /></div>
              <div className="md:col-span-2"><Label help="Optional fingerprint (SHA-256) of the signed authorization letter or contract. It proves later which document the permission was based on.">Authorization document (SHA-256 digest)</Label>
                <div className="flex gap-2"><Input value={f.authorization_doc_sha256} onChange={(e) => set("authorization_doc_sha256", e.target.value)} placeholder="64-digit hex" />
                  <label className="inline-flex h-[42px] shrink-0 cursor-pointer items-center gap-2 rounded-xl border border-white/15 px-3 text-xs font-medium text-slate-200 hover:border-violet-400/50"><FileCheck2 className="h-4 w-4" />Compute from file<input type="file" className="hidden" onChange={(e) => onDoc(e.target.files?.[0])} /></label></div></div>
              <div><Label help="How long the scope can be used. After that, tests are refused until you sign a new one.">Validity (days, max 90)</Label><Input type="number" min={1} max={90} value={f.valid_days} onChange={(e) => set("valid_days", +e.target.value)} /></div>
            </div>
            <div><div className="mb-2 text-sm font-medium text-white">Authorized endpoints</div>
              {f.endpoints.map((e: any, i: number) => (
                <div key={i} className="mb-3 grid gap-2 rounded-xl border border-white/10 bg-white/[0.02] p-3 md:grid-cols-12">
                  <div className="md:col-span-12"><NativeSelect value="" data-testid="fill-target" onChange={(x) => fromTarget(i, x.target.value)}><option value="">{saved?.length ? "Fill from a saved target…" : "No saved targets yet (add one on the Targets page)"}</option>{(saved || []).map((t: any) => <option key={t.id} value={t.id}>{t.name} · {t.model} · {t.request_url}</option>)}</NativeSelect></div>
                  <div className="md:col-span-6"><Input placeholder="https://… full URL" value={e.url} onChange={(x) => setEp(i, "url", x.target.value)} /></div>
                  <div className="md:col-span-3"><NativeSelect value={e.provider} onChange={(x) => setEp(i, "provider", x.target.value)}>{(meta?.providers || []).map((p: string) => <option key={p}>{p}</option>)}</NativeSelect></div>
                  <div className="md:col-span-3"><Input placeholder={["chroma", "qdrant", "weaviate", "mcp"].includes(e.provider) ? "(not needed for vector stores and MCP servers)" : "model"} value={e.model} onChange={(x) => setEp(i, "model", x.target.value)} /></div>
                  <div className="md:col-span-5"><Input placeholder="API key environment variable name" value={e.api_key_env} onChange={(x) => setEp(i, "api_key_env", x.target.value)} /></div>
                  <div className="md:col-span-5"><Input placeholder="document upload URL (indirect tests, optional)" value={e.ingest_url} onChange={(x) => setEp(i, "ingest_url", x.target.value)} /></div>
                  <div className="md:col-span-12"><Input placeholder="document delete URL (cleanup; the {name} placeholder is replaced with the document name, optional)" value={e.ingest_delete_url} onChange={(x) => setEp(i, "ingest_delete_url", x.target.value)} /></div>
                  {isTemplated(e.provider) && <div className="md:col-span-12"><CustomHttpFields testPrefix={`sc-${i}`} url={e.url} template={e.request_template || ""} path={e.response_path || ""} ws={e.provider === "ws_json"} done={e.done_path || ""} onChange={(k, v) => setEp(i, k, v)} /></div>}
                  <div className="md:col-span-12"><Input placeholder="OAuth 2.0 token URL (only for targets that use OAuth; optional)" value={e.token_url || ""} onChange={(x) => setEp(i, "token_url", x.target.value)} /></div>
                  <label className="flex items-center gap-2 text-xs text-slate-300 md:col-span-2"><Check_ checked={e.local} onCheckedChange={(v) => setEp(i, "local", !!v)} />local</label>
                  {f.endpoints.length > 1 && <button className="text-xs text-red-300 md:col-span-12" onClick={() => set("endpoints", f.endpoints.filter((_: any, j: number) => j !== i))}><Trash2 className="mr-1 inline h-3 w-3" />remove</button>}
                </div>))}
              <Button variant="outline" size="sm" onClick={() => set("endpoints", [...f.endpoints, EP])}><Plus className="h-3.5 w-3.5" />add endpoint</Button>
              <Hint>“Local” allows loopback/internal network addresses (for local models). Cloud metadata and link-local addresses are never opened. If document upload is used, define a delete URL so that uploaded documents are removed at the end of the test.</Hint></div>
            <div><div className="mb-2 text-sm font-medium text-white">Allowed test categories</div>
              <div className="grid gap-2 md:grid-cols-3">{[...(meta?.attack_classes || []), ...(meta?.analysis_classes || [])].map((c: any) => (
                <label key={c.id} className="flex cursor-pointer items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 text-sm text-slate-200 hover:border-violet-400/40">
                  <Check_ checked={f.attack_classes.includes(c.id)} onCheckedChange={(v) => set("attack_classes", v ? [...f.attack_classes, c.id] : f.attack_classes.filter((x: string) => x !== c.id))} />{c.label}</label>))}</div>
              {f.attack_classes.includes("tool_abuse") && <label className="mt-3 flex items-center gap-3 rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100"><Check_ checked={f.tool_abuse_attested} onCheckedChange={(v) => set("tool_abuse_attested", !!v)} />I attest in writing that the target's tools run in a test/sandbox environment.</label>}</div>
            <div><div className="mb-2 text-sm font-medium text-white">Adaptive mode (Attacker agent)</div>
              <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3 text-sm text-slate-200 hover:border-violet-400/40">
                <Check_ checked={f.adaptive_allowed} onCheckedChange={(v) => set("adaptive_allowed", !!v)} />
                <span>Allow an Attacker LLM to rewrite test messages the target refuses.<span className="mt-1 block text-xs text-slate-400">Off by default. When on, it is part of the signed content: runs under this scope may use adaptive mode, up to the number of rewrite rounds below per case. Rewrites still obey every limit on this scope.</span></span></label>
              {f.adaptive_allowed && <div className="mt-3 max-w-[220px]"><Label>Max rewrite rounds per case (1-5)</Label><Input type="number" min={1} max={5} value={f.max_adaptive_rounds} onChange={(e) => set("max_adaptive_rounds", Math.min(5, Math.max(1, +e.target.value || 1)))} /></div>}</div>
            <div><div className="mb-2 text-sm font-medium text-white">AI Security Suite permissions</div>
              <div className="grid gap-2 md:grid-cols-2">
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3 text-sm text-slate-200 hover:border-violet-400/40" data-testid="scope-multimodal">
                  <Check_ checked={f.multimodal_allowed} onCheckedChange={(v) => set("multimodal_allowed", !!v)} />
                  <span>Allow image and audio files (multimodal carrier).<span className="mt-1 block text-xs text-slate-400">Off by default. Files come from the library and are only carried; they are read (OCR, metadata) before sending and never sent if a canary is inside.</span></span></label>
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3 text-sm text-slate-200 hover:border-violet-400/40" data-testid="scope-campaign">
                  <Check_ checked={f.campaign_allowed} onCheckedChange={(v) => set("campaign_allowed", !!v)} />
                  <span>Allow multi-session campaigns.<span className="mt-1 block text-xs text-slate-400">Off by default. Each session is a normal governed run; the plan between sessions is code over library cases.</span></span></label>
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3 text-sm text-slate-200 hover:border-violet-400/40" data-testid="scope-branching">
                  <Check_ checked={f.branching_allowed} onCheckedChange={(v) => set("branching_allowed", !!v)} />
                  <span>Allow multi-turn branching.<span className="mt-1 block text-xs text-slate-400">Off by default. The code picks the next library message from the target's reply with the case's own rules; branches only go forward and never generate text.</span></span></label></div>
              {f.campaign_allowed && <div className="mt-3 max-w-[260px]"><Label>Max sessions per campaign (1-10)</Label><Input type="number" min={1} max={10} value={f.max_campaign_sessions} onChange={(e) => set("max_campaign_sessions", Math.min(10, Math.max(1, +e.target.value || 1)))} /></div>}</div>
            <div><div className="mb-2 text-sm font-medium text-white">Limits</div>
              <div className="grid gap-3 md:grid-cols-5">{Object.entries(limits).map(([k, v]) => <div key={k}><Label>{k}</Label><Input type="number" value={v as number} onChange={(e) => set("limits", { ...limits, [k]: +e.target.value })} /></div>)}</div></div>
            <Button size="lg" onClick={preview}><Fingerprint className="h-4 w-4" />Preview and prepare for signing</Button>
          </CardContent></Card>
      )}

      <Stagger className="space-y-3">
        {scopes?.map((s: any) => (
          <Item key={s.id}><Card className="p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex gap-4"><div className={`grid h-11 w-11 place-items-center rounded-xl ${s.valid ? "bg-emerald-500/15" : "bg-red-500/15"}`}>{s.valid ? <ShieldCheck className="h-5 w-5 text-emerald-300" /> : <ShieldAlert className="h-5 w-5 text-red-300" />}</div>
                <div><div className="font-medium text-white">{s.name} <span className="text-xs font-normal text-slate-500">v{s.version} · {s.client}</span></div>
                  <div className="mt-0.5 text-xs text-slate-500">{fmtDate(s.valid_from)} → {fmtDate(s.valid_until)} · approved by {s.approved_by}</div>
                  <div className="mt-2 flex flex-wrap gap-1.5">{s.adaptive_allowed && <Badge tone="amber">Adaptive ≤ {s.max_adaptive_rounds} rounds</Badge>}{s.multimodal_allowed && <Badge tone="amber">Multimodal files</Badge>}{s.branching_allowed && <Badge tone="amber">Multi-turn branching</Badge>}{s.campaign_allowed && <Badge tone="amber">Campaigns ≤ {s.max_campaign_sessions} sessions</Badge>}{s.attack_classes.map((a: string) => <Badge key={a} tone="violet">{[...(meta?.attack_classes || []), ...(meta?.analysis_classes || [])].find((c: any) => c.id === a)?.label || a}</Badge>)}</div>
                  <div className="mt-2 break-all font-mono text-[11px] text-slate-600">{s.digest}</div></div></div>
              <div className="flex items-center gap-2">
                {s.valid ? <Badge tone="green"><CheckCircle2 className="h-3 w-3" />Signed · valid</Badge> : <Badge tone="red"><XCircle className="h-3 w-3" />{s.invalid_reason}</Badge>}
                {!s.revoked_at && can("admin") && <Button variant="outline" size="sm" onClick={async () => { if (confirm("Revoke this scope? This cannot be undone.")) { await api(`/scopes/${s.id}/revoke`, { method: "POST" }); reload(); } }}>Revoke</Button>}
              </div></div>
            {!s.valid && <p className="mt-3 text-xs text-red-300">{s.invalid_message}</p>}
          </Card></Item>
        ))}
        {scopes && scopes.length === 0 && !form && <Card className="py-14 text-center text-sm text-slate-500">No scopes yet. {can("admin") ? "Start with “New scope”." : "An admin must create and sign a scope."}</Card>}
      </Stagger>

      {/* Signing approval: the entire content, digest and a checkbox - no blind signing */}
      <Dialog open={!!prep} onOpenChange={(o) => !o && setPrep(null)}>
        <DialogContent>
          {prep && <>
            <DialogTitle>Signing approval <span className="ml-2 text-sm font-normal text-slate-500">version v{prep.version}</span></DialogTitle>
            <DialogDescription>The content below will be signed <b className="text-slate-200">exactly as shown</b>. If the digest you approved differs from the digest of the content that is saved, the server refuses to sign.</DialogDescription>
            {!prep.signing_available && <Notice tone="red">The server has no signing key; this scope cannot be signed (REDWITNESS_SCOPE_KEYS).</Notice>}
            <div className="mt-4 space-y-4 text-sm">
              <div className="grid gap-2 md:grid-cols-3"><KV k="Name" v={prep.content.name} /><KV k="Client" v={prep.content.client} /><KV k="Authorized by" v={prep.content.authorized_by} /><KV k="Start" v={fmtDate(prep.content.valid_from)} /><KV k="End" v={fmtDate(prep.content.valid_until)} /><KV k="Approver" v={prep.approver} /></div>
              <KV k="Authorization document digest" v={prep.content.authorization_doc_sha256} mono />
              <div><div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Endpoints</div>{prep.content.endpoints.map((e: any) => <div key={e.url} className="mb-1 rounded-lg bg-black/30 px-3 py-2 font-mono text-xs text-slate-300">{e.url} · {e.model} · {e.provider}{e.local && <span className="text-amber-300"> · LOCAL (internal network allowed)</span>}{e.ingest_url && <span> · document upload: {e.ingest_url}</span>}{e.ingest_delete_url && <span> · cleanup: {e.ingest_delete_url}</span>}{e.api_key_env && <span> · key: ${e.api_key_env}</span>}{e.request_template && <pre className="mt-2 whitespace-pre-wrap text-[11px] text-slate-400">request template: {e.request_template}{"\n"}response path: {e.response_path}{e.done_path ? `\nend-of-reply field: ${e.done_path}` : ""}</pre>}{e.token_url && <span> · OAuth token URL: {e.token_url}</span>}</div>)}</div>
              <div><div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Categories</div><div className="flex flex-wrap gap-1.5">{prep.content.attack_classes.map((a: string) => <Badge key={a} tone="violet">{[...(meta?.attack_classes || []), ...(meta?.analysis_classes || [])].find((c: any) => c.id === a)?.label || a}</Badge>)}</div>{prep.content.tool_abuse_attested && <p className="mt-1 text-xs text-amber-300">A “test environment” attestation was given for tool abuse.</p>}</div>
              <div data-testid="adaptive-grant"><div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Adaptive mode (Attacker agent)</div>
                {prep.adaptive?.allowed ? <p className="rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">ALLOWED - runs under this scope may let an Attacker LLM rewrite refused test messages, up to <b>{prep.adaptive.max_rounds}</b> round(s) per case.</p>
                  : <p className="text-xs text-slate-300">Not allowed - runs cannot use the Attacker agent.</p>}</div>
              <div data-testid="branching-grant"><div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Multi-turn branching</div>
                {prep.content.branching_allowed ? <p className="rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">ALLOWED - a case may choose its next library message from the target's reply with its own rules (forward-only; the code decides, no text is generated).</p>
                  : <p className="text-xs text-slate-300">Not allowed - branching cases are refused.</p>}</div>
              <div><div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Limits</div><div className="grid grid-cols-2 gap-x-6 md:grid-cols-3">{Object.entries(prep.content.limits).map(([k, v]) => <div key={k} className="flex justify-between border-b border-white/[0.06] py-1 text-xs"><span className="text-slate-500">{k}</span><span className="text-slate-200">{String(v)}</span></div>)}</div></div>
              <div className="rounded-xl border border-violet-400/30 bg-violet-500/10 p-3"><div className="text-[11px] uppercase tracking-wider text-violet-200/80">Digest to be signed (SHA-256)</div><div className="mt-1 break-all font-mono text-sm text-violet-100">{prep.digest}</div></div>
            </div>
            <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm text-slate-200"><Check_ checked={ack} onCheckedChange={(v) => setAck(!!v)} className="mt-0.5" />I have read the endpoints, categories, adaptive-mode setting and limits above; I confirm I am authorized to test these targets.</label>
            <div className="mt-5 flex justify-end gap-2"><Button variant="ghost" onClick={() => setPrep(null)}>Edit</Button><Button disabled={!ack || !prep.signing_available} onClick={sign}><Fingerprint className="h-4 w-4" />Sign and save</Button></div>
          </>}
        </DialogContent>
      </Dialog>
    </>
  );
}
const KV = ({ k, v, mono }: { k: string; v: string; mono?: boolean }) => <div><div className="text-[11px] uppercase tracking-wider text-slate-500">{k}</div><div className={`break-all text-slate-100 ${mono ? "font-mono text-xs" : ""}`}>{v}</div></div>;
