"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Loader2, Play, ScanSearch, ShieldCheck } from "lucide-react";
import AuthFields from "@/components/AuthFields";
import { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { Check_ } from "@/components/ui/misc";
import { api, fmtNum, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import { getPref, ONBOARDING_ACTIVE } from "@/lib/prefs";
import { PRESETS, requestUrl } from "@/lib/targets";
import { cn } from "@/lib/utils";

const EMPTY = { base_url: "", model: "", provider: "openai_compat", auth_type: "bearer", auth_header: "", api_key: "" };

/** URL + credential, then Review (shows exactly what will be signed) and Start. It still creates and signs a normal short-lived scope; nothing is loosened. */
export default function QuickScan() {
  const router = useRouter();
  const { can } = useMe();
  const { data: targets } = usePoll(() => api("/targets"), 0);
  const { data: system } = usePoll(() => api("/system"), 0);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const all: string[] = (meta?.owasp || []).map((c: any) => c.id);
  const [cats, setCats] = useState<string[] | null>(null);                       // null = every OWASP category
  const chosen = cats ?? all;
  const allOn = chosen.length === all.length;
  useEffect(() => {                                                              // /new?owasp=LLM01_...,LLM02_... (from the OWASP scan dialog)
    const q = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("owasp") : null;
    if (q) setCats(q.split(",").filter(Boolean));
  }, []);
  const toggleCat = (id: string) => { setCats((chosen.includes(id) ? chosen.filter((x) => x !== id) : [...chosen, id])); setPlan(null); setAuth(false); };
  const [targetId, setTargetId] = useState("");
  const [f, setF] = useState<any>(EMPTY);
  const [tools, setTools] = useState(false);
  const [attest, setAttest] = useState(false);
  const [auth, setAuth] = useState(false);
  const [plan, setPlan] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const set = (k: string, v: any) => { setF((p: any) => ({ ...p, [k]: v })); setPlan(null); setAuth(false); };
  const saved = (targets || []).find((t: any) => t.id === targetId);
  const body = () => ({ ...(targetId ? { target_id: targetId, api_key: f.api_key || null } : { base_url: f.base_url, model: f.model, provider: f.provider, auth_type: f.auth_type, auth_header: f.auth_type === "header" ? (f.auth_header || "Authorization") : null, api_key: f.api_key || null }),
    include_tools: tools, tools_attested: tools && attest, ...(allOn ? {} : { owasp: chosen }) });
  const canReview = (targetId || (f.base_url.trim() && f.model.trim())) && (!tools || attest) && chosen.length > 0;

  const review = async () => { setErr(""); setBusy("review"); try { setPlan(await api("/quick-scan/prepare", { method: "POST", body: JSON.stringify(body()) })); setAuth(false); } catch (e: any) { setErr(e.message); } finally { setBusy(""); } };
  const start = async () => {
    setErr(""); setBusy("start");
    try { const r = await api("/quick-scan", { method: "POST", body: JSON.stringify({ ...body(), authorized: true, expected_hash: plan.digest, lineage_id: plan.lineage_id, valid_from: plan.valid_from }) }); router.push(getPref(ONBOARDING_ACTIVE) ? "/" : `/runs/${r.id}`); }
    catch (e: any) { setErr(e.message); setBusy(""); }
  };

  if (!can("admin")) return <Notice tone="amber"><b>Quick scan needs an admin.</b> It creates and signs the authorization scope for the scan. You can still run tests inside an existing signed scope with “Custom test”.</Notice>;

  return (
    <Card data-testid="quick-scan"><CardContent className="space-y-6 p-7">
      <div className="flex items-start gap-3"><div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-violet-500/30 to-blue-500/20 text-violet-200"><ScanSearch className="h-5 w-5" /></div>
        <div><div className="text-lg font-semibold text-white">Scan a target</div><p className="text-sm text-slate-400">Enter the address and how to sign in. AIVeritX runs the whole OWASP LLM Top 10 kit plus Crescendo and Markdown-leak checks (and tool abuse if you attest below) in one run. It still creates a short-lived signed scope for you; you review it first.</p></div></div>

      {err && <Notice tone="red">{err}</Notice>}
      {system && !system.judge_configured && <Notice tone="amber"><b>The judge model is not set up.</b> Put its API key in your .env file, then choose the model under <Link href="/settings" className="underline">Settings → Judge LLM</Link>.</Notice>}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="md:col-span-2"><Label help="Pick a target you saved before, or enter a new address below. Nothing is sent until you review the plan and sign it.">Target</Label>
          <NativeSelect data-testid="qs-target" value={targetId} onChange={(e) => { setTargetId(e.target.value); setPlan(null); setAuth(false); }}>
            <option value="">New target (enter the address below)</option>{(targets || []).map((t: any) => <option key={t.id} value={t.id}>{t.name} · {t.model}</option>)}</NativeSelect></div>
        {!targetId && <>
          <div className="md:col-span-2 flex flex-wrap gap-2">{Object.entries(PRESETS).filter(([k]) => k !== "custom").map(([id, p]) => <button key={id} onClick={() => { setF((x: any) => ({ ...x, provider: p.provider, base_url: p.base_url, model: p.model })); setPlan(null); }} className="rounded-full border border-white/10 px-3.5 py-1.5 text-xs font-medium text-slate-300 transition hover:border-violet-400/50 hover:bg-violet-500/10 hover:text-white">{p.label}</button>)}</div>
          <div><Label help="The address of the API you want to scan, for example https://api.openai.com/v1. You must be allowed to test it.">Base URL</Label><Input data-testid="qs-url" value={f.base_url} onChange={(e) => set("base_url", e.target.value)} placeholder="https://api.openai.com/v1" />{f.base_url && <Hint>Requests go to <span className="font-mono text-slate-300">{requestUrl(f.provider, f.base_url)}</span></Hint>}</div>
          <div><Label help="The model id that API expects, such as gpt-4o or llama3.2.">Model name</Label><Input data-testid="qs-model" value={f.model} onChange={(e) => set("model", e.target.value)} placeholder="e.g. gpt-4o" /></div>
          <div className="md:col-span-2"><AuthFields testPrefix="qs" authType={f.auth_type} authHeader={f.auth_header} secret={f.api_key} onChange={(k, v) => set(k, v)} /></div></>}
        {targetId && saved && <div className="md:col-span-2 text-xs text-slate-400">Uses the saved target <span className="font-mono text-slate-300">{saved.request_url}</span>{saved.has_key ? " and its key held in memory." : saved.api_key_env ? ` and the key from $${saved.api_key_env}.` : "."}
          <div className="mt-3"><Label>Credential (optional: replaces the one held in memory)</Label><Input type="password" autoComplete="off" value={f.api_key} onChange={(e) => set("api_key", e.target.value)} /></div></div>}
      </div>

      <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <label className="flex items-center gap-3 text-sm text-slate-200"><Check_ checked={tools} onCheckedChange={(v) => { setTools(!!v); setPlan(null); setAuth(false); }} data-testid="qs-tools" />Also run tool-abuse checks (fake tools; nothing is executed)</label>
        {tools && <label className="mt-3 flex items-center gap-3 rounded-lg border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100"><Check_ checked={attest} onCheckedChange={(v) => { setAttest(!!v); setPlan(null); }} data-testid="qs-attest" />I attest in writing that the target&apos;s tools run in a test or sandbox environment.</label>}
      </div>

      <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4" data-testid="qs-cats">
        <div className="mb-2 flex items-center justify-between"><div className="text-sm font-medium text-white">What to test <span className="text-xs font-normal text-slate-500">{allOn ? "all OWASP LLM Top 10 categories" : `${chosen.length} of ${all.length} categories`}</span></div>
          <div className="flex gap-3 text-xs"><button className="text-violet-300 hover:underline" onClick={() => { setCats(null); setPlan(null); }}>All</button><button className="text-slate-400 hover:underline" onClick={() => { setCats([]); setPlan(null); }}>Clear</button></div></div>
        <div className="flex flex-wrap gap-1.5">{(meta?.owasp || []).map((c: any) => { const on = chosen.includes(c.id); return <button key={c.id} onClick={() => toggleCat(c.id)} title={c.en} className={cn("rounded-full border px-3 py-1 text-xs transition", on ? "border-violet-400/50 bg-violet-500/20 text-white" : "border-white/10 text-slate-500 hover:text-slate-300")}><span className="font-mono">{c.code}</span> {c.en}</button>; })}</div></div>

      {!plan && <Button disabled={!canReview || !!busy || (system && !system.judge_configured)} onClick={review} data-testid="qs-review">{busy === "review" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}Review the scan</Button>}

      {plan && (
        <div className="space-y-4 rounded-2xl border border-violet-400/30 bg-violet-500/[0.06] p-5" data-testid="qs-plan">
          <div className="text-sm font-medium text-white">Review: this is exactly what will be signed and run</div>
          <div className="grid gap-3 md:grid-cols-4 text-sm">
            <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Target</div><div className="break-all font-mono text-xs text-slate-200">{plan.request_url}</div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Tests</div><div className="text-slate-200">{plan.cases} cases{` · ${plan.categories_planned.length} categor${plan.categories_planned.length === 1 ? "y" : "ies"}`}{plan.skipped_cases ? <span className="text-slate-500"> ({plan.skipped_cases} skipped: not authorized)</span> : null}</div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Valid for</div><div className="text-slate-200">7 days</div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-slate-500">Budget</div><div className="text-slate-200">{fmtNum(plan.content.limits.max_total_tokens)} tokens · {plan.content.limits.max_requests} requests</div></div></div>
          <div className="flex flex-wrap gap-1.5">{plan.content.attack_classes.map((c: string) => <Badge key={c} tone="violet">{c.replace(/_/g, " ")}</Badge>)}{plan.local && <Badge tone="amber">local / private network</Badge>}{plan.content.adaptive_allowed ? null : <Badge>no adaptive rewriting</Badge>}</div>
          {plan.categories_skipped?.length > 0 && <div className="rounded-lg border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-100" data-testid="qs-skipped">Not run: {plan.categories_skipped.map((c: string) => c.split("_")[0]).join(", ")}. Tool-abuse categories need the test-environment attestation above; they stay “Not tested” in the matrix.</div>}
          <div className="font-mono text-[11px] text-slate-500">digest {plan.digest}</div>
          <label className="flex items-start gap-3 rounded-xl border border-white/10 bg-black/20 p-3 text-sm text-slate-200"><Check_ checked={auth} onCheckedChange={(v) => setAuth(!!v)} data-testid="qs-authorized" />
            <span>I am authorized to test this target. I understand AIVeritX will send many test requests to it, within the limits above, and that this confirmation is recorded in the audit log.</span></label>
          <div className="flex gap-2"><Button size="lg" disabled={!auth || !!busy} onClick={start} data-testid="qs-start">{busy === "start" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}Sign and start scan</Button><Button variant="ghost" onClick={() => setPlan(null)}>Change</Button></div>
        </div>)}
    </CardContent></Card>
  );
}
