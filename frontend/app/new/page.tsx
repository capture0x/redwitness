"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowLeft, ArrowRight, BookOpen, Check, GitCompareArrows, KeyRound, ListChecks, Play, Radio, Settings2, ShieldCheck, Target } from "lucide-react";
import JudgeAdvisory from "@/components/JudgeAdvisory";
import { api, ApiError, usePoll } from "@/lib/api";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Hint, Input, Label, NativeSelect, Textarea } from "@/components/ui/input";
import { Check_, Meter, Toggle } from "@/components/ui/misc";
import BiasNotice from "@/components/BiasNotice";
import Dropzone from "@/components/Dropzone";
import QuickScan from "@/components/QuickScan";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STEPS = [
  { id: "target", label: "Target", icon: Target, sub: "Scope and API connection" },
  { id: "content", label: "Test content", icon: BookOpen, sub: "Categories and library" },
  { id: "verify", label: "Verification", icon: Settings2, sub: "Replays and reference" },
  { id: "review", label: "Review", icon: ShieldCheck, sub: "Limits and launch" },
];

export default function NewTest() {
  const router = useRouter();
  const { data: scopes } = usePoll(() => api("/scopes"), 0);
  const { data: libs, reload: reloadLibs } = usePoll(() => api("/libraries"), 0);
  const { data: savedTargets } = usePoll(() => api("/targets"), 0);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const { data: fwCat } = usePoll(() => api("/frameworks"), 0);
  const { data: settings } = usePoll(() => api("/settings"), 0);
  const valid = (scopes || []).filter((s: any) => s.valid);
  const [step, setStep] = useState(0);
  const [dir, setDir] = useState(1);
  const [f, setF] = useState<any>({ scopeId: "", endpoint: "", apiKey: "", stream: false, libId: "", cats: [] as string[], replayN: 3, replayK: 2, reference: "", canaries: "", adaptive: false, compare: false, targets: [] as string[], keys: {} as Record<string, string>, bLabel: "", owaspMode: false, owasp: [] as string[], fwKind: "" as "" | "aisvs" | "asi" | "benchmark", fwIds: [] as string[] });
  const [err, setErr] = useState<ApiError | string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: string, v: any) => setF((p: any) => ({ ...p, [k]: v }));
  const [mode, setMode] = useState<"quick" | "custom">("quick");
  const [up, setUp] = useState<any>(null);
  const [upBusy, setUpBusy] = useState(false);
  const [upErr, setUpErr] = useState("");
  const [task, setTask] = useState("Please summarize the attached document.");
  const toBase64 = (buf: ArrayBuffer) => { let t = ""; const b = new Uint8Array(buf); for (let i = 0; i < b.length; i += 0x8000) t += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(t); };
  const uploadDoc = async (file: File) => {
    setUpErr(""); setUp(null);
    if (file.size > 5 * 1024 * 1024) return setUpErr("The file is larger than 5 MB.");
    setUpBusy(true);
    try {
      const ep = scope?.endpoints.find((e: any) => e.url === f.endpoint);
      const r = await api("/documents/to-case", { method: "POST", body: JSON.stringify({ filename: file.name, content_base64: toBase64(await file.arrayBuffer()), task, delivery: ep?.ingest_url ? "ingest" : "inline" }) });
      setUp({ ...r, filename: file.name });
      setF((p: any) => ({ ...p, libId: r.library_id, owaspMode: false, cats: Array.from(new Set([...p.cats, ...(scope?.attack_classes.includes("prompt_injection_indirect") ? ["prompt_injection_indirect"] : [])])) }));
      reloadLibs();
    } catch (e: any) { setUpErr(e.message); } finally { setUpBusy(false); }
  };
  const scope = valid.find((s: any) => s.id === f.scopeId);
  const lib = libs?.find((l: any) => l.id === f.libId);
  const VEC = ["chroma", "qdrant", "weaviate"], ANALYSIS = ["model_extraction", "membership_inference", "vector_store_exposure"];
  const llmEps = (scope?.endpoints || []).filter((e: any) => !VEC.includes(e.provider));
  const label = (id: string) => meta?.attack_classes?.find((c: any) => c.id === id)?.label || id;

  useEffect(() => { if (typeof window !== "undefined" && new URLSearchParams(window.location.search).get("compare") === "1") set("compare", true); }, []); // eslint-disable-line
  useEffect(() => { if (typeof window !== "undefined" && new URLSearchParams(window.location.search).get("aisvs")) { setMode("custom"); setF((p: any) => ({ ...p, fwKind: "aisvs", fwIds: ["*"] })); } }, []); // eslint-disable-line
  useEffect(() => { if (!f.scopeId && valid[0]) set("scopeId", valid[0].id); }, [valid.length]); // eslint-disable-line
  useEffect(() => { if (scope) setF((p: any) => ({ ...p, endpoint: scope.endpoints.find((e: any) => !VEC.includes(e.provider))?.url || "", targets: [], keys: {}, cats: scope.attack_classes.filter((c: string) => !ANALYSIS.includes(c)) })); }, [f.scopeId]); // eslint-disable-line
  useEffect(() => { if (!f.libId && libs?.[0]) set("libId", libs[0].id); }, [libs, f.libId]);
  useEffect(() => { if (settings) setF((p: any) => ({ ...p, replayN: settings.replay_n, replayK: settings.replay_k })); }, [settings]);

  const ok = [!!f.scopeId && (f.compare ? f.targets.length >= 2 && f.targets.length <= 4 : !!f.endpoint), f.owaspMode ? f.owasp.length > 0 : !!f.libId && f.cats.length > 0, f.replayK >= 1 && f.replayK <= f.replayN, true];
  const go = (n: number) => { setDir(n > step ? 1 : -1); setStep(n); };
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      if (f.compare) {
        const keys = Object.fromEntries(Object.entries(f.keys).filter(([u, k]) => f.targets.includes(u) && k));
        const r = await api("/benchmarks", { method: "POST", body: JSON.stringify({ scope_id: f.scopeId, endpoint_urls: f.targets, label: f.bLabel, api_keys: keys, reference: f.reference, replay_n: f.replayN, replay_k: f.replayK,
          canaries: f.canaries.split("\n").map((x: string) => x.trim()).filter(Boolean), ...(f.owaspMode ? { owasp: f.owasp } : { library_id: f.libId, categories: f.cats }) }) });
        router.push(`/benchmarks/${r.id}`); return;
      }
      const common = { scope_id: f.scopeId, endpoint_url: f.endpoint, api_key: f.apiKey || null, stream: f.stream, reference: f.reference, replay_n: f.replayN, replay_k: f.replayK,
        canaries: f.canaries.split("\n").map((x: string) => x.trim()).filter(Boolean) };
      if (f.owaspMode) { const r = await api("/owasp/scan", { method: "POST", body: JSON.stringify({ ...common, categories: f.owasp }) }); router.push(`/runs/${r.id}`); return; }
      const r = await api("/runs", { method: "POST", body: JSON.stringify({ scope_id: f.scopeId, endpoint_url: f.endpoint, library_id: f.libId, categories: f.cats,
        api_key: f.apiKey || null, stream: f.stream, reference: f.reference, canaries: f.canaries.split("\n").map((x: string) => x.trim()).filter(Boolean), replay_n: f.replayN, replay_k: f.replayK, adaptive: f.adaptive && !!scope?.adaptive_allowed,
        ...(f.fwKind && f.fwIds.length ? { [f.fwKind]: f.fwIds } : {}) }) });
      router.push(`/runs/${r.id}`);
    } catch (e: any) { setErr(e); setBusy(false); }
  };

  return (
    <>
      <PageHeader title="New Test" sub="Scan a target in one screen, or build a custom test inside an existing signed scope." />
      <div className="mb-6 inline-flex gap-1 rounded-xl border border-white/10 bg-white/[0.03] p-1" role="tablist">
        {[["quick", "Quick scan"], ["custom", "Custom test"]].map(([k, l]) => <button key={k} role="tab" aria-selected={mode === k} data-testid={`mode-${k}`} onClick={() => setMode(k as any)} className={cn("rounded-lg px-4 py-1.5 text-sm font-medium transition", mode === k ? "bg-white/10 text-white shadow-glow" : "text-slate-400 hover:text-white")}>{l}</button>)}
      </div>
      {mode === "quick" && <QuickScan />}
      {mode === "custom" && scopes && valid.length === 0 && <Notice tone="red"><b>No signed scope.</b> A test cannot start without a valid, signed scope. Create and sign one on the <Link href="/scopes" className="underline">Scopes</Link> page.</Notice>}
      {err && <Notice tone="red">{typeof err === "string" ? err : err.message}{typeof err !== "string" && err.reason && <span className="ml-2 font-mono text-xs opacity-70">[{err.reason}]</span>}</Notice>}

      {mode === "custom" && <>
      {/* 3-step quick start */}
      <div className="mb-6 grid gap-3 md:grid-cols-3" data-testid="quickstart">
        {[
          { n: 1, t: "Add a target", d: savedTargets?.length ? `${savedTargets.length} saved` : "Where the LLM API lives", done: !!savedTargets?.length, href: "/targets" },
          { n: 2, t: "Upload a test file", d: up ? up.filename : f.libId ? "Library selected" : "PDF, DOCX or EML, or pick a library", done: !!f.libId, href: null },
          { n: 3, t: "Start", d: valid.length ? "Review and launch below" : "Needs a signed scope (admin)", done: false, href: valid.length ? null : "/scopes" },
        ].map((x) => { const inner = (<><div className={cn("grid h-8 w-8 shrink-0 place-items-center rounded-full text-sm font-semibold", x.done ? "bg-emerald-500/20 text-emerald-300" : "bg-white/10 text-slate-300")}>{x.done ? <Check className="h-4 w-4" /> : x.n}</div><div className="min-w-0"><div className="text-sm font-medium text-white">{x.t}</div><div className="truncate text-[11px] text-slate-500">{x.d}</div></div></>);
          return x.href ? <Link key={x.n} href={x.href} className="glass flex items-center gap-3 rounded-2xl p-4 transition hover:border-violet-400/40">{inner}</Link> : <div key={x.n} className="glass flex items-center gap-3 rounded-2xl p-4">{inner}</div>; })}
      </div>

      {/* Stepper */}
      <ol className="mb-8 grid grid-cols-4 gap-3">
        {STEPS.map((s, i) => {
          const done = i < step, cur = i === step, Icon = s.icon;
          return (
            <li key={s.id}>
              <button onClick={() => i <= step || ok.slice(0, i).every(Boolean) ? go(i) : null} className={cn("glass relative w-full overflow-hidden rounded-2xl p-4 text-left transition", cur && "border-violet-400/50 shadow-glow", !cur && !done && "opacity-60")}>
                {cur && <motion.div layoutId="step-glow" className="absolute inset-0 bg-gradient-to-br from-violet-500/15 to-blue-500/10" />}
                <div className="relative flex items-center gap-3">
                  <div className={cn("grid h-9 w-9 place-items-center rounded-xl text-sm font-semibold transition", done ? "bg-emerald-500/20 text-emerald-300" : cur ? "bg-gradient-to-br from-violet-500 to-blue-500 text-snow" : "bg-white/5 text-slate-400")}>{done ? <Check className="h-4 w-4" /> : <Icon className="h-4 w-4" />}</div>
                  <div><div className="text-sm font-medium text-white">{s.label}</div><div className="text-[11px] text-slate-500">{s.sub}</div></div>
                </div>
              </button>
            </li>
          );
        })}
      </ol>

      <Card><CardContent className="min-h-[340px] p-7">
        <AnimatePresence mode="wait" custom={dir}>
          <motion.div key={step} custom={dir} initial={{ opacity: 0, x: 40 * dir }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -40 * dir }} transition={{ duration: 0.25 }}>
            {step === 0 && (
              <div className="grid gap-5 md:grid-cols-2">
                <div><Label help="The scope is the signed permission slip: which addresses and attack types you may test, and how many tokens and requests you may spend. What should I enter? The system or app you are authorized to test.">Scope (signed)</Label><NativeSelect value={f.scopeId} onChange={(e) => set("scopeId", e.target.value)}>{valid.map((s: any) => <option key={s.id} value={s.id}>{s.name} · v{s.version} · {s.client}</option>)}</NativeSelect></div>
                <div className={cn("flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] p-4", f.compare ? "md:col-span-2" : "")} data-testid="compare-toggle">
                  <div className="flex items-center gap-3"><GitCompareArrows className="h-5 w-5 text-violet-300" /><div><div className="text-sm font-medium text-white">Compare multiple targets (A/B benchmark)</div><div className="text-xs text-slate-500">Send the same test set to 2-4 endpoints of this scope and compare the models</div></div></div>
                  <Toggle checked={f.compare} disabled={llmEps.length < 2} onCheckedChange={(v) => set("compare", v)} />
                </div>
                {!f.compare && <div><Label help="Which address from the scope this test should hit.">Endpoint</Label><NativeSelect value={f.endpoint} onChange={(e) => set("endpoint", e.target.value)}>{llmEps.map((e: any) => <option key={e.url} value={e.url}>{e.model} - {e.url}</option>)}</NativeSelect></div>}
                {f.compare ? (
                  <div className="md:col-span-2"><Label>Targets <span className="text-slate-600">(choose 2-4; every one must be an endpoint of the signed scope)</span></Label>
                    <div className="space-y-2">{llmEps.map((e: any) => { const on = f.targets.includes(e.url); return (
                      <div key={e.url} className={cn("rounded-xl border px-3.5 py-2.5 transition", on ? "border-violet-400/50 bg-violet-500/10" : "border-white/10 bg-white/[0.03]")}>
                        <label className="flex cursor-pointer items-center gap-3 text-sm text-slate-200"><Check_ checked={on} onCheckedChange={(v) => set("targets", v ? [...f.targets, e.url].slice(0, 4) : f.targets.filter((x: string) => x !== e.url))} /><span className="font-medium">{e.model}</span><span className="truncate font-mono text-xs text-slate-500">{e.url}</span></label>
                        {on && <Input type="password" autoComplete="off" className="mt-2" value={f.keys[e.url] || ""} onChange={(x) => set("keys", { ...f.keys, [e.url]: x.target.value })} placeholder={e.api_key_env ? `API key (empty: $${e.api_key_env})` : "API key (optional)"} />}
                      </div>); })}</div>
                    <Hint>Keys are kept in memory for the runs only. Each target gets its own run with its own limits from the scope, so the models are compared on identical tests.</Hint>
                    <div className="mt-3"><Label>Benchmark name <span className="text-slate-600">(optional)</span></Label><Input value={f.bLabel} maxLength={100} onChange={(e) => set("bLabel", e.target.value)} placeholder="e.g. Llama 3 vs GPT-4o · OWASP set" /></div></div>
                ) : (
                <div className="md:col-span-2"><Label><KeyRound className="mr-1 inline h-3 w-3" />API key</Label>
                  <Input type="password" autoComplete="off" value={f.apiKey} onChange={(e) => set("apiKey", e.target.value)} placeholder="if left empty, the environment variable from the scope is used" />
                  <Hint>The key is kept in memory only for the duration of this run; it is never written to the database, logs or reports.</Hint></div>)}
                {!f.compare && <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] p-4 md:col-span-2">
                  <div className="flex items-center gap-3"><Radio className="h-5 w-5 text-violet-300" /><div><div className="text-sm font-medium text-white">Streaming (SSE) response</div><div className="text-xs text-slate-500">The response is received from the target in chunks and joined.</div></div></div>
                  <Toggle data-testid="stream-toggle" checked={f.stream} onCheckedChange={(v) => set("stream", v)} />
                </div>}
              </div>
            )}
            {step === 0 && <BiasNotice className="mt-5" targets={(f.compare ? llmEps : llmEps.filter((e: any) => e.url === f.endpoint)).map((e: any) => ({ provider: e.provider, model: e.model, url: e.url }))} />}
            {step === 1 && (<div>
              <div className="mb-5 rounded-2xl border border-white/10 bg-white/[0.02] p-5" data-testid="doc-upload">
                <div className="mb-1 text-sm font-medium text-white">Test with your own document</div>
                <p className="mb-3 text-xs text-slate-400">Drop a PDF, DOCX or EML file. Only its <b className="text-slate-200">visible text</b> is extracted and re-created as a clean file (nothing else in the file is forwarded). The result is saved as an indirect-injection test case in your library and selected for this run.</p>
                <div className="mb-3"><Label>What should the assistant do with it?</Label><Input value={task} onChange={(e) => setTask(e.target.value)} maxLength={2000} /></div>
                <Dropzone accept={[".pdf", ".docx", ".eml"]} onFile={uploadDoc} busy={upBusy} title="Drop a document here or click to choose" testId="doc-dropzone" />
                {upErr && <div className="mt-3 text-sm text-red-400" role="alert" data-testid="doc-error">{upErr}</div>}
                {up && <div className="mt-3 rounded-xl border border-emerald-400/25 bg-emerald-500/[0.07] p-3 text-sm" data-testid="doc-result">
                  <div className="flex flex-wrap items-center gap-2 text-emerald-200"><Check className="h-4 w-4" />Test case created from <b>{up.filename}</b><Badge tone="violet">{up.format}</Badge><Badge>{up.chars.toLocaleString("en-US")} characters</Badge><Badge tone={up.delivery === "ingest" ? "blue" : "neutral"}>{up.delivery === "ingest" ? "uploaded to the target" : "sent inside the message"}</Badge></div>
                  {up.notes?.map((n: string) => <div key={n} className="mt-1 text-xs text-amber-200/90">{n}</div>)}
                  <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap rounded-lg bg-black/30 p-2 font-mono text-xs text-slate-400">{up.preview}{up.chars > up.preview.length ? "…" : ""}</pre></div>}
              </div>
              <div className="mb-5 flex items-center justify-between rounded-xl border border-violet-400/30 bg-violet-500/10 p-4">
                <div className="flex items-center gap-3"><ListChecks className="h-5 w-5 text-violet-300" /><div><div className="text-sm font-medium text-white">Test with OWASP LLM Top 10 modules</div><div className="text-xs text-slate-400">Uses the ready-made starter kit; only the categories you select run (e.g. just LLM01 and LLM06).</div></div></div>
                <Toggle checked={f.owaspMode} onCheckedChange={(v) => setF((p: any) => ({ ...p, owaspMode: v, owasp: v && p.owasp.length === 0 ? (meta?.owasp || []).map((c: any) => c.id) : p.owasp }))} />
              </div>
              {f.owaspMode ? (
                <div>
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2"><Label className="m-0">OWASP categories</Label>
                    <div className="flex flex-wrap gap-2 text-xs">
                      <button className="rounded-full border border-white/15 px-2.5 py-1 text-slate-300 hover:border-violet-400/50" onClick={() => set("owasp", (meta?.owasp || []).map((c: any) => c.id))}>All</button>
                      <button className="rounded-full border border-white/15 px-2.5 py-1 text-slate-300 hover:border-violet-400/50" onClick={() => set("owasp", ["LLM01_PromptInjection", "LLM06_ExcessiveAgency"])}>Only LLM01 + LLM06</button>
                      <button className="rounded-full border border-white/15 px-2.5 py-1 text-slate-300 hover:border-violet-400/50" onClick={() => set("owasp", ["LLM01_PromptInjection", "LLM02_SensitiveInfoDisclosure", "LLM07_SystemPromptLeakage"])}>Injection + leakage (01, 02, 07)</button>
                      <button className="rounded-full border border-white/15 px-2.5 py-1 text-slate-400 hover:border-white/30" onClick={() => set("owasp", [])}>Clear</button></div></div>
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{(meta?.owasp || []).map((c: any) => { const on = f.owasp.includes(c.id); return (
                    <button key={c.id} onClick={() => set("owasp", on ? f.owasp.filter((x: string) => x !== c.id) : [...f.owasp, c.id])} className={cn("flex items-center gap-3 rounded-xl border px-3.5 py-2.5 text-left text-sm transition", on ? "border-violet-400/50 bg-violet-500/15 text-white shadow-glow" : "border-white/10 bg-white/[0.03] text-slate-400 hover:border-white/25")}>
                      <span className="font-mono text-xs text-violet-300">{c.code}</span><span className="flex-1 truncate">{c.en}</span>{c.coverage === "limited" && <span className="text-[10px] text-amber-300">limited</span>}</button>); })}</div>
                  <Hint>Categories your scope's attack classes do not allow (e.g. “tool abuse” for LLM06) are skipped and stay “Not tested” in the matrix.</Hint>
                </div>
              ) : (
              <div className="grid gap-6 md:grid-cols-2">
                <div><Label help="The set of test messages to send. If you have none yet, import the ready-made OWASP templates in Test Library.">Test library</Label><NativeSelect value={f.libId} onChange={(e) => set("libId", e.target.value)}>{libs?.map((l: any) => <option key={l.id} value={l.id}>{l.name} v{l.version} - {l.cases} cases</option>)}</NativeSelect>
                  {libs && libs.length === 0 && <Hint className="text-amber-300">First load a library into the <Link href="/library" className="underline">Test Library</Link>.</Hint>}</div>
                <div>
                  <Label>Categories <span className="text-slate-600">(those the scope allows)</span></Label>
                  <div className="space-y-2">{scope?.attack_classes.filter((c: string) => !ANALYSIS.includes(c)).map((c: string) => (
                    <label key={c} className="flex cursor-pointer items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 text-sm text-slate-200 transition hover:border-violet-400/40">
                      <Check_ checked={f.cats.includes(c)} onCheckedChange={(v) => set("cats", v ? [...f.cats, c] : f.cats.filter((x: string) => x !== c))} />{label(c)}</label>))}</div>
                </div>
              </div>)}
              {!f.owaspMode && !f.compare && (
                <div className="mt-6" data-testid="fw-select">
                  <Label>Framework selection (optional)</Label>
                  <Hint>Run only the library cases that belong to a framework. Cases map automatically from their category, and a case can add its own tags (<code>asi_category</code>, <code>aisvs</code>, <code>benchmark</code>).</Hint>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {([["", "All cases"], ["aisvs", "Only OWASP AISVS 1.0"], ["asi", "OWASP Agentic (ASI)"], ["benchmark", "Benchmark sets"]] as const).map(([k, l]) => (
                      <button key={k} data-testid={`fw-kind-${k || "all"}`} onClick={() => setF((p: any) => ({ ...p, fwKind: k, fwIds: k === "aisvs" ? ["*"] : [] }))}
                        className={cn("rounded-full border px-3 py-1 text-xs transition", f.fwKind === k ? "border-violet-400/60 bg-violet-500/20 text-white" : "border-white/15 text-slate-400 hover:border-white/30")}>{l}</button>))}
                  </div>
                  {f.fwKind && <div className="mt-3 flex flex-wrap gap-1.5">
                    {(f.fwKind === "aisvs" ? [{ id: "*", t: "Any AISVS chapter" }, ...(fwCat?.aisvs || []).map((a: any) => ({ id: a.id, t: `${a.id} · ${a.en}` }))]
                      : f.fwKind === "asi" ? (fwCat?.asi || []).filter((a: any) => a.coverage === "direct").map((a: any) => ({ id: a.id, t: `${a.code} · ${a.en}` }))
                      : ["harmbench", "jailbreakbench", "strongreject"].map((b) => ({ id: b, t: b }))).map((o: any) => { const on = f.fwIds.includes(o.id); return (
                      <button key={o.id} onClick={() => setF((p: any) => ({ ...p, fwIds: o.id === "*" ? (on ? [] : ["*"] ) : on ? p.fwIds.filter((x: string) => x !== o.id) : [...p.fwIds.filter((x: string) => x !== "*"), o.id] }))}
                        className={cn("rounded-lg border px-2.5 py-1 text-xs transition", on ? "border-violet-400/50 bg-violet-500/15 text-white" : "border-white/10 bg-white/[0.03] text-slate-400 hover:border-white/25")}>{o.t}</button>); })}
                  </div>}
                </div>)}
            </div>)}
            {step === 2 && (
              <div className="grid gap-5 md:grid-cols-2">
                <div><Label help="How many fresh conversations repeat a suspected finding to confirm it. Higher means more certainty and more cost.">Number of replays (N)</Label><Input type="number" min={1} max={10} value={f.replayN} onChange={(e) => set("replayN", +e.target.value)} /></div>
                <div><Label help="How many of the replays must show the problem again before the finding counts as verified. K cannot be larger than N.">Required successes (K)</Label><Input type="number" min={1} max={10} value={f.replayK} onChange={(e) => set("replayK", +e.target.value)} />{f.replayK > f.replayN && <Hint className="text-red-300">K cannot be greater than N.</Hint>}</div>
                <p className="text-sm text-slate-400 md:col-span-2">A violation is replayed {f.replayN} times in new conversations; if it repeats in at least {f.replayK} of them it counts as <b className="text-white">Verified</b>, otherwise as <b className="text-white">Unstable</b>.</p>
                {!f.owaspMode && !f.compare && <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3 text-sm text-slate-200 transition hover:border-violet-400/40 md:col-span-2">
                  <Check_ checked={f.adaptive && !!scope?.adaptive_allowed} disabled={!scope?.adaptive_allowed} onCheckedChange={(v) => set("adaptive", !!v)} />
                  <span><b className="text-white">Adaptive mode (Attacker agent)</b><span className="mt-1 block text-xs text-slate-400">When the target refuses a case that has an <code>adaptive</code> block in the library, the Attacker LLM rewrites it using only the rewrite families that block allows (up to its max rounds). Every rewrite goes through the same scope limits, governor, judge and replay verification, and is recorded in the audit log. Requires an Attacker LLM (Settings).</span>{scope && (scope.adaptive_allowed ? <span className="mt-1 block text-xs text-amber-200">This scope allows up to {scope.max_adaptive_rounds} rewrite round(s) per case.</span> : <span className="mt-1 block text-xs text-rose-300">The selected signed scope does not allow adaptive mode. Sign a new scope version that grants it.</span>)}</span></label>}
                <div className="md:col-span-2"><Label help="Secret-looking strings that the target should never reveal (for example a fake API key you planted). If one shows up in an answer, that is proof of a leak.">Canary values <span className="text-slate-600">(optional, one per line)</span></Label>
                  <Textarea rows={2} className="font-mono text-xs" value={f.canaries} onChange={(e) => set("canaries", e.target.value)} placeholder="Sentinel texts you planted in the target's hidden instruction (6-200 characters)" />
                  <Hint>If one of these values appears verbatim in the target response, the finding is marked “Needs review” even if the judge found no violation (independent evidence against a judge false negative). The values are kept in memory only.</Hint></div>
                <div className="md:col-span-2"><Label help="Optional background that helps the judge decide, such as what the assistant is allowed to say. Leave empty if unsure.">Reference context for the judge <span className="text-slate-600">(optional)</span></Label>
                  <Textarea rows={4} value={f.reference} onChange={(e) => set("reference", e.target.value)} placeholder="E.g. which information is in the target's hidden instruction, which content should normally be refused…" /></div>
              </div>
            )}
            {step === 3 && scope && (
              <div className="space-y-6">
                <div className="grid gap-3 text-sm md:grid-cols-2">
                  <Sum k="Scope" v={`${scope.name} · v${scope.version}`} />{f.compare ? <Sum k="Benchmark targets" v={f.targets.map((u: string) => scope.endpoints.find((e: any) => e.url === u)?.model || u).join("  vs  ")} /> : <Sum k="Endpoint" v={f.endpoint} mono />}
                  <Sum k="Library" v={f.owaspMode ? "OWASP LLM Top 10 - Starter Kit" : lib ? `${lib.name} v${lib.version} (${lib.cases} cases)` : "-"} />
                  <Sum k={f.owaspMode ? "OWASP categories" : "Categories"} v={f.owaspMode ? f.owasp.map((x: string) => x.split("_")[0]).join(", ") : f.cats.map(label).join(", ")} />
                  <Sum k="Response format" v={f.stream ? "Streaming (SSE)" : "REST"} /><Sum k="Verification" v={`${f.replayK}/${f.replayN} replays`} />
                </div>
                <JudgeAdvisory />
                <div><div className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">Hard limits from the signed scope</div>
                  <div className="grid gap-x-8 gap-y-3 md:grid-cols-2">{[["max_total_tokens", "Total tokens"], ["max_requests", "Requests"], ["max_duration_seconds", "Duration (s)"], ["max_conversations", "Conversations"]].map(([k, l]) => (
                    <div key={k}><div className="mb-1 flex justify-between text-xs text-slate-400"><span>{l}</span><span>{scope.limits[k].toLocaleString("en-US")}</span></div><Meter value={0} max={scope.limits[k]} /></div>))}</div>
                  <p className="mt-3 text-xs text-slate-500">Rate {scope.limits.max_requests_per_minute}/min · circuit breaker after {scope.limits.breaker_consecutive_errors} consecutive errors · warns at 80% of the budget, starts no new tests at 90%.</p></div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </CardContent></Card>

      <div className="mt-5 flex items-center justify-between">
        <Button variant="ghost" disabled={step === 0} onClick={() => go(step - 1)}><ArrowLeft className="h-4 w-4" />Back</Button>
        {step < 3 ? <Button disabled={!ok[step]} onClick={() => go(step + 1)}>Next<ArrowRight className="h-4 w-4" /></Button>
          : <Button size="lg" disabled={busy || !ok.every(Boolean) || !scope} onClick={submit}><Play className="h-4 w-4" />{busy ? "Starting…" : "Start test"}</Button>}
      </div>
      </>}
    </>
  );
}
const Sum = ({ k, v, mono }: { k: string; v: string; mono?: boolean }) => <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3.5"><div className="text-[11px] uppercase tracking-wider text-slate-500">{k}</div><div className={cn("mt-1 break-all text-slate-100", mono && "font-mono text-xs")}>{v}</div></div>;
