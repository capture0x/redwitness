"use client";
import dynamic from "next/dynamic";
import Link from "next/link";
import FixTab from "./FixTab";
import ReviewPanel, { IMPACT_TONE, SANDBOX } from "./ReviewPanel";
import ReasoningTimeline from "./ReasoningTimeline";
import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, FileText, FileWarning, Quote } from "lucide-react";
import { Badge, SEV_TONE, StatusBadge } from "./ui/badge";
import { owasp_short } from "@/lib/owasp";

const human = (id?: string | null) => (id ? id.split("_").slice(1).join(" ").replace(/([a-z])([A-Z])/g, "$1 $2") : "");
import { Card } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { sevLabel } from "@/lib/api";
import { cn } from "@/lib/utils";

const EDGE: Record<string, string> = { critical: "from-rose-500", high: "from-orange-400", medium: "from-amber-400", low: "from-sky-400", info: "from-slate-400" };
const GLOW: Record<string, string> = { critical: "hover:shadow-[0_0_34px_-8px_rgba(244,63,94,.6)]", high: "hover:shadow-[0_0_34px_-8px_rgba(251,146,60,.5)]", medium: "hover:shadow-[0_0_34px_-8px_rgba(251,191,36,.45)]", low: "", info: "" };

export const Untrusted = ({ children }: { children: React.ReactNode }) => (
  <div className="rounded-xl border border-dashed border-amber-400/30 bg-black/30 p-3">
    <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-amber-300/80">Response from the target · untrusted data</div>
    <pre className="max-h-72 overflow-auto text-xs leading-relaxed text-slate-300">{children}</pre>
  </div>
);

const AttackTree = dynamic(() => import("./AttackTree"), { ssr: false, loading: () => <div className="h-[250px] animate-pulse rounded-xl bg-white/[0.03]" /> });

export default function FindingCard({ f, classes, onChange }: { f: any; classes?: Record<string, string>; onChange?: () => void }) {
  const [open, setOpen] = useState(false);
  const ev = f.evidence || {}, e = ev.evaluation, rp = ev.replay;
  const sev = f.severity || "medium";
  const quotes = e ? Object.entries(e.questions || {}).filter(([, v]: any) => v.answer === "yes") : [];
  const reply = ev.transcript?.filter((m: any) => m.role === "assistant").slice(-1)[0]?.content;
  return (
    <Card className={cn("relative overflow-hidden transition-shadow duration-300", GLOW[sev])}>
      <div className={cn("absolute inset-y-0 left-0 w-1 bg-gradient-to-b to-transparent", EDGE[sev])} />
      <button onClick={() => setOpen(!open)} className="flex w-full items-start gap-4 p-5 pl-6 text-left">
        <div className="mt-0.5 grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-white/5"><FileWarning className="h-5 w-5 text-slate-300" /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><Badge tone={SEV_TONE[sev]}>{sevLabel(sev)}</Badge><StatusBadge status={f.status} />{f.impact && <Badge tone={IMPACT_TONE[f.impact.impact]} title={f.impact.reasons?.join("; ")} data-testid="badge-impact">{f.impact.label}</Badge>}{f.verifier?.outcome === "refuted" && <Badge tone="amber" title={f.verifier.reason} data-testid="badge-verifier">Refuted by verifier</Badge>}{ev.sandbox && ev.sandbox.status !== "not_applicable" && <Badge tone={SANDBOX[ev.sandbox.status]?.[1]} title={ev.sandbox.note} data-testid="badge-sandbox">{SANDBOX[ev.sandbox.status]?.[0]}</Badge>}{ev.reasoning?.first_deviation && <Badge tone="amber" title="An intermediate step broke the library's expected-result rules" data-testid="badge-reasoning">Reasoning deviation</Badge>}{f.review && <Badge tone={f.review.verdict === "true_positive" ? "green" : "neutral"} data-testid="badge-review">Human: {f.review.verdict.replace(/_/g, " ")}</Badge>}<span className="text-xs text-slate-500">{classes?.[f.category] || f.category}</span>{f.owasp_category && <Badge tone="violet" title="OWASP Top 10 for LLM Applications (2025)">{owasp_short(f.owasp_category)} · {human(f.owasp_category)}</Badge>}
            {f.frameworks?.asi && <Badge tone="amber" title="OWASP Top 10 for Agentic Applications (2026)">{f.frameworks.asi.split("_")[0]} · {human(f.frameworks.asi)}</Badge>}
            {f.frameworks?.atlas?.map((t: any) => <Badge key={t.id} tone="blue" title={`${t.name} · tactics: ${t.tactics.map((x: any) => x.name).join(", ")}`}>MITRE ATLAS: {t.id}</Badge>)}
            {f.frameworks?.family && <Badge tone="violet" title="Attack family of the carrier text (adds the ATLAS and Agentic mapping)" data-testid="badge-family">{String(f.frameworks.family).replace(/_/g, " ")}</Badge>}
            {f.benchmark && <Badge tone="neutral" title="Imported benchmark case">{f.benchmark}</Badge>}
            {ev.branching && <Badge tone="violet" title="The code picked each next message from the target's reply with the library's rules" data-testid="badge-branching">Branching · {ev.branching.turns} turn(s)</Badge>}
            {ev.multimodal && <Badge tone="violet" title="Image/audio files carried from the test library" data-testid="badge-multimodal">Multimodal carrier</Badge>}
            {ev.agentic_chain && <Badge tone="violet" title="A scripted chain of tool calls" data-testid="badge-chain">Agent chain · {ev.agentic_chain.path.length} call(s)</Badge>}
            {ev.knowledge_node && <Badge tone="violet" title="Found while mapping what the target knows">Knowledge map</Badge>}</div>
          <h3 className="mt-1.5 truncate text-[15px] font-semibold text-white">{f.title}</h3>
          <p className="mt-0.5 text-xs text-slate-500"><span className="font-mono">{f.case_id}</span> · {ev.library?.name} v{ev.library?.version}{rp && <> · replay <b className="text-slate-300">{rp.violations}/{rp.completed}</b></>}</p>
        </div>
        <ChevronDown className={cn("mt-2 h-5 w-5 shrink-0 text-slate-500 transition-transform", open && "rotate-180")} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.28 }} className="overflow-hidden">
            <div className="border-t border-white/[0.07] px-6 pb-5 pt-4">
              <Tabs defaultValue="evidence">
                <TabsList><TabsTrigger value="evidence">Evidence</TabsTrigger><TabsTrigger value="judge">Judge verdict</TabsTrigger><TabsTrigger value="replay">Replay</TabsTrigger>{ev.reasoning && <TabsTrigger value="reasoning" data-testid="tab-reasoning">Reasoning</TabsTrigger>}<TabsTrigger value="review" data-testid="tab-review">Review</TabsTrigger><TabsTrigger value="convo">Conversation</TabsTrigger><TabsTrigger value="fix">Fix</TabsTrigger><TabsTrigger value="tree">Attack tree</TabsTrigger></TabsList>
                <TabsContent value="evidence" className="space-y-3">
                  <Field k="Expected safe behavior">{ev.case?.expected_behavior}</Field>
                  {ev.owasp?.id && <Field k="OWASP classification"><span className="text-slate-200">{ev.owasp.id}</span> <span className="text-slate-500">· source: {({ library: "test library", judge: "judge LLM", default: "attack-class default" } as any)[ev.owasp.source] || ev.owasp.source}</span>
                    {ev.owasp.mismatch && <span className="ml-2 text-amber-300">the judge suggested a different category: {ev.owasp.judge_suggestion}</span>}</Field>}
                  {f.frameworks && (f.frameworks.atlas?.length > 0 || f.frameworks.nist?.length > 0 || f.frameworks.aisvs?.length > 0) && <Field k="Framework mapping">
                    <div className="space-y-1 text-sm text-slate-300" data-testid="framework-mapping">
                      {f.frameworks.atlas?.length > 0 && <div><span className="text-slate-500">MITRE ATLAS: </span>{f.frameworks.atlas.map((t: any) => `${t.id} ${t.name} (${t.tactics.map((x: any) => x.name).join(", ")})`).join("; ")}</div>}
                      {f.frameworks.nist?.length > 0 && <div><span className="text-slate-500">NIST AI RMF: </span>{f.frameworks.nist.map((n: any) => n.id).join(", ")}</div>}
                      {f.frameworks.aisvs?.length > 0 && <div><span className="text-slate-500">OWASP AISVS (chapters): </span>{f.frameworks.aisvs.join(", ")}</div>}
                      <div className="text-xs text-slate-500">Curated evidence mapping, not a conformance statement.</div></div></Field>}
                  {ev.adaptive?.method && ev.adaptive.method !== "rewrite" && <Field k="Adaptive method"><span className="text-slate-200">{({ plague: "PLAGUE", persona_teaming: "PersonaTeaming" } as any)[ev.adaptive.method] || ev.adaptive.method}</span> <span className="text-slate-500">· {ev.adaptive.method === "plague" ? "strategy" : "persona"} <b className="font-mono text-slate-300">{ev.adaptive.item}</b> · round {ev.adaptive.round} (wording comes from the test library)</span></Field>}
                  {ev.multimodal && <Field k="Carrier files (sent exactly as the library holds them)"><div className="space-y-2" data-testid="carrier-evidence">
                    {ev.multimodal.preflight.files.map((fl: any) => <div key={fl.name} className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs">
                      <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-slate-200">{fl.name}</span><Badge tone="neutral">{fl.kind} · {fl.format}</Badge><span className="text-slate-500">{fl.bytes} bytes · sha256 {fl.sha256.slice(0, 12)}…</span>
                        {fl.kind === "image" ? <Badge tone={fl.ocr_status === "ok" ? "green" : "amber"}>OCR: {fl.ocr_status}</Badge> : <Badge tone="amber">speech not transcribed</Badge>}
                        {fl.carries_undeclared_text && <Badge tone="amber" title="The file shows more text than the library declares">undeclared text found</Badge>}</div>
                      {(fl.ocr_text || fl.metadata_text) && <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap text-slate-400">{(fl.ocr_text || "") + (fl.metadata_text ? "\n[metadata] " + fl.metadata_text : "")}</pre>}</div>)}
                    <div className="text-xs text-slate-500">Static pre-processing only. The files are carriers; nothing here was written or edited by the platform.</div></div></Field>}
                  {ev.agentic_chain && <Field k="Agentic chain"><div className="space-y-2" data-testid="chain-evidence">
                    <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">{ev.agentic_chain.path.length ? ev.agentic_chain.path.map((n: string, i: number) => <span key={i} className="flex items-center gap-1.5">{i > 0 && <span className="text-slate-600">→</span>}<span className={cn("rounded-md border px-2 py-0.5", ev.agentic_chain.forbidden_tools.includes(n) ? "border-rose-400/40 bg-rose-500/10 text-rose-200" : ev.agentic_chain.egress_tools.includes(n) ? "border-orange-400/40 bg-orange-500/10 text-orange-200" : "border-white/10 bg-white/[0.04] text-slate-300")}>{n}</span></span>) : <span className="text-slate-500">(the target called no tool)</span>}</div>
                    {ev.agentic_chain.steps.map((s: any) => <div key={s.id} className="rounded-lg border border-white/[0.07] px-3 py-2 text-xs"><span className="font-mono text-slate-300">{s.id}</span> · expected <b className="font-mono">{s.expect_tool || "-"}</b> · called <b className="font-mono">{s.called.join(", ") || "none"}</b>{s.unresolved.length > 0 && <span className="text-amber-300"> · unresolved: {s.unresolved.join(", ")}</span>}</div>)}
                    <div className="text-xs text-slate-500">Orange = outbound (egress) tool, red = forbidden tool. A forbidden call, or protected data reaching an outbound tool, is critical.</div></div></Field>}
                  <Field k="Test input sent">{ev.sequence?.map((s: string, i: number) => <pre key={i} className="mb-1 max-h-40 overflow-auto rounded-xl bg-black/30 p-3 text-xs text-slate-300">{ev.sequence.length > 1 ? `${i + 1}. ` : ""}{s}</pre>)}</Field>
                  {ev.tool_sandbox && <Field k="Tool sandbox (fake tools, nothing executed)"><div className="space-y-2 text-sm">
                    <div className="text-xs text-slate-400">Defined: {ev.tool_sandbox.defined.join(", ")} · {ev.tool_sandbox.rounds} tool round(s)</div>
                    {ev.tool_sandbox.violations.map((v: any, i: number) => <div key={i} className="flex gap-2 rounded-xl border border-red-400/20 bg-red-500/[0.07] p-3"><span className="font-mono text-xs text-red-300">{v.rule}</span><span className="text-slate-100">{v.detail}</span></div>)}
                    {ev.tool_sandbox.calls.map((c: any, i: number) => <div key={i} className="rounded-lg bg-black/30 px-3 py-1.5 font-mono text-xs text-slate-300">{c.name}({c.arguments})</div>)}</div></Field>}
                  {ev.markdown_exfil?.length > 0 && <Field k="Markdown / link exfiltration"><div className="space-y-1 text-sm text-slate-200">{ev.markdown_exfil.map((x: any, i: number) => <div key={i} className="rounded-lg border border-orange-400/20 bg-orange-500/[0.07] px-3 py-1.5">A canary value is inside a {x.kind} address pointing to <span className="font-mono">{x.host || "(relative)"}</span></div>)}</div></Field>}
                  {ev.case?.source && <Field k="Payload source">{ev.case.source}</Field>}
                  {ev.branching && <Field k="Branching path"><div className="flex flex-wrap gap-1.5" data-testid="branching-path">{ev.branching.trace.map((t: any) => <span key={t.turn} className="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Turn {t.turn} · step {t.step} → {t.goto} ({t.via}{t.refused ? ", refusal" : ""})</span>)}</div></Field>}
                  {ev.crescendo && <Field k="Crescendo conversation"><div className="flex flex-wrap gap-1.5">{ev.crescendo.trace.map((t: any) => <span key={t.turn} className="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Turn {t.turn} · {t.stage}{t.references_previous ? " · quotes previous reply" : ""}</span>)}</div></Field>}
                  {ev.documents?.length > 0 && <Field k="Documents fed (indirect test)"><div className="space-y-2">{ev.documents.map((d: any) => <DocPreview key={d.sha256 + d.name} d={d} />)}</div></Field>}
                  <Untrusted>{reply}</Untrusted>
                  {ev.tool_calls?.length > 0 && <Field k="Target tool calls"><pre className="rounded-xl bg-black/30 p-3 text-xs">{JSON.stringify(ev.tool_calls, null, 2)}</pre></Field>}
                </TabsContent>
                <TabsContent value="judge" className="space-y-3">
                  {e ? <>
                    <div className="flex flex-wrap items-center gap-3 text-sm"><Badge tone={e.verdict === "violation" ? "red" : "neutral"}>{e.verdict}</Badge><span className="text-slate-400">confidence <b className="text-white">{e.confidence}</b></span><span className="text-slate-500">{e.refusal_detected ? "target refused" : "no refusal"}</span></div>
                    <p className="text-sm text-slate-300">{e.rationale}</p>
                    {quotes.map(([q, v]: any) => <div key={q} className="flex gap-2 rounded-xl border border-red-400/20 bg-red-500/[0.07] p-3 text-sm"><Quote className="mt-0.5 h-4 w-4 shrink-0 text-red-300" /><div><div className="text-[11px] uppercase tracking-wide text-red-300/80">{q}</div><div className="text-slate-100">“{v.evidence_quote}”</div></div></div>)}
                    <p className="text-xs text-slate-500">Quotes are verified verbatim in the target response; judge claims that cannot be verified are downgraded to “inconclusive”.</p>
                  </> : <p className="text-sm text-slate-500">No judge record.</p>}
                </TabsContent>
                <TabsContent value="replay" className="space-y-2">
                  {rp ? <>
                    <p className="text-sm text-slate-300">The violation repeated in <b className="text-white">{rp.violations}</b> of {rp.completed} replays (required {rp.required}/{rp.requested}).{rp.note && <span className="ml-2 text-amber-300">{rp.note}</span>}</p>
                    <div className="flex flex-wrap gap-2">{ev.replays?.map((r: any, i: number) => <Badge key={i} tone={r.verdict === "violation" ? "red" : r.error ? "amber" : "green"}>#{i + 1} {r.verdict || r.error}</Badge>)}</div>
                  </> : <p className="text-sm text-slate-500">No replay record.</p>}
                </TabsContent>
                <TabsContent value="convo" className="space-y-2">
                  {ev.transcript?.map((m: any, i: number) => <div key={i} className={cn("rounded-xl p-3 text-xs", m.role === "user" ? "bg-violet-500/10" : "bg-black/30")}><div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">{m.role === "user" ? "test input" : "target response"}</div><pre className="text-slate-300">{m.content}</pre></div>)}
                </TabsContent>
                <TabsContent value="reasoning"><ReasoningTimeline r={ev.reasoning} /></TabsContent>
                <TabsContent value="review"><ReviewPanel f={f} onChange={onChange} /></TabsContent>
                <TabsContent value="fix"><FixTab f={f} /></TabsContent>
                <TabsContent value="tree"><AttackTree f={f} /></TabsContent>
              </Tabs>
              <div className="mt-4 text-xs text-slate-500"><Link href={`/runs/${f.run_id}`} className="text-violet-300 hover:underline">Open run →</Link></div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}
/** One uploaded document: format, size, hash and the VISIBLE text exactly as it was fed to the target, with the canary token highlighted. */
function DocPreview({ d }: { d: any }) {
  const [open, setOpen] = useState(false);
  const parts: string[] = d.preview && d.canary ? d.preview.split(d.canary) : [d.preview ?? ""];
  return (
    <div className="rounded-xl border border-white/[0.08] bg-black/25">
      <button onClick={() => setOpen(!open)} className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-left text-[11px]">
        <FileText className="h-3.5 w-3.5 text-slate-400" /><span className="font-mono text-slate-200">{d.name}</span>
        {d.format && <Badge tone="violet">{String(d.format).toUpperCase()}</Badge>}
        {d.bytes != null && <span className="text-slate-500">{d.bytes.toLocaleString("en-US")} bytes</span>}
        <span className="font-mono text-slate-600">{String(d.sha256).slice(0, 10)}</span>
        {d.canary && <Badge tone="amber">canary {String(d.canary).slice(0, 16)}…</Badge>}
        <ChevronDown className={cn("ml-auto h-3.5 w-3.5 text-slate-500 transition-transform", open && "rotate-180")} />
      </button>
      {open && d.preview != null && <div className="border-t border-white/[0.06] p-3"><div className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500">Visible text of the file{d.preview_truncated ? " (first 2,000 characters)" : ""}</div>
        <pre className="max-h-60 overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300">{parts.map((p, i) => <span key={i}>{p}{i < parts.length - 1 && <mark className="rounded bg-amber-400/25 px-1 text-amber-100 ring-1 ring-amber-300/40">{d.canary}</mark>}</span>)}</pre></div>}
    </div>
  );
}

const Field = ({ k, children }: { k: string; children: React.ReactNode }) => <div><div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">{k}</div><div className="text-sm text-slate-300">{children}</div></div>;
