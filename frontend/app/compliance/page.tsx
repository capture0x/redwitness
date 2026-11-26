"use client";
import Link from "next/link";
import { useState } from "react";
import { Info } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import { OWASP_STATUS, OwaspStatus } from "@/lib/owasp";
import PageHeader from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

const pct = (v: number | null) => (v === null || v === undefined ? "-" : `${(v * 100).toFixed(1)}%`);

function StatusPill({ s }: { s: OwaspStatus }) {
  const st = OWASP_STATUS[s];
  return <Badge tone={st.tone as any}><i className={cn("h-1.5 w-1.5 rounded-full", st.dot)} />{st.label}</Badge>;
}

/** One framework table. Columns are evaluated tests, violations (judge) and verified findings (replayed). */
function FwTable({ rows, idKey, title, sub }: { rows: any[]; idKey: string; title: (r: any) => string; sub?: (r: any) => string | undefined }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-white/10">
      <table className="w-full text-left text-sm">
        <thead className="bg-white/[0.04] text-[11px] uppercase tracking-wide text-slate-500"><tr><th className="px-4 py-3">ID</th><th className="px-4 py-3">Area</th><th className="px-4 py-3 text-right">Evaluated</th><th className="px-4 py-3 text-right">Violations</th><th className="px-4 py-3 text-right">Verified</th><th className="px-4 py-3">Status</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r[idKey]} className="border-t border-white/[0.06]" data-testid={`fw-row-${r[idKey]}`}>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-[13px] text-slate-200">{r.code || r.id}</td>
            <td className="px-4 py-3"><div className="font-medium text-white">{title(r)}</div>{sub?.(r) && <div className="mt-0.5 text-xs text-slate-500">{sub(r)}</div>}</td>
            <td className="px-4 py-3 text-right tabular-nums text-slate-300">{r.tested}</td>
            <td className="px-4 py-3 text-right tabular-nums text-slate-300">{r.violations}</td>
            <td className={cn("px-4 py-3 text-right tabular-nums", r.verified ? "font-semibold text-rose-300" : "text-slate-300")}>{r.verified}</td>
            <td className="px-4 py-3"><StatusPill s={r.status} /></td></tr>))}</tbody>
      </table>
    </div>
  );
}

export default function CompliancePage() {
  const [endpoint, setEndpoint] = useState("");
  const { data: m } = usePoll(() => api("/owasp/matrix"), 0);
  const { data: s } = usePoll(() => api(`/frameworks/stats${endpoint ? `?endpoint=${encodeURIComponent(endpoint)}` : ""}`), 5000, [endpoint]);
  const nist = (fn: string) => (s?.nist || []).filter((n: any) => n.function === fn);
  const bench: any[] = s?.benchmarks || [];
  const aisvsTested = (s?.aisvs || []).filter((a: any) => a.tested).length;
  return (
    <>
      <PageHeader title="Compliance Suite" sub="The same test results seen through OWASP Agentic (ASI), MITRE ATLAS, NIST AI RMF, OWASP AISVS and benchmark scores. Counts come from the latest run per endpoint." />
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <div className="w-80"><NativeSelect value={endpoint} onChange={(e) => setEndpoint(e.target.value)} data-testid="fw-endpoint">
          <option value="">All endpoints (latest run each)</option>{m?.endpoints?.map((e: string) => <option key={e} value={e}>{e}</option>)}</NativeSelect></div>
        <Link href="/owasp" className="text-sm text-indigo-300 hover:text-indigo-200">OWASP LLM Top 10 matrix →</Link>
      </div>
      <Tabs defaultValue="atlas">
        <TabsList className="mb-4 flex-wrap"><TabsTrigger value="atlas">MITRE ATLAS</TabsTrigger><TabsTrigger value="families">Attack families</TabsTrigger><TabsTrigger value="agentic">Agentic (ASI)</TabsTrigger><TabsTrigger value="nist">NIST AI RMF</TabsTrigger><TabsTrigger value="aisvs">OWASP AISVS</TabsTrigger><TabsTrigger value="bench">Benchmark score (ASR)</TabsTrigger></TabsList>

        <TabsContent value="atlas"><Card><CardHeader><div><CardTitle>Threat matrix - MITRE ATLAS</CardTitle><CardDescription>Which techniques your tests exercised and what happened. Rows with no evaluated test show “Not tested”.</CardDescription></div></CardHeader>
          <CardContent>{s ? <FwTable rows={s.atlas} idKey="id" title={(r) => r.name} sub={(r) => r.tactics.map((t: any) => `${t.name} (${t.id})`).join(" · ")} /> : <div className="glass h-40 animate-pulse rounded-2xl" />}</CardContent></Card></TabsContent>

        <TabsContent value="families"><Card><CardHeader><div><CardTitle>Attack families</CardTitle><CardDescription>How each family of carrier texts did, and the Agentic (ASI) area and ATLAS techniques it is evidence for. Import payload libraries in Library to fill this table.</CardDescription></div></CardHeader>
          <CardContent>{s ? <FwTable rows={s.families || []} idKey="id" title={(r) => r.en} sub={(r) => `${r.asi.split("_")[0]} · ${r.atlas.map((t: any) => t.id).join(", ")}`} /> : <div className="glass h-40 animate-pulse rounded-2xl" />}</CardContent></Card></TabsContent>

        <TabsContent value="agentic"><Card><CardHeader><div><CardTitle>OWASP Top 10 for Agentic Applications (2026)</CardTitle><CardDescription>ASI01-ASI03 are probed directly; ASI04-ASI10 need a live multi-agent setup and are only partly reachable through a chat endpoint.</CardDescription></div></CardHeader>
          <CardContent>{s ? <FwTable rows={s.asi} idKey="id" title={(r) => r.en} sub={(r) => r.coverage === "limited" ? `Limited coverage · ${r.desc}` : r.desc} /> : <div className="glass h-40 animate-pulse rounded-2xl" />}
            <p className="mt-3 text-xs text-slate-500">Run these with the “ADV_agentic” example in Library, or tag your own cases with <code>asi_category</code>. Agent identity spoofing and excessive agency are mapped to ASI03; tool abuse to ASI02; plan manipulation to ASI01.</p></CardContent></Card></TabsContent>

        <TabsContent value="nist"><div className="space-y-5">
          {["Measure", "Manage"].map((fn) => <Card key={fn}><CardHeader><div><CardTitle>{fn}</CardTitle><CardDescription>{fn === "Measure" ? "Is the system's security, privacy, safety and validity evaluated?" : "Are risks responded to, monitored and contained?"}</CardDescription></div></CardHeader>
            <CardContent>{s ? <FwTable rows={nist(fn)} idKey="id" title={(r) => r.en} /> : <div className="glass h-32 animate-pulse rounded-2xl" />}</CardContent></Card>)}
          <p className="flex gap-2 text-xs text-slate-500"><Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />Test results are evidence for these subcategories; they are not an AI RMF conformance assessment. “Manage” rows show where test evidence supports the response, monitoring and containment practices; the practices themselves need a process review.</p></div></TabsContent>

        <TabsContent value="aisvs"><Card><CardHeader><div><CardTitle>OWASP AISVS 1.0</CardTitle><CardDescription>{aisvsTested} of {(s?.aisvs || []).length} chapters have evidence. Mapped at chapter level; requirement-level ids are not asserted.</CardDescription></div>
          <Link href="/new?aisvs=*" className="text-sm text-indigo-300 hover:text-indigo-200" data-testid="aisvs-only-link">Test only AISVS-mapped cases →</Link></CardHeader>
          <CardContent>{s ? <FwTable rows={s.aisvs} idKey="id" title={(r) => r.en} /> : <div className="glass h-40 animate-pulse rounded-2xl" />}</CardContent></Card></TabsContent>

        <TabsContent value="bench"><Card><CardHeader><div><CardTitle>Benchmark score - Attack Success Rate</CardTitle><CardDescription>Share of benchmark prompts after which the judge found a violation. Lower is better. Import a dataset in Library.</CardDescription></div></CardHeader>
          <CardContent><div className="grid gap-4 md:grid-cols-3">{bench.map((b) => (
            <div key={b.name} className="rounded-2xl border border-white/10 bg-white/[0.03] p-5" data-testid={`bench-${b.name}`}>
              <div className="text-sm font-semibold capitalize text-white">{b.name}</div>
              <div className="mt-3 text-3xl font-semibold tabular-nums text-white">{pct(b.asr)}</div>
              <div className="text-xs text-slate-500">ASR · {b.evaluated} prompts evaluated</div>
              <div className="mt-3 text-sm text-slate-300">Verified by replay: <b className={b.verified ? "text-rose-300" : ""}>{pct(b.asr_verified)}</b> <span className="text-slate-500">({b.verified})</span></div>
              {b.evaluated === 0 && !b.inconclusive && <div className="mt-2 text-xs text-slate-500">Not run yet.</div>}
              {b.inconclusive > 0 && <div className="mt-2 text-xs text-amber-300" data-testid={`bench-inconclusive-${b.name}`}>{b.inconclusive} inconclusive (judge output unusable) - not counted in the ASR.</div>}</div>))}</div>
            <p className="mt-4 text-xs text-slate-500">ASR here is a binary judge verdict per prompt. It is not the official scorer of HarmBench, JailbreakBench or StrongREJECT, so do not compare it with published leaderboards.</p></CardContent></Card></TabsContent>
      </Tabs>
      {s && <p className="mt-6 text-xs text-slate-600">{s.note}</p>}
    </>
  );
}
