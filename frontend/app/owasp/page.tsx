"use client";
import Link from "next/link";
import { useState } from "react";
import { motion } from "framer-motion";
import { ArrowUpRight, Info, ListChecks, Play } from "lucide-react";
import { api, fmtDate, usePoll } from "@/lib/api";
import { OWASP_DISCLAIMER, OWASP_STATUS, OwaspStatus } from "@/lib/owasp";
import { useMe } from "@/lib/me";
import PageHeader from "@/components/PageHeader";
import OwaspScanDialog from "@/components/OwaspScanDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/input";
import { Tip } from "@/components/ui/misc";
import { ComplianceMeter } from "@/components/charts/charts";
import { ChartSkeleton } from "@/components/ui/misc";
import { cn } from "@/lib/utils";

export default function OwaspPage() {
  const { can } = useMe();
  const [endpoint, setEndpoint] = useState("");
  const [scan, setScan] = useState<string[] | null>(null);
  const { data: m } = usePoll(() => api(`/owasp/matrix${endpoint ? `?endpoint=${encodeURIComponent(endpoint)}` : ""}`), 4000, [endpoint]);
  const [tab, setTab] = useState<"llm" | "asi">("llm");
  const { data: fw } = usePoll(() => api(`/frameworks/stats${endpoint ? `?endpoint=${encodeURIComponent(endpoint)}` : ""}`), 5000, [endpoint]);
  const cats: any[] = m?.categories || [];
  const legend = (["clean", "review", "vulnerable", "testing", "not_tested"] as OwaspStatus[]).map((k) => ({ k, n: cats.filter((c) => c.status === k).length }));
  return (
    <>
      <PageHeader title="OWASP Compliance" sub="OWASP Top 10 for LLM Applications (2025) - coverage and compliance matrix. Each card shows the category's latest evaluation status."
        right={can("operator") ? <Button onClick={() => setScan([])}><Play className="h-4 w-4" />Start OWASP scan</Button> : undefined} />
      <div className="mb-5 inline-flex gap-1 rounded-xl border border-white/10 bg-white/[0.03] p-1" role="tablist">
        {([["llm", "LLM Top 10 (2025)"], ["asi", "Agentic (ASI) 2026"]] as const).map(([k, l]) => (
          <button key={k} role="tab" aria-selected={tab === k} data-testid={`owasp-tab-${k}`} onClick={() => setTab(k)}
            className={cn("rounded-lg px-4 py-1.5 text-sm font-medium transition", tab === k ? "bg-white/10 text-white" : "text-slate-400 hover:text-white")}>{l}</button>))}
      </div>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <div className="w-80"><NativeSelect value={endpoint} onChange={(e) => setEndpoint(e.target.value)}>
          <option value="">All endpoints (latest run per category)</option>{m?.endpoints?.map((e: string) => <option key={e} value={e}>{e}</option>)}</NativeSelect></div>
        {tab === "llm" && <div className="flex flex-wrap gap-2">{legend.map(({ k, n }) => (
          <Badge key={k} tone={OWASP_STATUS[k].tone === "neutral" ? "neutral" : (OWASP_STATUS[k].tone as any)}><i className={cn("h-1.5 w-1.5 rounded-full", OWASP_STATUS[k].dot)} />{OWASP_STATUS[k].label} · {n}</Badge>))}</div>}
      </div>

      {tab === "asi" && (<>
        <p className="mb-4 max-w-3xl text-sm text-slate-400">OWASP Top 10 for Agentic Applications (2026). ASI01-ASI03 are probed directly (goal hijack, tool misuse, identity and privilege abuse, including agent identity spoofing and excessive agency). ASI04-ASI10 need a live multi-agent environment and are only partly reachable through a chat endpoint, so they are marked “limited coverage”.</p>
        <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-5" data-testid="asi-grid">
          {!fw && Array.from({ length: 10 }, (_, i) => <div key={i} className="glass h-56 animate-pulse rounded-2xl" />)}
          {(fw?.asi || []).map((c: any) => { const st = OWASP_STATUS[c.status as OwaspStatus]; const Icon = st.icon; return (
            <Card key={c.id} data-testid={`asi-${c.code}`} className={cn("flex h-full flex-col border bg-gradient-to-b to-transparent", st.ring, st.glow, st.wash)}>
              <div className="flex flex-1 flex-col p-5">
                <div className="flex items-start justify-between"><div className={cn("grid h-10 w-10 place-items-center rounded-xl bg-white/[0.05] ring-1 ring-inset ring-white/10", st.text)}><Icon className="h-5 w-5" /></div><span className="font-mono text-[13px] font-semibold text-slate-300">{c.code}</span></div>
                <div className="mt-4 text-[15px] font-semibold leading-snug text-white">{c.en}</div>
                <div className={cn("mt-1 flex items-center gap-1.5 text-[12px] font-medium", st.text)}><i className={cn("h-1.5 w-1.5 rounded-full", st.dot)} />{st.label}</div>
                <p className="mt-3 line-clamp-4 text-[12px] leading-relaxed text-slate-500">{c.desc}</p>
                <div className="mt-auto flex flex-wrap gap-1.5 pt-4">
                  {c.coverage === "limited" && <Badge tone="amber">limited coverage</Badge>}
                  {c.tested > 0 && <Badge tone="green">{c.tested - c.violations} clean</Badge>}
                  {c.verified > 0 && <Badge tone="red">{c.verified} verified</Badge>}
                  {c.violations > c.verified && <Badge tone="amber">{c.violations - c.verified} to review</Badge>}</div>
              </div></Card>); })}
        </div>
        <p className="mt-5 text-xs text-slate-500">Cases join a category through the <code>asi_category</code> field (or automatically for tool abuse and indirect injection). Load “Advanced example - Agentic risks” from Library to try it.</p>
      </>)}
      {tab === "llm" && (<>
      <div className="mb-8 grid gap-5 lg:grid-cols-3">
        <Card><CardHeader><div><CardTitle>Compliance score</CardTitle><CardDescription>Share of “clean” among the tested categories</CardDescription></div>
          <Tip label="Score = clean categories / tested categories. Untested categories are not counted in the score; that is why coverage (tested/10) is shown alongside. Not a certificate."><Info className="h-4 w-4 cursor-help text-slate-500" /></Tip></CardHeader>
          <CardContent>{m ? <ComplianceMeter score={m.score ?? null} coverage={m.coverage ?? 0} tested={m.tested ?? 0} total={m.total ?? 10} categories={m.categories} /> : <ChartSkeleton h={130} />}</CardContent></Card>
        <Card className="lg:col-span-2"><CardHeader><CardTitle>How to read this?</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-300">
            <p>Cards reflect the result of the <b className="text-white">latest run</b> that covers the category. “Vulnerable” only shows for findings <b className="text-white">verified by replaying</b> in new conversations; unverified/inconclusive results are separated as “Needs review”.</p>
            <p className="rounded-xl border border-amber-400/25 bg-amber-500/[0.07] p-3 text-xs leading-relaxed text-amber-100">{OWASP_DISCLAIMER}</p>
            {m && <div className="text-xs text-slate-500">This edition: {m.edition}. 2023 (v1.1) ids (e.g. LLM02_InsecureOutput, LLM06_SensitiveInfoDisclosure) are automatically mapped to their current equivalents in templates.</div>}
          </CardContent></Card>
      </div>

      <h2 className="mb-4 text-[15px] font-semibold text-white">Coverage and compliance matrix</h2>
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-5">
        {!m && Array.from({ length: 10 }, (_, i) => <div key={i} className="glass h-64 animate-pulse rounded-2xl" />)}
        {cats.map((c, i) => {
          const st = OWASP_STATUS[c.status as OwaspStatus];
          const Icon = st.icon;
          return (
            <motion.div key={c.id} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04, duration: 0.4 }} whileHover={{ y: -4 }} className="h-full">
              <Card className={cn("group relative flex h-full flex-col overflow-hidden border bg-gradient-to-b to-transparent transition-shadow duration-300 hover:shadow-[0_18px_40px_-18px_rgba(0,0,0,.8)]", st.ring, st.glow, st.wash)}>
                <span className={cn("absolute inset-x-0 top-0 h-[2px] origin-left scale-x-[0.3] transition-transform duration-500 group-hover:scale-x-100", st.bar)} />
                <div className="flex flex-1 flex-col p-5">
                  <div className="flex items-start justify-between">
                    <div className={cn("grid h-10 w-10 place-items-center rounded-xl bg-white/[0.05] ring-1 ring-inset ring-white/10 transition-transform duration-300 group-hover:scale-110 group-hover:rotate-[-4deg]", st.text)}><Icon className={cn("h-5 w-5", c.status === "testing" && "animate-spin")} /></div>
                    <span className="font-mono text-[13px] font-semibold text-slate-300">{c.code}</span>
                  </div>
                  <div className="mt-4 text-[15px] font-semibold leading-snug text-white">{c.en}</div>
                  <div className={cn("mt-1 flex items-center gap-1.5 text-[12px] font-medium", st.text)}><i className={cn("h-1.5 w-1.5 rounded-full", st.dot)} />{st.label}</div>
                  <p className="mt-3 line-clamp-3 text-[12px] leading-relaxed text-slate-500">{c.desc}</p>
                  <div className="mb-4 mt-4 flex flex-wrap items-center gap-1.5">
                    {c.coverage === "limited" && <Tip label="Only partially covered by black-box API testing; a full assessment needs a manual/architecture review."><Badge tone="amber">limited coverage</Badge></Tip>}
                    {c.status !== "not_tested" && c.status !== "testing" && <>
                      <Badge tone="green">{c.counts.clean} clean</Badge>
                      {c.counts.verified > 0 && <Badge tone="red">{c.counts.verified} verified</Badge>}
                      {c.counts.review + c.counts.inconclusive > 0 && <Badge tone="amber">{c.counts.review + c.counts.inconclusive} to review</Badge>}</>}
                  </div>
                  {c.last_run_at && <div className="mt-3 text-[11px] text-slate-600">{fmtDate(c.last_run_at)}</div>}
                  <div className="mt-auto flex items-center justify-between border-t border-white/[0.06] pt-3 [&]:mt-auto">
                    <Link href={`/findings?owasp=${c.id}`} className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] font-medium text-indigo-300 transition hover:text-indigo-200">Findings<ArrowUpRight className="h-3 w-3 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" /></Link>
                    {can("operator") && <button onClick={() => setScan([c.id])} title="Scan only this category" className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] text-slate-500 transition hover:text-white"><ListChecks className="h-3 w-3" />Scan this</button>}
                  </div>
                </div>
              </Card>
            </motion.div>);
        })}
      </div>
      </>)}
      <OwaspScanDialog open={scan !== null} onOpenChange={(o) => !o && setScan(null)} preset={scan || undefined} />
    </>
  );
}
