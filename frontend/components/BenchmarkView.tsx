"use client";
import Link from "next/link";
import { useState } from "react";
import { motion } from "framer-motion";
import { Crown, Radar as RadarIcon, BarChart3 } from "lucide-react";
import { MODEL_COLORS, ModelCompareBars, ModelRadar } from "@/components/charts/charts";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fmtNum } from "@/lib/api";
import { owasp_short } from "@/lib/owasp";
import { cn } from "@/lib/utils";

const pct = (v: number | null | undefined) => (v == null ? "-" : `${Math.round(v * 100)}%`);
const STATUS_TONE: Record<string, any> = { running: "blue", completed: "green", partial: "amber" };

/** Leaderboard cards: rank, model, failure rate, verified findings. Lower failure rate = better. */
export function Leaderboard({ b, compact = false }: { b: any; compact?: boolean }) {
  const ordered = [...b.targets].map((t: any, i: number) => ({ t, i })).sort((x, y) => x.t.rank - y.t.rank);
  if (compact) return (
    <Card className="h-full"><CardHeader><div><CardTitle>Leaderboard</CardTitle><CardDescription>Lower failure rate ranks higher</CardDescription></div></CardHeader>
      <CardContent className="space-y-3 pt-4">{ordered.map(({ t, i }) => (
        <Link key={t.run_id} href={`/runs/${t.run_id}`} className="surface-hover flex items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3.5">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full text-[12px] font-semibold text-slate-900" style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }}>{t.rank}</span>
          <div className="min-w-0 flex-1"><div className="truncate text-[13px] font-medium text-white">{t.model}</div><div className="text-[11px] text-slate-500">{t.verified} verified · {t.tested} tests</div></div>
          <div className={cn("text-[20px] font-semibold tabular", (t.fail_rate ?? 0) === 0 ? "text-emerald-300" : (t.fail_rate ?? 0) < 0.25 ? "text-amber-300" : "text-rose-300")}>{pct(t.fail_rate)}</div>
        </Link>))}</CardContent></Card>
  );
  return (
    <div className={cn("grid gap-4", ordered.length > 2 ? "md:grid-cols-3" : "md:grid-cols-2")}>
      {ordered.map(({ t, i }) => (
        <motion.div key={t.run_id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: t.rank * 0.06 }}>
          <Card className={cn("surface-hover relative overflow-hidden p-5", t.rank === 1 && b.status !== "running" && "border-emerald-400/30")}>
            <div className="absolute inset-x-0 top-0 h-[3px]" style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }} />
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0"><div className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-slate-500">{t.rank === 1 && b.status !== "running" ? <Crown className="h-3.5 w-3.5 text-amber-300" /> : null}#{t.rank}</div>
                <div className="mt-1 truncate text-[16px] font-semibold text-white">{t.model}</div><div className="truncate font-mono text-[11px] text-slate-500">{t.endpoint_url}</div></div>
              <Badge tone={STATUS_TONE[t.status === "completed" ? "completed" : t.status === "running" ? "running" : "partial"]}>{t.status}</Badge>
            </div>
            <div className="mt-4 flex items-end gap-6">
              <div><div className={cn("text-[34px] font-semibold leading-none tabular", (t.fail_rate ?? 0) === 0 ? "text-emerald-300" : (t.fail_rate ?? 0) < 0.25 ? "text-amber-300" : "text-rose-300")}>{pct(t.fail_rate)}</div><div className="mt-1 text-[11px] text-slate-500">failure rate</div></div>
              <div><div className="text-[20px] font-semibold leading-none text-white tabular">{t.verified}</div><div className="mt-1 text-[11px] text-slate-500">verified findings</div></div>
              <div><div className="text-[20px] font-semibold leading-none text-white tabular">{t.tested}</div><div className="mt-1 text-[11px] text-slate-500">tests evaluated</div></div>
            </div>
            <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500"><span>{fmtNum(t.tokens)} tokens</span><Link href={`/runs/${t.run_id}`} className="text-indigo-300 hover:underline">Open run →</Link></div>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}

export function Legend({ targets }: { targets: any[] }) {
  return <div className="flex flex-wrap gap-x-5 gap-y-1 text-[12px] text-slate-400">{targets.map((t, i) => <span key={t.run_id} className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full" style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }} />{t.model}</span>)}</div>;
}

/** Bars and radar over the same data, plus a note when the comparison is not like-for-like. */
export function CompareChart({ b, height = 260, title = "Failure rate by OWASP category", compact = false }: { b: any; height?: number; title?: string; compact?: boolean }) {
  const [view, setView] = useState<"bars" | "radar">("bars");
  return (
    <Card>
      <CardHeader><div><CardTitle>{title}</CardTitle><CardDescription>{b.label} · share of evaluated tests the model failed (lower is better)</CardDescription></div>
        {!compact && <div className="flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5">{([["bars", BarChart3], ["radar", RadarIcon]] as const).map(([k, Icon]) => (
          <button key={k} onClick={() => setView(k)} aria-pressed={view === k} aria-label={k} className={cn("rounded-full px-2.5 py-1.5 transition-colors", view === k ? "bg-white/[0.12] text-white" : "text-slate-500 hover:text-slate-200")}><Icon className="h-3.5 w-3.5" /></button>))}</div>}</CardHeader>
      <CardContent className="pt-4">
        <div className="mb-3"><Legend targets={b.targets} /></div>
        {view === "bars" || compact ? <ModelCompareBars categories={b.categories} targets={b.targets} height={height} /> : <ModelRadar categories={b.categories} targets={b.targets} height={height + 40} />}
        {!b.comparable && b.status !== "running" && <p className="mt-3 rounded-lg border border-amber-400/25 bg-amber-500/[0.07] px-3 py-2 text-[12px] text-amber-100">Not a like-for-like comparison: at least one target did not finish the whole test set, so its numbers cover fewer tests.</p>}
      </CardContent>
    </Card>
  );
}

/** Per-category table with the exact counts behind the bars. */
export function CompareTable({ b }: { b: any }) {
  return (
    <Card className="overflow-hidden"><div className="overflow-x-auto"><table className="w-full text-[13px]">
      <thead><tr className="border-b border-white/[0.07] text-left text-[11px] uppercase tracking-wider text-slate-500"><th className="px-5 py-3 font-medium">OWASP category</th>{b.targets.map((t: any, i: number) => <th key={t.run_id} className="px-5 py-3 font-medium"><span className="mr-1.5 inline-block h-2 w-2 rounded-full" style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }} />{t.model}</th>)}</tr></thead>
      <tbody>{b.categories.map((c: string) => {
        const rates = b.targets.map((t: any) => t.categories[c]?.fail_rate);
        const worst = Math.max(...rates.map((r: number | null) => r ?? -1));
        return (<tr key={c} className="border-b border-white/[0.05] last:border-0"><td className="px-5 py-2.5"><span className="font-mono text-xs text-indigo-300">{owasp_short(c)}</span> <span className="text-slate-400">{c.split("_")[1]?.replace(/([A-Z])/g, " $1").trim()}</span></td>
          {b.targets.map((t: any) => { const d = t.categories[c]; const bad = d?.fail_rate != null && d.fail_rate === worst && worst > 0 && b.targets.length > 1;
            return <td key={t.run_id} className={cn("px-5 py-2.5 tabular", bad ? "text-rose-300" : "text-slate-200")}>{d ? <>{pct(d.fail_rate)} <span className="text-slate-600">· {d.violations}/{d.tested}{d.verified ? ` · ${d.verified} verified` : ""}</span></> : <span className="text-slate-600">not tested</span>}</td>; })}</tr>);
      })}</tbody></table></div></Card>
  );
}
