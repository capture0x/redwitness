"use client";
import Link from "next/link";
import { useState } from "react";
import { Activity, ArrowUpRight, Coins, FlaskConical, ListChecks, Plus, ShieldAlert, Target } from "lucide-react";
import GettingStarted from "@/components/GettingStarted";
import OwaspScanDialog from "@/components/OwaspScanDialog";
import LiveStream from "@/components/dashboard/LiveStream";
import RecentActivity from "@/components/dashboard/RecentActivity";
import SystemHealth from "@/components/dashboard/SystemHealth";
import { CompareChart, Leaderboard } from "@/components/BenchmarkView";
import { ComplianceMeter, PassRateTrend, RiskTrend, SeverityBars, Spark, TokenArea } from "@/components/charts/charts";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartSkeleton, KpiSkeleton } from "@/components/ui/misc";
import { Count, Item, Stagger } from "@/components/motion";
import PageHeader, { Notice } from "@/components/PageHeader";
import { api, fmtNum, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import { useHealth, useLiveFeed, useTokenRate } from "@/lib/queries";
import { cn } from "@/lib/utils";

export default function Dashboard() {
  const { can } = useMe();
  const { data: st, loading, updatedAt } = usePoll(() => api("/stats"), 4000);
  const { data: runs, loading: runsLoading } = usePoll(() => api("/runs"), 4000);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const { data: ow } = usePoll(() => api("/owasp/matrix"), 5000);
  const { data: bms } = usePoll(() => api("/benchmarks"), 8000);
  const latestId: string | undefined = bms?.[0]?.id;
  const { data: bench } = usePoll(() => (latestId ? api(`/benchmarks/${latestId}`) : Promise.resolve(null)), 4000, [latestId]);
  const health = useHealth();
  const live = useLiveFeed();
  const tokenRate = useTokenRate(st?.tokens, updatedAt);
  const [scanOpen, setScanOpen] = useState(false);
  const ts: any[] = st?.timeseries ?? [];
  const sys = health.data?.sys;
  const kpis = [
    { id: "t", label: "Tests performed", value: st?.attempts ?? 0, hint: `${fmtNum(st?.runs)} runs`, icon: FlaskConical, color: "#8e92ff", spark: ts.map((d) => d.passed + d.failed) },
    { id: "v", label: "Verified findings", value: st?.findings_verified ?? 0, hint: `${fmtNum(st?.findings_total)} records incl. candidates`, icon: ShieldAlert, color: "#fb7185", spark: ts.map((d) => d.verified) },
    { id: "k", label: "Tokens spent", value: st?.tokens ?? 0, hint: "target + judge", icon: Coins, color: "#38bdf8", spark: ts.map((d) => d.tokens) },
    { id: "r", label: "Running runs", value: st?.running ?? 0, hint: st?.pass_rate != null ? `pass rate ${Math.round(st.pass_rate * 100)}%` : "no evaluations yet", icon: Activity, color: "#34d399", spark: [] as number[] },
  ];
  const riskColor = (st?.risk_score ?? 0) >= 75 ? "text-rose-300" : (st?.risk_score ?? 0) >= 50 ? "text-orange-300" : (st?.risk_score ?? 0) >= 25 ? "text-amber-300" : "text-emerald-300";
  return (
    <>
      <PageHeader title="Overview" sub="Test pass rate, risk score and token usage across all runs, with live system activity."
        right={can("operator") ? <><Button variant="secondary" onClick={() => setScanOpen(true)}><ListChecks className="h-4 w-4" />OWASP scan</Button><Link href="/new"><Button><Plus className="h-4 w-4" />New test</Button></Link></> : undefined} />
      <GettingStarted />
      {sys?.warnings?.map((w: string) => <Notice key={w}>{w}</Notice>)}

      <Stagger className="mb-8 grid grid-cols-2 gap-6 lg:grid-cols-4">
        {kpis.map(({ id, label, value, hint, icon: Icon, color, spark }) => (
          <Item key={id}>{loading ? <KpiSkeleton /> : (
            <Card className="kpi group relative min-h-[200px] overflow-hidden p-8 pb-16" style={{ ["--kpi" as any]: color }}>
              <div className="flex items-center justify-between text-[12.5px] font-medium text-slate-400"><span>{label}</span>
                <span className="grid h-8 w-8 place-items-center rounded-lg bg-white/[0.05] ring-1 ring-inset ring-white/[0.08]"><Icon className="h-4 w-4" style={{ color }} /></span></div>
              <div className="mt-4 text-[46px] font-bold leading-none tracking-tighter text-white tabular"><Count to={value} /></div>
              <div className="mt-2.5 text-[12px] text-slate-500">{hint}</div>
              {spark.length > 0 && <div className="absolute inset-x-0 bottom-0 h-12 opacity-70"><Spark values={spark} color={color} id={id} height={48} /></div>}
            </Card>)}</Item>
        ))}
      </Stagger>

      <div className="mb-8 grid gap-6 lg:grid-cols-3">
        <Card><CardHeader><div><CardTitle>Risk score</CardTitle><CardDescription>Weighted verified findings</CardDescription></div><Target className="h-4 w-4 text-slate-600" /></CardHeader>
          <CardContent>{loading ? <ChartSkeleton h={170} /> : (<>
            <div className="flex items-end gap-3"><div className={cn("text-[52px] font-bold leading-none tracking-tighter tabular", riskColor)}>{st?.risk_score ?? 0}</div><div className="pb-1.5 text-[12px] text-slate-500">/ 100 · {st?.risk_label}</div></div>
            <div className="mt-5"><RiskTrend data={ts} height={130} /></div>
            <div className="mt-2 text-[11px] text-slate-600">Verified findings per day · last 7 days</div></>)}</CardContent></Card>
        <Card className="lg:col-span-2"><CardHeader><div><CardTitle>Pass-rate trend</CardTitle><CardDescription>Share of evaluations without a violation, per day (replays excluded)</CardDescription></div>
          <div className="text-right"><div className="text-[24px] font-semibold leading-none text-emerald-300 tabular">{st?.pass_rate != null ? `${Math.round(st.pass_rate * 100)}%` : "-"}</div><div className="mt-1 text-[11px] text-slate-600">overall</div></div></CardHeader>
          <CardContent className="pt-3">{loading ? <ChartSkeleton h={258} /> : <PassRateTrend data={ts} height={258} />}</CardContent></Card>
      </div>

      <div className="mb-8 grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2"><LiveStream feed={live.data} loading={live.isPending} /></div>
        <SystemHealth latency={health.data?.latency} latencyHistory={health.history} agents={sys?.live_runs ?? live.data?.runs ?? 0} tokenRate={tokenRate} loading={health.isPending} warnings={sys?.warnings?.length ?? 0} />
      </div>

      <div className="mb-8">
        {bench ? (<><div className="mb-3 flex items-center justify-between"><h2 className="text-[15px] font-semibold text-white">Model comparison</h2><Link href={`/benchmarks/${bench.id}`} className="inline-flex items-center gap-1 text-[12px] font-medium text-indigo-300 hover:text-indigo-200">Full benchmark<ArrowUpRight className="h-3 w-3" /></Link></div>
          <div className="grid gap-6 lg:grid-cols-5"><div className="lg:col-span-3"><CompareChart b={bench} compact height={230} title="Model comparison" /></div>
            <div className="lg:col-span-2"><Leaderboard b={bench} compact /></div></div></>) : (
          <Card><CardHeader><div><CardTitle>Model comparison</CardTitle><CardDescription>Send one test set to several models and see where each one fails</CardDescription></div></CardHeader>
            <CardContent className="flex items-center justify-between gap-4 text-sm text-slate-500"><span>No benchmark yet.</span>{can("operator") && <Link href="/new?compare=1"><Button variant="secondary" size="sm"><Plus className="h-3.5 w-3.5" />Start a benchmark</Button></Link>}</CardContent></Card>)}
      </div>

      <div className="mb-8 grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2"><RecentActivity runs={runs} loading={runsLoading} /></div>
        <Card><CardHeader><div><CardTitle>OWASP compliance</CardTitle><CardDescription>Top 10 for LLM Applications (2025)</CardDescription></div>
          <Link href="/owasp" className="inline-flex items-center gap-1 text-[12px] font-medium text-indigo-300 transition hover:text-indigo-200">Matrix<ArrowUpRight className="h-3 w-3" /></Link></CardHeader>
          <CardContent>
            <ComplianceMeter score={ow?.score ?? null} coverage={ow?.coverage ?? 0} tested={ow?.tested ?? 0} total={ow?.total ?? 10} categories={ow?.categories} />
            <div className="mt-6 flex items-center justify-between gap-3 border-t border-white/[0.06] pt-4 text-[12px] text-slate-500">
              <span>{ow?.vulnerable ?? 0} vulnerable · {ow?.review ?? 0} to review</span>
              {can("operator") && <Button size="sm" variant="outline" onClick={() => setScanOpen(true)}><ListChecks className="h-3.5 w-3.5" />Scan</Button>}</div>
          </CardContent></Card>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2"><CardHeader><div><CardTitle>Token usage</CardTitle><CardDescription>Target + judge tokens per day</CardDescription></div></CardHeader><CardContent className="pt-3">{loading ? <ChartSkeleton h={220} /> : <TokenArea data={ts} height={220} />}</CardContent></Card>
        <Card><CardHeader><div><CardTitle>Findings by severity</CardTitle><CardDescription>Verified only</CardDescription></div></CardHeader><CardContent className="pt-3">{loading ? <ChartSkeleton h={200} /> : <SeverityBars counts={st?.severity_counts ?? {}} labels={meta?.severities ?? {}} height={220} />}</CardContent></Card>
      </div>
      <OwaspScanDialog open={scanOpen} onOpenChange={setScanOpen} />
    </>
  );
}
