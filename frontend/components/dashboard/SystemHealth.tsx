"use client";
import { useEffect, useRef, useState } from "react";
import { Bot, Gauge, Zap } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { Spark } from "@/components/charts/charts";
import { fmtCompact } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Live metric panel: API latency (measured round trip), active agents (running runs) and token burn rate. */
export default function SystemHealth({ latency, latencyHistory, agents, tokenRate, loading, warnings }: { latency?: number; latencyHistory: number[]; agents: number; tokenRate: number[]; loading: boolean; warnings: number }) {
  const [agentHist, setAgentHist] = useState<number[]>([]);
  const latest = useRef(agents);
  latest.current = agents;
  useEffect(() => { const t = setInterval(() => setAgentHist((h) => [...h.slice(-23), latest.current]), 3000); return () => clearInterval(t); }, []);
  const lat = latency ?? 0;
  const latTone = lat < 150 ? "text-emerald-300" : lat < 500 ? "text-amber-300" : "text-rose-300";
  const rate = tokenRate.at(-1) ?? 0;
  const rows = [
    { icon: Gauge, label: "API latency", value: latency == null ? "-" : `${lat} ms`, tone: latTone, spark: latencyHistory, color: lat < 150 ? "#34d399" : lat < 500 ? "#fbbf24" : "#fb7185", id: "lat" },
    { icon: Bot, label: "Active agents", value: String(agents), tone: agents ? "text-sky-300" : "text-slate-300", spark: agentHist.length > 1 ? agentHist : [0, agents], color: "#38bdf8", id: "ag" },
    { icon: Zap, label: "Token burn rate", value: `${fmtCompact(rate)}/min`, tone: "text-indigo-300", spark: tokenRate, color: "#aeb1ff", id: "tk" },
  ];
  return (
    <Card>
      <CardHeader><div><CardTitle>System health</CardTitle><CardDescription>Live metrics · refreshed every 3 s</CardDescription></div>
        <span className={cn("flex items-center gap-2 rounded-full px-3 py-1 text-[11px] font-semibold ring-1 ring-inset", warnings ? "bg-amber-500/10 text-amber-200 ring-amber-400/25" : "bg-emerald-500/10 text-emerald-200 ring-emerald-400/30")}>
          <span className="relative flex h-2 w-2"><span className={cn("absolute inline-flex h-full w-full rounded-full animate-pulse-dot", warnings ? "bg-amber-400" : "bg-emerald-400")} /><span className={cn("relative inline-flex h-2 w-2 rounded-full", warnings ? "bg-amber-400" : "bg-emerald-400")} /></span>{warnings ? `${warnings} warning(s)` : "Operational"}</span></CardHeader>
      <CardContent className="space-y-7 pt-7">
        {rows.map(({ icon: Icon, label, value, tone, spark, color, id }) => (
          <div key={id} className="flex items-center gap-4">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-white/[0.04] ring-1 ring-inset ring-white/[0.07]" style={{ boxShadow: `0 0 18px -8px ${color}` }}><Icon className="h-4 w-4" style={{ color }} /></div>
            <div className="min-w-0 flex-1"><div className="text-[12px] text-slate-500">{label}</div>
              {loading ? <Skeleton className="mt-1 h-5 w-20" /> : <div className={cn("text-[20px] font-bold leading-tight tabular", tone)}>{value}</div>}</div>
            <div className="w-28 shrink-0"><Spark values={spark} color={color} id={id} height={44} /></div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
