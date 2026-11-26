"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Pause, Play, Search, Terminal } from "lucide-react";
import PageHeader from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { DOT, TXT, describe } from "@/components/dashboard/LiveStream";
import { LiveEvent, useLogs } from "@/lib/queries";
import { cn } from "@/lib/utils";

const LIMIT = 300;
const FILTERS: { key: string; label: string; test: (e: LiveEvent) => boolean }[] = [
  { key: "all", label: "All", test: () => true },
  { key: "violation", label: "Violations", test: (e) => e.verdict === "violation" },
  { key: "clean", label: "Clean results", test: (e) => e.verdict === "no_violation" },
  { key: "blocked", label: "Blocked", test: (e) => e.outcome === "blocked" },
  { key: "error", label: "Errors", test: (e) => e.outcome === "error" },
];
const stamp = (ts: number) => { const d = new Date(ts * 1000); return `${d.toLocaleDateString("en-CA")} ${d.toLocaleTimeString("en-GB")}`; };

export default function Logs() {
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const logs = useLogs(LIMIT, paused);
  const feed = logs.data;
  const rows = useMemo(() => {
    const f = FILTERS.find((x) => x.key === filter)!;
    const needle = q.trim().toLowerCase();
    return (feed?.events ?? []).filter(f.test).filter((e) => !needle || `${e.case_id} ${e.run_id} ${e.owasp ?? ""} ${e.outcome}`.toLowerCase().includes(needle));
  }, [feed, filter, q]);
  return (
    <>
      <PageHeader title="Engine logs" sub="Every real engine step across all runs, newest first. Prompts and target responses are not shown here."
        right={<>
          <Badge tone={feed?.live ? "green" : "neutral"}>{feed?.live ? "LIVE" : "IDLE"}</Badge>
          <Button variant="secondary" size="sm" onClick={() => setPaused((p) => !p)}>{paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}{paused ? "Resume" : "Pause"}</Button>
        </>} />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <button key={f.key} onClick={() => setFilter(f.key)} aria-pressed={filter === f.key}
              className={cn("rounded-full px-3 py-1.5 text-[12px] font-medium ring-1 ring-inset transition-colors", filter === f.key ? "bg-white/[0.1] text-white ring-white/20" : "text-slate-400 ring-white/[0.07] hover:text-slate-200")}>{f.label}</button>
          ))}
        </div>
        <div className="relative ml-auto w-full sm:w-72"><Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <Input aria-label="Search" placeholder="Search case, run or OWASP id…" value={q} onChange={(e) => setQ(e.target.value)} className="pl-9" /></div>
      </div>
      <Card className="overflow-hidden">
        <div className="max-h-[calc(100vh-290px)] min-h-[320px] overflow-y-auto bg-black/25 p-4 font-mono text-[12px] leading-6">
          {logs.isPending ? <div className="space-y-2.5">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-3.5" />)}</div>
            : rows.length === 0 ? <div className="grid h-60 place-items-center text-center text-slate-600"><div><Terminal className="mx-auto mb-2 h-6 w-6" />{(feed?.events.length ?? 0) === 0 ? "No engine activity has been recorded yet." : "No log entries match."}</div></div>
            : <ul>{rows.map((e) => { const l = describe(e); return (
                <li key={`${e.run_id}-${e.seq}`} className="flex items-baseline gap-3 rounded px-1 hover:bg-white/[0.03]">
                  <span className="shrink-0 text-slate-600 tabular">{stamp(e.at)}</span>
                  <i className={cn("h-1.5 w-1.5 shrink-0 translate-y-[-1px] rounded-full", DOT[l.tone])} />
                  <Link href={`/runs/${e.run_id}`} className={cn("min-w-0 flex-1 truncate hover:underline", TXT[l.tone])}>{l.text}</Link>
                  {e.owasp && <span className="shrink-0 text-slate-500">{e.owasp}</span>}
                  {e.tokens > 0 && <span className="shrink-0 text-slate-600 tabular">{e.tokens} tokens</span>}
                </li>); })}</ul>}
        </div>
      </Card>
      <p className="mt-3 text-[12px] text-slate-500">{rows.length} entries · Showing the latest {LIMIT} steps.{!paused && " · Auto-refresh"}</p>
    </>
  );
}
