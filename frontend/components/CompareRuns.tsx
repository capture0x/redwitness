"use client";
import { useState } from "react";
import { GitCompareArrows } from "lucide-react";
import { Badge, SEV_TONE } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Hint, Label, NativeSelect } from "@/components/ui/input";
import { api, fmtDate, sevLabel, usePoll } from "@/lib/api";

const GROUPS: [string, string, any, string][] = [
  ["fixed", "Fixed", "green", "verified in the earlier run, tested again here and not found"],
  ["new", "New", "red", "verified here, not in the earlier run"],
  ["still_open", "Still open", "amber", "verified in both runs"],
  ["not_retested", "Not retested", "neutral", "verified earlier, but this run did not test the case"],
];

/** What changed between this run and an earlier one: fixed, new, still open and not retested findings (by test case). */
export default function CompareRuns({ run }: { run: any }) {
  const { data: runs } = usePoll(() => api("/runs"), 0);
  const others = (runs || []).filter((r: any) => r.id !== run.id && r.status !== "running" && (r.config?.kind || "") !== "mcp_scan");
  const same = others.filter((r: any) => r.endpoint_url === run.endpoint_url);
  const [base, setBase] = useState("");
  const { data: cmp } = usePoll(() => (base ? api(`/runs/${run.id}/compare?base=${base}`) : Promise.resolve(null)), 0, [base]);
  if (run.status === "running" || others.length === 0) return null;
  return (
    <Card className="mb-6" data-testid="compare-runs"><CardContent className="space-y-4 p-5">
      <div className="flex items-center gap-2 font-medium text-white"><GitCompareArrows className="h-4 w-4 text-violet-300" />Compare with an earlier run</div>
      <div className="max-w-xl"><Label>Earlier run</Label>
        <NativeSelect data-testid="compare-base" value={base} onChange={(e) => setBase(e.target.value)}>
          <option value="">Choose a run…</option>
          {(same.length ? same : others).map((r: any) => <option key={r.id} value={r.id}>{fmtDate(r.created_at)} · {r.config?.library?.name || "Run"} · {r.verified} verified</option>)}</NativeSelect>
        {!same.length && <Hint>No other run of this target yet; runs of other targets are listed.</Hint>}</div>
      {cmp && <>
        {!cmp.same_target && <Hint className="text-amber-300">The two runs tested different targets.</Hint>}
        <div className="grid gap-3 md:grid-cols-4" data-testid="compare-result">{GROUPS.map(([k, label, tone, help]) => (
          <div key={k} className="rounded-xl border border-white/10 bg-white/[0.02] p-3" data-testid={`compare-${k}`}>
            <div className="flex items-center justify-between"><Badge tone={tone}>{label}</Badge><span className="text-lg font-semibold text-white">{cmp[k].length}</span></div>
            <p className="mt-1 text-[11px] text-slate-500">{help}</p>
            <div className="mt-2 space-y-1">{cmp[k].map((x: any) => <div key={x.case_id} className="flex items-center gap-1.5 text-xs text-slate-300"><Badge tone={SEV_TONE[x.severity]}>{sevLabel(x.severity)}</Badge><span className="truncate" title={x.case_id}>{x.title}</span></div>)}</div>
          </div>))}</div>
      </>}
    </CardContent></Card>
  );
}
