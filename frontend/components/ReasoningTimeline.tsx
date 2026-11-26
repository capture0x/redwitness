"use client";
import { CheckCircle2, CircleDashed, Lightbulb, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/** The steps of a reasoning_chain case as a timeline: what was sent (with the library's hint or constraint), what the target answered, and which rule a step broke. */
export default function ReasoningTimeline({ r }: { r: any }) {
  if (!r) return null;
  return (
    <div className="space-y-3" data-testid="reasoning-timeline">
      <div className="flex flex-wrap items-center gap-2 text-sm text-slate-300">
        {r.first_deviation ? <Badge tone="amber" data-testid="reasoning-deviation">Reasoning deviation at step {r.first_deviation}</Badge> : <Badge tone="green">No deviation</Badge>}
        <span className="text-xs text-slate-500">{r.deviations.length} of {r.checked} checked step(s) deviated · {r.total} step(s) in total</span>
      </div>
      <ol className="relative space-y-3 border-l border-white/10 pl-5">
        {r.steps.map((s: any) => (
          <li key={s.id} className="relative" data-testid={`reasoning-step-${s.id}`}>
            <span className={cn("absolute -left-[31px] top-1 grid h-5 w-5 place-items-center rounded-full bg-panel ring-1", s.deviated ? "ring-amber-400/60" : s.checked ? "ring-emerald-400/50" : "ring-white/15")}>
              {s.deviated ? <TriangleAlert className="h-3 w-3 text-amber-300" /> : s.checked ? <CheckCircle2 className="h-3 w-3 text-emerald-300" /> : <CircleDashed className="h-3 w-3 text-slate-500" />}
            </span>
            <div className={cn("rounded-xl border p-3", s.deviated ? "border-amber-400/30 bg-amber-500/[0.05]" : "border-white/[0.08] bg-black/20")}>
              <div className="mb-1 flex items-center gap-2 text-xs text-slate-400"><b className="text-slate-200">Step {s.index}: {s.id}</b>{s.hint && <Badge tone="violet"><Lightbulb className="h-3 w-3" />{s.hint_kind}</Badge>}</div>
              <pre className="whitespace-pre-wrap text-xs leading-relaxed text-slate-300">{s.sent}</pre>
              <div className="mt-2 text-[10px] uppercase tracking-wider text-amber-300/80">Intermediate answer · untrusted data</div>
              <pre className="max-h-40 overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300">{s.reply}{s.reply_truncated ? " ..." : ""}</pre>
              {s.checks.length > 0 && <ul className="mt-2 space-y-0.5 text-[11px]">{s.checks.map((c: any, i: number) => <li key={i} className={c.ok ? "text-emerald-300/80" : "text-amber-300"}>{c.ok ? "met" : "broken"} · {c.rule}: {c.detail}</li>)}</ul>}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
