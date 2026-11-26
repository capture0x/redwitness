"use client";
import { Target } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const pct = (v: number | null | undefined) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
const ci = (x: number[] | null | undefined) => (x ? `95% CI ${Math.round(x[0] * 100)}-${Math.round(x[1] * 100)}%` : "no labels yet");

/** Precision / recall measured from human review, with the honest limits. `onApply` (Settings only) puts the suggested confidence threshold into the form. */
export default function CalibrationPanel({ onApply, refreshKey = 0 }: { onApply?: (t: number) => void; refreshKey?: number }) {
  const { data: c } = usePoll<any>(() => api("/calibration"), 0, [refreshKey]);
  if (!c) return null;
  const Kpi = ({ k, v, s, id }: any) => <div className="rounded-xl border border-white/[0.08] bg-black/20 px-4 py-3" data-testid={id}><div className="text-[11px] uppercase tracking-wider text-slate-500">{k}</div><div className="text-2xl font-semibold text-white">{v}</div><div className="text-[11px] text-slate-500">{s}</div></div>;
  return (
    <div className="glass mb-5 rounded-2xl p-5" data-testid="calibration-panel">
      <div className="mb-3 flex items-center gap-2"><Target className="h-4 w-4 text-violet-300" /><h2 className="text-sm font-semibold text-white">Detection quality (measured by human review)</h2><Badge tone="neutral">{c.reviewed} reviewed</Badge></div>
      {c.reviewed === 0 ? <p className="text-sm text-slate-400">No findings have been reviewed yet. Open a finding and mark it as a true or false positive; precision and recall are computed from those labels.</p> : <>
        <div className="grid gap-3 sm:grid-cols-4">
          <Kpi id="cal-precision" k="Precision" v={pct(c.precision)} s={ci(c.precision_ci)} /><Kpi id="cal-recall" k="Recall (reviewed)" v={pct(c.recall)} s={ci(c.recall_ci)} />
          <Kpi k="True / false positives" v={`${c.tp} / ${c.fp}`} s="reported findings" /><Kpi k="Missed / correctly held back" v={`${c.fn} / ${c.tn}`} s="not reported" /></div>
        {c.verifier.reviewed_refutations > 0 && <p className="mt-3 text-xs text-slate-400">Adversarial verifier: {c.verifier.correct} of {c.verifier.reviewed_refutations} reviewed refutations were correct ({pct(c.verifier.accuracy)}).</p>}
        <p className="mt-3 text-xs text-slate-300" data-testid="cal-threshold">{c.threshold.threshold != null ? <>Suggestion: {c.threshold.reason}. Current minimum confidence is <b>{c.settings.min_confidence}</b>; suggested <b>{c.threshold.threshold}</b>.{onApply && <Button className="ml-2" size="sm" variant="secondary" type="button" onClick={() => onApply(c.threshold.threshold)}>Use {c.threshold.threshold} in the form</Button>}</> : <>Threshold advice: {c.threshold.reason}.</>}</p>
      </>}
      <p className="mt-2 text-[11px] leading-relaxed text-slate-500">{c.note} Nothing changes automatically: suggestions are applied only when you press Save in Settings.</p>
    </div>
  );
}
