"use client";
import Link from "next/link";
import { AlertTriangle, ShieldCheck } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Judge/verifier vs target independence (self-preference bias). The server classifies; this only shows the result. */
export default function BiasNotice({ targets, className }: { targets: { provider: string; model: string; url: string }[]; className?: string }) {
  const key = JSON.stringify(targets);
  const { data } = usePoll<any>(() => (targets.length ? api("/bias/assess", { method: "POST", body: JSON.stringify({ targets }) }) : Promise.resolve(null)), 0, [key]);
  if (!data || !data.targets?.length) return null;
  const issues = data.targets.flatMap((t: any) => [t.judge, t.verifier].filter((a: any) => a && a.level !== "independent"));
  if (!issues.length) return <div data-testid="bias-ok" className={cn("flex items-center gap-2 rounded-xl border border-emerald-400/25 bg-emerald-500/[0.07] p-3 text-xs text-emerald-100", className)}><ShieldCheck className="h-4 w-4 text-emerald-300" />Judge and target are from different model families.</div>;
  const hard = issues.some((a: any) => a.same_family);
  return (
    <div role="alert" data-testid="bias-warning" className={cn("flex gap-3 rounded-xl border p-3.5 text-sm backdrop-blur", hard ? "border-amber-400/40 bg-amber-500/10 text-amber-50" : "border-sky-400/25 bg-sky-500/[0.07] text-slate-200", className)}>
      <AlertTriangle className={cn("mt-0.5 h-4 w-4 shrink-0", hard ? "text-amber-300" : "text-sky-300")} />
      <div className="space-y-1">
        <div className="font-medium text-white">{hard ? "Bias control: the evaluator is not independent of the target" : "Bias control: independence not confirmed"}</div>
        {Array.from(new Set(issues.map((a: any) => a.message))).map((m: any) => <p key={m} className="text-xs leading-relaxed text-slate-300">{m}</p>)}
        <p className="text-xs text-slate-400">Policy: <b className="text-slate-200">{data.policy}</b>{data.policy === "block" && " - the run will be refused."} <Link href="/settings" className="text-violet-300 hover:underline">Choose an independent judge →</Link></p>
      </div>
    </div>
  );
}
