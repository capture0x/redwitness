"use client";
import { AlertTriangle, Info } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Judge model selection warning. The server (judge_advisory) evaluates signs of a small/local model; 'warn' is shown highlighted. */
export default function JudgeAdvisory({ compact = false, className }: { compact?: boolean; className?: string }) {
  const { data: sys } = usePoll(() => api("/system"), 8000);
  const a = sys?.judge_advisory;
  if (!a) return null;
  const warn = a.level === "warn";
  const Icon = warn ? AlertTriangle : Info;
  return (
    <div role={warn ? "alert" : "note"} className={cn("flex gap-3 rounded-xl border p-3.5 text-sm backdrop-blur", warn ? "border-amber-400/40 bg-amber-500/10 text-amber-50" : "border-sky-400/25 bg-sky-500/[0.07] text-slate-200", className)}>
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", warn ? "text-amber-300" : "text-sky-300")} />
      <div>
        <div className="font-medium text-white">{warn ? "Judge model warning" : "About the judge model"}</div>
        {!compact && <p className="mt-0.5 leading-relaxed text-slate-300">{a.message}</p>}
        {compact && <p className="mt-0.5 text-xs leading-relaxed text-slate-300">Small/local judge models can cause false negatives; a capable model (Claude Sonnet/Opus, GPT-4o class) is recommended in production.</p>}
        {warn && a.reasons?.length > 0 && <p className="mt-1.5 text-xs text-amber-200/90">Reason: {a.reasons.join("; ")}.</p>}
      </div>
    </div>
  );
}
