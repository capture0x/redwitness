import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badge = cva("inline-flex items-center gap-1.5 rounded-full px-2.5 py-[3px] text-[11px] font-medium ring-1 ring-inset", {
  variants: {
    tone: {
      neutral: "bg-slate-500/10 text-slate-300 ring-slate-400/20",
      violet: "bg-indigo-500/12 text-indigo-200 ring-indigo-400/25",
      blue: "bg-sky-500/12 text-sky-200 ring-sky-400/25",
      green: "bg-emerald-500/12 text-emerald-200 ring-emerald-400/25",
      amber: "bg-amber-500/12 text-amber-200 ring-amber-400/25",
      red: "bg-rose-500/12 text-rose-200 ring-rose-400/25",
      critical: "bg-rose-600/20 text-rose-200 ring-rose-400/40 shadow-glow-red",
      high: "bg-orange-500/15 text-orange-200 ring-orange-400/30",
      medium: "bg-amber-500/12 text-amber-200 ring-amber-400/25",
      low: "bg-sky-500/15 text-sky-200 ring-sky-400/30",
      info: "bg-slate-500/15 text-slate-300 ring-slate-400/25",
    },
  },
  defaultVariants: { tone: "neutral" },
});
export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badge> {}
export const Badge = ({ className, tone, ...p }: BadgeProps) => <span className={cn(badge({ tone }), className)} {...p} />;

export const SEV_TONE: Record<string, any> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
export const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export const STATUS: Record<string, { label: string; tone: any }> = {
  verified: { label: "Verified", tone: "red" }, unstable: { label: "Unstable", tone: "amber" }, candidate: { label: "Candidate", tone: "amber" },
  needs_review: { label: "Needs review", tone: "blue" }, false_positive: { label: "False positive", tone: "neutral" }, running: { label: "Running", tone: "blue" },
  completed: { label: "Completed", tone: "green" }, completed_budget: { label: "Finished within budget", tone: "green" },
  halted: { label: "Halted", tone: "red" }, failed: { label: "Error", tone: "red" }, stopped: { label: "Stopped", tone: "neutral" },
};
export const StatusBadge = ({ status }: { status: string }) => {
  const s = STATUS[status] || { label: status, tone: "neutral" };
  return <Badge tone={s.tone}>{status === "running" && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-blue-300" />}{s.label}</Badge>;
};
