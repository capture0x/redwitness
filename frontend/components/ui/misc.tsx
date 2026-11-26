"use client";
import * as React from "react";
import * as Progress from "@radix-ui/react-progress";
import * as Switch from "@radix-ui/react-switch";
import * as Tooltip from "@radix-ui/react-tooltip";
import * as Checkbox from "@radix-ui/react-checkbox";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

export const Meter = ({ value, max, className }: { value: number; max: number; className?: string }) => {
  const pct = Math.min(100, max ? (value / max) * 100 : 0);
  const tone = pct >= 90 ? "from-rose-500 to-red-500" : pct >= 80 ? "from-amber-400 to-orange-500" : "from-indigo-500 to-violet-400";
  return (
    <Progress.Root value={pct} className={cn("relative h-2 w-full overflow-hidden rounded-full bg-white/10", className)}>
      <Progress.Indicator className={cn("h-full rounded-full bg-gradient-to-r transition-all duration-700", tone)} style={{ width: `${pct}%` }} />
    </Progress.Root>
  );
};
export const Toggle = ({ className, ...p }: React.ComponentProps<typeof Switch.Root>) => (
  <Switch.Root className={cn("relative h-6 w-11 rounded-full bg-white/10 transition data-[state=checked]:bg-indigo-500", className)} {...p}>
    <Switch.Thumb className="block h-5 w-5 translate-x-0.5 rounded-full bg-white transition-transform data-[state=checked]:translate-x-[22px]" />
  </Switch.Root>
);
export const Check_ = ({ className, ...p }: React.ComponentProps<typeof Checkbox.Root>) => (
  <Checkbox.Root className={cn("flex h-5 w-5 shrink-0 items-center justify-center rounded-md border border-white/20 bg-white/5 transition data-[state=checked]:border-indigo-400 data-[state=checked]:bg-indigo-500", className)} {...p}>
    <Checkbox.Indicator><Check className="h-3.5 w-3.5 text-white" /></Checkbox.Indicator>
  </Checkbox.Root>
);
export const Tip = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <Tooltip.Root delayDuration={150}>
    <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
    <Tooltip.Portal><Tooltip.Content sideOffset={6} className="z-50 max-w-xs rounded-lg border border-white/10 bg-navy-800 px-3 py-2 text-xs text-slate-200 shadow-glass">{label}</Tooltip.Content></Tooltip.Portal>
  </Tooltip.Root>
);
export const TooltipProvider = Tooltip.Provider;
export const Skeleton = ({ className }: { className?: string }) => <div className={cn("relative overflow-hidden rounded-lg bg-white/[0.05] before:absolute before:inset-0 before:-translate-x-full before:animate-[shimmer_1.6s_infinite] before:bg-gradient-to-r before:from-transparent before:via-white/[0.07] before:to-transparent", className)} />;
/** Skeleton of a KPI card. */
export const KpiSkeleton = () => (<div className="glass rounded-2xl p-6"><Skeleton className="h-3 w-24" /><Skeleton className="mt-5 h-9 w-28" /><Skeleton className="mt-4 h-3 w-36" /></div>);
/** Skeleton of a chart card. */
export const ChartSkeleton = ({ h = 200 }: { h?: number }) => (<div className="space-y-3" style={{ height: h }}><div className="flex h-full items-end gap-2">{[40, 65, 50, 80, 55, 90, 70, 60, 85, 75].map((v, i) => <div key={i} className="flex-1 animate-pulse rounded-t-md bg-white/[0.05]" style={{ height: `${v}%`, animationDelay: `${i * 90}ms` }} />)}</div></div>);
/** Skeleton rows of a table / list. */
export const RowsSkeleton = ({ rows = 5 }: { rows?: number }) => (<div className="space-y-3">{Array.from({ length: rows }, (_, i) => (<div key={i} className="flex items-center gap-4"><Skeleton className="h-9 w-9 shrink-0 rounded-full" /><div className="flex-1 space-y-2"><Skeleton className="h-3 w-2/5" /><Skeleton className="h-3 w-1/4" /></div><Skeleton className="h-5 w-16 rounded-full" /></div>))}</div>);
