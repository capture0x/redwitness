"use client";
import Link from "next/link";
import { ArrowRight, Check, PartyPopper, Rocket } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Meter } from "@/components/ui/misc";
import { api, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import { ONBOARDING_ACTIVE, ONBOARDING_DISMISSED, setPref, usePref } from "@/lib/prefs";
import { cn } from "@/lib/utils";

/** First-run wizard on the dashboard: judge, target, first scan. It reads the real state, so a step turns green by itself. */
export default function GettingStarted() {
  const { can } = useMe();
  const { data: sys } = usePoll(() => api("/system"), 5000);
  const { data: targets } = usePoll(() => api("/targets"), 5000);
  const { data: runs } = usePoll(() => api("/runs"), 5000);
  const [dismissed] = usePref(ONBOARDING_DISMISSED);
  const [active] = usePref(ONBOARDING_ACTIVE);
  if (!sys || !targets || !runs || dismissed) return null;

  const steps = [
    { id: "judge", done: !!sys.judge_configured, title: "Add the judge API key",
      text: "The judge model reads each answer and decides whether a rule was broken. Put its key in your .env file (for example ANTHROPIC_API_KEY=...), run docker compose up -d, then pick the model in Settings.",
      action: "Open Settings", href: "/settings", allowed: can("admin"), blocked: "Ask an admin to set this up." },
    { id: "target", done: targets.length > 0, title: "Add a target",
      text: "The target is the chatbot or LLM API you want to test. Saving it sends nothing; a test only starts after you sign a scope.",
      action: "Add target", href: "/targets", allowed: can("operator"), blocked: "Ask an operator to add one." },
    { id: "scan", done: runs.length > 0, title: "Start your first scan",
      text: "Quick scan runs the OWASP LLM Top 10 kit against your target. You review the plan and sign it before anything is sent.",
      action: "Start first scan", href: "/new", allowed: can("operator"), blocked: "Ask an operator to start it." },
  ];
  const doneCount = steps.filter((s) => s.done).length;
  const all = doneCount === steps.length;
  const current = steps.find((s) => !s.done);
  if (all && !active) return null;

  if (all) return (
    <Card data-testid="gs-done" className="mb-8 border-emerald-400/25 bg-emerald-500/[0.06]"><CardContent className="flex flex-wrap items-center justify-between gap-4 p-6">
      <div className="flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-500/20 text-emerald-300"><PartyPopper className="h-5 w-5" /></div>
        <div><div className="text-[15px] font-semibold text-white">You are all set</div><p className="text-[13px] text-slate-400">Your first scan is running or finished. Findings appear on the Findings page as soon as they are verified.</p></div></div>
      <div className="flex gap-2"><Link href="/findings"><Button variant="secondary">See findings</Button></Link>
        <Button data-testid="gs-finish" onClick={() => { setPref(ONBOARDING_ACTIVE, false); setPref(ONBOARDING_DISMISSED, true); }}>Go to dashboard</Button></div>
    </CardContent></Card>
  );

  return (
    <Card data-testid="getting-started" className="mb-8 overflow-hidden border-indigo-400/20"><CardContent className="p-0">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.06] bg-gradient-to-r from-indigo-500/[0.10] to-transparent px-7 py-5">
        <div className="flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl bg-indigo-500/20 text-indigo-200"><Rocket className="h-5 w-5" /></div>
          <div><div className="text-[16px] font-semibold text-white">Welcome to AIVeritX</div><p className="text-[13px] text-slate-400">Three steps to your first verified result. Step {doneCount + 1} of {steps.length}.</p></div></div>
        <div className="flex items-center gap-4"><div className="w-40"><Meter value={doneCount} max={steps.length} /></div>
          <button data-testid="gs-skip" onClick={() => setPref(ONBOARDING_DISMISSED, true)} className="text-[12px] text-slate-500 underline-offset-2 transition hover:text-slate-300 hover:underline">Skip for now</button></div>
      </div>
      <ol className="divide-y divide-white/[0.05]">
        {steps.map((s, i) => {
          const isCurrent = current?.id === s.id;
          return (
            <li key={s.id} data-testid={`gs-step-${s.id}`} data-done={s.done} className={cn("flex flex-wrap items-center gap-4 px-7 py-5 transition", isCurrent && "bg-white/[0.025]", !s.done && !isCurrent && "opacity-60")}>
              <div className={cn("grid h-8 w-8 shrink-0 place-items-center rounded-full text-[13px] font-semibold ring-1 ring-inset", s.done ? "bg-emerald-500/20 text-emerald-300 ring-emerald-400/40" : isCurrent ? "bg-indigo-500/25 text-indigo-100 ring-indigo-300/50" : "bg-white/[0.04] text-slate-500 ring-white/10")}>
                {s.done ? <Check className="h-4 w-4" data-testid={`gs-tick-${s.id}`} /> : i + 1}</div>
              <div className="min-w-0 flex-1"><div className={cn("text-[14px] font-medium", s.done ? "text-slate-400 line-through decoration-slate-600" : "text-white")}>{s.title}</div>
                {!s.done && <p className="mt-0.5 max-w-2xl text-[12.5px] leading-relaxed text-slate-400">{s.text}</p>}</div>
              {isCurrent && (s.allowed
                ? <Link href={s.href} onClick={() => { if (s.id === "scan") setPref(ONBOARDING_ACTIVE, true); }}><Button data-testid={`gs-go-${s.id}`}>{s.action}<ArrowRight className="h-4 w-4" /></Button></Link>
                : <span className="text-[12px] text-amber-300">{s.blocked}</span>)}
            </li>
          );
        })}
      </ol>
    </CardContent></Card>
  );
}
