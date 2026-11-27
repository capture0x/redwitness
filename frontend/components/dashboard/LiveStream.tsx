"use client";
import Link from "next/link";
import { AnimatePresence, motion } from "framer-motion";
import { Ban, CheckCircle2, Dot, FileUp, HelpCircle, Send, ShieldAlert, Trash2, XCircle, type LucideIcon } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { LiveEvent, LiveFeed } from "@/lib/queries";
import { cn } from "@/lib/utils";

type Kind = "request" | "ok" | "violation" | "inconclusive" | "blocked" | "error" | "upload" | "cleanup" | "other";
type Line = { tone: "info" | "ok" | "bad" | "warn" | "mute"; text: string; title: string; meta: string; kind: Kind };

/** Turns a stored attempt record into one human-readable log line. Only real engine steps are shown. */
export function describe(e: LiveEvent): Line {
  const where = `${e.case_id}${e.turn ? ` · turn ${e.turn}` : ""}${e.replay ? " · replay" : ""}`;
  const o = e.outcome;
  const mk = (tone: Line["tone"], kind: Kind, title: string, meta: string): Line => ({ tone, kind, title, meta, text: meta ? `${title} · ${meta}` : title });
  if (o === "sent") return mk("info", "request", "Request sent to target", where);
  if (o.startsWith("judged:")) {
    const v = e.verdict ?? o.split(":")[1];
    const c = e.confidence != null ? ` · confidence ${e.confidence}` : "";
    return v === "violation" ? mk("bad", "violation", "Judge: violation", where + c) : v === "no_violation" ? mk("ok", "ok", "Judge: no violation", where + c) : mk("warn", "inconclusive", "Judge: inconclusive", where + c);
  }
  if (o === "blocked") return mk("warn", "blocked", "Governor refused request", where + (e.blocked_reason ? ` · ${e.blocked_reason}` : ""));
  if (o === "error") return mk("bad", "error", "Target error", where);
  if (o === "ingested") return mk("info", "upload", "Document uploaded to target", e.case_id);
  if (o === "cleaned") return mk("mute", "cleanup", "Uploaded document removed from target", e.case_id);
  if (o.startsWith("cleanup")) return mk("warn", "cleanup", `Cleanup ${o.replace("cleanup_", "")}`, e.case_id);
  return mk("mute", "other", o, where);
}
export const DOT = { info: "bg-sky-400/80", ok: "bg-emerald-400/80", bad: "bg-rose-400/80", warn: "bg-amber-400/80", mute: "bg-slate-600" } as const;
export const TXT = { info: "text-slate-300", ok: "text-emerald-300/80", bad: "text-rose-300/80", warn: "text-amber-300/80", mute: "text-slate-500" } as const;
export const clock = (ts: number) => new Date(ts * 1000).toLocaleTimeString("en-GB");

const ICON: Record<Kind, LucideIcon> = { request: Send, ok: CheckCircle2, violation: ShieldAlert, inconclusive: HelpCircle, blocked: Ban, error: XCircle, upload: FileUp, cleanup: Trash2, other: Dot };
const BUBBLE: Record<Line["tone"], string> = {
  info: "bg-sky-500/10 text-sky-300/80 ring-sky-400/20",
  ok: "bg-emerald-500/10 text-emerald-300/80 ring-emerald-400/20",
  bad: "bg-rose-500/10 text-rose-300/80 ring-rose-400/25",
  warn: "bg-amber-500/10 text-amber-300/80 ring-amber-400/20",
  mute: "bg-white/[0.05] text-slate-400 ring-white/10",
};

/** Live timeline of what the agents are doing right now (or the last run's steps when idle). New steps slide in from the top. */
export default function LiveStream({ feed, loading }: { feed?: LiveFeed | null; loading: boolean }) {
  const events = (feed?.events ?? []).slice(0, 7);
  return (
    <Card className="flex flex-col">
      <CardHeader><div><CardTitle>Agent live stream</CardTitle><CardDescription>{feed?.live ? `${feed.runs} run(s) in progress · real engine steps` : "Idle · showing the steps of the latest run"}</CardDescription></div>
        <span className={cn("flex items-center gap-2 rounded-full px-3 py-1 text-[11px] font-semibold tracking-wide ring-1 ring-inset", feed?.live ? "bg-emerald-500/10 text-emerald-200 ring-emerald-400/30" : "bg-white/[0.04] text-slate-400 ring-white/10")}>
          <span className="relative flex h-2 w-2"><span className={cn("absolute inline-flex h-full w-full rounded-full", feed?.live ? "animate-pulse-dot bg-emerald-400" : "")} /><span className={cn("relative inline-flex h-2 w-2 rounded-full", feed?.live ? "bg-emerald-400" : "bg-slate-600")} /></span>
          {feed?.live ? "LIVE" : "IDLE"}</span></CardHeader>
      <CardContent className="flex-1 pt-6">
        <div className="terminal relative min-h-[360px] overflow-hidden rounded-2xl p-6 font-mono">
          <div aria-hidden className="mb-4 flex items-center gap-1.5 font-mono text-[11px] text-slate-600"><i className="h-2 w-2 rounded-full bg-rose-400/60" /><i className="h-2 w-2 rounded-full bg-amber-400/60" /><i className="h-2 w-2 rounded-full bg-emerald-400/60" /><span className="ml-2">agent@redwitness ~ tail -f engine.log</span></div>
          {loading ? <div className="space-y-5">{[0, 1, 2, 3, 4].map((i) => <div key={i} className="flex items-center gap-4"><Skeleton className="h-8 w-8 rounded-full" /><Skeleton className="h-4 flex-1" /></div>)}</div>
            : events.length === 0 ? <div className="grid h-[320px] place-items-center text-center text-slate-600">No agent activity yet.<br />Start a test to see it here.</div>
            : (
              <ol className="relative">
                <span aria-hidden className="absolute bottom-4 left-[15px] top-4 w-px bg-gradient-to-b from-indigo-300/35 via-white/10 to-transparent" />
                <AnimatePresence initial={false}>
                  {events.map((e) => { const l = describe(e), Icon = ICON[l.kind]; return (
                    <motion.li key={`${e.run_id}-${e.seq}`} layout="position" initial={{ opacity: 0, y: -28, filter: "blur(4px)" }} animate={{ opacity: 1, y: 0, filter: "blur(0px)" }} exit={{ opacity: 0 }} transition={{ type: "spring", stiffness: 300, damping: 30 }} className="relative flex items-start gap-4 pb-5 last:pb-0">
                      <span className={cn("relative z-10 grid h-[31px] w-[31px] shrink-0 place-items-center rounded-full ring-1 ring-inset", BUBBLE[l.tone])}><Icon className="h-[15px] w-[15px]" /></span>
                      <Link href={`/runs/${e.run_id}`} className="group min-w-0 flex-1 pt-0.5">
                        <div className="flex items-baseline justify-between gap-3"><span className={cn("truncate text-[14px] font-medium group-hover:underline", TXT[l.tone])}>{l.title}</span><span className="shrink-0 font-mono text-[12px] text-slate-500 tabular">{clock(e.at)}</span></div>
                        {l.meta && <div className="mt-0.5 truncate font-mono text-[12.5px] text-slate-500">{l.meta}</div>}
                      </Link>
                    </motion.li>); })}
                </AnimatePresence>
                {feed?.live && <li className="relative flex items-center gap-4 pt-1 text-slate-500"><span className="relative z-10 grid h-[31px] w-[31px] place-items-center"><span className="h-2 w-2 animate-pulse-dot rounded-full bg-indigo-300/70" /></span><span className="text-[12.5px]">waiting for the next step…</span></li>}
              </ol>
            )}
        </div>
      </CardContent>
    </Card>
  );
}
