"use client";
import Link from "next/link";
import ThemeToggle from "@/components/ThemeToggle";
import { usePathname, useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { BookOpenCheck, FlaskConical, KeyRound, LayoutDashboard, GitCompareArrows, PackageSearch, Plug, ScanEye, Crosshair, ListChecks, Layers, Boxes, LogOut, OctagonX, ScrollText, Settings, ShieldCheck, ShieldHalf, Siren, Terminal, Users } from "lucide-react";
import { useState } from "react";
import { useMe, ROLE_LABEL, routeRole } from "@/lib/me";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "./ui/dialog";
import { Input, Label } from "./ui/input";
import { Tip } from "./ui/misc";
import { api, usePoll } from "@/lib/api";
import { cn } from "@/lib/utils";
import BrandMark from "./BrandMark";
import { Button } from "./ui/button";

const WORKSPACE = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/targets", label: "Targets", icon: Crosshair },
  { href: "/new", label: "New Test", icon: FlaskConical },
  { href: "/findings", label: "Findings", icon: Siren },
  { href: "/settings", label: "Settings", icon: Settings },
];
const MORE = [
  { label: "Testing", items: [
    { href: "/library", label: "Test Library", icon: BookOpenCheck },
    { href: "/benchmarks", label: "Benchmarks", icon: GitCompareArrows },
    { href: "/defense", label: "Defense Efficacy", icon: ShieldHalf },
    { href: "/suite", label: "AI Security Suite", icon: Boxes },
    { href: "/privacy", label: "Privacy & Extraction", icon: ScanEye },
    { href: "/model-scans", label: "Model Supply Chain", icon: PackageSearch },
    { href: "/mcp", label: "MCP Servers", icon: Plug },
    { href: "/logs", label: "Logs", icon: Terminal },
  ] },
  { label: "Compliance", items: [
    { href: "/owasp", label: "OWASP Compliance", icon: ListChecks },
    { href: "/compliance", label: "Compliance Suite", icon: Layers },
    { href: "/scopes", label: "Scopes", icon: ShieldCheck },
    { href: "/audit", label: "Audit", icon: ScrollText },
  ] },
  { label: "Administration", items: [{ href: "/users", label: "Users", icon: Users }] },
];

export default function Sidebar() {
  const path = usePathname();
  const router = useRouter();
  const { data: sys } = usePoll(() => api("/system"), 5000);
  const { me, can } = useMe();
  const [pwOpen, setPwOpen] = useState(false);
  const [pw, setPw] = useState({ current: "", next: "" });
  const [pwErr, setPwErr] = useState<string | null>(null);
  const changePw = async () => {
    setPwErr(null);
    try { await api("/auth/password", { method: "POST", body: JSON.stringify({ current: pw.current, new: pw.next }) }); router.replace("/login"); } catch (e: any) { setPwErr(e.message); }
  };
  const active = (h: string) => (h === "/" ? path === "/" : path.startsWith(h) || (h === "/findings" && path.startsWith("/runs")));
  const checks = [
    { ok: !!sys, label: "Server", val: sys ? "running" : "down" },
    { ok: !!sys?.signing_key, label: "Signing key", val: sys?.signing_key ? "ready" : "missing" },
    { ok: !!sys?.judge_configured, label: "Judge LLM", val: sys?.judge_configured ? "ready" : "missing" },
    { ok: sys?.audit_chain_ok !== false, label: "Audit chain", val: sys?.audit_chain_ok === false ? "BROKEN" : "intact" },
  ];
  const healthy = checks.every((c) => c.ok);
  const groups = [{ label: "Workspace", items: WORKSPACE }, ...MORE];
  return (
    <aside className="relative flex w-[232px] shrink-0 flex-col border-r border-white/[0.06] bg-sidebar/55 backdrop-blur-xl">
      <div className="px-5 pb-5 pt-6">
        <div className="flex items-center gap-2.5">
          <BrandMark size={34} />
          <div className="text-[15px] font-semibold tracking-tight text-white">RedWitness</div>
        </div>
      </div>
      <nav className="flex-1 space-y-8 overflow-y-auto px-3 pt-2">
        {groups.map((g) => {
          const items = g.items.filter(({ href }) => can(routeRole(href)));
          if (!items.length) return null;
          return (
            <div key={g.label} className="pb-1" data-testid={`nav-group-${g.label.toLowerCase()}`}>
              <div className="eyebrow mb-2 px-3">{g.label}</div>
              <div className="space-y-0.5">
                {items.map(({ href, label, icon: Icon }) => (
                  <Link key={href} href={href} className={cn("group relative flex h-9 items-center gap-2.5 rounded-lg px-3 text-[13px] font-medium transition-colors", active(href) ? "text-white" : "text-slate-400 hover:text-slate-100")}>
                    {active(href) && <motion.span layoutId="nav-pill" className="absolute inset-0 rounded-lg bg-white/[0.06] before:absolute before:inset-y-2 before:left-0 before:w-[2px] before:rounded-full before:bg-indigo-300/70 before:content-['']" transition={{ type: "spring", stiffness: 420, damping: 34 }} />}
                    {!active(href) && <span className="absolute inset-0 rounded-lg bg-white/0 transition-colors group-hover:bg-white/[0.04]" />}
                    <Icon className={cn("relative h-[16px] w-[16px] transition-colors", active(href) ? "text-slate-100" : "text-slate-500 group-hover:text-slate-300")} />
                    <span className="relative">{label}</span>
                  </Link>
                ))}
              </div>
            </div>
          );
        })}
      </nav>
      <div className="space-y-3 p-3">
        <ThemeToggle />
        <Tip label={checks.map((c) => `${c.label}: ${c.val}`).join(" · ")}>
          <div className="flex cursor-default items-center gap-2 rounded-lg px-3 py-2 text-[12px] text-slate-400">
            <span className="relative flex h-2 w-2"><span className={cn("absolute inline-flex h-full w-full rounded-full", healthy ? "animate-pulse-dot bg-emerald-400" : "")} /><span className={cn("relative inline-flex h-2 w-2 rounded-full", healthy ? "bg-emerald-400" : "bg-rose-500 shadow-[0_0_8px_#f43f5e]")} /></span>
            {healthy ? "All systems operational" : `${checks.filter((c) => !c.ok).length} issue(s) detected`}
          </div>
        </Tip>
        {can("operator") && <Button variant="danger" size="sm" className="w-full" disabled={!sys?.live_runs}
          onClick={async () => { if (confirm("Stop all running tests?")) await api("/kill", { method: "POST" }); }}>
          <OctagonX className="h-3.5 w-3.5" />Stop all{sys?.live_runs ? ` (${sys.live_runs})` : ""}
        </Button>}
        {me && (
          <div className="flex items-center gap-2.5 rounded-xl border border-white/[0.06] bg-white/[0.02] p-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-full bg-gradient-to-br from-indigo-400 to-violet-600 text-[13px] font-semibold uppercase text-snow">{me.username[0]}</div>
            <div className="min-w-0 flex-1 leading-tight"><div className="truncate text-[13px] font-medium text-slate-100">{me.username}</div><div className="text-[11px] text-slate-500">{ROLE_LABEL[me.role]}</div></div>
            <button title="Change password" onClick={() => setPwOpen(true)} className="rounded-md p-1.5 text-slate-500 transition hover:bg-white/10 hover:text-white"><KeyRound className="h-3.5 w-3.5" /></button>
            <button title="Sign out" aria-label="Sign out" onClick={async () => { await api("/auth/logout", { method: "POST" }); router.replace("/login"); }} className="rounded-md p-1.5 text-slate-500 transition hover:bg-white/10 hover:text-white"><LogOut className="h-3.5 w-3.5" /></button>
          </div>
        )}
      </div>
      <Dialog open={pwOpen} onOpenChange={setPwOpen}>
        <DialogContent className="w-[min(440px,94vw)]">
          <DialogTitle>Change password</DialogTitle>
          <DialogDescription>After the change all sessions (including this one) are closed; you sign in again.</DialogDescription>
          {pwErr && <div className="mt-3 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{pwErr}</div>}
          <div className="mt-4 space-y-3"><div><Label>Current password</Label><Input type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></div>
            <div><Label>New password (at least 12 characters)</Label><Input type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /></div></div>
          <div className="mt-5 flex justify-end"><Button disabled={pw.next.length < 12 || !pw.current} onClick={changePw}>Change</Button></div>
        </DialogContent>
      </Dialog>
    </aside>
  );
}
