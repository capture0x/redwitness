"use client";
import Link from "next/link";
import { ArrowUpRight } from "lucide-react";
import { Badge, StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RowsSkeleton } from "@/components/ui/misc";
import { fmtNum, timeAgo } from "@/lib/api";

const dur = (r: any) => { const end = r.finished_at ?? (r.status === "running" ? Date.now() / 1000 : null); if (!end) return "-"; const s = Math.max(0, Math.round(end - r.created_at)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`; };

/** The latest runs: started tests and finished campaigns. */
export default function RecentActivity({ runs, loading }: { runs?: any[] | null; loading: boolean }) {
  return (
    <Card>
      <CardHeader><div><CardTitle>Recent activity</CardTitle><CardDescription>Latest started tests and finished runs</CardDescription></div>
        <Link href="/findings" className="inline-flex items-center gap-1 text-[12px] font-medium text-indigo-300 transition hover:text-indigo-200">All findings<ArrowUpRight className="h-3 w-3" /></Link></CardHeader>
      <CardContent className="pt-4">
        {loading ? <RowsSkeleton rows={5} /> : !runs?.length ? <p className="py-10 text-center text-sm text-slate-500">No runs yet.</p> : (
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-[11px] uppercase tracking-wider text-slate-600"><th className="pb-3 font-medium">Run</th><th className="pb-3 font-medium">Status</th><th className="pb-3 text-right font-medium">Findings</th><th className="pb-3 text-right font-medium">Tokens</th><th className="pb-3 text-right font-medium">Duration</th><th className="pb-3 text-right font-medium">Started</th></tr></thead>
            <tbody>
              {runs.slice(0, 7).map((r) => (
                <tr key={r.id} className="group border-t border-white/[0.05] transition-colors hover:bg-white/[0.025]">
                  <td className="max-w-[220px] py-3.5 pr-3"><Link href={`/runs/${r.id}`} className="block truncate font-medium text-slate-100 group-hover:text-white">{r.config?.library?.name || "-"}</Link><div className="truncate font-mono text-[11px] text-slate-600">{r.id.slice(0, 8)}</div></td>
                  <td className="py-3.5"><StatusBadge status={r.status} /></td>
                  <td className="py-3.5 text-right tabular">{r.verified > 0 ? <Badge tone="red">{r.verified} verified</Badge> : <span className="text-slate-600">{r.findings ? `${r.findings} open` : "-"}</span>}</td>
                  <td className="py-3.5 text-right tabular text-slate-400">{fmtNum(r.tokens_used)}</td>
                  <td className="py-3.5 text-right tabular text-slate-400">{dur(r)}</td>
                  <td className="py-3.5 text-right text-slate-500">{timeAgo(r.created_at)}</td>
                </tr>))}
            </tbody>
          </table>)}
      </CardContent>
    </Card>
  );
}
