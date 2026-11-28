"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { ArrowLeft, CircleStop, Download, FileDown, FileText, ShieldAlert } from "lucide-react";
import ClientReportDialog from "@/components/ClientReportDialog";
import FindingCard, { Untrusted } from "@/components/FindingCard";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Meter, Skeleton } from "@/components/ui/misc";
import { api, fmtDate, fmtNum, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";

export default function RunPage() {
  const { id } = useParams<{ id: string }>();
  const { can } = useMe();
  const [reportOpen, setReportOpen] = useState(false);
  const { data: r, error } = usePoll(() => api(`/runs/${id}`), 2000, [id]);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const { data: reasons } = usePoll(() => api("/reasons"), 0);
  const classes = Object.fromEntries((meta?.attack_classes || []).map((c: any) => [c.id, c.label]));
  if (error) return <Notice tone="red">{error}</Notice>;
  if (!r) return <div className="space-y-4"><Skeleton className="h-12 w-72" /><Skeleton className="h-32" /><Skeleton className="h-64" /></div>;
  const s = r.snapshot || {}, L = r.limits;
  const why = (code: string) => reasons?.find((x: any) => x.code === code)?.explanation;
  const byCase = new Map<string, any[]>();
  r.attempts.forEach((a: any) => { const k = `${a.case_id}|${a.conversation_id}`; byCase.set(k, [...(byCase.get(k) || []), a]); });
  const meters = L ? [["Token", s.tokens_used ?? r.tokens_used, L.max_total_tokens], ["Requests", s.requests ?? r.requests, L.max_requests], ["Conversations", s.conversations ?? r.conversations, L.max_conversations], ["Duration (s)", Math.round(s.elapsed_seconds ?? 0), L.max_duration_seconds]] : [];
  return (
    <>
      <Link href="/" className="mb-3 inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300"><ArrowLeft className="h-3.5 w-3.5" />Dashboard</Link>
      <PageHeader title={r.config?.library?.name || "Run"} sub={`${r.config?.model} · ${r.endpoint_url} · ${fmtDate(r.created_at)}`}
        right={<>
          <StatusBadge status={r.status} />
          <Button size="sm" data-testid="client-report" disabled={r.status === "running"} onClick={() => setReportOpen(true)}><FileText className="h-4 w-4" />Client report</Button>
          <a href={`/api/runs/${id}/report.pdf`}><Button variant="secondary" size="sm"><FileDown className="h-4 w-4" />Technical PDF</Button></a>
          <a href={`/api/runs/${id}/findings.csv`}><Button variant="secondary" size="sm"><Download className="h-4 w-4" />CSV</Button></a>
          {r.status === "running" && can("operator") && <Button variant="danger" size="sm" onClick={() => api(`/runs/${id}/stop`, { method: "POST" })}><CircleStop className="h-4 w-4" />Stop</Button>}
        </>} />
      <ClientReportDialog open={reportOpen} onOpenChange={setReportOpen} run={r} />
      {r.config?.owasp_planned?.length > 0 && <div className="mb-4 flex flex-wrap items-center gap-1.5 text-xs text-slate-400">OWASP:{r.config.owasp_planned.map((c: string) => <Badge key={c} tone="violet">{c.split("_")[0]}</Badge>)}
        {r.config.owasp_skipped?.length > 0 && <span className="text-amber-300">· skipped (not allowed by the scope): {r.config.owasp_skipped.map((c: string) => c.split("_")[0]).join(", ")}</span>}</div>}
      {r.attempts.some((a: any) => a.outcome === "cleanup_failed") && <Notice tone="red"><b>Document cleanup failed:</b> {r.attempts.filter((a: any) => a.outcome === "cleanup_failed").length} document(s) uploaded to the target could not be deleted (the reason is on each row). Clean up the remaining documents on the target manually.</Notice>}
      {r.attempts.some((a: any) => a.outcome === "cleanup_skipped") && <Notice>This run used document upload (ingest) but the scope has <b>no delete URL defined</b>; the uploaded documents remained on the target. Add <code>ingest_delete_url</code> to the next scope version.</Notice>}
      {r.status !== "running" && r.stop_reason && <Notice tone={r.status === "completed" ? "green" : "amber"}><b className="font-mono">{r.stop_reason}</b>{why(r.stop_reason) && <> - {why(r.stop_reason)}</>}</Notice>}
      {s.circuit && <Notice tone="red"><ShieldAlert className="mr-1 inline h-4 w-4" />Circuit breaker open: {s.circuit}. Resuming is an operator decision.</Notice>}
      {meters.length > 0 && (
        <div className="mb-6 grid gap-4 md:grid-cols-4">{meters.map(([l, v, m]: any) => (
          <Card key={l} className="p-4"><div className="mb-2 flex justify-between text-xs text-slate-400"><span>{l}</span><span className="text-slate-300">{fmtNum(v)} / {fmtNum(m)}</span></div><Meter value={v} max={m} /></Card>))}</div>
      )}
      <h2 className="mb-3 text-sm font-semibold text-white">Findings <span className="text-slate-500">({r.findings.length})</span></h2>
      <div className="mb-8 space-y-3">{r.findings.map((f: any) => <FindingCard key={f.id} f={f} classes={classes} />)}{r.findings.length === 0 && <p className="text-sm text-slate-500">No findings yet.</p>}</div>
      <h2 className="mb-3 text-sm font-semibold text-white">Test flow</h2>
      <div className="space-y-3">
        {[...byCase.entries()].map(([k, list]) => (
          <Card key={k}><CardHeader><div className="flex items-center gap-2"><span className="font-mono text-sm text-white">{list[0].case_id}</span><Badge tone="violet">{classes[list[0].category] || list[0].category}</Badge>{list[0].is_replay ? <Badge tone="amber">verification replay</Badge> : null}</div></CardHeader>
            <CardContent className="space-y-3">
              {list.map((a: any) => a.outcome.startsWith("judged:") ? (
                <div key={a.id} className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs">
                  <b className={a.evaluation?.verdict === "violation" ? "text-red-300" : "text-emerald-300"}>Judge: {a.evaluation?.verdict}</b>{" "}
                  {a.evaluation?.downgrade_reason && <span className="ml-2 text-amber-300">({a.evaluation.downgrade_reason})</span>}
                  <span className="ml-2 text-slate-500">confidence {a.evaluation?.confidence} · {a.evaluation?.refusal_detected ? "target refused" : "no refusal"}</span>
                  <div className="mt-1 text-slate-400">{a.evaluation?.rationale}</div></div>
              ) : a.outcome === "ingested" || a.outcome === "cleaned" || a.outcome.startsWith("cleanup") ? <div key={a.id} className={`text-xs ${a.outcome === "cleanup_failed" ? "text-red-300" : a.outcome === "cleanup_skipped" ? "text-amber-300" : "text-slate-400"}`}>{a.outcome === "cleaned" ? "🧹" : a.outcome.startsWith("cleanup") ? "⚠️" : "📎"} {a.prompt}{a.blocked_reason ? ` - ${a.blocked_reason}` : ""}</div> : (
                <div key={a.id}>
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Turn {a.turn} · test input sent</div>
                  <pre className="max-h-40 overflow-auto rounded-xl bg-violet-500/[0.08] p-3 text-xs text-slate-300">{a.prompt}</pre>
                  {a.outcome === "blocked" ? <Notice>Blocked: <b className="font-mono">{a.blocked_reason}</b> - {why(a.blocked_reason)}</Notice>
                    : a.outcome === "error" ? <Notice tone="red">{a.response}</Notice> : <div className="mt-2"><Untrusted>{a.response}</Untrusted></div>}
                </div>
              ))}
            </CardContent></Card>
        ))}
        {byCase.size === 0 && <p className="text-sm text-slate-500">No requests sent yet.</p>}
      </div>
    </>
  );
}
