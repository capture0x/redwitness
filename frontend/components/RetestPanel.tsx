"use client";
import Link from "next/link";
import { useState } from "react";
import { Loader2, RotateCcw } from "lucide-react";
import { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Hint, Input, Label } from "@/components/ui/input";
import { api, fmtDate, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";

const OUTCOME: Record<string, { label: string; tone: any }> = {
  fixed: { label: "Fixed", tone: "green" }, still_vulnerable: { label: "Still vulnerable", tone: "red" },
  inconclusive: { label: "Inconclusive", tone: "amber" }, running: { label: "Running…", tone: "blue" },
};

/** Retest one finding after a fix: only its case is run again (same signed scope, target and library) and the result is linked here. */
export default function RetestPanel({ f }: { f: any }) {
  const { can } = useMe();
  const { data: hist, reload } = usePoll(() => api(`/findings/${f.id}/retests`), 3000, [f.id]);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const mcp = String(f.case_id || "").startsWith("mcp:");
  const start = async () => {
    setErr(""); setBusy(true);
    try { await api(`/findings/${f.id}/retest`, { method: "POST", body: JSON.stringify({ api_key: key || null }) }); setKey(""); reload(); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const last = hist?.[0];
  return (
    <div className="space-y-3" data-testid="retest-panel">
      <p className="text-sm text-slate-300">After the team ships a fix, run <b>only this case</b> again with the same signed scope, target and library. A fix counts when the case reaches a verdict and the finding does not come back.</p>
      {last && <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="retest-latest">Latest retest: <Badge tone={OUTCOME[last.outcome]?.tone}>{OUTCOME[last.outcome]?.label || last.outcome}</Badge><span className="text-xs text-slate-500">{fmtDate(last.created_at)}</span></div>}
      {err && <Notice tone="red">{err}</Notice>}
      {mcp ? <Hint>MCP findings are rechecked by auditing the server again on the MCP Servers page.</Hint> : can("operator") && <div className="flex flex-wrap items-end gap-2">
        <div className="w-72"><Label help="Optional. The saved credential is used; enter one only if it is no longer held in memory (after a restart).">Credential <span className="text-slate-600">(optional)</span></Label>
          <Input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} /></div>
        <Button data-testid="retest-start" disabled={busy || last?.outcome === "running"} onClick={start}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />}Retest</Button></div>}
      {hist && hist.length > 0 && <div className="space-y-1.5">{hist.map((h: any) => <div key={h.run_id} className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
        <Badge tone={OUTCOME[h.outcome]?.tone}>{OUTCOME[h.outcome]?.label || h.outcome}</Badge>{fmtDate(h.created_at)}{h.stop_reason && <span className="text-amber-300">· {h.stop_reason}</span>}
        <Link href={`/runs/${h.run_id}`} className="text-violet-300 hover:underline">run →</Link></div>)}</div>}
    </div>
  );
}
