"use client";
import { useState } from "react";
import { FileText, Loader2 } from "lucide-react";
import { Notice } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input, Label, NativeSelect } from "@/components/ui/input";
import { Check_ } from "@/components/ui/misc";
import { api, fmtDate, usePoll } from "@/lib/api";

/** Options for the client-ready penetration test report. Other finished runs under the same signed scope can be added (one engagement, one report). */
export default function ClientReportDialog({ open, onOpenChange, run }: { open: boolean; onOpenChange: (o: boolean) => void; run: any }) {
  const { data: runs } = usePoll(() => api("/runs"), 0, [open]);
  const siblings = (runs || []).filter((x: any) => x.scope_id === run.scope_id && x.id !== run.id && x.status !== "running");
  const [f, setF] = useState({ client: "", project: "", tester: "", classification: "Confidential", include_unverified: false, format: "pdf" });
  const [extra, setExtra] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const set = (k: string, v: any) => setF((p) => ({ ...p, [k]: v }));

  const download = async () => {
    setErr(""); setBusy(true);
    try {
      const r = await fetch("/api/client-report", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json", "x-aiveritx-csrf": "1" },
        body: JSON.stringify({ ...f, run_ids: [run.id, ...extra] }) });
      if (!r.ok) { let m = `HTTP ${r.status}`; try { const d = await r.json(); m = typeof d.detail === "string" ? d.detail : d.detail?.message || m; } catch { /* not JSON */ } throw new Error(m); }
      const blob = await r.blob();
      const name = (r.headers.get("content-disposition") || "").match(/filename="([^"]+)"/)?.[1] || `pentest-report.${f.format}`;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      onOpenChange(false);
    } catch (e: any) { setErr(e.message || "The report could not be created."); } finally { setBusy(false); }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="client-report-dialog" className="space-y-4">
        <DialogTitle className="flex items-center gap-2"><FileText className="h-5 w-5 text-violet-300" />Client report</DialogTitle>
        <DialogDescription>A penetration test report for the client: executive summary, scope and authorization, findings with steps to reproduce and remediation, and appendices. Credentials never appear in it.</DialogDescription>
        {err && <Notice tone="red">{err}</Notice>}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label>Client</Label><Input data-testid="cr-client" value={f.client} maxLength={120} onChange={(e) => set("client", e.target.value)} placeholder="e.g. Acme Corp" /></div>
          <div><Label>Project</Label><Input data-testid="cr-project" value={f.project} maxLength={120} onChange={(e) => set("project", e.target.value)} placeholder="e.g. Support chatbot assessment" /></div>
          <div><Label>Tester</Label><Input data-testid="cr-tester" value={f.tester} maxLength={120} onChange={(e) => set("tester", e.target.value)} placeholder="Your name or team" /></div>
          <div><Label help="Printed on the cover and in the footer of every page.">Classification</Label><NativeSelect data-testid="cr-classification" value={f.classification} onChange={(e) => set("classification", e.target.value)}>{["Confidential", "Internal", "Restricted", "Public"].map((c) => <option key={c}>{c}</option>)}</NativeSelect></div>
          <div><Label>Format</Label><NativeSelect data-testid="cr-format" value={f.format} onChange={(e) => set("format", e.target.value)}><option value="pdf">PDF</option><option value="docx">Word (DOCX, editable)</option></NativeSelect></div>
        </div>
        <label className="flex items-start gap-2 text-sm text-slate-300"><Check_ data-testid="cr-unverified" checked={f.include_unverified} onCheckedChange={(v) => set("include_unverified", !!v)} />
          <span>Include unverified findings <span className="text-xs text-slate-500">(needs review, unstable, candidate). Off: only findings confirmed by replay.</span></span></label>
        {siblings.length > 0 && <div>
          <Label help="Runs under the same signed scope belong to one engagement. The same weakness found in several runs is listed once.">Also include runs from this engagement</Label>
          <div className="max-h-40 space-y-1.5 overflow-auto rounded-lg border border-white/10 p-2" data-testid="cr-runs">
            {siblings.map((x: any) => <label key={x.id} className="flex items-center gap-2 text-xs text-slate-300"><Check_ checked={extra.includes(x.id)} onCheckedChange={(v) => setExtra((p) => (v ? [...p, x.id] : p.filter((y) => y !== x.id)))} />
              <span className="truncate">{x.config?.library?.name || "Run"} · {fmtDate(x.created_at)} · {x.verified} verified</span></label>)}
          </div></div>}
        <div className="flex gap-2"><Button data-testid="cr-download" disabled={busy || run.status === "running"} onClick={download}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}Create report</Button>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button></div>
      </DialogContent>
    </Dialog>
  );
}
