"use client";
import { useEffect, useState } from "react";
import { Download, FileText, Siren } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import { useMe } from "@/lib/me";
import FindingCard from "@/components/FindingCard";
import PageHeader from "@/components/PageHeader";
import CalibrationPanel from "@/components/CalibrationPanel";
import { Stagger, Item } from "@/components/motion";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/misc";
import { api, usePoll } from "@/lib/api";
import { cn } from "@/lib/utils";

const STATUSES = [["", "All"], ["verified", "Verified"], ["unstable", "Unstable"], ["candidate", "Candidate"], ["needs_review", "Needs review"], ["false_positive", "False positives"]];

export default function Findings() {
  const { can } = useMe();
  const { data: st } = usePoll(() => api("/stats"), 5000);
  const [status, setStatus] = useState("verified");
  const [cat, setCat] = useState("");
  const [sev, setSev] = useState("");
  const [ow, setOw] = useState("");
  // can arrive from the /owasp page with ?owasp=LLM07_... (instead of useSearchParams: needs no Suspense in static generation)
  useEffect(() => { const q = new URLSearchParams(window.location.search).get("owasp"); if (q) { setOw(q); setStatus(""); } }, []);
  const [rev, setRev] = useState(0);
  const { data: fs, loading, reload } = usePoll(() => api(`/findings?status=${status}&category=${cat}&owasp=${ow}`), 5000, [status, cat, ow]);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const classes = Object.fromEntries((meta?.attack_classes || []).map((c: any) => [c.id, c.label]));
  const noData = (st?.findings_total ?? 0) === 0 && !cat && !sev && !ow;
  const list = (fs || []).filter((f: any) => !sev || f.severity === sev);
  const chip = (on: boolean) => cn("rounded-full border px-3.5 py-1.5 text-xs font-medium transition", on ? "border-violet-400/50 bg-violet-500/20 text-white shadow-glow" : "border-white/10 text-slate-400 hover:border-white/25 hover:text-slate-200");
  return (
    <>
      <PageHeader title="Findings" sub="Responses that deviated from the expected safe behavior. Only “Verified” findings were reproduced in new conversations. False positives (refuted by the verifier or a reviewer) are excluded from reports."
        right={<a href={`/api/findings.csv?status=${status}&category=${cat}&owasp=${ow}`}><Button variant="secondary"><Download className="h-4 w-4" />CSV</Button></a>} />
      <CalibrationPanel refreshKey={rev} />
      <div className="mb-3 flex flex-wrap gap-2">{STATUSES.map(([k, l]) => <button key={k} className={chip(status === k)} onClick={() => setStatus(k)}>{l}</button>)}</div>
      <div className="mb-3 flex flex-wrap gap-2">
        <button className={chip(!cat)} onClick={() => setCat("")}>All categories</button>
        {(meta?.attack_classes || []).map((c: any) => <button key={c.id} className={chip(cat === c.id)} onClick={() => setCat(c.id)}>{c.label}</button>)}
      </div>
      <div className="mb-3 flex flex-wrap gap-2">
        <button className={chip(!ow)} onClick={() => setOw("")}>All OWASP categories</button>
        {(meta?.owasp || []).map((c: any) => <button key={c.id} title={c.en} className={chip(ow === c.id)} onClick={() => setOw(c.id)}><span className="font-mono">{c.code}</span> {c.en}</button>)}
      </div>
      <div className="mb-6 flex flex-wrap gap-2">
        <button className={chip(!sev)} onClick={() => setSev("")}>All severities</button>
        {["critical", "high", "medium", "low", "info"].map((s) => <button key={s} className={chip(sev === s)} onClick={() => setSev(s)}>{meta?.severities?.[s] || s}</button>)}
      </div>
      {loading && <div className="space-y-3"><Skeleton className="h-24" /><Skeleton className="h-24" /></div>}
      <Stagger className="space-y-3">{list.map((f: any) => <Item key={f.id}><FindingCard f={f} classes={classes} onChange={() => { reload(); setRev((x) => x + 1); }} /></Item>)}</Stagger>
      {!loading && list.length === 0 && st && noData && (
        (st?.attempts ?? 0) === 0
          ? <EmptyState testId="findings-empty" icon={Siren} title="No findings yet. Start your first scan" text="A scan sends test messages to your target and keeps only the problems that reproduce. Your first results appear here." action={can("operator") ? "Start" : undefined} href="/new" secondary={can("operator") ? { label: "Add a target first", href: "/targets" } : undefined} />
          : <EmptyState testId="findings-empty" icon={Siren} title="Scans ran and nothing was found" text="No answer broke a rule, which is a good sign. Run another scan with more categories to widen the check." action={can("operator") ? "Start another scan" : undefined} href="/new" />
      )}
      {!loading && list.length === 0 && st && !noData && (
        <div data-testid="findings-filtered" className="glass flex flex-col items-center rounded-2xl py-14 text-center"><FileText className="mb-3 h-10 w-10 text-slate-600" /><p className="text-sm text-slate-300">No findings match these filters.</p><p className="mt-1 text-xs text-slate-500">Try the “All” status, or clear the category and severity filters.</p>
          <Button className="mt-4" variant="secondary" size="sm" onClick={() => { setStatus(""); setCat(""); setSev(""); setOw(""); }}>Clear filters</Button></div>
      )}
    </>
  );
}
