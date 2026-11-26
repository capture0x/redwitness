"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { CheckCircle2, ListChecks, Play, TriangleAlert } from "lucide-react";
import { api, ApiError, usePoll } from "@/lib/api";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "./ui/dialog";
import { Hint, Input, Label, NativeSelect, Textarea } from "./ui/input";
import { Badge } from "./ui/badge";
import JudgeAdvisory from "./JudgeAdvisory";
import { cn } from "@/lib/utils";
import { useMe } from "@/lib/me";

/** One-click OWASP scan: scope/endpoint + category selection → /api/owasp/scan. */
export default function OwaspScanDialog({ open, onOpenChange, preset }: { open: boolean; onOpenChange: (o: boolean) => void; preset?: string[] }) {
  const { data: scopes } = usePoll(() => api("/scopes"), 0);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const { can } = useMe();
  const VEC = ["chroma", "qdrant", "weaviate"];
  const valid = (scopes || []).filter((s: any) => s.valid && s.endpoints.some((e: any) => !VEC.includes(e.provider)));
  const cats: any[] = meta?.owasp || [];
  const [scopeId, setScopeId] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [sel, setSel] = useState<string[]>([]);
  const [apiKey, setApiKey] = useState("");
  const [canaries, setCanaries] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | string | null>(null);
  const [res, setRes] = useState<any>(null);
  const scope = valid.find((s: any) => s.id === scopeId);

  useEffect(() => { if (open) { setRes(null); setErr(null); } }, [open]);
  useEffect(() => { if (!scopeId && valid[0]) setScopeId(valid[0].id); }, [valid.length]); // eslint-disable-line
  useEffect(() => { if (scope) setEndpoint(scope.endpoints.find((e: any) => !VEC.includes(e.provider))?.url || ""); }, [scopeId]); // eslint-disable-line
  // The selection is rebuilt every time the dialog opens (so a previous selection does not break presets like "Scan only this").
  useEffect(() => { if (open && cats.length) setSel(preset?.length ? preset : cats.map((c) => c.id)); }, [open, cats.length]); // eslint-disable-line
  const toggle = (id: string) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  const start = async () => {
    setBusy(true); setErr(null);
    try {
      setRes(await api("/owasp/scan", { method: "POST", body: JSON.stringify({ scope_id: scopeId, endpoint_url: endpoint, categories: sel, api_key: apiKey || null,
        canaries: canaries.split("\n").map((x) => x.trim()).filter(Boolean) }) }));
    } catch (e: any) { setErr(e); } finally { setBusy(false); }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle className="flex items-center gap-2"><ListChecks className="h-5 w-5 text-violet-300" />OWASP LLM Top 10 scan</DialogTitle>
        <DialogDescription>Runs the starter kit's basic quality probes for the selected categories, inside your signed scope.</DialogDescription>
        {valid.length === 0 && <div className="mt-4 rounded-xl border border-violet-400/30 bg-violet-500/10 p-4 text-sm text-slate-200" data-testid="owasp-noscope"><b className="text-white">No signed scope yet.</b> {can("admin")
          ? <>You do not need to build one by hand: enter the target address and sign-in on one screen and AIVeritX creates a short-lived signed scope for you. <Link href={`/new?owasp=${encodeURIComponent(sel.join(","))}`} onClick={() => onOpenChange(false)}><Button className="mt-3 w-full" data-testid="owasp-to-quick"><Play className="h-4 w-4" />Scan a target by URL ({sel.length} categories)</Button></Link></>
          : <>An admin has to sign a scope for the target first (Scopes), or run a quick scan for you.</>}</div>}
        {err && <div className="mt-4 rounded-xl border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{typeof err === "string" ? err : err.message}</div>}
        {res ? (
          <div className="mt-5 space-y-3">
            <div className="flex items-center gap-2 text-emerald-300"><CheckCircle2 className="h-5 w-5" />Scan started · {res.cases} cases</div>
            <div className="flex flex-wrap gap-1.5">{res.owasp_planned.map((c: string) => <Badge key={c} tone="violet">{c.split("_")[0]}</Badge>)}</div>
            {res.owasp_skipped?.length > 0 && (
              <div className="flex gap-2 rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100"><TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
                <div>Skipped because your scope does not allow the attack classes of these categories: <b>{res.owasp_skipped.map((c: string) => c.split("_")[0]).join(", ")}</b>. They stay “Not tested” in the matrix.</div></div>)}
            <Link href={`/runs/${res.id}`}><Button className="w-full">Open run</Button></Link>
          </div>
        ) : (
          <div className="mt-5 space-y-5">
            <div className="grid gap-4 md:grid-cols-2">
              <div><Label>Scope (signed)</Label><NativeSelect value={scopeId} onChange={(e) => setScopeId(e.target.value)}>{valid.map((s: any) => <option key={s.id} value={s.id}>{s.name} · v{s.version}</option>)}</NativeSelect></div>
              <div><Label>Endpoint</Label><NativeSelect value={endpoint} onChange={(e) => setEndpoint(e.target.value)}>{scope?.endpoints.filter((e: any) => !VEC.includes(e.provider)).map((e: any) => <option key={e.url} value={e.url}>{e.model} - {e.url}</option>)}</NativeSelect></div>
              <div className="md:col-span-2"><Label>API key <span className="text-slate-600">(memory only; if empty, the credential saved with the target or the scope's environment variable is used)</span></Label><Input type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)} /></div>
            </div>
            <div>
              <div className="mb-2 flex items-center justify-between"><Label className="m-0">Categories</Label>
                <div className="flex gap-3 text-xs"><button className="text-violet-300 hover:underline" onClick={() => setSel(cats.map((c) => c.id))}>All</button><button className="text-slate-400 hover:underline" onClick={() => setSel([])}>Clear</button></div></div>
              <div className="grid gap-2 sm:grid-cols-2">{cats.map((c) => {
                const on = sel.includes(c.id);
                return (
                  <button key={c.id} onClick={() => toggle(c.id)} className={cn("flex items-center gap-3 rounded-xl border px-3 py-2.5 text-left text-sm transition", on ? "border-violet-400/50 bg-violet-500/15 text-white shadow-glow" : "border-white/10 bg-white/[0.03] text-slate-400 hover:border-white/25")}>
                    <span className="font-mono text-xs text-violet-300">{c.code}</span><span className="flex-1 truncate">{c.en}</span>{c.coverage === "limited" && <Badge tone="amber">limited</Badge>}</button>);
              })}</div>
            </div>
            <div><Label>Canary values <span className="text-slate-600">(optional, one per line)</span></Label><Textarea rows={2} className="font-mono text-xs" value={canaries} onChange={(e) => setCanaries(e.target.value)} />
              <Hint>Sentinel texts you planted in the target; if one appears verbatim in a response the finding becomes “Needs review” no matter what the judge says.</Hint></div>
            <JudgeAdvisory compact />
            {can("admin") && valid.length > 0 && <div className="text-xs text-slate-500">Another target? <Link href={`/new?owasp=${encodeURIComponent(sel.join(","))}`} onClick={() => onOpenChange(false)} className="text-violet-300 underline">Scan it by URL instead</Link></div>}
            <Button size="lg" className="w-full" disabled={busy || !scopeId || !endpoint || sel.length === 0 || valid.length === 0} onClick={start}><Play className="h-4 w-4" />{busy ? "Starting…" : `Scan ${sel.length} categories`}</Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
