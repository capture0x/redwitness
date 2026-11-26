"use client";
import { useRef, useState } from "react";
import { FileSearch, ShieldAlert, ShieldCheck, Upload } from "lucide-react";
import PageHeader from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { api, fmtDate, fmtNum, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import { useQueryClient } from "@tanstack/react-query";

const MAX = 32 * 1024 * 1024;
const VERDICT: Record<string, { label: string; tone: any }> = {
  unsafe: { label: "Unsafe", tone: "critical" }, suspicious: { label: "Suspicious", tone: "medium" },
  clean: { label: "No executable code found", tone: "green" }, unsupported: { label: "Unsupported format", tone: "neutral" },
};

function toBase64(buf: ArrayBuffer) {
  let s = ""; const b = new Uint8Array(buf);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

function Result({ r }: { r: any }) {
  const v = VERDICT[r.verdict] || VERDICT.unsupported;
  return (
    <Card className="p-5 space-y-4" data-testid="scan-result">
      <div className="flex flex-wrap items-center gap-3">
        {r.verdict === "unsafe" ? <ShieldAlert className="h-5 w-5 text-red-400" /> : <ShieldCheck className="h-5 w-5 text-emerald-400" />}
        <div className="font-medium text-white">{r.filename}</div><Badge tone={v.tone}>{v.label}</Badge><Badge>{r.format}</Badge>
        <span className="text-xs text-slate-500">{fmtNum(r.size)} bytes</span>
      </div>
      <div className="font-mono text-xs text-slate-400 break-all">SHA-256 {r.sha256}{r.hash_match === true && <span className="ml-2 text-emerald-400">matches the expected hash</span>}</div>
      {r.imports?.length > 0 && <div><div className="mb-1 text-xs uppercase tracking-wide text-slate-500">Globals the file would import</div>
        <div className="flex flex-wrap gap-1.5">{r.imports.map((i: string) => <code key={i} className="rounded bg-white/5 px-1.5 py-0.5 text-xs text-slate-300">{i}</code>)}</div></div>}
      <div className="space-y-2">{r.findings.map((f: any, i: number) => (
        <div key={i} className="flex items-start gap-3 rounded-lg border border-white/5 bg-white/[0.02] p-3 text-sm">
          <Badge tone={f.severity === "info" ? "info" : f.severity}>{f.severity}</Badge>
          <div><div className="text-slate-200">{f.message}</div><div className="text-xs text-slate-500">{f.code}{f.location ? ` · ${f.location}` : ""}</div></div></div>))}
        {r.findings.length === 0 && <div className="text-sm text-slate-400">No findings.</div>}</div>
      <ul className="list-disc space-y-1 pl-5 text-xs text-amber-200/80">{r.limits.map((l: string) => <li key={l}>{l}</li>)}</ul>
    </Card>
  );
}

export default function ModelScans() {
  const { can } = useMe();
  const qc = useQueryClient();
  const { data } = usePoll(() => api("/model-scans"), 8000);
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [expected, setExpected] = useState("");
  const file = useRef<HTMLInputElement>(null);

  async function scan() {
    const f = file.current?.files?.[0];
    setErr(""); setRes(null);
    if (!f) return setErr("Choose a model file first.");
    if (f.size > MAX) return setErr("The file is larger than 32 MB. Scan a smaller shard or check the file on the machine that holds it.");
    setBusy(true);
    try {
      const r = await api("/model-scans", { method: "POST", body: JSON.stringify({ filename: f.name, content_base64: toBase64(await f.arrayBuffer()), expected_sha256: expected.trim() }) });
      setRes(r); qc.invalidateQueries({ queryKey: ["poll"] });
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title="Model supply chain" sub="Static analysis of model files (.pkl, .pt, .pth, .bin, .ckpt, .safetensors, .npy). The file is parsed, never loaded or executed, and is not stored." />
      {can("operator") && (
        <Card className="mb-5 space-y-3 p-5">
          <div className="grid gap-3 md:grid-cols-2">
            <div><Label>Model file (max 32 MB)</Label><Input ref={file} type="file" data-testid="scan-file" /></div>
            <div><Label>Expected SHA-256 (optional)</Label><Input value={expected} onChange={(e) => setExpected(e.target.value)} placeholder="Hash published by the model owner" /></div>
          </div>
          {err && <div className="text-sm text-red-400" role="alert">{err}</div>}
          <Button onClick={scan} disabled={busy}><Upload className="h-4 w-4" />{busy ? "Scanning…" : "Scan file"}</Button>
        </Card>)}
      {res && <div className="mb-5"><Result r={res} /></div>}
      <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Previous scans</div>
      {!data ? <Skeleton className="h-24" /> : data.length === 0 ? <Card className="py-10 text-center text-sm text-slate-500">No scans yet.</Card> : (
        <div className="grid gap-2">{data.map((s: any) => (
          <Card key={s.id} className="flex flex-wrap items-center gap-3 p-4 text-sm"><FileSearch className="h-4 w-4 text-indigo-300" />
            <span className="font-medium text-white">{s.filename}</span><Badge tone={(VERDICT[s.verdict] || VERDICT.unsupported).tone}>{(VERDICT[s.verdict] || VERDICT.unsupported).label}</Badge>
            <Badge>{s.format}</Badge><span className="font-mono text-xs text-slate-500">{s.sha256.slice(0, 16)}…</span>
            <span className="ml-auto text-xs text-slate-500">{fmtDate(s.created_at)} · {s.created_by}</span></Card>))}</div>)}
    </>
  );
}
