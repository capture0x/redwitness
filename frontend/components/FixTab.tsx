"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Loader2, ShieldAlert, Sparkles, Wrench } from "lucide-react";
import { api, fmtDate } from "@/lib/api";
import { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Hint, Label, NativeSelect, Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { useMe } from "@/lib/me";

function CodeBlock({ title, text, lang }: { title: string; text: string; lang: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => { try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1800); } catch { /* clipboard blocked */ } };
  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-black/40">
      <div className="flex items-center justify-between border-b border-white/[0.06] bg-white/[0.03] px-3.5 py-2"><span className="text-[11px] font-medium uppercase tracking-wider text-slate-400">{title}<span className="ml-2 font-mono normal-case text-slate-600">{lang}</span></span>
        <button onClick={copy} aria-label={`Copy ${title}`} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[11px] text-slate-300 transition hover:bg-white/10 hover:text-white">{done ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Copy className="h-3.5 w-3.5" />}{done ? "Copied" : "Copy"}</button></div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap p-4 font-mono text-[12px] leading-relaxed text-slate-200">{text}</pre>
    </div>
  );
}

/** "Fix" tab of a finding: asks the Remediator LLM for a hardened prompt and/or a code patch. Suggestions are advisory and never applied automatically. */
export default function FixTab({ f }: { f: any }) {
  const { can } = useMe();
  const qc = useQueryClient();
  const key = ["remediation", f.id];
  const q = useQuery({ queryKey: key, queryFn: () => api(`/findings/${f.id}/remediation`), staleTime: 30_000 });
  const [kind, setKind] = useState("both");
  const [sys, setSys] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const generate = async () => {
    setBusy(true); setErr(null);
    try { qc.setQueryData(key, await api(`/findings/${f.id}/remediation`, { method: "POST", body: JSON.stringify({ kind, system_prompt: sys }) })); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const r = q.data?.result;
  return (
    <div className="space-y-4">
      <Notice tone="amber"><ShieldAlert className="mr-1.5 inline h-3.5 w-3.5" />This suggestion is <b>not applied automatically</b>. It is written by an AI model: review it, adapt it to your application and re-run this test to confirm the fix before you ship it.</Notice>
      {q.isPending ? <Skeleton className="h-24" /> : (
        <>
          {r && <div className="space-y-4" data-testid="fix-result">
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500"><Badge tone="violet"><Sparkles className="h-3 w-3" />{q.data.model}</Badge>generated {fmtDate(q.data.created_at)} by {q.data.created_by}{q.data.had_system_prompt ? " · based on your system prompt" : " · generic hardening (no system prompt provided)"}</div>
            <div><div className="text-sm font-medium text-white">{r.summary}</div><p className="mt-1 text-sm text-slate-400"><b className="text-slate-300">Why it happened:</b> {r.root_cause}</p></div>
            {r.secure_prompt && <CodeBlock title="Secure prompt" lang="text" text={r.secure_prompt} />}
            {r.code_patch && <CodeBlock title="Code patch" lang="diff" text={r.code_patch} />}
            {r.controls?.length > 0 && <div><div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-500">Controls beyond the prompt</div><ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">{r.controls.map((c: string, i: number) => <li key={i}>{c}</li>)}</ul></div>}
            {r.caveats?.length > 0 && <div><div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-500">Limits of this advice</div><ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">{r.caveats.map((c: string, i: number) => <li key={i}>{c}</li>)}</ul></div>}
            <p className="text-[11px] text-slate-600">Secret values the target leaked are masked as [REDACTED] in this suggestion.</p>
          </div>}
          {can("operator") ? (
            <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-4">
              <div className="grid gap-4 md:grid-cols-4">
                <div><Label>Produce</Label><NativeSelect value={kind} onChange={(e) => setKind(e.target.value)}><option value="both">Prompt + code</option><option value="prompt">Secure prompt only</option><option value="code">Code patch only</option></NativeSelect></div>
                <div className="md:col-span-3"><Label>Your current system prompt <span className="text-slate-600">(optional)</span></Label>
                  <Textarea rows={3} value={sys} maxLength={12000} onChange={(e) => setSys(e.target.value)} placeholder="Paste it to get a tailored rewrite. It is sent to the Remediator model for this request only and is never stored." /></div>
              </div>
              {err && <div className="mt-3 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-200">{err}</div>}
              <div className="mt-3 flex items-center justify-between gap-3"><Hint className="m-0">The finding&apos;s test message and the target&apos;s reply are sent to the Remediator model (Settings).</Hint>
                <Button onClick={generate} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}{r ? "Regenerate" : "Suggest a fix"}</Button></div>
            </div>
          ) : !r && <p className="text-sm text-slate-500">No fix suggestion has been generated for this finding yet. An operator can generate one.</p>}
        </>
      )}
    </div>
  );
}
