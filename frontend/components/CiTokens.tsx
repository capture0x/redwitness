"use client";
import { useState } from "react";
import { Copy, KeyRound, Plus, ShieldOff, Webhook } from "lucide-react";
import { api, fmtDate, usePoll } from "@/lib/api";
import { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";

const snippet = (token: string, origin: string) => `# GitHub Actions step (store the token as a secret, never in the repo)
- name: AIVeritX scan
  env: { AIVERITX_TOKEN: \${{ secrets.AIVERITX_TOKEN }} }
  run: |
    JOB=$(curl -sf -X POST ${origin}/api/scan-ci \\
      -H "Authorization: Bearer $AIVERITX_TOKEN" -H "Content-Type: application/json" \\
      -d '{"scope_id":"<scope id>","endpoint_url":"<target url>","library_id":"<library id>","label":"'"$GITHUB_SHA"'","fail_on":"high"}' | jq -r .job_id)
    until R=$(curl -sf -H "Authorization: Bearer $AIVERITX_TOKEN" ${origin}/api/scan-ci/$JOB) && [ "$(echo "$R" | jq -r .status)" != running ]; do sleep 10; done
    echo "$R" | jq .gate; test "$(echo "$R" | jq -r .gate.passed)" = true`;

const TONE: Record<string, any> = { active: "green", revoked: "red", expired: "amber" };

/** Admin-only: issue, list and revoke API tokens for CI/CD pipelines (the `ci` identity: start scans and read their results, nothing else). */
export default function CiTokens() {
  const { data: tokens, reload } = usePoll(() => api("/ci-tokens"), 0);
  const { data: scopes } = usePoll(() => api("/scopes"), 0);
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: "", lineage: "", ttl: 90 });
  const [made, setMade] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const lineages = Array.from(new Map((scopes || []).filter((s: any) => s.valid).map((s: any) => [s.lineage_id, s])).values()) as any[];
  const create = async () => {
    setErr(null);
    try { setMade(await api("/ci-tokens", { method: "POST", body: JSON.stringify({ name: f.name.trim(), lineage_ids: [f.lineage], ttl_days: f.ttl }) })); reload(); }
    catch (e: any) { setErr(e.message); }
  };
  const revoke = async (t: any) => { if (confirm(`Revoke “${t.name}”? Pipelines using it stop working immediately.`)) { await api(`/ci-tokens/${t.id}/revoke`, { method: "POST" }); reload(); } };
  const close = () => { setOpen(false); setMade(null); setErr(null); setCopied(false); setF({ name: "", lineage: "", ttl: 90 }); };
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return (
    <Card className="mt-5">
      <CardHeader><div><CardTitle>CI/CD access tokens</CardTitle><CardDescription>Let pipelines (GitHub Actions, Jenkins…) start a scan and read the JSON result. A token cannot sign in to this UI and can do nothing else.</CardDescription></div>
        <Button size="sm" onClick={() => setOpen(true)}><Plus className="h-3.5 w-3.5" />New token</Button></CardHeader>
      <CardContent>
        {!tokens ? null : tokens.length === 0 ? <p className="text-sm text-slate-500">No tokens yet.</p> : (
          <div className="divide-y divide-white/[0.06]">{tokens.map((t: any) => (
            <div key={t.id} className="flex flex-wrap items-center gap-x-5 gap-y-2 py-3 text-sm">
              <KeyRound className="h-4 w-4 text-slate-500" />
              <div className="min-w-[180px] flex-1"><div className="font-medium text-slate-100">{t.name}</div><div className="font-mono text-[11px] text-slate-500">{t.prefix}…  · created by {t.created_by}</div></div>
              <Badge tone={TONE[t.status]}>{t.status}</Badge>
              <div className="text-xs text-slate-400">expires {fmtDate(t.expires_at)}<br />{t.last_used_at ? `last used ${fmtDate(t.last_used_at)}` : "never used"}</div>
              {t.status === "active" && <Button variant="ghost" size="sm" onClick={() => revoke(t)}><ShieldOff className="h-3.5 w-3.5" />Revoke</Button>}
            </div>))}</div>)}
        <Hint><Webhook className="mr-1 inline h-3 w-3" />Endpoints: <code>POST /api/scan-ci</code> returns a <code>job_id</code> at once; poll <code>GET /api/scan-ci/&#123;job_id&#125;</code>. Limits: 6 starts/min, 2 scans at once per token. The result has a pass/fail <code>gate</code> and never contains prompts or target responses.</Hint>
      </CardContent>
      <Dialog open={open} onOpenChange={(v) => !v && close()}>
        <DialogContent className="w-[min(640px,94vw)]">
          <DialogTitle>{made ? "Token created" : "New CI token"}</DialogTitle>
          {!made ? <>
            <DialogDescription>The token can only scan under the signed scope you choose, and stops working at its expiry date or when you revoke it.</DialogDescription>
            {err && <Notice tone="red">{err}</Notice>}
            <div className="mt-4 space-y-3">
              <div><Label>Name</Label><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. github-actions-main" /></div>
              <div><Label>Scope it may scan under</Label><NativeSelect value={f.lineage} onChange={(e) => setF({ ...f, lineage: e.target.value })}><option value="">Select a signed scope…</option>{lineages.map((s: any) => <option key={s.lineage_id} value={s.lineage_id}>{s.name} · {s.client}</option>)}</NativeSelect>
                <Hint>Applies to every version of that scope, so re-signing it does not break the pipeline.</Hint></div>
              <div><Label>Expires after (days, 1-365)</Label><Input type="number" min={1} max={365} value={f.ttl} onChange={(e) => setF({ ...f, ttl: Math.min(365, Math.max(1, +e.target.value || 1)) })} /></div>
            </div>
            <div className="mt-5 flex justify-end"><Button disabled={f.name.trim().length < 3 || !f.lineage} onClick={create}>Create token</Button></div>
          </> : <>
            <Notice tone="amber">Copy this token now. It is shown only once; the server keeps just a hash.</Notice>
            <div className="flex items-center gap-2 rounded-xl border border-white/10 bg-black/30 p-3"><code data-testid="new-token" className="min-w-0 flex-1 break-all text-xs text-emerald-200">{made.token}</code>
              <Button size="sm" variant="secondary" onClick={async () => { try { await navigator.clipboard.writeText(made.token); setCopied(true); } catch { /* clipboard blocked */ } }}><Copy className="h-3.5 w-3.5" />{copied ? "Copied" : "Copy"}</Button></div>
            <div className="mt-4 text-[11px] uppercase tracking-wider text-slate-500">Example pipeline step</div>
            <pre className="mt-1 max-h-60 overflow-auto rounded-xl bg-black/30 p-3 text-[11px] leading-5 text-slate-300">{snippet(made.token, origin)}</pre>
            <div className="mt-4 flex justify-end"><Button onClick={close}>Done</Button></div>
          </>}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
