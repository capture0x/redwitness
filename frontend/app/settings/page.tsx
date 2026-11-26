"use client";
import { useEffect, useState } from "react";
import { Boxes, Gavel, RefreshCcw, Save, Server, Swords, Wrench, ShieldAlert } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import JudgeAdvisory from "@/components/JudgeAdvisory";
import CiTokens from "@/components/CiTokens";
import BiasControl from "@/components/BiasControl";
import CalibrationPanel from "@/components/CalibrationPanel";
import { ROLE_LABEL, useMe } from "@/lib/me";

export default function Settings() {
  const { me } = useMe();
  const { data: cur, reload } = usePoll(() => api("/settings"), 0);
  const { data: sys } = usePoll(() => api("/system"), 5000);
  const [f, setF] = useState<any>({});
  const [msg, setMsg] = useState<{ t: "green" | "red"; m: string } | null>(null);
  useEffect(() => { if (cur) setF(cur); }, [cur]);
  const set = (k: string, v: any) => setF({ ...f, [k]: v });
  const save = async () => {
    try { await api("/settings", { method: "PUT", body: JSON.stringify(f) }); setMsg({ t: "green", m: "Settings saved." }); reload(); }
    catch (e: any) { setMsg({ t: "red", m: e.message }); }
  };
  const Row = ({ k, children }: { k: string; children: React.ReactNode }) => <div className="flex items-center justify-between border-b border-white/[0.06] py-2.5 text-sm last:border-0"><span className="text-slate-400">{k}</span><span className="text-slate-100">{children}</span></div>;
  return (
    <>
      <PageHeader title="Settings" sub="Judge LLM and verification defaults. API keys are never stored; only the environment variable name is given." right={<Button onClick={save}><Save className="h-4 w-4" />Save</Button>} />
      {msg && <Notice tone={msg.t}>{msg.m}</Notice>}
      <div className="grid gap-5 lg:grid-cols-2">
        <Card><CardHeader><div><CardTitle>Judge LLM (Evaluator)</CardTitle><CardDescription>Evaluates responses against the expected behavior</CardDescription></div><Gavel className="h-4 w-4 text-slate-500" /></CardHeader>
          <CardContent className="space-y-4">
            <JudgeAdvisory />
            <div><Label help="Who hosts the judge model. Choose anthropic for Claude, or openai_compat for OpenAI, Ollama, vLLM and similar servers.">Provider</Label><NativeSelect value={f.judge_provider || ""} onChange={(e) => set("judge_provider", e.target.value)}><option value="anthropic">anthropic</option><option value="openai_compat">openai_compat</option></NativeSelect></div>
            <div><Label help="The judge reads the target's answers and decides if a rule was broken. Use a strong model (Claude Sonnet or Opus class); small local models miss real leaks.">Model</Label><Input value={f.judge_model || ""} onChange={(e) => set("judge_model", e.target.value)} /></div>
            {f.judge_provider === "openai_compat" && <div><Label help="The chat-completions address of your OpenAI-compatible server, for example http://host.docker.internal:11434/v1/chat/completions.">Endpoint URL</Label><Input value={f.judge_url || ""} onChange={(e) => set("judge_url", e.target.value)} /></div>}
            <div><Label help="Enter only the NAME of the variable (for example ANTHROPIC_API_KEY). The key itself lives in your .env file and is never stored in the database.">API key environment variable name</Label><Input value={f.judge_api_key_env || ""} onChange={(e) => set("judge_api_key_env", e.target.value)} placeholder="if empty, ANTHROPIC_API_KEY" /></div>
            <div><Label help="How sure the judge must be before its verdict counts. Higher means fewer false alarms but more missed findings. 0.7 is a good start.">Minimum confidence threshold (0-1)</Label><Input type="number" step="0.05" min={0} max={1} value={f.min_confidence ?? 0.7} onChange={(e) => set("min_confidence", +e.target.value)} />
              <Hint>Decisions below the threshold count as “inconclusive”. A violation quote must appear verbatim in the target response.</Hint></div>
          </CardContent></Card>
        <div className="space-y-5">
          <BiasControl f={f} set={set} />
          <Card><CardHeader><div><CardTitle>Adversarial verifier</CardTitle><CardDescription>After a finding is replay-confirmed, a second model tries to refute it. A grounded refutation marks it a false positive. Leave the provider empty to reuse the judge (a different model is better).</CardDescription></div><ShieldAlert className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent className="space-y-4">
              <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" data-testid="verifier-enabled" checked={f.verifier_enabled ?? true} onChange={(e) => set("verifier_enabled", e.target.checked)} />Run the adversarial verifier</label>
              {(f.verifier_enabled ?? true) && <>
                <div><Label>Provider</Label><NativeSelect value={f.verifier_provider || ""} onChange={(e) => set("verifier_provider", e.target.value)}><option value="">same as judge</option><option value="anthropic">anthropic</option><option value="openai_compat">openai_compat</option></NativeSelect></div>
                {f.verifier_provider && <><div><Label>Model</Label><Input value={f.verifier_model || ""} onChange={(e) => set("verifier_model", e.target.value)} /></div>
                  {f.verifier_provider === "openai_compat" && <div><Label>Endpoint URL</Label><Input value={f.verifier_url || ""} onChange={(e) => set("verifier_url", e.target.value)} /></div>}
                  <div><Label>API key environment variable name</Label><Input value={f.verifier_api_key_env || ""} onChange={(e) => set("verifier_api_key_env", e.target.value)} /></div></>}
                <div><Label>Minimum confidence to accept a refutation (0-1)</Label><Input type="number" step="0.05" min={0} max={1} value={f.verifier_min_confidence ?? 0.8} onChange={(e) => set("verifier_min_confidence", +e.target.value)} />
                  <Hint>A refutation also needs a verbatim quote from the response or the sent messages. Findings proven by code (canary, sandbox rule, exfil URL) are never sent to the verifier.</Hint></div></>}
            </CardContent></Card>
          <Card><CardHeader><div><CardTitle>Sandbox verification</CardTitle><CardDescription>Hands the target&apos;s own output (HTML, SQL) of a verified finding to an isolated runner and labels it verified exploitable or not exploitable. Labels only: a finding is never removed and its severity never changes.</CardDescription></div><Boxes className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent className="space-y-3">
              <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" data-testid="sandbox-enabled" checked={f.sandbox_verifier_enabled ?? false} onChange={(e) => set("sandbox_verifier_enabled", e.target.checked)} />Run sandboxed verification</label>
              <p className="text-xs text-slate-400" data-testid="sandbox-runner-state">Runner: {sys?.sandbox_enabled ? (sys.sandbox_runner_up ? <span className="text-emerald-300">running</span> : <span className="text-amber-300">not running</span>) : "not enabled"}. The runner has no network, a read-only filesystem and no capabilities, and the backend never gets the Docker socket.</p>
              {f.sandbox_verifier_enabled && !sys?.sandbox_runner_up && <Hint>Start it with <code className="rounded bg-black/30 px-1">docker compose --profile sandbox up -d</code>. Without it, findings are labelled “unavailable”.</Hint>}
            </CardContent></Card>
          <Card><CardHeader><div><CardTitle>Attacker LLM</CardTitle><CardDescription>Rewrites refused cases in adaptive runs. Leave the provider empty to reuse the judge (a different model is recommended).</CardDescription></div><Swords className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent className="space-y-4">
              <div><Label>Provider</Label><NativeSelect value={f.attacker_provider || ""} onChange={(e) => set("attacker_provider", e.target.value)}><option value="">same as judge</option><option value="anthropic">anthropic</option><option value="openai_compat">openai_compat</option></NativeSelect></div>
              {f.attacker_provider && <><div><Label>Model</Label><Input value={f.attacker_model || ""} onChange={(e) => set("attacker_model", e.target.value)} /></div>
                {f.attacker_provider === "openai_compat" && <div><Label>Endpoint URL</Label><Input value={f.attacker_url || ""} onChange={(e) => set("attacker_url", e.target.value)} /></div>}
                <div><Label>API key environment variable name</Label><Input value={f.attacker_api_key_env || ""} onChange={(e) => set("attacker_api_key_env", e.target.value)} /></div></>}
              <Row k="Status">{sys?.attacker_configured ? <Badge tone="green">configured</Badge> : <Badge tone="amber">not configured</Badge>}</Row>
            </CardContent></Card>
          <Card><CardHeader><div><CardTitle>Remediator LLM</CardTitle><CardDescription>Writes fix suggestions on the Findings “Fix” tab. Leave the provider empty to reuse the judge.</CardDescription></div><Wrench className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent className="space-y-4">
              <div><Label>Provider</Label><NativeSelect value={f.remediator_provider || ""} onChange={(e) => set("remediator_provider", e.target.value)}><option value="">same as judge</option><option value="anthropic">anthropic</option><option value="openai_compat">openai_compat</option></NativeSelect></div>
              {f.remediator_provider && <><div><Label>Model</Label><Input value={f.remediator_model || ""} onChange={(e) => set("remediator_model", e.target.value)} /></div>
                {f.remediator_provider === "openai_compat" && <div><Label>Endpoint URL</Label><Input value={f.remediator_url || ""} onChange={(e) => set("remediator_url", e.target.value)} /></div>}
                <div><Label>API key environment variable name</Label><Input value={f.remediator_api_key_env || ""} onChange={(e) => set("remediator_api_key_env", e.target.value)} /></div></>}
              <Row k="Status">{sys?.remediator_configured ? <Badge tone="green">configured</Badge> : <Badge tone="amber">not configured</Badge>}</Row>
            </CardContent></Card>
          <Card><CardHeader><div><CardTitle>Verification defaults</CardTitle><CardDescription>Starting values for new tests</CardDescription></div><RefreshCcw className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent><div className="grid grid-cols-2 gap-4"><div><Label help="How many fresh conversations repeat a suspected finding to confirm it. More replays means more certainty and more cost.">Replays (N)</Label><Input type="number" min={1} max={10} value={f.replay_n ?? 3} onChange={(e) => set("replay_n", +e.target.value)} /></div><div><Label>Successes (K)</Label><Input type="number" min={1} max={10} value={f.replay_k ?? 2} onChange={(e) => set("replay_k", +e.target.value)} /></div></div>
              <Hint>The rate limit, token budget, duration and circuit-breaker thresholds are part of the <b>signed scope</b> and are set on the “Scopes” page; they cannot be changed here.</Hint></CardContent></Card>
          <Card><CardHeader><div><CardTitle>System status</CardTitle></div><Server className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent>
              <Row k="Signing key">{sys?.signing_key ? <Badge tone="green">configured</Badge> : <Badge tone="red">missing</Badge>}</Row>
              <Row k="Judge LLM">{sys?.judge_configured ? <Badge tone="green">{sys.judge_provider} / {sys.judge_model}</Badge> : <Badge tone="red">not configured</Badge>}</Row>
              <Row k="Audit chain">{sys?.audit_chain_ok === false ? <Badge tone="red">BROKEN</Badge> : <Badge tone="green">intact</Badge>}</Row>
              <Row k="Signed-in user">{me ? `${me.username} · ${ROLE_LABEL[me.role]}` : "-"}</Row>
            </CardContent></Card>
        </div>
      </div>
      <div className="mt-5"><CalibrationPanel onApply={(t) => set("min_confidence", t)} /></div>
      <CiTokens />
    </>
  );
}
