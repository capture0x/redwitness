"use client";
import Link from "next/link";
import { useState } from "react";
import { Loader2, Play, Plug, ShieldCheck } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label, NativeSelect } from "@/components/ui/input";
import { Skeleton, Toggle } from "@/components/ui/misc";
import { api, fmtDate, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";

const ISSUE_LABEL: Record<string, string> = {
  MCP_TOOL_POISONING: "hidden instructions", MCP_HIDDEN_CHARACTERS: "invisible characters", MCP_ENCODED_PAYLOAD: "encoded payload", MCP_TOOL_SHADOWING: "shadows other tools",
  MCP_DANGEROUS_CAPABILITY: "risky capability", MCP_SECRET_IN_DEFINITION: "secret in definition", MCP_DEFINITION_CHANGED: "changed since last scan", MCP_JUDGE_SUSPICIOUS: "judge: suspicious",
};

/** Read-only MCP server audit: lists tools, prompts and resources (never calls a tool) and checks the definitions. Results are normal findings. */
export default function McpPage() {
  const { can } = useMe();
  const { data: scopes } = usePoll(() => api("/scopes"), 0);
  const { data: scans, reload } = usePoll(() => api("/mcp-scans"), 3000);
  const usable = (scopes || []).filter((s: any) => s.valid && s.attack_classes.includes("mcp_server_audit") && s.endpoints.some((e: any) => e.provider === "mcp"));
  const [f, setF] = useState({ scope_id: "", endpoint_url: "", auth_type: "none", auth_header: "", api_key: "", judge_review: false });
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const scope = usable.find((s: any) => s.id === f.scope_id) || usable[0];
  const eps = (scope?.endpoints || []).filter((e: any) => e.provider === "mcp");
  const ep = f.endpoint_url || eps[0]?.url || "";
  const set = (k: string, v: any) => setF((p) => ({ ...p, [k]: v }));

  const start = async () => {
    setErr(""); setBusy(true);
    try {
      const r = await api("/mcp-scans", { method: "POST", body: JSON.stringify({ ...f, scope_id: scope.id, endpoint_url: ep, auth_header: f.auth_type === "header" ? f.auth_header || "Authorization" : null, api_key: f.auth_type === "none" ? null : f.api_key }) });
      setOpen(r.id); set("api_key", ""); reload();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader title="MCP Servers" sub="Read-only audit of Model Context Protocol servers: hidden instructions in tool descriptions, risky tools, leaked secrets, missing authentication and definitions that change between scans." />
      <Notice tone="blue"><ShieldCheck className="mr-1 inline h-4 w-4" />AIVeritX only <b>lists</b> what the server offers (initialize, tools/list, prompts/list, resources/list). It never calls a tool, reads a resource or runs a command, and every request goes through the signed scope. Only HTTP servers are supported, not stdio.</Notice>
      {err && <Notice tone="red">{err}</Notice>}
      {can("operator") && (usable.length === 0 ? (
        <div data-testid="mcp-no-scope"><Notice tone="amber"><b>No signed scope covers an MCP server yet.</b> In <Link href="/scopes" className="underline">Scopes</Link>, add the server's address with the provider <span className="font-mono">mcp</span>, tick <b>MCP server audit (read-only)</b> and sign.</Notice></div>
      ) : (
        <Card className="mb-6" data-testid="mcp-form"><CardContent className="grid gap-4 p-6 md:grid-cols-2">
          <div><Label>Signed scope</Label><NativeSelect data-testid="mcp-scope" value={scope?.id || ""} onChange={(e) => setF((p) => ({ ...p, scope_id: e.target.value, endpoint_url: "" }))}>{usable.map((s: any) => <option key={s.id} value={s.id}>{s.name}</option>)}</NativeSelect></div>
          <div><Label>MCP server</Label><NativeSelect data-testid="mcp-endpoint" value={ep} onChange={(e) => set("endpoint_url", e.target.value)}>{eps.map((e: any) => <option key={e.url} value={e.url}>{e.url}</option>)}</NativeSelect></div>
          <div><Label help="Leave on None first: the audit also reports whether the server lets anyone in without a credential.">Authentication</Label>
            <NativeSelect data-testid="mcp-auth" value={f.auth_type} onChange={(e) => set("auth_type", e.target.value)}><option value="none">None</option><option value="bearer">Bearer token</option><option value="header">Custom header</option></NativeSelect></div>
          {f.auth_type !== "none" && <div className="grid gap-2 md:grid-cols-2">
            {f.auth_type === "header" && <div><Label>Header name</Label><Input value={f.auth_header} onChange={(e) => set("auth_header", e.target.value)} placeholder="X-Api-Key" /></div>}
            <div className={f.auth_type === "header" ? "" : "md:col-span-2"}><Label>Credential (memory only)</Label><Input data-testid="mcp-secret" type="password" autoComplete="off" value={f.api_key} onChange={(e) => set("api_key", e.target.value)} /></div></div>}
          <label className="flex items-center gap-3 text-sm text-slate-300 md:col-span-2"><Toggle data-testid="mcp-judge" checked={f.judge_review} onCheckedChange={(v) => set("judge_review", v)} />
            Also let the judge model read every description <span className="text-xs text-slate-500">(it must quote the suspicious text; its results need human review)</span></label>
          <div className="md:col-span-2"><Button data-testid="mcp-start" disabled={busy || !ep} onClick={start}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}Audit server</Button></div>
        </CardContent></Card>))}

      {!scans ? <Skeleton className="h-28" /> : scans.length === 0 ? (
        <EmptyState testId="mcp-empty" icon={Plug} title="No MCP audits yet" text="Add an MCP server to a signed scope, then audit it here. Nothing is called on the server; only its tool, prompt and resource lists are read." />
      ) : <div className="grid gap-3">{scans.map((s: any) => {
        const m = s.mcp || {};
        return (
          <Card key={s.id} className="surface-hover" data-testid="mcp-scan"><CardContent className="space-y-3 p-5">
            <div className="flex flex-wrap items-center gap-2"><button className="font-medium text-white hover:underline" onClick={() => setOpen(open === s.id ? null : s.id)}>{m.server?.name || s.endpoint_url}</button>
              {m.server?.version && <Badge>{m.server.version}</Badge>}<StatusBadge status={s.status} />
              {m.auth && <Badge tone={m.auth === "none required" ? "critical" : "green"}>auth: {m.auth}</Badge>}
              <Badge tone={s.verified ? "high" : "green"}>{s.verified} finding(s)</Badge>{m.tools && <Badge tone="neutral">{m.tools.length} tools</Badge>}
              <span className="text-xs text-slate-500">{fmtDate(s.created_at)}</span>
              <Link href={`/runs/${s.id}`} className="ml-auto text-xs text-violet-300 underline">Findings and reports</Link></div>
            <div className="truncate font-mono text-xs text-slate-500">{s.endpoint_url}</div>
            {open === s.id && m.tools && <div className="overflow-x-auto"><table className="w-full text-left text-xs" data-testid="mcp-tools">
              <thead className="text-slate-500"><tr><th className="py-1.5 pr-3">Tool</th><th className="pr-3">Parameters</th><th className="pr-3">Checks</th><th>Description (untrusted, as listed by the server)</th></tr></thead>
              <tbody>{m.tools.map((t: any) => <tr key={t.name} className="border-t border-white/5 align-top">
                <td className="py-2 pr-3 font-mono text-slate-200">{t.name}</td><td className="pr-3 font-mono text-slate-400">{(t.params || []).join(", ")}</td>
                <td className="pr-3"><div className="flex flex-wrap gap-1">{t.issues?.length ? t.issues.map((c: string) => <Badge key={c} tone="high">{ISSUE_LABEL[c] || c}</Badge>) : <Badge tone="green">clean</Badge>}</div></td>
                <td className="whitespace-pre-wrap break-words text-slate-400">{t.description}</td></tr>)}</tbody></table>
              {(m.prompts?.length > 0 || m.resources?.length > 0) && <div className="mt-2 text-xs text-slate-500">Also listed: {m.prompts?.length || 0} prompt(s), {m.resources?.length || 0} resource(s). {m.judge_reviewed ? `Judge reviewed ${m.judge_reviewed} description(s).` : ""}</div>}
            </div>}
          </CardContent></Card>);
      })}</div>}
    </>
  );
}
