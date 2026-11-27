"use client";
import Link from "next/link";
import { useState } from "react";
import { Crosshair, KeyRound, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Check_, Skeleton } from "@/components/ui/misc";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { api, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";
import AuthFields from "@/components/AuthFields";
import CustomHttpFields from "@/components/CustomHttpFields";
import { AUTH_LABEL, DEFAULT_PATH, DEFAULT_TEMPLATE, PRESETS, PROVIDER_LABEL, looksLocal, pathError, requestUrl, templateError } from "@/lib/targets";

const EMPTY = { name: "", provider: "openai_compat", base_url: "", model: "", api_key: "", auth_type: "bearer", auth_header: "", api_key_env: "", local: false, ingest_url: "", ingest_delete_url: "", request_template: "", response_path: "" };

export default function Targets() {
  const { can } = useMe();
  const { data: targets, reload } = usePoll(() => api("/targets"), 0);
  const [f, setF] = useState<any>(EMPTY);
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState(false);
  const [adv, setAdv] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: string, v: any) => setF((p: any) => ({ ...p, [k]: v }));
  const url = requestUrl(f.provider, f.base_url);
  const custom = f.provider === "http_json";
  const withCustomDefaults = (x: any) => x.provider === "http_json" && !x.request_template ? { ...x, request_template: DEFAULT_TEMPLATE, response_path: x.response_path || DEFAULT_PATH } : x;
  const customOk = !custom || (!templateError(f.request_template) && !pathError(f.response_path));

  const preset = (id: string) => { const p = PRESETS[id]; setF(withCustomDefaults({ ...EMPTY, ...p, local: looksLocal(p.base_url) })); };
  const openNew = () => { setEditing(null); setF({ ...EMPTY, ...PRESETS.openai }); setAdv(false); setErr(null); setOk(null); setForm(true); };
  const openEdit = (t: any) => { setEditing(t.id); setF({ ...EMPTY, name: t.name, provider: t.provider, base_url: t.base_url, model: t.model, auth_type: t.auth_type || "bearer", auth_header: t.auth_header || "", api_key_env: t.api_key_env || "", local: t.local, ingest_url: t.ingest_url || "", ingest_delete_url: t.ingest_delete_url || "", request_template: t.request_template || "", response_path: t.response_path || "" }); setAdv(!!(t.ingest_url || t.api_key_env)); setErr(null); setOk(null); setForm(true); };

  const save = async () => {
    setErr(null); setBusy(true);
    try {
      const body: any = { name: f.name, provider: f.provider, base_url: f.base_url, model: f.model, local: f.local, auth_type: f.auth_type, auth_header: f.auth_type === "header" ? (f.auth_header || "Authorization") : null, api_key_env: f.api_key_env || null, ingest_url: custom ? null : f.ingest_url || null, ingest_delete_url: custom ? null : f.ingest_delete_url || null,
        request_template: custom ? f.request_template : null, response_path: custom ? f.response_path.trim() : null };
      if (f.api_key) body.api_key = f.api_key;                       // empty field on edit = keep the key held in memory
      await api(editing ? `/targets/${editing}` : "/targets", { method: editing ? "PUT" : "POST", body: JSON.stringify(body) });
      setOk(editing ? "Target updated." : "Target saved."); setForm(false); setF(EMPTY); reload();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const del = async (t: any) => { if (!confirm(`Delete target “${t.name}”? Existing signed scopes are not affected.`)) return; try { await api(`/targets/${t.id}`, { method: "DELETE" }); reload(); } catch (e: any) { setErr(e.message); } };
  const clearKey = async (t: any) => { try { await api(`/targets/${t.id}`, { method: "PUT", body: JSON.stringify({ name: t.name, provider: t.provider, base_url: t.base_url, model: t.model, local: t.local, auth_type: t.auth_type, auth_header: t.auth_header, api_key_env: t.api_key_env, ingest_url: t.ingest_url, ingest_delete_url: t.ingest_delete_url, request_template: t.request_template, response_path: t.response_path, api_key: "" }) }); reload(); } catch (e: any) { setErr(e.message); } };

  return (
    <>
      <PageHeader title="Targets" sub="The LLM APIs you test. Add one here, then pick it when you create a scope."
        right={!form && can("operator") && <Button onClick={openNew} data-testid="add-target"><Plus className="h-4 w-4" />Add target</Button>} />
      {err && <Notice tone="red">{err}</Notice>}{ok && <Notice tone="green">{ok}</Notice>}
      <Notice tone="blue"><ShieldCheck className="mr-1 inline h-4 w-4" />Saving a target does not contact it. Nothing is sent until a test starts under a <b>signed scope</b>. API keys are kept in server memory only: they are never written to the database and are asked for again after a restart.</Notice>

      {form && (
        <Card className="mb-8"><CardContent className="space-y-5 p-6">
          <div className="flex flex-wrap gap-2">{Object.entries(PRESETS).map(([id, p]) => <button key={id} onClick={() => preset(id)} className="rounded-full border border-white/10 px-3.5 py-1.5 text-xs font-medium text-slate-300 transition hover:border-violet-400/50 hover:bg-violet-500/10 hover:text-white">{p.label}</button>)}</div>
          <div className="grid gap-4 md:grid-cols-2">
            <div><Label help="A label only you see, so you can recognise the target in lists and reports. For example: Support bot (staging).">Name</Label><Input data-testid="t-name" value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Support bot (staging)" /></div>
            <div><Label help={custom ? "Optional for a custom API: only a label shown in lists and reports (it is not sent unless your template contains it)." : "The model id the target API expects, such as gpt-4o, claude-sonnet-5-5 or llama3.2. It is sent with every request."}>{custom ? "Model label (optional)" : "Model name"}</Label><Input data-testid="t-model" value={f.model} onChange={(e) => set("model", e.target.value)} placeholder={custom ? "e.g. support-bot" : "e.g. gpt-4o, llama3.2"} /></div>
            <div><Label help="The request format the target speaks. OpenAI-compatible covers OpenAI, Ollama, vLLM, LM Studio and most gateways. Choose Anthropic for the Claude API. Choose Custom HTTP for any other JSON chat API, such as the backend of a web chatbot.">Provider</Label><NativeSelect data-testid="t-provider" value={f.provider} onChange={(e) => setF((p: any) => withCustomDefaults({ ...p, provider: e.target.value }))}><option value="openai_compat">OpenAI-compatible (OpenAI, Ollama, vLLM, LM Studio …)</option><option value="anthropic">Anthropic</option><option value="http_json">Custom HTTP API (JSON)</option></NativeSelect></div>
            <div><Label help={custom ? "The full address the chat request is POSTed to, exactly as your app calls it, for example https://app.example.com/api/chat." : "The address of the API without the final /chat/completions part. AIVeritX adds the right path for the provider (shown below the field)."}>{custom ? "Request URL" : "Base URL"}</Label><Input data-testid="t-url" value={f.base_url} onChange={(e) => { set("base_url", e.target.value); setF((p: any) => ({ ...p, base_url: e.target.value, local: looksLocal(e.target.value) })); }} placeholder={custom ? "https://app.example.com/api/chat" : "https://api.openai.com/v1"} />
              {url && !custom && <Hint>Requests go to <span className="font-mono text-slate-300">{url}</span></Hint>}</div>
            {custom && <div className="md:col-span-2"><CustomHttpFields url={url} template={f.request_template} path={f.response_path} onChange={(k, v) => set(k, v)}
              onImport={(r) => setF((p: any) => ({ ...p, base_url: r.url, request_template: r.template, local: looksLocal(r.url), ...(r.secret ? { auth_type: r.auth_type, auth_header: r.auth_header, api_key: r.secret } : {}) }))} /></div>}
            <div className="md:col-span-2"><AuthFields authType={f.auth_type} authHeader={f.auth_header} secret={f.api_key} editing={!!editing} onChange={(k, v) => set(k === "api_key" ? "api_key" : k, v)} /></div>
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-300"><Check_ checked={f.local} onCheckedChange={(v) => set("local", !!v)} />Local / private network address <span className="text-xs text-slate-500">(needed for localhost, Ollama or internal servers; cloud metadata addresses stay blocked)</span></label>
          <button className="text-xs text-violet-300 underline" onClick={() => setAdv(!adv)}>{adv ? "Hide" : "Show"} advanced ({custom ? "environment variable" : "environment variable, document upload"})</button>
          {adv && <div className="grid gap-4 md:grid-cols-3">
            <div><Label help="Optional. If the key is already in the server environment, enter only its variable name here instead of typing the key.">API key environment variable</Label><Input value={f.api_key_env} onChange={(e) => set("api_key_env", e.target.value)} placeholder="MY_TARGET_API_KEY" /></div>
            {!custom && <><div><Label help="Only for RAG tests: the address where AIVeritX uploads a test document so the target can read it. Leave empty if you do not test document ingestion.">Document upload URL <span className="text-slate-600">(RAG tests)</span></Label><Input value={f.ingest_url} onChange={(e) => set("ingest_url", e.target.value)} placeholder="https://…/ingest" /></div>
            <div><Label>Document delete URL</Label><Input value={f.ingest_delete_url} onChange={(e) => set("ingest_delete_url", e.target.value)} placeholder="https://…/ingest/{name}" /></div></>}</div>}
          <div className="flex gap-2"><Button disabled={busy || !f.name.trim() || !f.base_url.trim() || (!custom && !f.model.trim()) || !customOk} onClick={save} data-testid="save-target">{editing ? "Save changes" : "Save target"}</Button><Button variant="ghost" onClick={() => setForm(false)}>Cancel</Button></div>
        </CardContent></Card>)}

      {!targets ? <Skeleton className="h-28" /> : targets.length === 0 && !form ? (
        <EmptyState testId="targets-empty" icon={Crosshair} title="No targets yet. Add the app you want to test" text="A target is the chatbot or LLM API you want to check: OpenAI, Anthropic, Ollama or your own endpoint. Saving it sends nothing. Add one, then start a scan." action={can("operator") ? "Add your first target" : undefined} onClick={openNew} secondary={can("operator") ? { label: "Or run a Quick scan", href: "/new" } : undefined} />
      ) : (
        <div className="grid gap-3">{targets.map((t: any) => (
          <Card key={t.id} className="surface-hover"><CardContent className="flex flex-wrap items-center gap-4 p-5">
            <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-violet-500/25 to-blue-500/15 text-violet-200"><Crosshair className="h-5 w-5" /></div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-white">{t.name}</span><Badge tone="violet">{PROVIDER_LABEL[t.provider] || t.provider}</Badge><Badge>{t.model}</Badge>{t.auth_type && t.auth_type !== "bearer" && <Badge tone="blue">{t.auth_type === "header" ? `header: ${t.auth_header}` : AUTH_LABEL[t.auth_type]}</Badge>}
                {t.local && <Badge tone="amber">local</Badge>}
                {t.has_key ? <Badge tone="green"><KeyRound className="h-3 w-3" />key in memory</Badge> : t.api_key_env ? <Badge tone="blue">key from ${t.api_key_env}</Badge> : <Badge tone="neutral">no key</Badge>}</div>
              <div className="mt-1 truncate font-mono text-xs text-slate-500">{t.request_url}</div></div>
            <div className="flex flex-wrap items-center gap-2">
              {can("admin") && <Link href={`/scopes?target=${t.id}`}><Button size="sm" variant="secondary"><ShieldCheck className="h-3.5 w-3.5" />Create scope</Button></Link>}
              {can("operator") && <>{t.has_key && <Button size="sm" variant="ghost" onClick={() => clearKey(t)}>Forget key</Button>}
                <Button size="sm" variant="outline" onClick={() => openEdit(t)}><Pencil className="h-3.5 w-3.5" />Edit</Button>
                <Button size="sm" variant="ghost" className="text-red-300" onClick={() => del(t)}><Trash2 className="h-3.5 w-3.5" /></Button></>}
            </div></CardContent></Card>))}</div>)}
    </>
  );
}
