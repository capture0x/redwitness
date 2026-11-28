"use client";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { AUTH_LABEL } from "@/lib/targets";

const COPY: Record<string, { label: string; placeholder: string; hint: string }> = {
  bearer: { label: "API key / Bearer token", placeholder: "sk-…  (optional for local models)", hint: "Sent as “Authorization: Bearer …” (Anthropic: “x-api-key”). Held in memory only." },
  cookie: { label: "Cookie string", placeholder: "session=abc123; token=xyz", hint: "Copy it from your browser: developer tools → Network → any request to the target → Cookie. Sent as the Cookie header. Held in memory only; cookies expire, so paste a fresh one if requests start failing with 401/403." },
  header: { label: "Header value", placeholder: "Bearer eyJ…  or any value", hint: "Sent exactly as “<header name>: <value>”. Held in memory only." },
};
export type Hdr = { name: string; value: string };

/** Auth type + credentials shared by the Targets page and the quick scan: an API key, cookie or custom header, OAuth 2.0, and extra headers
 *  (CSRF token, tenant id ...). Every secret here is kept in server memory only, never stored. */
export default function AuthFields({ f, set, editing, testPrefix = "t" }: { f: any; set: (k: string, v: any) => void; editing?: boolean; testPrefix?: string }) {
  const type = f.auth_type || "bearer";
  const c = COPY[type];
  const hdrs: Hdr[] = f.extra_headers || [];
  const setHdr = (i: number, k: keyof Hdr, v: string) => set("extra_headers", hdrs.map((h, j) => (j === i ? { ...h, [k]: v } : h)));
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div><Label help="How the target expects you to prove who you are. Most APIs use an API key (Bearer). Pick Cookie for a chatbot behind a login, Custom header for gateways with their own header name, or OAuth 2.0 when the app gets short-lived tokens from an identity provider.">Authentication</Label>
        <NativeSelect data-testid={`${testPrefix}-auth`} value={type} onChange={(e) => set("auth_type", e.target.value)}>{Object.entries(AUTH_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect></div>
      {type === "header" && <div><Label help="The exact name of the HTTP header that carries your credential, for example X-Api-Key.">Header name</Label><Input data-testid={`${testPrefix}-header`} value={f.auth_header || ""} onChange={(e) => set("auth_header", e.target.value)} placeholder="Authorization" /></div>}
      {c && <div className="md:col-span-2"><Label help="The secret is kept in server memory only. It is never written to the database, and you are asked again after a restart."><KeyRound className="mr-1 inline h-3 w-3" />{c.label} {editing && <span className="text-slate-600">(leave empty to keep the current one)</span>}</Label>
        <Input data-testid={`${testPrefix}-key`} type="password" autoComplete="off" value={f.api_key || ""} onChange={(e) => set("api_key", e.target.value)} placeholder={c.placeholder} />
        <Hint>{c.hint}</Hint></div>}
      {type === "oauth" && <div className="grid gap-3 rounded-xl border border-white/10 bg-white/[0.02] p-4 md:col-span-2 md:grid-cols-2" data-testid={`${testPrefix}-oauth`}>
        <div className="md:col-span-2"><Label help="The identity provider's token endpoint. It becomes part of the signed scope: tokens are only ever requested from this address.">Token URL</Label>
          <Input data-testid={`${testPrefix}-token-url`} value={f.token_url || ""} onChange={(e) => set("token_url", e.target.value)} placeholder="https://login.example.com/oauth2/token" /></div>
        <div><Label help="Client credentials: a service account (client id + secret). Refresh token: a user session you already have a refresh token for.">Grant</Label>
          <NativeSelect data-testid={`${testPrefix}-grant`} value={f.oauth_grant || "client_credentials"} onChange={(e) => set("oauth_grant", e.target.value)}>
            <option value="client_credentials">Client credentials</option><option value="refresh_token">Refresh token</option></NativeSelect></div>
        <div><Label>Client id</Label><Input data-testid={`${testPrefix}-client-id`} value={f.oauth_client_id || ""} onChange={(e) => set("oauth_client_id", e.target.value)} /></div>
        {(f.oauth_grant || "client_credentials") === "client_credentials"
          ? <div><Label>Client secret {editing && <span className="text-slate-600">(empty: keep)</span>}</Label><Input data-testid={`${testPrefix}-client-secret`} type="password" autoComplete="off" value={f.oauth_client_secret || ""} onChange={(e) => set("oauth_client_secret", e.target.value)} /></div>
          : <div><Label>Refresh token {editing && <span className="text-slate-600">(empty: keep)</span>}</Label><Input data-testid={`${testPrefix}-refresh`} type="password" autoComplete="off" value={f.oauth_refresh_token || ""} onChange={(e) => set("oauth_refresh_token", e.target.value)} /></div>}
        <div><Label>Scope <span className="text-slate-600">(optional)</span></Label><Input value={f.oauth_scope || ""} onChange={(e) => set("oauth_scope", e.target.value)} placeholder="chat.read chat.write" /></div>
        <Hint className="md:col-span-2">The access token is fetched before the first request and fetched again when it expires or the target answers 401. Client secret and refresh token stay in server memory.</Hint>
      </div>}
      <div className="md:col-span-2" data-testid={`${testPrefix}-extra-headers`}>
        <Label help="Further headers the app needs on every request, for example a CSRF token or a tenant id. Values are secrets: held in memory only. Headers that control the connection or the body (Host, Content-Type, Cookie ...) are not allowed.">Extra headers <span className="text-slate-600">(optional)</span></Label>
        {hdrs.map((h, i) => <div key={i} className="mb-2 flex gap-2">
          <Input className="w-56 font-mono" placeholder="X-CSRF-Token" value={h.name} onChange={(e) => setHdr(i, "name", e.target.value)} data-testid={`${testPrefix}-hdr-name-${i}`} />
          <Input className="flex-1 font-mono" type="password" autoComplete="off" placeholder="value" value={h.value} onChange={(e) => setHdr(i, "value", e.target.value)} data-testid={`${testPrefix}-hdr-value-${i}`} />
          <Button variant="ghost" size="sm" onClick={() => set("extra_headers", hdrs.filter((_, j) => j !== i))} aria-label="Remove header"><Trash2 className="h-3.5 w-3.5" /></Button></div>)}
        {hdrs.length < 10 && <Button variant="outline" size="sm" onClick={() => set("extra_headers", [...hdrs, { name: "", value: "" }])} data-testid={`${testPrefix}-hdr-add`}><Plus className="h-3.5 w-3.5" />Add header</Button>}
      </div>
    </div>
  );
}

/** The auth part of a request body (targets and quick scan). Empty extra-header rows are dropped; untouched OAuth secrets are left out. */
export function authBody(f: any) {
  const hdrs = (f.extra_headers || []).filter((h: Hdr) => h.name.trim());
  return {
    auth_type: f.auth_type, auth_header: f.auth_type === "header" ? (f.auth_header || "Authorization") : null,
    extra_headers: f.extra_headers === undefined ? null : hdrs.map((h: Hdr) => ({ name: h.name.trim(), value: h.value })),
    ...(f.auth_type === "oauth" ? { token_url: f.token_url || null, oauth_grant: f.oauth_grant || "client_credentials", oauth_client_id: f.oauth_client_id || null,
      oauth_client_secret: f.oauth_client_secret || null, oauth_refresh_token: f.oauth_refresh_token || null, oauth_scope: f.oauth_scope || null } : {}),
  };
}
