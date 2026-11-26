"use client";
import { KeyRound } from "lucide-react";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { AUTH_LABEL } from "@/lib/targets";

const COPY: Record<string, { label: string; placeholder: string; hint: string }> = {
  bearer: { label: "API key / Bearer token", placeholder: "sk-…  (optional for local models)", hint: "Sent as “Authorization: Bearer …” (Anthropic: “x-api-key”). Held in memory only." },
  cookie: { label: "Cookie string", placeholder: "session=abc123; token=xyz", hint: "Copy it from your browser: developer tools → Network → any request to the target → Cookie. Sent as the Cookie header. Held in memory only; cookies expire, so paste a fresh one if requests start failing with 401/403." },
  header: { label: "Header value", placeholder: "Bearer eyJ…  or any value", hint: "Sent exactly as “<header name>: <value>”. Held in memory only." },
};

/** Auth type + credential inputs shared by the Targets page and the quick scan. The credential is never stored, only kept in server memory. */
export default function AuthFields({ authType, authHeader, secret, onChange, editing, testPrefix = "t" }: {
  authType: string; authHeader: string; secret: string; onChange: (k: "auth_type" | "auth_header" | "api_key", v: string) => void; editing?: boolean; testPrefix?: string;
}) {
  const c = COPY[authType] || COPY.bearer;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div><Label help="How the target expects you to prove who you are. Most APIs use an API key (Bearer). Pick Cookie for a chatbot behind a login, or Custom header for gateways that use their own header name.">Authentication</Label>
        <NativeSelect data-testid={`${testPrefix}-auth`} value={authType} onChange={(e) => onChange("auth_type", e.target.value)}>{Object.entries(AUTH_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect></div>
      {authType === "header" && <div><Label help="The exact name of the HTTP header that carries your credential, for example X-Api-Key.">Header name</Label><Input data-testid={`${testPrefix}-header`} value={authHeader} onChange={(e) => onChange("auth_header", e.target.value)} placeholder="Authorization" /></div>}
      <div className="md:col-span-2"><Label help="The secret is kept in server memory only. It is never written to the database, and you are asked again after a restart."><KeyRound className="mr-1 inline h-3 w-3" />{c.label} {editing && <span className="text-slate-600">(leave empty to keep the current one)</span>}</Label>
        <Input data-testid={`${testPrefix}-key`} type="password" autoComplete="off" value={secret} onChange={(e) => onChange("api_key", e.target.value)} placeholder={c.placeholder} />
        <Hint>{c.hint}</Hint></div>
    </div>
  );
}
