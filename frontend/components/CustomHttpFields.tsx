"use client";
import { useState } from "react";
import { ClipboardPaste, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Hint, Input, Label, Textarea } from "@/components/ui/input";
import { parseCurl, type CurlImport } from "@/lib/curl";
import { pathError, renderPreview, templateError } from "@/lib/targets";

/** Request template and response path for a custom HTTP (JSON) target. "Preview request" renders the body locally: nothing is sent. */
export default function CustomHttpFields({ url, template, path, onChange, onImport, testPrefix = "t" }: {
  url: string; template: string; path: string; onChange: (k: "request_template" | "response_path", v: string) => void;
  onImport?: (r: CurlImport) => void; testPrefix?: string;
}) {
  const [preview, setPreview] = useState<string | null>(null);
  const [curlOpen, setCurlOpen] = useState(false);
  const [curl, setCurl] = useState("");
  const [typed, setTyped] = useState("");
  const [imp, setImp] = useState<{ ok?: CurlImport; err?: string } | null>(null);
  const doImport = () => {
    try {
      const r = parseCurl(curl, typed);
      onChange("request_template", r.template); onImport?.(r); setImp({ ok: r }); setPreview(null);
      setCurl("");                                                       // the pasted command may hold a session cookie: do not keep it on screen
    } catch (e: any) { setImp({ err: e.message }); }
  };
  const tErr = template.trim() ? templateError(template) : "";
  const pErr = path.trim() ? pathError(path) : "";
  return (
    <div className="space-y-4 rounded-xl border border-white/10 bg-white/[0.02] p-4" data-testid={`${testPrefix}-custom-http`}>
      {onImport && <div>
        <button className="inline-flex items-center gap-1.5 text-xs font-medium text-violet-300 underline-offset-2 hover:underline" onClick={() => setCurlOpen(!curlOpen)} data-testid={`${testPrefix}-curl-toggle`}>
          <ClipboardPaste className="h-3.5 w-3.5" />{curlOpen ? "Hide" : "Import from a copied request (cURL)"}</button>
        {curlOpen && <div className="mt-3 space-y-3 rounded-lg border border-violet-400/20 bg-violet-500/[0.04] p-3">
          <p className="text-xs text-slate-400">In your browser open the chatbot, then Developer tools → Network. Send one message, right-click the request → Copy → <b>Copy as cURL (bash)</b> and paste it here. It is read in your browser; the address, body template and credential fields below are filled in for you to review.</p>
          <Textarea data-testid={`${testPrefix}-curl`} rows={4} className="font-mono text-[11px]" value={curl} onChange={(e) => setCurl(e.target.value)} placeholder="curl 'https://app.example.com/api/chat' -H 'content-type: application/json' -b 'session=…' --data-raw '{&quot;message&quot;:&quot;Hello&quot;}'" spellCheck={false} />
          <div><Label help="Optional but recommended: the exact text you typed in the chatbot before copying the request. Its place in the body becomes {{prompt}}.">Message you sent</Label>
            <Input data-testid={`${testPrefix}-curl-typed`} value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="e.g. What are your opening hours?" /></div>
          <Button size="sm" variant="secondary" disabled={!curl.trim()} onClick={doImport} data-testid={`${testPrefix}-curl-import`}>Import</Button>
          {imp?.err && <Hint className="text-red-400">{imp.err}</Hint>}
          {imp?.ok && <div className="space-y-1 text-xs text-slate-300" data-testid={`${testPrefix}-curl-result`}>
            <div>Imported the request URL, the body template{imp.ok.secret ? ` and the ${imp.ok.auth_type === "cookie" ? "session cookie" : imp.ok.auth_type === "bearer" ? "bearer token" : `${imp.ok.auth_header} header`} (held in memory only)` : ""}. Check the response path below: it cannot be read from the request.</div>
            <div className="text-slate-500">Message field: {imp.ok.promptFound ? "found ({{prompt}})" : "not found"} · conversation id: {imp.ok.sessionFound ? "found ({{session_id}})" : "none"}</div>
            {imp.ok.ignoredHeaders.length > 0 && <div className="text-amber-300">Not sent (only one credential header is supported): {imp.ok.ignoredHeaders.join(", ")}</div>}
            {imp.ok.warnings.map((w) => <div key={w} className="text-amber-300">{w}</div>)}
          </div>}
        </div>}
      </div>}
      <div>
        <Label help="The JSON body your API expects. {{prompt}} is replaced with the test message, {{messages}} with the whole conversation as a list of role/content objects, and {{session_id}} with one random id per conversation (for APIs that keep the chat on the server). Tip: copy a real request from your browser's developer tools and replace the message text with {{prompt}}.">Request body template (JSON)</Label>
        <Textarea data-testid={`${testPrefix}-template`} rows={6} className="font-mono text-xs" value={template} onChange={(e) => { onChange("request_template", e.target.value); setPreview(null); }} spellCheck={false} />
        {tErr ? <Hint className="text-red-400">{tErr}</Hint> : <Hint>Sent as a POST with <span className="font-mono">Content-Type: application/json</span>. The template is part of the signed scope.</Hint>}
      </div>
      <div>
        <Label help="Where the reply text is in the JSON response, as a dotted path. Examples: reply, data.answer, choices.0.message.content.">Response path</Label>
        <Input data-testid={`${testPrefix}-path`} className="font-mono" value={path} onChange={(e) => onChange("response_path", e.target.value)} placeholder="e.g. reply or data.answer" />
        {pErr && <Hint className="text-red-400">{pErr}</Hint>}
      </div>
      <div>
        <Button size="sm" variant="secondary" disabled={!!tErr || !template.trim()} onClick={() => setPreview(renderPreview(template, "Hello, what can you help me with?"))} data-testid={`${testPrefix}-preview`}><Eye className="h-3.5 w-3.5" />Preview request</Button>
        <span className="ml-3 text-xs text-slate-500">Shows the request locally. Nothing is sent.</span>
        {preview && <pre data-testid={`${testPrefix}-preview-body`} className="mt-3 max-h-64 overflow-auto rounded-lg border border-white/10 bg-black/30 p-3 font-mono text-[11px] text-slate-300">{`POST ${url || "<request URL>"}\nContent-Type: application/json\n\n${preview}`}</pre>}
      </div>
    </div>
  );
}
