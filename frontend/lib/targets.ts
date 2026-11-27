export const PRESETS: Record<string, { label: string; provider: string; base_url: string; model: string; name: string }> = {
  openai: { label: "OpenAI", provider: "openai_compat", base_url: "https://api.openai.com/v1", model: "gpt-4o", name: "OpenAI" },
  anthropic: { label: "Anthropic", provider: "anthropic", base_url: "https://api.anthropic.com", model: "claude-sonnet-5-5", name: "Anthropic" },
  ollama: { label: "Ollama (local)", provider: "openai_compat", base_url: "http://localhost:11434/v1", model: "llama3.2", name: "Ollama" },
  custom: { label: "Custom (OpenAI-compatible)", provider: "openai_compat", base_url: "", model: "", name: "" },
  http_json: { label: "Custom HTTP API (JSON)", provider: "http_json", base_url: "", model: "", name: "" },
};

export const PROVIDER_LABEL: Record<string, string> = { openai_compat: "OpenAI-compatible", anthropic: "Anthropic", http_json: "Custom HTTP" };
export const DEFAULT_TEMPLATE = '{\n  "message": "{{prompt}}",\n  "session_id": "{{session_id}}"\n}';
export const DEFAULT_PATH = "reply";

/** The full request address from the base address (mirrors the server: <base>/chat/completions, or <base>/v1/messages for Anthropic). */
export const requestUrl = (provider: string, base: string) => {
  if (provider === "http_json") return base.trim();                    // a custom API: the address is used exactly as given
  const b = base.trim().replace(/\/+$/, "");
  if (!b) return "";
  if (provider === "anthropic") return b.endsWith("/messages") ? b : b + (b.endsWith("/v1") ? "/messages" : "/v1/messages");
  return b.endsWith("/chat/completions") ? b : b + "/chat/completions";
};

export const looksLocal = (u: string) => {
  try { const h = new URL(u).hostname; return h === "localhost" || h.endsWith(".local") || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || h === "::1" || h === "[::1]"; } catch { return false; }
};

export const AUTH_LABEL: Record<string, string> = { bearer: "API key / Bearer token", cookie: "Cookie / session", header: "Custom header" };

const PH = /\{\{\s*([A-Za-z_]+)\s*\}\}/g;
const ONE_PASS = /\{\{prompt\}\}|\{\{session_id\}\}/g;

/** Mirrors the server's template check (llm_redteam/customhttp.py): returns an error message, or "" when the template is usable. */
export function templateError(text: string): string {
  const t = (text || "").trim();
  if (!t) return "The request template is required.";
  let obj: any;
  try { obj = JSON.parse(t); } catch (e: any) { return `The request template is not valid JSON (${e.message}).`; }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return "The request template must be a JSON object, for example {\"message\": \"{{prompt}}\"}.";
  const seen = new Set<string>();
  let err = "";
  const walk = (v: any) => {
    if (err) return;
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.entries(v).forEach(([k, x]) => { if (PH.test(k)) err = "Placeholders are only allowed in values, not in key names."; PH.lastIndex = 0; walk(x); });
    else if (typeof v === "string") for (const m of v.matchAll(PH)) {
      const name = `{{${m[1]}}}`;
      if (m[0] !== name || !["{{prompt}}", "{{messages}}", "{{session_id}}"].includes(name)) { err = `Unknown placeholder ${m[0]}: use {{prompt}}, {{messages}} or {{session_id}}.`; return; }
      if (name === "{{messages}}" && v !== "{{messages}}") { err = "{{messages}} must be the whole value, for example \"history\": \"{{messages}}\"."; return; }
      seen.add(name);
    }
    if (typeof v === "string" && !err) { const rest = v.replace(PH, ""); if (rest.includes("{{") || rest.includes("}}")) err = "A placeholder is not closed: write {{prompt}}, {{messages}} or {{session_id}} exactly."; }
  };
  walk(obj);
  if (err) return err;
  if (!seen.has("{{prompt}}") && !seen.has("{{messages}}")) return "The request template must contain {{prompt}} or {{messages}}.";
  return "";
}

export const pathError = (p: string) => !(p || "").trim() ? "The response path is required, for example reply or data.answer."
  : (p.trim().split(".").every((s) => /^[A-Za-z0-9_\-$@]{1,64}$/.test(s)) ? "" : "Response path: names and list indexes separated by dots, for example data.messages.0.text.");

/** The body the server would send for a sample message. Local only: nothing is sent. */
export function renderPreview(text: string, prompt: string): string {
  const sub = (v: any): any => Array.isArray(v) ? v.map(sub) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, sub(x)]))
    : typeof v === "string" ? (v === "{{messages}}" ? [{ role: "user", content: prompt }] : v.replace(ONE_PASS, (m) => (m === "{{prompt}}" ? prompt : "3f9c2a…(one per conversation)"))) : v;
  return JSON.stringify(sub(JSON.parse(text)), null, 2);
}
