/**
 * "Copy as cURL" import for custom HTTP targets. Runs in the browser only: the pasted command (which may hold a session cookie) is parsed
 * here and never sent anywhere as a whole. Supports the bash variant browsers produce: '...' , "..." and $'...' quoting, backslash line
 * continuations, -H/--header, -b/--cookie, -d/--data/--data-raw/--data-binary, -X/--request and the URL.
 */
export type CurlImport = {
  url: string; method: string; body: any; template: string; promptFound: boolean; sessionFound: boolean;
  auth_type: "bearer" | "cookie" | "header"; auth_header: string; secret: string; ignoredHeaders: string[]; warnings: string[];
};

const PROMPT_KEYS = /^(message|prompt|question|query|input|text|content|q|user_input|userMessage|user_message|msg)$/i;
const SESSION_KEYS = /(session|conversation|thread|chat)_?id$|^(session|conversation|thread|chatId|sessionId|conversationId|threadId)$/i;
const SKIP_HEADERS = new Set(["content-type", "content-length", "accept", "accept-encoding", "accept-language", "connection", "host", "origin", "referer", "user-agent",
  "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "priority", "pragma", "cache-control", "dnt", "te"]);

export function tokenize(cmd: string): string[] {
  const s = cmd.replace(/\\\r?\n/g, " ").replace(/\^\r?\n/g, " ");                // bash and cmd.exe line continuations
  const out: string[] = [];
  let i = 0, cur = "", has = false;
  const esc: Record<string, string> = { n: "\n", t: "\t", r: "\r", "\\": "\\", "'": "'", '"': '"' };
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { if (has) { out.push(cur); cur = ""; has = false; } i++; continue; }
    has = true;
    if (c === "$" && s[i + 1] === "'") {                                         // ANSI-C quoting: $'...\n...'
      i += 2;
      while (i < s.length && s[i] !== "'") {
        if (s[i] === "\\" && i + 1 < s.length) {
          const n = s[i + 1];
          if (n === "u" && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 2, i + 6))) { cur += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16)); i += 6; continue; }
          if (n === "x" && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 2, i + 4))) { cur += String.fromCharCode(parseInt(s.slice(i + 2, i + 4), 16)); i += 4; continue; }
          cur += esc[n] ?? n; i += 2; continue;
        }
        cur += s[i++];
      }
      i++; continue;
    }
    if (c === "'") { const j = s.indexOf("'", i + 1); if (j < 0) throw new Error("unclosed ' quote"); cur += s.slice(i + 1, j); i = j + 1; continue; }
    if (c === '"') {
      i++;
      while (i < s.length && s[i] !== '"') { if (s[i] === "\\" && i + 1 < s.length && '"\\$`'.includes(s[i + 1])) { cur += s[i + 1]; i += 2; } else cur += s[i++]; }
      if (i >= s.length) throw new Error('unclosed " quote');
      i++; continue;
    }
    if (c === "\\" && i + 1 < s.length) { cur += s[i + 1]; i += 2; continue; }
    cur += c; i++;
  }
  if (has) out.push(cur);
  return out;
}

export function parseCurl(cmd: string, typedMessage = ""): CurlImport {
  const t = tokenize(cmd.trim());
  if (!t.length || !/^curl(\.exe)?$/i.test(t[0])) throw new Error("This does not look like a cURL command. In the browser use Network → right-click the request → Copy → Copy as cURL (bash).");
  let url = "", method = "", data: string | null = null;
  const headers: [string, string][] = [];
  const warnings: string[] = [];
  for (let i = 1; i < t.length; i++) {
    const a = t[i];
    const val = () => { if (i + 1 >= t.length) throw new Error(`${a} needs a value`); return t[++i]; };
    if (a === "-H" || a === "--header") { const h = val(); const k = h.indexOf(":"); if (k > 0) headers.push([h.slice(0, k).trim(), h.slice(k + 1).trim()]); }
    else if (a === "-b" || a === "--cookie") headers.push(["cookie", val()]);
    else if (["-d", "--data", "--data-raw", "--data-binary", "--data-ascii"].includes(a)) data = val();
    else if (a === "--data-urlencode" || a === "-F" || a === "--form") { val(); warnings.push("Form or URL-encoded bodies are not supported: a custom HTTP target sends a JSON body."); }
    else if (a === "-X" || a === "--request") method = val().toUpperCase();
    else if (a === "--url") url = val();
    else if (a === "-u" || a === "--user") { val(); warnings.push("Basic authentication (-u) is not imported: use a custom Authorization header instead."); }
    else if (["-A", "--user-agent", "-e", "--referer", "-o", "--output", "--max-time", "-m", "--connect-timeout"].includes(a)) val();
    else if (a.startsWith("-")) { /* flags without a value: --compressed, -s, -k, -L, -i ... */ }
    else if (!url) url = a;
  }
  if (!/^https?:\/\//i.test(url)) throw new Error("No http(s) URL found in the command.");
  const u = new URL(url);
  if (u.search) warnings.push("The URL has a query string, which a target address may not contain. Remove it or move the values into the body.");
  method = method || (data !== null ? "POST" : "GET");
  if (method !== "POST") warnings.push(`The request uses ${method}; custom HTTP targets are sent as POST.`);
  let body: any = null;
  if (data === null) throw new Error("The command has no request body (--data-raw). Copy the request that sends the chat message.");
  try { body = JSON.parse(data); } catch { throw new Error("The request body is not JSON. Custom HTTP targets need a JSON body."); }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("The request body must be a JSON object.");

  // credential: cookie first, then Authorization, then the first other x-* token header
  let auth_type: CurlImport["auth_type"] = "bearer", auth_header = "", secret = "";
  const ignored: string[] = [];
  const cookie = headers.find(([k]) => k.toLowerCase() === "cookie");
  const authz = headers.find(([k]) => k.toLowerCase() === "authorization");
  if (cookie) { auth_type = "cookie"; secret = cookie[1]; }
  else if (authz) {
    const m = authz[1].match(/^Bearer\s+(.+)$/i);
    if (m) { auth_type = "bearer"; secret = m[1]; } else { auth_type = "header"; auth_header = "Authorization"; secret = authz[1]; }
  }
  for (const [k] of headers) {
    const l = k.toLowerCase();
    if (SKIP_HEADERS.has(l) || (cookie && l === "cookie") || (authz && l === "authorization")) continue;
    if (!secret && /^x-[a-z0-9-]*(token|key|auth|api)/i.test(k)) { auth_type = "header"; auth_header = k; secret = headers.find(([h]) => h === k)![1]; continue; }
    ignored.push(k);
  }
  if (cookie && authz) ignored.push("authorization");

  // template: the typed message (or the most likely message field) becomes {{prompt}}, conversation ids become {{session_id}}
  let promptFound = false, sessionFound = false;
  const typed = typedMessage.trim();
  const walk = (v: any, key = ""): any => {
    if (Array.isArray(v)) return v.map((x) => walk(x, key));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, k)]));
    if (typeof v === "string") {
      if (typed && v.includes(typed)) { promptFound = true; return v.split(typed).join("{{prompt}}"); }
      if (SESSION_KEYS.test(key) && v) { sessionFound = true; return "{{session_id}}"; }
    }
    return v;
  };
  let tpl = walk(body);
  if (!promptFound) {                                                            // no typed text: the first likely message field
    const pick = (v: any): boolean => {
      if (Array.isArray(v)) return v.some(pick);
      if (v && typeof v === "object") for (const k of Object.keys(v)) { if (PROMPT_KEYS.test(k) && typeof v[k] === "string") { v[k] = "{{prompt}}"; return true; } if (pick(v[k])) return true; }
      return false;
    };
    promptFound = pick(tpl);
  }
  if (!promptFound) warnings.push("Could not tell which field holds the message. Type the message you sent in the box above, or put {{prompt}} into the template yourself.");
  return { url: `${u.origin}${u.pathname}`, method, body, template: JSON.stringify(tpl, null, 2), promptFound, sessionFound,
           auth_type, auth_header, secret, ignoredHeaders: ignored, warnings };
}
