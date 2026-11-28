// Unit tests for lib/curl.ts (the "Copy as cURL" import). Transpiled with the project's own TypeScript; no extra test dependency.
import fs from "fs";
import assert from "assert/strict";
import ts from "typescript";

const src = fs.readFileSync(new URL("../lib/curl.ts", import.meta.url), "utf8");
const js = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { parseCurl, tokenize } = await import("data:text/javascript;base64," + Buffer.from(js).toString("base64"));
let n = 0;
const test = (name, fn) => { fn(); n++; console.log("ok -", name); };

test("Chrome bash copy with cookie, $'...' body and line continuations", () => {
  const cmd = `curl 'https://app.example.com/api/chat' \\
  -H 'accept: application/json' \\
  -H 'content-type: application/json' \\
  -b 'sid=abc123; theme=dark' \\
  -H 'origin: https://app.example.com' \\
  -H 'x-request-id: 77' \\
  --data-raw $'{"question":"What are your opening hours?","conversation_id":"c-9f2","lang":"en","note":"it\\'s ok"}'`;
  const r = parseCurl(cmd, "What are your opening hours?");
  assert.equal(r.url, "https://app.example.com/api/chat");
  assert.equal(r.method, "POST");
  assert.deepEqual(JSON.parse(r.template), { question: "{{prompt}}", conversation_id: "{{session_id}}", lang: "en", note: "it's ok" });
  assert.equal(r.auth_type, "cookie"); assert.equal(r.secret, "sid=abc123; theme=dark");
  assert.deepEqual(r.extraHeaders, [{ name: "x-request-id", value: "77" }]);
  assert.ok(r.promptFound && r.sessionFound && r.warnings.length === 0);
});

test("CSRF and tenant headers become extra headers next to the cookie", () => {
  const r = parseCurl(`curl 'https://app.example.com/api/chat' -b 'sid=1' -H 'X-CSRF-Token: csrf-123' -H 'X-Tenant: acme' -H 'accept: */*' --data-raw '{"message":"hi"}'`, "hi");
  assert.equal(r.auth_type, "cookie");
  assert.deepEqual(r.extraHeaders, [{ name: "X-CSRF-Token", value: "csrf-123" }, { name: "X-Tenant", value: "acme" }]);
});

test("only extra headers (no credential) give the 'none' auth type", () => {
  const r = parseCurl(`curl 'https://app.example.com/api/chat' -H 'X-Tenant: acme' --data-raw '{"message":"hi"}'`, "hi");
  assert.equal(r.auth_type, "none"); assert.equal(r.secret, "");
});

test("Bearer token and a guessed message field without typed text", () => {
  const r = parseCurl(`curl -X POST "https://bot.example.com/v2/ask" -H "Authorization: Bearer tok-1" -H "Content-Type: application/json" -d "{\\"input\\": \\"hi\\", \\"user\\": {\\"sessionId\\": \\"s1\\"}}"`);
  assert.equal(r.auth_type, "bearer"); assert.equal(r.secret, "tok-1");
  assert.deepEqual(JSON.parse(r.template), { input: "{{prompt}}", user: { sessionId: "{{session_id}}" } });
});

test("a custom x-*-token header becomes the credential", () => {
  const r = parseCurl(`curl https://x.example.com/c --data-raw '{"message":"hello"}' -H 'X-Api-Token: secret-9'`);
  assert.equal(r.auth_type, "header"); assert.equal(r.auth_header, "X-Api-Token"); assert.equal(r.secret, "secret-9");
  assert.equal(r.method, "POST");
});

test("typed message inside a longer string keeps the rest of the text", () => {
  const r = parseCurl(`curl https://x.example.com/c --data-raw '{"payload":{"messages":[{"role":"user","content":"Q: hello there"}]}}'`, "hello there");
  assert.equal(JSON.parse(r.template).payload.messages[0].content, "Q: {{prompt}}");
});

test("warnings: query string, GET-style method, unknown message field", () => {
  const r = parseCurl(`curl 'https://x.example.com/c?debug=1' -X PUT --data-raw '{"foo":"bar"}'`);
  assert.equal(r.url, "https://x.example.com/c");
  assert.ok(r.warnings.some((w) => w.includes("query string")) && r.warnings.some((w) => w.includes("PUT")) && r.warnings.some((w) => w.includes("Could not tell")));
});

test("refusals with a clear message", () => {
  assert.throws(() => parseCurl("wget https://x"), /does not look like a cURL/);
  assert.throws(() => parseCurl("curl https://x.example.com/c"), /no request body/);
  assert.throws(() => parseCurl("curl https://x.example.com/c --data-raw 'a=1'"), /not JSON/);
  assert.throws(() => parseCurl("curl https://x.example.com/c --data-raw '[1]'"), /JSON object/);
  assert.throws(() => parseCurl("curl ftp://x --data-raw '{}'"), /No http/);
  assert.throws(() => tokenize("curl 'unclosed"), /unclosed/);
});

console.log(`${n} curl import tests passed`);
