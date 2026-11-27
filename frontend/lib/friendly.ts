/** Turns a technical API error into what the person should do next. Unknown messages are kept as they are. */
const RULES: [RegExp, string][] = [
  [/judge LLM is not configured/i, "The judge model is not set up yet. Open Settings → Judge LLM, choose a provider and model, and put the API key in your .env file (for example ANTHROPIC_API_KEY)."],
  [/(Attacker|Remediator) LLM is not configured/i, "That helper model is not set up. Open Settings and choose a model for it, or leave it empty to reuse the judge. The API key goes in your .env file."],
  [/API keys are never stored/i, "Do not paste the key here. Put it in your .env file and enter only the variable name (for example ANTHROPIC_API_KEY)."],
  [/target with this name already exists/i, "A target with this name already exists. Choose another name, or edit the existing one on the Targets page."],
  [/Target not found/i, "This target no longer exists. Reload the page and pick another one."],
  [/Confirm that you are authorized/i, "Tick “I am authorized to test this target” to continue."],
  [/Review the scan first|expected_hash\) is required/i, "Press Review first and read the plan before you sign. RedWitness never signs a scope you have not seen."],
  [/No runnable case/i, "No test case fits this selection. Import the ready-made templates in Test Library (or widen the scope's attack classes), then try again."],
  [/Scope not found or already revoked/i, "This scope is no longer valid. Create a new scope version on the Scopes page."],
  [/Tool-abuse checks need the attestation/i, "Tick the box that says the target's tools run in a test environment, or switch tool-abuse checks off."],
  [/does not allow adaptive mode/i, "This scope does not allow adaptive rewriting. Create a new scope version that grants it, or turn adaptive mode off."],
  [/does not allow campaigns/i, "This scope does not allow campaigns. Create a new scope version that grants it."],
  [/Not an endpoint of this signed scope/i, "That address is not part of the signed scope. Pick one of the scope's endpoints, or create a new scope that includes it."],
];

export function friendlyError(status: number, reason: string | null, message: string): string {
  for (const [re, text] of RULES) if (re.test(message)) return text;
  if (status === 403) return "You do not have permission for this action. Ask an admin to change your role on the Users page.";
  if (status === 429) return "Too many requests in a short time. Wait a moment and try again.";
  if (status === 503 && /signing/i.test(message)) return "No signing key is set up, so scopes cannot be signed. Add REDWITNESS_SCOPE_KEYS to your .env file (./scripts/init-env.sh creates it) and restart.";
  if (status >= 500) return `The server hit an error (${message || `HTTP ${status}`}). Try again. If it repeats, run "docker compose logs backend" and look at the last lines.`;
  return message;
}

export const NETWORK_ERROR = "Cannot reach the RedWitness server. Check that it is running (docker compose ps), then reload the page.";
