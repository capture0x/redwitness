export const PRESETS: Record<string, { label: string; provider: string; base_url: string; model: string; name: string }> = {
  openai: { label: "OpenAI", provider: "openai_compat", base_url: "https://api.openai.com/v1", model: "gpt-4o", name: "OpenAI" },
  anthropic: { label: "Anthropic", provider: "anthropic", base_url: "https://api.anthropic.com", model: "claude-sonnet-5-5", name: "Anthropic" },
  ollama: { label: "Ollama (local)", provider: "openai_compat", base_url: "http://localhost:11434/v1", model: "llama3.2", name: "Ollama" },
  custom: { label: "Custom (OpenAI-compatible)", provider: "openai_compat", base_url: "", model: "", name: "" },
};

/** The full request address from the base address (mirrors the server: <base>/chat/completions, or <base>/v1/messages for Anthropic). */
export const requestUrl = (provider: string, base: string) => {
  const b = base.trim().replace(/\/+$/, "");
  if (!b) return "";
  if (provider === "anthropic") return b.endsWith("/messages") ? b : b + (b.endsWith("/v1") ? "/messages" : "/v1/messages");
  return b.endsWith("/chat/completions") ? b : b + "/chat/completions";
};

export const looksLocal = (u: string) => {
  try { const h = new URL(u).hostname; return h === "localhost" || h.endsWith(".local") || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || h === "::1" || h === "[::1]"; } catch { return false; }
};

export const AUTH_LABEL: Record<string, string> = { bearer: "API key / Bearer token", cookie: "Cookie / session", header: "Custom header" };
