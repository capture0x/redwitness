"""Judge LLM implementations (provider independent). The judge has no tools; it only produces text."""
import os

import httpx


class AnthropicJudge:
    def __init__(self, model: str, api_key: str):
        import anthropic
        self.model = model
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def complete(self, system: str, user: str, max_tokens: int) -> tuple[str, int]:
        r = await self._client.messages.create(model=self.model, max_tokens=max_tokens, system=system,
                                               messages=[{"role": "user", "content": user}])   # no temperature: anthropic SDK 2.x rejects it
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        return text, (r.usage.input_tokens or 0) + (r.usage.output_tokens or 0)


class OpenAICompatJudge:
    def __init__(self, url: str, model: str, api_key: str | None):
        self.url, self.model, self._key = url, model, api_key

    async def complete(self, system: str, user: str, max_tokens: int) -> tuple[str, int]:
        headers = {"content-type": "application/json"} | ({"authorization": f"Bearer {self._key}"} if self._key else {})
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        async with httpx.AsyncClient(follow_redirects=False, timeout=60) as c:
            r = await c.post(self.url, headers=headers, json=body)
        r.raise_for_status()
        d = r.json()
        u = d.get("usage") or {}
        return d["choices"][0]["message"]["content"] or "", (u.get("prompt_tokens") or 0) + (u.get("completion_tokens") or 0)


def build_judge(settings: dict, env=os.environ):
    """Builds the judge from settings; None when configuration is missing (the run cannot start, a message is shown)."""
    provider = settings.get("judge_provider", "anthropic")
    model = settings.get("judge_model", "claude-sonnet-5-5")
    key = env.get(settings.get("judge_api_key_env") or ("ANTHROPIC_API_KEY" if provider == "anthropic" else ""), "")
    if provider == "anthropic":
        return AnthropicJudge(model, key) if key else None
    if provider == "openai_compat" and settings.get("judge_url"):
        return OpenAICompatJudge(settings["judge_url"], model, key or None)
    return None


def build_role_llm(settings: dict, prefix: str, env=os.environ):
    """LLM for a helper role (`attacker`, `remediator`): uses the `<prefix>_*` settings when a provider is set there, otherwise the judge's
    configuration. (A model other than the judge is recommended.) Returns (llm | None, model name)."""
    if not settings.get(f"{prefix}_provider"):
        return build_judge(settings, env), settings.get("judge_model", "")
    s = {"judge_provider": settings[f"{prefix}_provider"], "judge_model": settings.get(f"{prefix}_model") or settings.get("judge_model", ""),
         "judge_api_key_env": settings.get(f"{prefix}_api_key_env", ""), "judge_url": settings.get(f"{prefix}_url", "")}
    return build_judge(s, env), s["judge_model"]


def build_attacker_llm(settings: dict, env=os.environ):
    return build_role_llm(settings, "attacker", env)


def build_remediator_llm(settings: dict, env=os.environ):
    return build_role_llm(settings, "remediator", env)
