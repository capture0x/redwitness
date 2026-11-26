"""
Evaluator decoupling ("Bias Control"). A judge that belongs to the same model family as the target tends to favour the target's own style
(self-preference bias), so its verdicts are weaker evidence. This module only CLASSIFIES the relationship between a judge/verifier and a target from their
provider / model name / address (pure text matching, no network) and suggests independent alternatives. It never changes a verdict.
"""
import re
from urllib.parse import urlsplit

# (regex on "provider model host", family); first match wins
_FAMILIES = [
    (r"claude|anthropic", "anthropic"),
    (r"gpt|chatgpt|\bo[1-9](?:-|\b)|davinci|openai", "openai"),
    (r"gemini|gemma|palm|googleapis|google", "google"),
    (r"llama|meta-llama|\bmeta\b", "meta"),
    (r"mistral|mixtral|codestral|ministral", "mistral"),
    (r"qwen|qwq|alibaba|dashscope", "alibaba"),
    (r"deepseek", "deepseek"),
    (r"grok|x\.ai", "xai"),
    (r"command-?r|cohere", "cohere"),
    (r"\bphi-?\d|microsoft", "microsoft"),
]
FAMILY_LABEL = {"anthropic": "Anthropic (Claude)", "openai": "OpenAI (GPT)", "google": "Google (Gemini/Gemma)", "meta": "Meta (Llama)", "mistral": "Mistral",
                "alibaba": "Alibaba (Qwen)", "deepseek": "DeepSeek", "xai": "xAI (Grok)", "cohere": "Cohere", "microsoft": "Microsoft (Phi)", "unknown": "Unknown"}
POLICIES = ("warn", "block", "off")

# Suggested independent judges. Model names are defaults, not a promise: edit them to what your account offers.
PRESETS = {
    "anthropic": {"judge_provider": "anthropic", "judge_model": "claude-sonnet-5-5", "judge_url": "", "judge_api_key_env": "ANTHROPIC_API_KEY"},
    "openai": {"judge_provider": "openai_compat", "judge_model": "gpt-4o", "judge_url": "https://api.openai.com/v1/chat/completions", "judge_api_key_env": "OPENAI_API_KEY"},
    "google": {"judge_provider": "openai_compat", "judge_model": "gemini-2.5-pro",
               "judge_url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "judge_api_key_env": "GEMINI_API_KEY"},
}


def family(provider: str = "", model: str = "", url: str = "") -> str:
    host = (urlsplit(url).hostname or "") if url else ""
    # "openai_compat" names a wire protocol (Ollama, vLLM, LM Studio ... speak it too), not a vendor: only the model name and the host count.
    prov = "anthropic" if provider == "anthropic" else ""
    for text in (str(model or "").lower(), f"{prov} {host}".lower()):                 # the model name is the strongest signal, then provider/host
        for pat, fam in _FAMILIES:
            if re.search(pat, text):
                return fam
    return "unknown"


def _norm_model(m: str) -> str:
    return re.sub(r"[-_:@ ]?\d{4}-?\d{2}-?\d{2}$", "", str(m or "").strip().lower())


def assess(judge: dict, target: dict, role: str = "judge") -> dict:
    """judge / target: {provider, model, url}. level: independent | same_family | same_model | unknown."""
    jf = family(judge.get("provider", ""), judge.get("model", ""), judge.get("url", ""))
    tf = family(target.get("provider", ""), target.get("model", ""), target.get("url", ""))
    same_model = bool(judge.get("model")) and _norm_model(judge.get("model")) == _norm_model(target.get("model"))
    if same_model:
        level, msg = "same_model", f"The {role} and the target are the same model ({judge.get('model')}): the model would grade its own output."
    elif jf != "unknown" and jf == tf:
        level, msg = "same_family", f"The {role} ({FAMILY_LABEL[jf]}) is in the same model family as the target: self-preference bias can hide real violations or inflate findings."
    elif jf == "unknown" or tf == "unknown":
        level, msg = "unknown", f"The model family of the {role} or the target could not be determined, so independence is not confirmed."
    else:
        level, msg = "independent", f"The {role} ({FAMILY_LABEL[jf]}) and the target ({FAMILY_LABEL[tf]}) are from different families."
    return {"role": role, "level": level, "judge_family": jf, "target_family": tf, "same_family": level in ("same_model", "same_family"),
            "independent": level == "independent", "message": msg}


def suggestions(target_family: str, available_env: dict[str, bool]) -> list[dict]:
    """Presets from OTHER families than the target, with whether the usual key variable is present in the server environment."""
    out = []
    for fam, p in PRESETS.items():
        if fam == target_family:
            continue
        out.append({"family": fam, "label": FAMILY_LABEL[fam], "settings": p, "key_present": bool(available_env.get(p["judge_api_key_env"]))})
    return sorted(out, key=lambda s: not s["key_present"])


def gate(policy: str, assessments: list[dict]) -> str | None:
    """A refusal message when the policy is 'block' and any assessed role is not independent of the target; otherwise None."""
    if policy != "block":
        return None
    bad = [a for a in assessments if a["same_family"]]
    return (" ".join(a["message"] for a in bad) + " Bias control is set to “block”: choose an independent judge in Settings → Bias control, or set the policy to “warn”.") if bad else None
