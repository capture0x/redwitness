"""
Custom HTTP (JSON) targets: chat APIs that do not speak the OpenAI or Anthropic format, for example a web chatbot's backend that takes
{"question": "..."} and answers {"data": {"reply": "..."}}.

The operator writes the request body as a JSON template and names where the reply text sits (a dotted path). Both are part of the SIGNED
scope, so a request is only ever built from a template someone approved.

Placeholders (only inside JSON string values, so substitution can never change the JSON structure):
  {{prompt}}      the last user message (may be embedded in a longer string)
  {{messages}}    the whole conversation as [{"role", "content"}] (must be the entire string value)
  {{session_id}}  a stable random id per conversation, for APIs that keep the session on the server (may be embedded)
"""
import json
import re

MAX_TEMPLATE = 8000
MAX_PATH = 200
PLACEHOLDERS = ("{{prompt}}", "{{messages}}", "{{session_id}}")
_ANY = re.compile(r"\{\{\s*([A-Za-z_]+)\s*\}\}")
_SEGMENT = re.compile(r"[A-Za-z0-9_\-$@]{1,64}")
_ONE_PASS = re.compile(r"\{\{prompt\}\}|\{\{session_id\}\}")


class TemplateError(ValueError):
    """The template or the response path is invalid; the message is shown to the operator."""


def parse_template(text: str | None) -> dict:
    """Validates a request template and returns it as a JSON object."""
    t = (text or "").strip()
    if not t:
        raise TemplateError("the request template is required for a custom HTTP target")
    if len(t) > MAX_TEMPLATE:
        raise TemplateError(f"the request template must be at most {MAX_TEMPLATE} characters")
    try:
        obj = json.loads(t)
    except ValueError as e:
        raise TemplateError(f"the request template is not valid JSON ({e.msg}, line {e.lineno})") from None
    if not isinstance(obj, dict):
        raise TemplateError("the request template must be a JSON object, for example {\"message\": \"{{prompt}}\"}")
    seen: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if _ANY.search(k):
                    raise TemplateError("placeholders are only allowed in values, not in key names")
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            for m in _ANY.finditer(v):
                name = "{{" + m.group(1) + "}}"
                if m.group(0) != name or name not in PLACEHOLDERS:
                    raise TemplateError(f"unknown placeholder {m.group(0)}: use {{{{prompt}}}}, {{{{messages}}}} or {{{{session_id}}}}")
                if name == "{{messages}}" and v != "{{messages}}":
                    raise TemplateError("{{messages}} must be the whole value, for example \"history\": \"{{messages}}\"")
                seen.add(name)
            if "{{" in _ANY.sub("", v) or "}}" in _ANY.sub("", v):
                raise TemplateError("a placeholder is not closed: write {{prompt}}, {{messages}} or {{session_id}} exactly")
    walk(obj)
    if not seen & {"{{prompt}}", "{{messages}}"}:
        raise TemplateError("the request template must contain {{prompt}} or {{messages}}, otherwise no test message would be sent")
    return obj


def parse_path(path: str | None) -> list[str]:
    """Validates a dotted response path such as 'answer', 'data.reply' or 'choices.0.message.content'."""
    p = (path or "").strip()
    if not p:
        raise TemplateError("the response path is required for a custom HTTP target, for example 'answer' or 'data.reply'")
    if len(p) > MAX_PATH:
        raise TemplateError(f"the response path must be at most {MAX_PATH} characters")
    parts = p.split(".")
    if not all(_SEGMENT.fullmatch(s) for s in parts):
        raise TemplateError("the response path: names and list indexes separated by dots, for example 'data.messages.0.text'")
    return parts


def render(template: str, messages: list[dict], session_id: str) -> dict:
    """The request body for one turn. Values are substituted inside the parsed object, so JSON escaping is never done by hand."""
    obj = parse_template(template)
    prompt = next((m.get("content") for m in reversed(messages) if m.get("role") == "user"), "")
    prompt = prompt if isinstance(prompt, str) else json.dumps(prompt, ensure_ascii=False)
    history = [{"role": m.get("role"), "content": m.get("content") if isinstance(m.get("content"), str) else json.dumps(m.get("content"), ensure_ascii=False)}
               for m in messages if m.get("role") in ("user", "assistant", "system")]

    def sub(v):
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        if isinstance(v, list):
            return [sub(x) for x in v]
        if isinstance(v, str):
            if v == "{{messages}}":
                return history
            # one pass, so text inside the prompt (for example a literal "{{session_id}}") is never expanded
            return _ONE_PASS.sub(lambda m: prompt if m.group(0) == "{{prompt}}" else session_id, v) if "{{" in v else v
        return v
    return sub(obj)


def extract(data, path: str):
    """The reply text at the dotted path. Raises KeyError/IndexError/TypeError (a protocol error) when the path does not exist."""
    cur = data
    for seg in parse_path(path):
        if isinstance(cur, list):
            if not seg.isdigit():
                raise TypeError(f"'{seg}' is not a list index")
            cur = cur[int(seg)]
        elif isinstance(cur, dict):
            cur = cur[seg]
        else:
            raise TypeError(f"cannot read '{seg}' from a {type(cur).__name__}")
    if cur is None:
        return ""
    return cur if isinstance(cur, str) else json.dumps(cur, ensure_ascii=False)
