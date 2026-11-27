"""Saved target connections (the Targets page). Only connection details are stored: the API key is NOT stored anywhere in the database."""
import ipaddress
import re
from urllib.parse import urlsplit

PROVIDERS = ("openai_compat", "anthropic", "http_json")
AUTH_TYPES = ("bearer", "cookie", "header")
FORBIDDEN_HEADERS = {"host", "content-length", "content-type", "accept", "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive", "expect",
                     "proxy-connection", "proxy-authorization", "anthropic-version", "cookie", "set-cookie", "origin"}
MAX_CREDENTIAL = 8000


class TargetInputError(ValueError):
    pass


def request_url(provider: str, base_url: str) -> str:
    """The full request address from the base address. OpenAI-compatible servers (OpenAI, Ollama, vLLM, LM Studio ...): <base>/chat/completions.
    Anthropic: <base>/v1/messages. A full request address is accepted as it is. Custom HTTP (http_json): the address is used exactly as given."""
    b = base_url.strip().rstrip("/")
    if provider == "http_json":
        return base_url.strip()
    if provider == "anthropic":
        return b if b.endswith("/messages") else b + ("/messages" if b.endswith("/v1") else "/v1/messages")
    return b if b.endswith("/chat/completions") else b + "/chat/completions"


def _check_http(u: str, what: str) -> None:
    p = urlsplit(u)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetInputError(f"{what} must be an http(s) address")
    if p.username or p.password:
        raise TargetInputError(f"{what} must not contain a user name or password (use the API key field)")
    if p.query or p.fragment:
        raise TargetInputError(f"{what} must not contain a query string or fragment")


def is_local_host(url: str) -> bool:
    h = (urlsplit(url).hostname or "").lower()
    if h in ("localhost", "host.docker.internal") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def clean_credential(kind: str, value: str) -> str:
    """The secret as it will be sent. A pasted 'Cookie: a=b' or 'Authorization: ...' prefix is dropped; anything that could split a header is refused."""
    v = (value or "").strip()
    if kind == "cookie":
        v = re.sub(r"^cookie\s*:\s*", "", v, flags=re.I)
    if not v or len(v) > MAX_CREDENTIAL:
        raise TargetInputError(f"the credential must be 1-{MAX_CREDENTIAL} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise TargetInputError("the credential contains a line break or control character")
    return v


def clean_header_name(name: str | None) -> str:
    n = (name or "Authorization").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", n) or n.lower() in FORBIDDEN_HEADERS:
        raise TargetInputError("header name: letters, digits and '-' only; headers that control the connection, the body or cookies are not allowed")
    return n


def validate(name: str, provider: str, base_url: str, model: str, api_key_env: str | None, ingest_url: str | None, ingest_delete_url: str | None,
             auth_type: str = "bearer", auth_header: str | None = None, request_template: str | None = None, response_path: str | None = None) -> dict:
    name, model = " ".join((name or "").split()), (model or "").strip()
    if not 1 <= len(name) <= 80:
        raise TargetInputError("name: 1-80 characters")
    if provider not in PROVIDERS:
        raise TargetInputError(f"provider must be one of {PROVIDERS}")
    if provider == "http_json":
        from .customhttp import TemplateError, parse_path, parse_template
        model = model or "custom"                                   # a custom API usually has no model name; it is only a label here
        try:
            parse_template(request_template)
            parse_path(response_path)
        except TemplateError as e:
            raise TargetInputError(str(e)) from None
        if ingest_url or ingest_delete_url:
            raise TargetInputError("document upload is not available for a custom HTTP target")
        request_template, response_path = request_template.strip(), response_path.strip()
    else:
        request_template = response_path = None
    if not model or len(model) > 200:
        raise TargetInputError("model name: 1-200 characters")
    base_url = (base_url or "").strip()
    _check_http(base_url, "Base URL")
    if api_key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", api_key_env):
        raise TargetInputError("the environment variable name may contain letters, digits and _ only")
    for u, w in ((ingest_url, "Document upload URL"), (ingest_delete_url, "Document delete URL")):
        if u:
            _check_http(u.replace("{name}", "x"), w)
    if ingest_delete_url and not ingest_url:
        raise TargetInputError("a delete URL needs an upload URL")
    if auth_type not in AUTH_TYPES:
        raise TargetInputError(f"auth type must be one of {AUTH_TYPES}")
    header = clean_header_name(auth_header) if auth_type == "header" else None
    return {"name": name, "provider": provider, "auth_type": auth_type, "auth_header": header, "base_url": base_url, "request_url": request_url(provider, base_url), "model": model,
            "api_key_env": api_key_env or None, "ingest_url": ingest_url or None, "ingest_delete_url": ingest_delete_url or None,
            "request_template": request_template, "response_path": response_path}


def default_name(base_url: str, model: str) -> str:
    host = urlsplit((base_url or "").strip()).hostname or "target"
    return f"{host} · {model}".strip(" ·")[:80] or "target"
