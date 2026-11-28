"""Saved target connections (the Targets page). Only connection details are stored: the API key is NOT stored anywhere in the database."""
import ipaddress
import re
from urllib.parse import urlsplit

PROVIDERS = ("openai_compat", "anthropic", "http_json", "ws_json")
AUTH_TYPES = ("bearer", "cookie", "header", "oauth", "none")
OAUTH_GRANTS = ("client_credentials", "refresh_token")
MAX_EXTRA_HEADERS = 10
FORBIDDEN_HEADERS = {"host", "content-length", "content-type", "accept", "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive", "expect",
                     "proxy-connection", "proxy-authorization", "anthropic-version", "cookie", "set-cookie", "origin"}
MAX_CREDENTIAL = 8000


class TargetInputError(ValueError):
    pass


def request_url(provider: str, base_url: str) -> str:
    """The full request address from the base address. OpenAI-compatible servers (OpenAI, Ollama, vLLM, LM Studio ...): <base>/chat/completions.
    Anthropic: <base>/v1/messages. A full request address is accepted as it is. Custom HTTP (http_json): the address is used exactly as given."""
    b = base_url.strip().rstrip("/")
    if provider in ("http_json", "ws_json"):
        return base_url.strip()
    if provider == "anthropic":
        return b if b.endswith("/messages") else b + ("/messages" if b.endswith("/v1") else "/v1/messages")
    return b if b.endswith("/chat/completions") else b + "/chat/completions"


def _check_http(u: str, what: str, schemes=("http", "https")) -> None:
    p = urlsplit(u)
    if p.scheme not in schemes or not p.hostname:
        raise TargetInputError(f"{what} must be an {'/'.join(schemes)} address")
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
             auth_type: str = "bearer", auth_header: str | None = None, request_template: str | None = None, response_path: str | None = None,
             done_path: str | None = None, token_url: str | None = None) -> dict:
    name, model = " ".join((name or "").split()), (model or "").strip()
    if not 1 <= len(name) <= 80:
        raise TargetInputError("name: 1-80 characters")
    if provider not in PROVIDERS:
        raise TargetInputError(f"provider must be one of {PROVIDERS}")
    if provider in ("http_json", "ws_json"):
        from .customhttp import TemplateError, parse_path, parse_template
        model = model or "custom"                                   # a custom API usually has no model name; it is only a label here
        try:
            parse_template(request_template)
            parse_path(response_path)
            if done_path and done_path.strip():
                if provider != "ws_json":
                    raise TargetInputError("the done path is only for WebSocket targets")
                parse_path(done_path)
        except TemplateError as e:
            raise TargetInputError(str(e)) from None
        if ingest_url or ingest_delete_url:
            raise TargetInputError("document upload is not available for a custom HTTP target")
        request_template, response_path = request_template.strip(), response_path.strip()
        done_path = done_path.strip() if provider == "ws_json" and done_path and done_path.strip() else None
    else:
        request_template = response_path = done_path = None
    token_url = (token_url or "").strip() or None
    if auth_type == "oauth":
        if not token_url:
            raise TargetInputError("OAuth needs the token URL of the identity provider")
        _check_http(token_url, "Token URL")
    elif token_url:
        raise TargetInputError("a token URL is only used with OAuth authentication")
    if not model or len(model) > 200:
        raise TargetInputError("model name: 1-200 characters")
    base_url = (base_url or "").strip()
    _check_http(base_url, "Request URL" if provider == "ws_json" else "Base URL", ("ws", "wss") if provider == "ws_json" else ("http", "https"))
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
    if auth_type in ("oauth", "none") and provider == "anthropic":
        raise TargetInputError("the Anthropic API uses an API key; OAuth and 'none' are for other targets")
    return {"name": name, "provider": provider, "auth_type": auth_type, "auth_header": header, "base_url": base_url, "request_url": request_url(provider, base_url), "model": model,
            "api_key_env": api_key_env or None, "ingest_url": ingest_url or None, "ingest_delete_url": ingest_delete_url or None,
            "request_template": request_template, "response_path": response_path, "done_path": done_path, "token_url": token_url}


def default_name(base_url: str, model: str) -> str:
    host = urlsplit((base_url or "").strip()).hostname or "target"
    return f"{host} · {model}".strip(" ·")[:80] or "target"


def clean_extra_headers(items, primary: str | None = None) -> tuple:
    """Further headers the app needs on every request (CSRF token, tenant id ...). Names follow the same rules as a custom auth header; values are secrets
    (memory only). They may not repeat each other or the credential's own header."""
    items = items or []
    if not isinstance(items, list) or len(items) > MAX_EXTRA_HEADERS:
        raise TargetInputError(f"at most {MAX_EXTRA_HEADERS} extra headers")
    out, seen = [], {(primary or "").lower()} - {""}
    for it in items:
        name = clean_header_name((it or {}).get("name"))
        if name.lower() in seen:
            raise TargetInputError(f"header {name!r} is given twice (or is already the credential header)")
        seen.add(name.lower())
        out.append((name, clean_credential("header", (it or {}).get("value") or "")))
    return tuple(out)


def clean_oauth(grant: str | None, client_id: str | None, client_secret: str | None, refresh_token: str | None, scope: str | None):
    from .targets import OAuth
    grant = grant or "client_credentials"
    if grant not in OAUTH_GRANTS:
        raise TargetInputError(f"OAuth grant must be one of {OAUTH_GRANTS}")
    cid = (client_id or "").strip()
    if not 1 <= len(cid) <= 500 or any(ord(c) < 33 for c in cid):
        raise TargetInputError("OAuth client id: 1-500 characters without spaces")
    secret = clean_credential("header", client_secret) if client_secret else ""
    refresh = clean_credential("header", refresh_token) if refresh_token else ""
    if grant == "client_credentials" and not secret:
        raise TargetInputError("the client credentials grant needs the client secret")
    if grant == "refresh_token" and not refresh:
        raise TargetInputError("the refresh token grant needs a refresh token")
    scope = " ".join((scope or "").split())
    if len(scope) > 500:
        raise TargetInputError("OAuth scope: at most 500 characters")
    return OAuth(grant, cid, secret, refresh, scope)
