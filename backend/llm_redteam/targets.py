"""
Target adapters: REST and SSE (stream), exponential backoff with jitter for 429/5xx, no retry on 401/403.
Redirects are NOT followed. Response size/time is bounded. The returned text is ALWAYS `Untrusted`.
The API key is only kept in memory; it is never written to error messages/logs.
"""
import asyncio
import json
import random
from dataclasses import dataclass, field

import httpcore
import httpx

from .evaluator import Untrusted, clean_untrusted
from .netcheck import PinError, default_resolver, pin_address
from .scope import Endpoint

ANTHROPIC_VERSION = "2023-06-01"


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Right before the TCP connection is opened, resolves the address, checks it and PINS it to the IP. In TLS, SNI and certificate
    verification are still done against the HOSTNAME (httpcore carries the host name separately); only the connected address is fixed."""

    def __init__(self, local: bool, resolver=default_resolver, on_pin=None):
        self._inner = httpcore.AnyIOBackend()
        self.local, self.resolver, self.on_pin = local, resolver, on_pin

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ip = pin_address(host, port, self.local, self.resolver)        # PinError: the connection is never opened
        if self.on_pin:
            self.on_pin(host, ip)
        return await self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                             socket_options=socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise PinError(__import__("llm_redteam.reasons", fromlist=["Reason"]).Reason.ENDPOINT_MALFORMED, {"why": "unix socket is forbidden"})

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


def pinned_client(local: bool, resolver=default_resolver, on_pin=None) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport()
    transport._pool = httpcore.AsyncConnectionPool(                    # replace httpx's pool with the pinned backend
        ssl_context=httpx.create_ssl_context(), max_connections=10, max_keepalive_connections=5,
        keepalive_expiry=30.0, http1=True, http2=False, network_backend=PinnedBackend(local, resolver, on_pin))
    return httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False)


class TargetError(Exception):
    """kind: auth | rate_limited | server | network | timeout | client | too_large | protocol | blocked"""

    def __init__(self, kind: str, message: str = "", status: int | None = None):
        super().__init__(f"{kind}: {message}")
        self.kind, self.message, self.status = kind, message, status


@dataclass(frozen=True)
class Credential:
    """How to authenticate to a target when it is not a plain API key: a browser cookie string or a custom header. The value is a secret: it is held in memory only
    and never appears in a repr, a log, the database or a response."""
    kind: str                  # cookie | header
    value: str
    header: str = "Authorization"

    def __repr__(self) -> str:
        return f"Credential({self.kind}, ***)"

    def headers(self) -> dict:
        return {"cookie": self.value} if self.kind == "cookie" else {self.header.lower(): self.value}


@dataclass
class Reply:
    text: Untrusted
    tool_calls: list = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    finish_reason: str = ""
    estimated: bool = False
    retries: int = 0
    mean_logprob: float | None = None      # average token log-probability, only when the adapter asked for logprobs and the target returned them


class TargetAdapter:
    def __init__(self, endpoint: Endpoint, api_key: str | None, *, stream: bool = False,
                 http: httpx.AsyncClient | None = None, timeout: float = 60.0, max_retries: int = 3,
                 backoff_base: float = 1.0, backoff_cap: float = 30.0, sleep=asyncio.sleep, on_wait=None,
                 max_bytes: int = 1_000_000, max_stream_seconds: float = 120.0, rng: random.Random | None = None,
                 pin_resolver=default_resolver, on_pin=None, logprobs: bool = False):
        self._cred = api_key if isinstance(api_key, Credential) else None
        self.ep, self._key, self.stream = endpoint, (None if self._cred else api_key), stream
        self.logprobs = logprobs and endpoint.provider == "openai_compat" and not stream
        # The default client pins to the IP (DNS-rebinding protection). If `http` is passed in from outside (tests) there is no pinning.
        self._http = http or pinned_client(endpoint.local, pin_resolver, on_pin)
        self._own_http = http is None
        self.timeout, self.max_retries = timeout, max_retries
        self.backoff_base, self.backoff_cap = backoff_base, backoff_cap
        self._sleep, self._on_wait = sleep, on_wait
        self.max_bytes, self.max_stream_seconds = max_bytes, max_stream_seconds
        self._rng = rng or random.Random()

    def __repr__(self):
        return f"TargetAdapter({self.ep.provider}, {self.ep.url}, key={'set' if (self._key or self._cred) else 'none'})"

    async def aclose(self):
        if self._own_http:
            await self._http.aclose()

    # ------------------------------------------------------------ building requests
    def _headers(self) -> dict:
        h = {"content-type": "application/json", "accept": "text/event-stream" if self.stream else "application/json"}
        if self.ep.provider == "anthropic":
            h["anthropic-version"] = ANTHROPIC_VERSION
        if self._cred:                                          # cookie / custom header
            h.update(self._cred.headers())
        elif self.ep.provider == "anthropic":
            if self._key:
                h["x-api-key"] = self._key
        elif self._key:
            h["authorization"] = f"Bearer {self._key}"
        return h

    def _body(self, messages: list[dict], max_tokens: int, tools: list[dict] | None = None) -> dict:
        b = {"model": self.ep.model, "max_tokens": max_tokens, "messages": messages}
        if tools:
            b["tools"] = tools
        if self.logprobs:
            b["logprobs"] = True
        if self.stream:
            b["stream"] = True
            if self.ep.provider == "openai_compat":
                b["stream_options"] = {"include_usage": True}
        return b

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), 60.0)
        return min(self.backoff_cap, self.backoff_base * (2 ** attempt)) * (0.5 + self._rng.random() / 2)

    # ------------------------------------------------------------ sending
    async def send(self, messages: list[dict], max_tokens: int, tools: list[dict] | None = None) -> Reply:
        reply = await self._retry(lambda: self._once(messages, max_tokens, tools))
        return reply

    async def ingest(self, name: str, content: str, *, data: bytes | None = None, content_type: str | None = None) -> None:
        """Sends a document to the target's document/knowledge-base upload endpoint (indirect tests). 2xx is expected.
        Plain-text documents go as {"name","content"}; other text formats add "content_type"; binary files (pdf/docx) go base64-encoded as
        {"name","content_type","content_base64"}."""
        if not self.ep.ingest_url:
            raise TargetError("client", "no ingest_url")
        await self._retry(lambda: self._once_ingest(name, content, data, content_type))

    async def delete_ingested(self, name: str) -> None:
        """Deletes the uploaded document from the target (cleanup). 2xx and 404 (already gone) count as success."""
        from urllib.parse import quote
        url = self.ep.ingest_delete_url
        if not url:
            raise TargetError("client", "no ingest_delete_url")
        body = None
        if "{name}" in url:
            url = url.replace("{name}", quote(name, safe=""))
        else:
            body = {"name": name}

        async def handle(resp):
            if resp.status_code == 404:
                return
            self._check_status(resp)
            await self._read_capped(resp)
        await self._retry(lambda: self._post(url, body, handle, method="DELETE"))

    async def _retry(self, op):
        last: TargetError | None = None
        for attempt in range(self.max_retries + 1):
            try:
                out = await op()
                if isinstance(out, Reply):
                    out.retries = attempt
                return out
            except TargetError as e:
                last = e
                if e.kind in ("auth", "client", "too_large", "protocol", "blocked") or attempt == self.max_retries:
                    raise
                retry_after = getattr(e, "retry_after", None)
            delay = self._delay(attempt, retry_after)
            if self._on_wait:
                self._on_wait(delay, last)
            await self._sleep(delay)
        raise last  # pragma: no cover

    async def _post(self, url: str, body: dict | None, handler, method: str = "POST"):
        try:
            req = self._http.build_request(method, url, headers=self._headers(), json=body, timeout=self.timeout)
            resp = await self._http.send(req, stream=True)
        except PinError as e:
            raise TargetError("blocked", e.reason.value) from None
        except httpx.TimeoutException:
            raise TargetError("timeout", "the request timed out") from None
        except httpx.HTTPError as e:
            raise TargetError("network", type(e).__name__) from None
        try:
            return await handler(resp)
        finally:
            await resp.aclose()

    async def _once(self, messages, max_tokens, tools=None) -> Reply:
        return await self._post(self.ep.url, self._body(messages, max_tokens, tools), self._handle)

    async def _once_ingest(self, name, content, data=None, content_type=None) -> None:
        async def handle(resp):
            self._check_status(resp)
            await self._read_capped(resp)
        if data is not None:
            import base64
            payload = {"name": name, "content_type": content_type, "content_base64": base64.b64encode(data).decode()}
        else:
            payload = {"name": name, "content": content} | ({"content_type": content_type} if content_type else {})
        await self._post(self.ep.ingest_url, payload, handle)

    def _check_status(self, resp: httpx.Response) -> None:
        st = resp.status_code
        if st in (401, 403):
            raise TargetError("auth", f"HTTP {st}", st)
        if 300 <= st < 400:
            raise TargetError("client", "redirects are not followed", st)
        if st == 429 or st >= 500:
            err = TargetError("rate_limited" if st == 429 else "server", f"HTTP {st}", st)
            ra = resp.headers.get("retry-after")
            try:
                err.retry_after = float(ra) if ra else None
            except ValueError:
                err.retry_after = None
            raise err
        if st >= 400:
            raise TargetError("client", f"HTTP {st}", st)

    async def _handle(self, resp: httpx.Response) -> Reply:
        self._check_status(resp)
        try:
            if self.stream and "text/event-stream" in resp.headers.get("content-type", ""):
                return await self._read_stream(resp)
            raw = await self._read_capped(resp)
            return self._parse_json(json.loads(raw))
        except TargetError:
            raise
        except httpx.TimeoutException:
            raise TargetError("timeout", "timed out while reading the response") from None
        except httpx.HTTPError as e:
            raise TargetError("network", type(e).__name__) from None
        except (ValueError, KeyError, IndexError, TypeError) as e:
            raise TargetError("protocol", f"unexpected response format: {type(e).__name__}") from None

    async def _read_capped(self, resp) -> bytes:
        buf = bytearray()
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) > self.max_bytes:
                raise TargetError("too_large", f"the response exceeded {self.max_bytes} bytes")
        return bytes(buf)

    # ------------------------------------------------------------ REST parsing
    def _parse_json(self, d: dict) -> Reply:
        if self.ep.provider == "anthropic":
            text = "".join(b.get("text", "") for b in d["content"] if b.get("type") == "text")
            calls = [{"id": b.get("id"), "name": b.get("name"), "arguments": b.get("input")} for b in d["content"] if b.get("type") == "tool_use"]
            u = d.get("usage") or {}
            return self._reply(text, calls, u.get("input_tokens"), u.get("output_tokens"), d.get("stop_reason", ""))
        ch = d["choices"][0]
        msg = ch["message"]
        calls = [{"id": c.get("id"), "name": (c.get("function") or {}).get("name"), "arguments": (c.get("function") or {}).get("arguments")}
                 for c in (msg.get("tool_calls") or [])]
        u = d.get("usage") or {}
        r = self._reply(msg.get("content") or "", calls, u.get("prompt_tokens"), u.get("completion_tokens"), ch.get("finish_reason") or "")
        lp = [t.get("logprob") for t in ((ch.get("logprobs") or {}).get("content") or []) if isinstance(t, dict) and isinstance(t.get("logprob"), (int, float))]
        if lp:
            r.mean_logprob = sum(lp) / len(lp)
        return r

    def _reply(self, text, calls, tin, tout, finish, truncated=False) -> Reply:
        estimated = tin is None or tout is None
        clean = clean_untrusted(text)
        return Reply(text=clean, tool_calls=calls, tokens_in=tin or 0,
                     tokens_out=tout if tout is not None else len(clean) // 4 + 1,
                     finish_reason="truncated" if truncated else finish, estimated=estimated)

    # ------------------------------------------------------------ SSE
    async def _read_stream(self, resp) -> Reply:
        loop = asyncio.get_running_loop()
        started, total = loop.time(), 0
        parts: list[str] = []
        calls: dict[int, dict] = {}
        tin = tout = None
        finish, truncated = "", False
        async for line in resp.aiter_lines():
            total += len(line) + 1
            if total > self.max_bytes or loop.time() - started > self.max_stream_seconds:
                truncated = True
                break
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                ev = json.loads(payload)
            except ValueError:
                continue
            if self.ep.provider == "anthropic":
                t = ev.get("type")
                if t == "message_start":
                    tin = (ev.get("message", {}).get("usage") or {}).get("input_tokens", tin)
                elif t == "content_block_start" and ev.get("content_block", {}).get("type") == "tool_use":
                    calls[ev["index"]] = {"name": ev["content_block"].get("name"), "arguments": ""}
                elif t == "content_block_delta":
                    dl = ev.get("delta", {})
                    if dl.get("type") == "text_delta":
                        parts.append(dl.get("text", ""))
                    elif dl.get("type") == "input_json_delta" and ev.get("index") in calls:
                        calls[ev["index"]]["arguments"] += dl.get("partial_json", "")
                elif t == "message_delta":
                    tout = (ev.get("usage") or {}).get("output_tokens", tout)
                    finish = (ev.get("delta") or {}).get("stop_reason", finish) or finish
                elif t == "error":
                    raise TargetError("server", "error event inside the stream")
            else:
                if ev.get("usage"):
                    tin, tout = ev["usage"].get("prompt_tokens", tin), ev["usage"].get("completion_tokens", tout)
                for ch in ev.get("choices") or []:
                    dl = ch.get("delta") or {}
                    if dl.get("content"):
                        parts.append(dl["content"])
                    for tc in dl.get("tool_calls") or []:
                        c = calls.setdefault(tc.get("index", 0), {"name": None, "arguments": ""})
                        f = tc.get("function") or {}
                        c["name"] = f.get("name") or c["name"]
                        c["arguments"] += f.get("arguments") or ""
                    finish = ch.get("finish_reason") or finish
        return self._reply("".join(parts), [calls[k] for k in sorted(calls)], tin, tout, finish, truncated)
