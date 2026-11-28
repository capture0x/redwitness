"""
WebSocket chat targets (ws_json): many web chat widgets talk over a WebSocket instead of HTTP POST.

Each test conversation gets its own connection, so servers that keep the chat state per connection see a real multi-turn conversation.
The request is the same signed JSON template as a custom HTTP target; the reply is read from every incoming JSON message at the response path
and joined (streamed tokens). The reply ends when the done path is true in a message, or, without a done path, after a short pause.

The connection goes through the same address check and IP pinning as HTTP targets: the socket is opened to the pinned IP first and only then handed to
the WebSocket library (TLS still verifies the host name). No redirects, no proxies from the environment, bounded frame size and reply time.
"""
import asyncio
import json
import socket
import ssl
from urllib.parse import urlsplit

from . import customhttp
from .netcheck import PinError, default_resolver, pin_address

MAX_FRAME = 1_000_000
IDLE_END = 1.5            # seconds of silence that end a reply when no done path is configured
MAX_OPEN = 4              # connections kept open at once (older conversations are closed)


class WsError(Exception):
    """kind matches TargetError kinds: auth | network | timeout | protocol | blocked | too_large"""

    def __init__(self, kind: str, message: str = ""):
        super().__init__(f"{kind}: {message}")
        self.kind, self.message = kind, message


async def _pinned_socket(url: str, local: bool, resolver, timeout: float) -> tuple[socket.socket, str]:
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "wss" else 80)
    try:
        ip = pin_address(u.hostname, port, local, resolver)
    except PinError as e:
        raise WsError("blocked", e.reason.value) from None
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(s, (ip, port)), timeout)
    except (OSError, asyncio.TimeoutError) as e:
        s.close()
        raise WsError("timeout" if isinstance(e, asyncio.TimeoutError) else "network", type(e).__name__) from None
    return s, u.hostname


class WsConversations:
    def __init__(self, url: str, local: bool, *, resolver=default_resolver, timeout: float = 60.0):
        self.url, self.local, self.resolver, self.timeout = url, local, resolver, timeout
        self._conns: dict[str, object] = {}

    async def _connect(self, headers: dict):
        from websockets.asyncio.client import connect
        from websockets.exceptions import InvalidStatus
        sock, host = await _pinned_socket(self.url, self.local, self.resolver, self.timeout)
        tls = ssl.create_default_context() if self.url.startswith("wss://") else None
        try:
            return await connect(self.url, sock=sock, ssl=tls, server_hostname=host if tls else None, additional_headers=headers,
                                 max_size=MAX_FRAME, open_timeout=self.timeout, proxy=None, compression=None)
        except InvalidStatus as e:
            sock.close()
            st = e.response.status_code
            raise WsError("auth" if st in (401, 403) else "protocol", f"HTTP {st} on the WebSocket handshake") from None
        except (OSError, asyncio.TimeoutError, Exception) as e:  # noqa: BLE001 - every handshake failure is a network error for the run
            sock.close()
            raise WsError("network", type(e).__name__) from None

    async def exchange(self, session: str, body: dict, headers: dict, response_path: str, done_path: str | None) -> str:
        ws = self._conns.get(session)
        if ws is None:
            while len(self._conns) >= MAX_OPEN:                         # conversations run one after another: close the oldest
                old = self._conns.pop(next(iter(self._conns)))
                await old.close()
            ws = self._conns[session] = await self._connect(headers)
        try:
            await ws.send(json.dumps(body, ensure_ascii=False))
            return await self._read_reply(ws, response_path, done_path)
        except WsError:
            self._conns.pop(session, None)
            await ws.close()
            raise
        except Exception as e:  # noqa: BLE001 - a dropped connection ends this conversation
            self._conns.pop(session, None)
            raise WsError("network", type(e).__name__) from None

    async def _read_reply(self, ws, response_path: str, done_path: str | None) -> str:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        parts: list[str] = []
        total = 0
        while True:
            left = deadline - loop.time()
            if left <= 0:
                if parts and not done_path:
                    break
                raise WsError("timeout", "no complete reply on the WebSocket in time")
            wait = min(left, IDLE_END) if parts and not done_path else left
            try:
                raw = await asyncio.wait_for(ws.recv(), wait)
            except asyncio.TimeoutError:
                if parts and not done_path:
                    break                                               # a pause after text: the reply is complete
                continue
            total += len(raw)
            if total > MAX_FRAME:
                raise WsError("too_large", "the reply exceeded the size limit")
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue                                                # pings, plain-text keep-alives: not part of the reply
            try:
                piece = customhttp.extract(msg, response_path)
                if piece:
                    parts.append(piece)
            except (KeyError, IndexError, TypeError):
                pass                                                    # status / typing messages without reply text
            if done_path:
                try:
                    if customhttp.extract(msg, done_path) not in ("", "false", "0", "null"):
                        break
                except (KeyError, IndexError, TypeError):
                    pass
        return "".join(parts)

    async def aclose(self):
        for ws in list(self._conns.values()):
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        self._conns.clear()
