#!/usr/bin/env python3
"""
Local FAKE WebSocket chat server (for the ws_json target tests). Needs the `websockets` package (backend venv); binds to loopback only.

  ws://127.0.0.1:<port>/chat         {"message", "session_id"} in -> streamed {"type": "token", "text": "..."} ... {"type": "end", "done": true}
  ws://127.0.0.1:<port>/chat-nodone  the same reply as tokens, but no end marker (the client must end on a pause)
  ws://127.0.0.1:<port>/secure/chat  like /chat, but the handshake needs the cookie "sid=ws-test-session" (otherwise HTTP 401)

The conversation is kept PER CONNECTION (like many web chat widgets), and the replies come from the same AcmeBot logic as sandbox/mock_llm.py,
so a multi-turn attack only works when the client keeps one connection per conversation.
"""
import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mock_llm  # noqa: E402  (AcmeBot reply logic; starts nothing on import)

from websockets.asyncio.server import serve  # noqa: E402
from websockets.http11 import Response  # noqa: E402
from websockets.datastructures import Headers  # noqa: E402

STATS = {"connections": 0, "messages": 0}


def gate(connection, request):
    if request.path not in ("/chat", "/chat-nodone", "/secure/chat"):
        return Response(404, "Not Found", Headers(), b"not found")
    if request.path == "/secure/chat" and "sid=ws-test-session" not in (request.headers.get("cookie") or ""):
        return Response(401, "Unauthorized", Headers(), b"unauthorized")
    return None


async def chat(ws):
    STATS["connections"] += 1
    history: list[dict] = []
    path = ws.request.path
    async for raw in ws:
        try:
            msg = json.loads(raw)
            text = msg["message"]
            assert isinstance(text, str)
        except (ValueError, KeyError, AssertionError):
            await ws.send(json.dumps({"type": "error", "error": "send {\"message\": ...}"}))
            continue
        STATS["messages"] += 1
        history.append({"role": "user", "content": text})
        reply, _ = mock_llm.respond(list(history), [])
        history.append({"role": "assistant", "content": reply})
        await ws.send(json.dumps({"type": "typing"}))                     # a status message without reply text
        words = reply.split(" ")
        for i, w in enumerate(words):
            await ws.send(json.dumps({"type": "token", "text": w + (" " if i < len(words) - 1 else "")}))
            await asyncio.sleep(0.005)
        if path != "/chat-nodone":
            await ws.send(json.dumps({"type": "end", "done": True}))


async def main(port: int):
    async with serve(chat, "127.0.0.1", port, process_request=gate):
        print(f"mock-ws 127.0.0.1:{port}", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9500)
    asyncio.run(main(ap.parse_args().port))
