#!/usr/bin/env python3
"""
Network-namespace bridge (sandbox only). The ONE hole between the isolated namespace and the LOCAL Ollama on the host:
  outside :  relay.py outside --sock S --target 127.0.0.1:11434   (unix socket -> loopback Ollama)
  inside  :  relay.py inside  --sock S --port 11434               (namespace loopback -> unix socket)
Unix sockets cross network namespaces; so the isolated namespace cannot reach the outside network but can reach Ollama through this socket only.
"""
import argparse
import asyncio


async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            w.close()
        except Exception:  # noqa: BLE001
            pass


async def main(a):
    async def handle(cr, cw):
        try:
            if a.mode == "outside":
                host, _, port = a.target.partition(":")
                ur, uw = await asyncio.open_connection(host, int(port))
            else:
                ur, uw = await asyncio.open_unix_connection(a.sock)
        except OSError:
            cw.close()
            return
        await asyncio.gather(pipe(cr, uw), pipe(ur, cw))

    if a.mode == "outside":
        srv = await asyncio.start_unix_server(handle, path=a.sock)
    else:
        srv = await asyncio.start_server(handle, "127.0.0.1", a.port)
    print(f"relay {a.mode} hazir", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["outside", "inside"])
    ap.add_argument("--sock", required=True)
    ap.add_argument("--target", default="127.0.0.1:11434")
    ap.add_argument("--port", type=int, default=11434)
    asyncio.run(main(ap.parse_args()))
