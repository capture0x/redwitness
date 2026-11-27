"""
Test infrastructure. Tests are HERMETIC: sockets may only connect to loopback; any attempt to reach outside
fails the test. The target LLM and the judge are fakes (tests/fakes.py).
"""
import asyncio
import glob
import os
import socket as S
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(autouse=True, scope="session")
def hermetic_network():
    real = {n: getattr(S.socket, n) for n in ("connect", "connect_ex", "sendto")}

    def check(addr):
        host = addr[0] if isinstance(addr, tuple) else None
        if host is not None and host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError(f"hermetic test tried to reach outside: {addr!r}")

    def connect(self, addr):
        check(addr)
        return real["connect"](self, addr)

    def connect_ex(self, addr):
        check(addr)
        return real["connect_ex"](self, addr)

    def sendto(self, data, *rest):
        check(rest[-1])
        return real["sendto"](self, data, *rest)

    S.socket.connect, S.socket.connect_ex, S.socket.sendto = connect, connect_ex, sendto
    yield
    for n, f in real.items():
        setattr(S.socket, n, f)


@pytest.fixture
def run():
    """Runs async code in a sync test (no extra plugin needed)."""
    return asyncio.run


@pytest.fixture
def target():
    from fakes import FakeTarget
    t = FakeTarget()
    yield t
    t.close()


# ---------------------------------------------------------------- PostgreSQL (real server; no sudo needed)
def _pg_bin():
    dirs = sorted(glob.glob("/usr/lib/postgresql/*/bin"), key=lambda p: int(p.split("/")[-2]))
    return dirs[-1] if dirs else None


@pytest.fixture(scope="session")
def pg_server(tmp_path_factory):
    """Admin DSN. If REDWITNESS_TEST_DSN is given that server is used; otherwise a temporary, user-owned cluster is started."""
    dsn = os.environ.get("REDWITNESS_TEST_DSN")
    if dsn:
        yield dsn
        return
    bindir = _pg_bin()
    if not bindir:
        pytest.skip("PostgreSQL not found; provide REDWITNESS_TEST_DSN")
    data = tmp_path_factory.mktemp("pg") / "data"
    with S.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    subprocess.run([f"{bindir}/initdb", "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--no-sync"],
                   check=True, capture_output=True)
    opts = f"-p {port} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off"
    subprocess.run([f"{bindir}/pg_ctl", "-D", str(data), "-o", opts, "-w", "-l", str(data.parent / "pg.log"), "start"],
                   check=True, capture_output=True)
    try:
        yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run([f"{bindir}/pg_ctl", "-D", str(data), "-m", "immediate", "stop"], capture_output=True)


@pytest.fixture
def fresh_db(pg_server):
    """DSN of an empty, temporary database; dropped at the end of the test."""
    import psycopg
    name = "rl_test_" + uuid.uuid4().hex[:12]
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    base, _, _ = pg_server.rpartition("/")
    yield f"{base}/{name}"
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
