"""
CI/CD access: API tokens for the `ci` role and the rate limiter in front of /api/scan-ci.

A CI token is NOT a user and cannot sign in to the UI. It can only start scans and read the results of the jobs it started (default deny
for everything else), only against the scope lineages it was issued for, and only until it expires or an admin revokes it.
Only a SHA-256 hash of the token is stored (the token is 256 bits of randomness, so a plain hash is sufficient); the plaintext is shown once.
"""
import hashlib
import secrets
import time
from collections import defaultdict, deque

TOKEN_PREFIX = "rlci_"
MAX_TTL_DAYS = 365
DEFAULT_TTL_DAYS = 90
FAIL_ON = ("critical", "high", "medium", "low")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

START_PER_MINUTE = 6          # POST /api/scan-ci per token
READ_PER_MINUTE = 120         # GET  /api/scan-ci/{id} per token
MAX_RUNNING_PER_TOKEN = 2     # concurrently running scans per token
BAD_AUTH_PER_MINUTE = 20      # failed token checks per client address


def new_token() -> tuple[str, str, str]:
    """(plaintext, sha256 hex, display prefix)"""
    t = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return t, hash_token(t), t[: len(TOKEN_PREFIX) + 6]


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def bearer(header: str | None) -> str | None:
    if not header or not header.lower().startswith("bearer "):
        return None
    t = header[7:].strip()
    return t if t.startswith(TOKEN_PREFIX) and len(t) < 200 else None


class RateLimiter:
    """Sliding window, in memory (per process). `hit` returns the seconds to wait, or 0 when the call is allowed."""

    def __init__(self, clock=time.monotonic):
        self._clock, self._hits = clock, defaultdict(deque)

    def hit(self, key: str, limit: int, window: float = 60.0) -> int:
        now, q = self._clock(), self._hits[key]
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return max(1, int(window - (now - q[0])) + 1)
        q.append(now)
        return 0
