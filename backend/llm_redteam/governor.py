"""
Governor: EVERY request to the target and every judge call passes through here first; the engine cannot bypass it.
Hard limits (from the signed scope), circuit breaker, cost protection. Every decision (allow/refuse) is written to the audit log with its own code.
"""
import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from .netcheck import check_endpoint, default_resolver
from .reasons import FATAL, Reason
from .scope import LLMScope

WARN_AT, WIND_DOWN_AT = 0.80, 0.90
MIN_RESPONSE_TOKENS = 16


class Denied(Exception):
    def __init__(self, reason: Reason, detail: dict | None = None):
        super().__init__(reason.value)
        self.reason, self.detail = reason, detail or {}

    @property
    def fatal(self) -> bool:
        return self.reason in FATAL


@dataclass
class Grant:
    max_tokens: int
    reserved: int
    conversation_id: str
    turn: int


def estimate_tokens(chars: int) -> int:
    return chars // 4 + 1


class Governor:
    def __init__(self, scope: LLMScope, audit: Callable | None = None, *, clock=time.monotonic,
                 sleep=asyncio.sleep, resolver=default_resolver):
        self.scope, self.limits = scope, scope.limits
        self._audit = audit or (lambda *a, **k: None)
        self._clock, self._sleep, self._resolver = clock, sleep, resolver
        self.started = clock()
        self.tokens_used = 0
        self.requests = 0
        self.conversations: set[str] = set()
        self.turns: dict[str, int] = {}
        self._window: deque[float] = deque()
        self.killed = False
        self.consecutive_errors = 0
        self.circuit: Reason | None = None            # CIRCUIT_OPEN | AUTH_FAILURE
        self._warned = False
        self.throttle_seconds = 0.0

    # ------------------------------------------------------------ state
    @property
    def budget_fraction(self) -> float:
        return self.tokens_used / self.limits.max_total_tokens

    @property
    def winding_down(self) -> bool:
        """After 90%, no new test is started; running work and verification replays are completed."""
        return self.budget_fraction >= WIND_DOWN_AT or self.requests >= self.limits.max_requests * WIND_DOWN_AT \
            or self.elapsed >= self.limits.max_duration_seconds * WIND_DOWN_AT

    @property
    def elapsed(self) -> float:
        return self._clock() - self.started

    def snapshot(self) -> dict:
        return {"tokens_used": self.tokens_used, "requests": self.requests, "conversations": len(self.conversations),
                "elapsed_seconds": round(self.elapsed, 1), "circuit": self.circuit.value if self.circuit else None,
                "budget_fraction": round(self.budget_fraction, 3), "throttle_seconds": round(self.throttle_seconds, 1)}

    def kill(self):
        self.killed = True
        self._audit("governor.kill", reason=Reason.KILLED, detail={})

    def _deny(self, reason: Reason, **detail):
        self._audit("governor.deny", reason=reason, detail=detail)
        raise Denied(reason, detail)

    def note_denial(self, reason: Reason, **detail):
        """Records a refusal without raising (for refusals made at connect time in the network layer)."""
        self._audit("governor.deny", reason=reason, detail=detail)

    def _check_common(self):
        if self.killed:
            self._deny(Reason.KILLED)
        if self.circuit is not None:
            self._deny(self.circuit)
        if self.elapsed >= self.limits.max_duration_seconds:
            self._deny(Reason.DURATION_EXCEEDED, elapsed=round(self.elapsed, 1))

    def _warn_if_needed(self):
        if not self._warned and self.budget_fraction >= WARN_AT:
            self._warned = True
            self._audit("governor.warning", reason=Reason.BUDGET_WARNING, detail=self.snapshot())

    # ------------------------------------------------------------ target request
    async def authorize(self, endpoint_url: str, category: str, conversation_id: str, new_chars: int,
                        context_chars: int, media: bool = False, branching: bool = False) -> Grant:
        """new_chars: message length in this turn; context_chars: total input length including conversation history."""
        self._check_common()
        ep = self.scope.endpoint(endpoint_url)
        if ep is None:
            self._deny(Reason.ENDPOINT_NOT_AUTHORIZED, endpoint=endpoint_url)
        bad, det = check_endpoint(ep.url, ep.local, self._resolver)
        if bad:
            self._deny(bad, endpoint=endpoint_url, **det)
        if category not in self.scope.attack_classes:
            self._deny(Reason.ATTACK_CLASS_NOT_ALLOWED, category=category)
        if category == "tool_abuse" and not self.scope.tool_abuse_attested:
            self._deny(Reason.TOOL_ABUSE_NOT_ATTESTED)
        if media and not self.scope.multimodal_allowed:
            self._deny(Reason.MULTIMODAL_NOT_ALLOWED)
        if branching and not self.scope.branching_allowed:
            self._deny(Reason.BRANCHING_NOT_ALLOWED)
        if new_chars > self.limits.max_prompt_chars:
            self._deny(Reason.PROMPT_TOO_LONG, chars=new_chars, max=self.limits.max_prompt_chars)
        is_new = conversation_id not in self.conversations
        if is_new and len(self.conversations) >= self.limits.max_conversations:
            self._deny(Reason.CONVERSATION_LIMIT, max=self.limits.max_conversations)
        if self.turns.get(conversation_id, 0) >= self.limits.max_turns_per_conversation:
            self._deny(Reason.TURN_LIMIT, max=self.limits.max_turns_per_conversation)
        if self.requests >= self.limits.max_requests:
            self._deny(Reason.REQUEST_LIMIT, max=self.limits.max_requests)
        est_in = estimate_tokens(context_chars)
        remaining = self.limits.max_total_tokens - self.tokens_used
        if remaining - est_in < MIN_RESPONSE_TOKENS:
            self._deny(Reason.TOKEN_BUDGET_EXHAUSTED, remaining=remaining, needed=est_in + MIN_RESPONSE_TOKENS)

        await self._rate_limit()
        self._check_common()                                   # kill/duration may have changed while waiting

        max_tokens = min(self.limits.max_response_tokens, remaining - est_in)
        reserved = est_in + max_tokens
        self.conversations.add(conversation_id)
        self.turns[conversation_id] = self.turns.get(conversation_id, 0) + 1
        self.requests += 1
        self.tokens_used += reserved
        self._window.append(self._clock())
        self._audit("governor.allow", detail={"endpoint": endpoint_url, "category": category,
                                              "conversation": conversation_id, "max_tokens": max_tokens})
        self._warn_if_needed()
        return Grant(max_tokens, reserved, conversation_id, self.turns[conversation_id])

    async def authorize_ingest(self, endpoint_url: str, category: str, doc_chars: int) -> None:
        """Document upload to the target (indirect tests). Subject to the request count and rate limit; does not count as a conversation/turn."""
        self._check_common()
        ep = self.scope.endpoint(endpoint_url)
        if ep is None:
            self._deny(Reason.ENDPOINT_NOT_AUTHORIZED, endpoint=endpoint_url)
        if not ep.ingest_url:
            self._deny(Reason.ENDPOINT_NOT_AUTHORIZED, endpoint=endpoint_url, why="ingest_url is not authorized")
        bad, det = check_endpoint(ep.ingest_url, ep.local, self._resolver)
        if bad:
            self._deny(bad, endpoint=ep.ingest_url, **det)
        if category not in self.scope.attack_classes:
            self._deny(Reason.ATTACK_CLASS_NOT_ALLOWED, category=category)
        if doc_chars > self.limits.max_prompt_chars:
            self._deny(Reason.PROMPT_TOO_LONG, chars=doc_chars, max=self.limits.max_prompt_chars)
        if self.requests >= self.limits.max_requests:
            self._deny(Reason.REQUEST_LIMIT, max=self.limits.max_requests)
        await self._rate_limit()
        self._check_common()
        self.requests += 1
        self._window.append(self._clock())
        self._audit("governor.allow", detail={"endpoint": ep.ingest_url, "category": category, "kind": "ingest"})

    async def authorize_probe(self, endpoint_url: str, category: str) -> None:
        """One read-only probe request that carries no tokens (vector store exposure test). Same checks as a chat request: kill switch, endpoint authorized
        in the signed scope, address check (private/metadata ranges), attack class, request total and rate limit."""
        self._check_common()
        ep = self.scope.endpoint(endpoint_url)
        if ep is None:
            self._deny(Reason.ENDPOINT_NOT_AUTHORIZED, endpoint=endpoint_url)
        bad, det = check_endpoint(ep.url, ep.local, self._resolver)
        if bad:
            self._deny(bad, endpoint=endpoint_url, **det)
        if category not in self.scope.attack_classes:
            self._deny(Reason.ATTACK_CLASS_NOT_ALLOWED, category=category)
        if self.requests >= self.limits.max_requests:
            self._deny(Reason.REQUEST_LIMIT, max=self.limits.max_requests)
        await self._rate_limit()
        self._check_common()
        self.requests += 1
        self._window.append(self._clock())
        self._audit("governor.allow", detail={"endpoint": endpoint_url, "category": category, "kind": "probe"})

    def authorize_cleanup(self, endpoint_url: str) -> None:
        """Deleting uploaded documents (cleanup). OBEYS the kill switch (no network request is made when killed); endpoint/address checks apply.
        It counts toward the request total but is NOT blocked by max_requests/rate/duration/circuit breaker: cleanup is small and bounded (one per document) and
        must be able to run even when a limit is exhausted so that an interrupted run does not LEAVE documents on the target."""
        if self.killed:
            self._deny(Reason.KILLED)
        ep = self.scope.endpoint(endpoint_url)
        if ep is None or not ep.ingest_delete_url:
            self._deny(Reason.ENDPOINT_NOT_AUTHORIZED, endpoint=endpoint_url, why="ingest_delete_url is not authorized")
        bad, det = check_endpoint(ep.ingest_delete_url.replace("{name}", "x"), ep.local, self._resolver)
        if bad:
            self._deny(bad, endpoint=ep.ingest_delete_url, **det)
        self.requests += 1
        self._audit("governor.allow", detail={"endpoint": ep.ingest_delete_url, "kind": "cleanup"})

    async def _rate_limit(self):
        rpm = self.limits.max_requests_per_minute
        while True:
            now = self._clock()
            while self._window and now - self._window[0] >= 60:
                self._window.popleft()
            if len(self._window) < rpm:
                return
            wait = 60 - (now - self._window[0]) + 0.01
            self.throttle_seconds += wait
            self._audit("governor.throttle", reason=Reason.RATE_THROTTLED, detail={"wait_seconds": round(wait, 2)})
            await self._sleep(wait)
            if self.killed or self.elapsed >= self.limits.max_duration_seconds:
                return

    def settle(self, grant: Grant, tokens_in: int, tokens_out: int):
        """Replaces the reservation with the real usage."""
        self.tokens_used += tokens_in + tokens_out - grant.reserved
        self._warn_if_needed()

    def refund(self, grant: Grant):
        """Refunds the reservation for a request that never reached the target (permanent error)."""
        self.tokens_used -= grant.reserved

    # ------------------------------------------------------------ judge calls
    def judge_allowed(self, est_tokens: int = 1500):
        self._check_common()
        if self.limits.max_total_tokens - self.tokens_used < est_tokens:
            self._deny(Reason.TOKEN_BUDGET_EXHAUSTED, remaining=self.limits.max_total_tokens - self.tokens_used,
                       needed=est_tokens, for_="judge")

    def charge_judge(self, tokens: int):
        self.tokens_used += tokens
        self._warn_if_needed()

    # ------------------------------------------------------------ circuit breaker
    def record_success(self):
        self.consecutive_errors = 0

    def record_error(self, kind: str):
        """kind: auth | server | network | timeout. 401/403 trips it immediately; the others after N consecutive errors."""
        if kind == "auth":
            self._open(Reason.AUTH_FAILURE, kind=kind)
            return
        if kind in ("server", "network", "timeout"):
            self.consecutive_errors += 1
            if self.consecutive_errors >= self.limits.breaker_consecutive_errors:
                self._open(Reason.CIRCUIT_OPEN, kind=kind, consecutive=self.consecutive_errors)

    def _open(self, reason: Reason, **detail):
        if self.circuit is None:                               # an opened circuit STAYS open for the rest of the run
            self.circuit = reason
            self._audit("governor.circuit_open", reason=reason, detail=detail)
