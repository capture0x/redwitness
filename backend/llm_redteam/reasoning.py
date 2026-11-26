"""
Reasoning-layer evaluation (type: reasoning_chain). The library lists the steps of a multi-step problem. Each step carries the message to send, an optional
`hint` or `constraint` (text written by the operator, appended to the message) and an `expect` rule table that states what a correct INTERMEDIATE answer
looks like. After every reply the CODE checks the rules; a step whose reply breaks them is a Reasoning Deviation. No model decides this and no text is
generated: every message that can ever be sent is written by the operator in the library.

Rule keys (all optional, at least one per step): contains (any of), not_contains (none of), refused, min_chars, max_chars.
"""
import re
from dataclasses import dataclass

from .branching import BranchError, _int, _terms, is_refusal

MAX_STEPS = 12
MAX_MESSAGE_CHARS = 20_000
MAX_HINT_CHARS = 2_000
REPLY_EXCERPT = 1_500
ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
EXPECT_KEYS = {"contains", "not_contains", "refused", "min_chars", "max_chars"}
HINT_KINDS = ("hint", "constraint")


class ReasoningError(ValueError):
    pass


@dataclass(frozen=True)
class RStep:
    id: str
    message: str
    hint: str = ""
    hint_kind: str = "hint"
    contains: tuple[str, ...] = ()
    not_contains: tuple[str, ...] = ()
    refused: bool | None = None
    min_chars: int | None = None
    max_chars: int | None = None

    def sent(self) -> str:
        """The text that goes to the target: the message, then the hint/constraint on a new line."""
        return self.message if not self.hint else f"{self.message}\n{self.hint}"


def parse_steps(raw) -> tuple[RStep, ...]:
    if not isinstance(raw, list) or not 2 <= len(raw) <= MAX_STEPS:
        raise ReasoningError(f"'reasoning' must be a list of 2-{MAX_STEPS} steps")
    out, ids = [], set()
    for s in raw:
        if not isinstance(s, dict):
            raise ReasoningError("every reasoning step must be an object")
        sid = s.get("id")
        if not isinstance(sid, str) or not ID_RE.fullmatch(sid) or sid in ids:
            raise ReasoningError("every reasoning step needs a unique 'id' of 1-40 characters (letters, digits, _ . -)")
        ids.add(sid)
        if set(s) - {"id", "message", "hint", "hint_kind", "expect"}:
            raise ReasoningError(f"step {sid!r}: only 'id', 'message', 'hint', 'hint_kind' and 'expect' are allowed")
        msg = s.get("message")
        if not isinstance(msg, str) or not msg.strip() or len(msg) > MAX_MESSAGE_CHARS or "\x00" in msg:
            raise ReasoningError(f"step {sid!r}: 'message' must be 1-{MAX_MESSAGE_CHARS} characters")
        hint = s.get("hint") or ""
        if not isinstance(hint, str) or len(hint) > MAX_HINT_CHARS or "\x00" in hint:
            raise ReasoningError(f"step {sid!r}: 'hint' must be text of at most {MAX_HINT_CHARS} characters")
        kind = s.get("hint_kind", "hint")
        if kind not in HINT_KINDS:
            raise ReasoningError(f"step {sid!r}: hint_kind must be one of {HINT_KINDS}")
        ex = s.get("expect") or {}
        if not isinstance(ex, dict) or set(ex) - EXPECT_KEYS:
            raise ReasoningError(f"step {sid!r}: 'expect' may use only {sorted(EXPECT_KEYS)}")
        kw: dict = {}
        try:
            for k in ("contains", "not_contains"):
                if k in ex:
                    kw[k] = _terms(ex[k], k)
            if "refused" in ex:
                if not isinstance(ex["refused"], bool):
                    raise ReasoningError(f"step {sid!r}: 'refused' must be true or false")
                kw["refused"] = ex["refused"]
            for k in ("min_chars", "max_chars"):
                if k in ex:
                    kw[k] = _int(ex[k], k)
        except BranchError as e:
            raise ReasoningError(f"step {sid!r}: {e}") from None
        out.append(RStep(sid, msg.strip(), hint.strip(), kind, **kw))
    if not any(st.contains or st.not_contains or st.refused is not None or st.min_chars is not None or st.max_chars is not None for st in out):
        raise ReasoningError("at least one step needs an 'expect' rule (otherwise nothing can be checked)")
    return tuple(out)


def check(step: RStep, reply: str) -> list[dict]:
    """The step's rules against one reply -> [{rule, ok, detail}] (only the rules the step defines)."""
    low, res = reply.lower(), []
    if step.contains:
        hit = [t for t in step.contains if t.lower() in low]
        res.append({"rule": "contains", "ok": bool(hit), "detail": "found: " + ", ".join(hit) if hit else "none of: " + ", ".join(step.contains)})
    if step.not_contains:
        hit = [t for t in step.not_contains if t.lower() in low]
        res.append({"rule": "not_contains", "ok": not hit, "detail": "forbidden text present: " + ", ".join(hit) if hit else "no forbidden text"})
    if step.refused is not None:
        got = is_refusal(reply)
        res.append({"rule": "refused", "ok": got == step.refused, "detail": f"expected refused={step.refused}, reply refused={got}"})
    if step.min_chars is not None:
        res.append({"rule": "min_chars", "ok": len(reply) >= step.min_chars, "detail": f"{len(reply)} characters, at least {step.min_chars} expected"})
    if step.max_chars is not None:
        res.append({"rule": "max_chars", "ok": len(reply) <= step.max_chars, "detail": f"{len(reply)} characters, at most {step.max_chars} expected"})
    return res


def trace_entry(step: RStep, index: int, sent: str, reply: str) -> dict:
    checks = check(step, reply)
    return {"index": index, "id": step.id, "sent": sent[:REPLY_EXCERPT], "hint": step.hint or None, "hint_kind": step.hint_kind if step.hint else None,
            "reply": reply[:REPLY_EXCERPT], "reply_truncated": len(reply) > REPLY_EXCERPT, "checks": checks,
            "checked": bool(checks), "deviated": any(not c["ok"] for c in checks)}


def summarize(trace: list[dict]) -> dict:
    dev = [t["id"] for t in trace if t["deviated"]]
    return {"steps": trace, "total": len(trace), "checked": sum(1 for t in trace if t["checked"]), "deviations": dev, "first_deviation": dev[0] if dev else None}


def rationale(summary: dict) -> str:
    if not summary["deviations"]:
        return "Every checked intermediate step matched its expected result."
    first = next(t for t in summary["steps"] if t["deviated"])
    why = "; ".join(c["detail"] for c in first["checks"] if not c["ok"])
    return f"Reasoning deviation at step {first['id']!r} ({len(summary['deviations'])} of {summary['checked']} checked steps deviated): {why}."
