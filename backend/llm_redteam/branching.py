"""
Multi-turn branching ("stateful" cases): the library lists the steps and, per step, an ordered rule table. After each target reply the CODE picks
the next step by evaluating those rules (substring checks, a refusal heuristic, length thresholds, canary presence). No model chooses the path and
no text is generated: every message that can ever be sent is written by the operator in the library.

Safety properties (enforced at import, not at run time):
  * Branches only go FORWARD (to a later step or to "end"), so a case can never loop; the longest path is the number of steps.
  * At most MAX_STEPS steps and MAX_RULES rules per step; the scope's per-conversation turn limit is checked against the longest path.
  * State (current step, turn counter, path) is held by the engine in plain variables and written to the finding's evidence as a trace.
"""
import re
from dataclasses import dataclass

MAX_STEPS = 20
MAX_RULES = 8
MAX_TERMS = 20
MAX_TERM_CHARS = 200
MAX_MESSAGE_CHARS = 20_000
END = "end"
NEXT = "next"
ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
# Generic English refusal wording. This only DETECTS a refusal in a reply (to route the next step); it contains no attack content.
REFUSAL_MARKERS = ("i can't", "i cannot", "i can’t", "i won't", "i'm sorry", "i am sorry", "i'm not able", "i am not able", "unable to help",
                   "can't help with", "cannot help with", "not able to assist", "i must decline")
RULE_KEYS = {"contains", "not_contains", "refused", "min_chars", "max_chars", "canary", "goto"}


class BranchError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    goto: str
    contains: tuple[str, ...] = ()
    not_contains: tuple[str, ...] = ()
    refused: bool | None = None
    min_chars: int | None = None
    max_chars: int | None = None
    canary: bool | None = None

    def matches(self, reply: str, canaries: list[str]) -> bool:
        low = reply.lower()
        if self.contains and not any(t.lower() in low for t in self.contains):
            return False
        if self.not_contains and any(t.lower() in low for t in self.not_contains):
            return False
        if self.refused is not None and is_refusal(reply) != self.refused:
            return False
        if self.min_chars is not None and len(reply) < self.min_chars:
            return False
        if self.max_chars is not None and len(reply) > self.max_chars:
            return False
        if self.canary is not None and any(c and c in reply for c in canaries) != self.canary:
            return False
        return True


@dataclass(frozen=True)
class BStep:
    id: str
    message: str
    rules: tuple[Rule, ...] = ()
    default: str = NEXT                 # "next" (the following step; "end" after the last one) | a later step id | "end"


def is_refusal(reply: str) -> bool:
    low = reply.lower()
    return any(m in low for m in REFUSAL_MARKERS)


def _terms(v, what: str) -> tuple[str, ...]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not 1 <= len(v) <= MAX_TERMS or not all(isinstance(t, str) and t.strip() and len(t) <= MAX_TERM_CHARS and "\x00" not in t for t in v):
        raise BranchError(f"'{what}' must be a list of 1-{MAX_TERMS} non-empty texts of at most {MAX_TERM_CHARS} characters")
    return tuple(t.strip() for t in v)


def _int(v, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 1_000_000:
        raise BranchError(f"'{what}' must be a whole number between 0 and 1000000")
    return v


def parse_steps(raw) -> tuple[BStep, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_STEPS:
        raise BranchError(f"'branching' must be a list of 1-{MAX_STEPS} steps")
    ids = []
    for s in raw:
        sid = s.get("id") if isinstance(s, dict) else None
        if not isinstance(sid, str) or not ID_RE.fullmatch(sid) or sid in (END, NEXT) or sid in ids:
            raise BranchError("every step needs a unique 'id' of 1-40 characters (letters, digits, _ . -); 'end' and 'next' are reserved")
        ids.append(sid)
    out = []
    for i, s in enumerate(raw):
        if set(s) - {"id", "message", "rules", "default"}:
            raise BranchError(f"step {s['id']!r}: only 'id', 'message', 'rules' and 'default' are allowed")
        msg = s.get("message")
        if not isinstance(msg, str) or not msg.strip() or len(msg) > MAX_MESSAGE_CHARS or "\x00" in msg:
            raise BranchError(f"step {s['id']!r}: 'message' must be 1-{MAX_MESSAGE_CHARS} characters")
        if i == 0 and "{previous_reply}" in msg:
            raise BranchError("the first step cannot use {previous_reply} (there is no previous reply yet)")

        def target(t, what, i=i, s=s):   # bind the current step explicitly
            if t in (END, NEXT):
                return t
            if t not in ids or ids.index(t) <= i:
                raise BranchError(f"step {s['id']!r}: {what} {t!r} must be 'end', 'next' or the id of a LATER step (branches only go forward)")
            return t

        rules_raw = s.get("rules") or []
        if not isinstance(rules_raw, list) or len(rules_raw) > MAX_RULES:
            raise BranchError(f"step {s['id']!r}: 'rules' must be a list of at most {MAX_RULES} rules")
        rules = []
        for r in rules_raw:
            if not isinstance(r, dict) or set(r) - RULE_KEYS or "goto" not in r:
                raise BranchError(f"step {s['id']!r}: every rule needs 'goto' and may use only {sorted(RULE_KEYS - {'goto'})}")
            kw: dict = {"goto": target(r["goto"], "goto")}
            if "contains" in r:
                kw["contains"] = _terms(r["contains"], "contains")
            if "not_contains" in r:
                kw["not_contains"] = _terms(r["not_contains"], "not_contains")
            for k in ("refused", "canary"):
                if k in r:
                    if not isinstance(r[k], bool):
                        raise BranchError(f"step {s['id']!r}: '{k}' must be true or false")
                    kw[k] = r[k]
            for k in ("min_chars", "max_chars"):
                if k in r:
                    kw[k] = _int(r[k], k)
            if len(kw) == 1:
                raise BranchError(f"step {s['id']!r}: a rule needs at least one condition")
            rules.append(Rule(**kw))
        out.append(BStep(s["id"], msg.strip(), tuple(rules), target(s.get("default", NEXT), "default")))
    return tuple(out)


def choose(steps: tuple[BStep, ...], index: int, reply: str, canaries: list[str]) -> tuple[int | None, dict]:
    """The step that follows steps[index] after `reply`. -> (next index or None for the end, trace entry). First matching rule wins."""
    step = steps[index]
    for n, rule in enumerate(step.rules):
        if rule.matches(reply, canaries):
            dest, via = rule.goto, f"rule {n + 1}"
            break
    else:
        dest, via = step.default, "default"
    if dest == NEXT:
        dest = steps[index + 1].id if index + 1 < len(steps) else END
    nxt = None if dest == END else next(i for i, s in enumerate(steps) if s.id == dest)
    return nxt, {"step": step.id, "via": via, "goto": dest, "refused": is_refusal(reply), "reply_chars": len(reply)}
