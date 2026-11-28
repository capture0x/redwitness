"""
Long-horizon, multi-session campaigns ("patient attacker" simulation) on top of the Crescendo cases.

A campaign works through a LADDER: library cases that share `campaign.ladder` and carry a `campaign.level` (1 = gentlest ... 5 = strongest).
Each SESSION is an ordinary run of ONE library case: same signed scope, Governor, canary, judge, replay verification and audit.
What a campaign adds is the planning between sessions, and all of it is plain code:

  * state       counters kept after every session: tries and outcomes per level, refusals per level, retreats, the sessions so far.
                Only code-made numbers and library ids are stored, never target text, so a hostile reply cannot steer the plan.
  * next step   chosen from the library's own cases, never written by a model:
                  clean answer          -> escalate to the next level that has an untried case
                  refusal               -> another untried case at the same level; if none, retreat one level (at most `patience` times per level)
                  verified violation    -> the campaign is finished (found)
                  nothing left to try   -> finished (exhausted)
  * pacing      a cool-down between sessions and a session cap (the smaller of the campaign's and the signed scope's cap)
"""
from dataclasses import dataclass

LEVELS = (1, 2, 3, 4, 5)
MAX_COOLDOWN = 86_400
DEFAULT_PATIENCE = 2
OUTCOMES = ("clean", "refused", "violation", "unverified", "error")


class CampaignError(ValueError):
    pass


@dataclass(frozen=True)
class Rung:
    ladder: str
    level: int


def new_state(levels: list[int]) -> dict:
    return {"level": min(levels), "levels": sorted(levels), "tried": [], "retreats": {}, "by_level": {str(lv): {"clean": 0, "refused": 0, "violation": 0, "unverified": 0, "error": 0} for lv in sorted(levels)},
            "refusal_turns": [], "sessions": [], "finished": None}


def next_case(state: dict, ladder: dict[int, list[str]], patience: int = DEFAULT_PATIENCE) -> tuple[str | None, str, int]:
    """-> (case_id | None, reason, new_level). `ladder`: level -> case ids in library order. A finished or stuck campaign returns (None, reason, level)."""
    if state.get("finished"):
        return None, state["finished"], state["level"]
    tried = set(state["tried"])
    levels = sorted(ladder)
    cur = state["level"]
    last = state["sessions"][-1]["outcome"] if state["sessions"] else None

    def untried(level: int) -> str | None:
        return next((c for c in ladder.get(level, []) if c not in tried), None)

    if last is None:
        c = untried(levels[0])
        return (c, "start at the gentlest level", levels[0]) if c else (None, "exhausted", cur)
    if last in ("clean", "unverified", "error"):
        for lv in [x for x in levels if x > cur] + [cur]:                  # a clean answer: climb first, come back to the rest of this level later
            c = untried(lv)
            if c:
                return c, ("escalate" if lv > cur else "next case at the same level"), lv
        return None, "exhausted", cur
    # refused
    c = untried(cur)
    if c:
        return c, "refused: another case at the same level", cur
    lower = [x for x in levels if x < cur]
    if lower and state["retreats"].get(str(cur), 0) < patience:
        for lv in reversed(lower):
            c = untried(lv)
            if c:
                return c, "refused: retreat one level", lv
    for lv in [x for x in levels if x > cur]:
        c = untried(lv)
        if c:
            return c, "refused: nothing left at this level, try the next", lv
    return None, "exhausted", cur


def record(state: dict, *, seq: int, run_id: str, case_id: str, level: int, outcome: str, refusal_turn: int | None, at: float, why: str) -> dict:
    """Adds one finished session to the state (counters only)."""
    if outcome not in OUTCOMES:
        raise CampaignError(f"unknown outcome {outcome!r}")
    state["tried"].append(case_id)
    state["by_level"][str(level)][outcome] += 1
    if outcome == "refused" and refusal_turn is not None:
        state["refusal_turns"].append({"level": level, "turn": refusal_turn})
    if level < state["level"]:
        state["retreats"][str(state["level"])] = state["retreats"].get(str(state["level"]), 0) + 1
    state["level"] = level
    state["sessions"].append({"seq": seq, "run_id": run_id, "case_id": case_id, "level": level, "outcome": outcome, "at": at, "why": why})
    if outcome == "violation":
        state["finished"] = "found"
    return state


def profile(state: dict) -> dict:
    """The target's observed defence behaviour as numbers (for the dashboard): refusal rate per level and the turn at which refusals tended to start."""
    rows = []
    for lv, c in state["by_level"].items():
        n = sum(c.values())
        rows.append({"level": int(lv), "sessions": n, **c, "refusal_rate": round(c["refused"] / n, 3) if n else None})
    turns = [r["turn"] for r in state["refusal_turns"]]
    return {"levels": rows, "mean_refusal_turn": round(sum(turns) / len(turns), 2) if turns else None}
