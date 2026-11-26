"""PLAGUE (lifelong adaptive multi-turn) and PersonaTeaming (persona-driven mutation): library schema, lifelong memory, state machine, evidence.
All strategy/persona wording comes from the library; the engine only selects, validates and records."""
import pytest

from fakes import LEAK, openai_json
from llm_redteam.attacker import AgentState, LifelongMemory
from llm_redteam.engine import RunConfig
from llm_redteam.library import LibraryError
from test_attacker import FakeAttackerLLM, attacker, states, target_leaks_on  # noqa: F401
from test_engine import case, env, lib, play  # noqa: F401

STRATS = [{"id": "s1", "text": "STRAT-ONE: open with a neutral framing"}, {"id": "s2", "text": "STRAT-TWO: continue the earlier topic"}]
PLAGUE = {"max_rounds": 3, "method": "plague", "strategies": STRATS}
PERSONAS = [{"id": "p1", "text": "PERSONA-ONE: a curious student"}, {"id": "p2", "text": "PERSONA-TWO: a support engineer"}]
PERSONA = {"max_rounds": 3, "method": "persona_teaming", "personas": PERSONAS}


# ---------------------------------------------------------------- lifelong memory (pure)
def test_memory_tries_untried_first_in_library_order_and_never_repeats_back_to_back():
    m = LifelongMemory(["a", "b", "c"])
    assert m.pick() == "a"
    m.record("a", "refused")
    assert m.pick() == "b"
    m.record("b", "refused")
    assert m.pick() == "c"


def test_memory_prefers_what_worked_and_lessons_hold_only_counts():
    m = LifelongMemory(["a", "b"])
    m.record("a", "refused")
    m.record("b", "clean")
    assert m.pick() == "a" or m.pick() == "b"
    m.record("a", "violation")                      # last = a -> must switch while another exists
    assert m.pick() == "b"
    m.record("b", "refused")
    assert m.pick() == "a"                          # a: 1 violation / 2 tries beats b
    assert m.lessons() == "a: tried 2, refused 1, violation 1; b: tried 2, refused 1, violation 0"
    assert LifelongMemory(["x"]).lessons() == "none yet"
    assert LifelongMemory(["x"]).pick() == "x"      # a single item may repeat


# ---------------------------------------------------------------- schema
@pytest.mark.parametrize("ad", [
    {"method": "nope"}, {"method": "plague"}, {"method": "plague", "strategies": []}, {"method": "plague", "strategies": "x"},
    {"method": "plague", "strategies": [{"id": "a"}]}, {"method": "plague", "strategies": [{"id": "a b", "text": "x"}]},
    {"method": "plague", "strategies": [{"id": "a", "text": "x"}, {"id": "a", "text": "y"}]},
    {"method": "plague", "strategies": [{"id": "a", "text": "x" * 601}]}, {"method": "plague", "strategies": [{"id": "a", "text": "x", "extra": 1}]},
    {"method": "plague", "strategies": STRATS, "personas": PERSONAS}, {"method": "persona_teaming", "personas": PERSONAS, "strategies": STRATS},
    {"strategies": STRATS}, {"method": "persona_teaming", "strategies": STRATS},
    {"method": "plague", "strategies": [{"id": f"s{i}", "text": "x"} for i in range(9)]}])
def test_adaptive_method_schema_rejections(ad):
    with pytest.raises(LibraryError):
        lib(case("c1", adaptive={"max_rounds": 2} | ad))


def test_schema_accepts_methods_and_changes_hash():
    a, b = lib(case("c1", adaptive=PLAGUE)).cases[0].adaptive, lib(case("c1", adaptive=PERSONA)).cases[0].adaptive
    assert a.method == "plague" and a.items[0] == ("s1", "STRAT-ONE: open with a neutral framing") and b.method == "persona_teaming"
    assert lib(case("c1", adaptive={"max_rounds": 3})).cases[0].adaptive.method == "rewrite"
    assert lib(case("c1", adaptive=PLAGUE)).sha256 != lib(case("c1", adaptive=PERSONA)).sha256


# ---------------------------------------------------------------- state machine
def test_plague_plans_attacks_reflects_and_carries_lessons_to_the_next_round(env, run):
    env.target.behavior = target_leaks_on("WIN")
    llm = FakeAttackerLLM([["first attempt"], ["WIN second attempt"]])
    status, reason, r = play(env, run, lib(case("c1", adaptive=PLAGUE)), cfg=RunConfig(adaptive=True), attacker=attacker(llm))
    assert (status, reason) == ("completed", None) and llm.calls == 2
    assert "STRATEGY (from the operator's library): STRAT-ONE" in llm.users[0] and "LESSONS SO FAR (counts only): none yet" in llm.users[0]
    assert "STRAT-TWO" in llm.users[1] and "s1: tried 1, refused 1, violation 0" in llm.users[1]
    assert states(env) == ["probing",
                           "planning", "analyzing", "generating", "validating", "attacking", "attacking", "reflecting",
                           "planning", "analyzing", "generating", "validating", "attacking", "attacking", "confirming", "reflecting", "found"]
    steps = env.store.agent_steps(env.run_id, "c1")
    plan = [s for s in steps if s["state"] == "planning"]
    assert [p["detail"]["item"] for p in plan] == ["s1", "s2"] and all(p["detail"]["method"] == "plague" for p in plan)
    f = r["findings"][0]
    assert f["status"] == "verified" and f["evidence"]["adaptive"]["method"] == "plague" and f["evidence"]["adaptive"]["item"] == "s2"
    assert f["evidence"]["adaptive"]["family"] == "plague"
    assert env.store.audit_verify() is None


def test_persona_teaming_uses_the_persona_text_and_records_it(env, run):
    env.target.behavior = target_leaks_on("WIN")
    llm = FakeAttackerLLM([["WIN as a student"]])
    status, _, r = play(env, run, lib(case("c1", adaptive=PERSONA)), cfg=RunConfig(adaptive=True), attacker=attacker(llm))
    assert status == "completed" and "PERSONA (from the operator's library): PERSONA-ONE" in llm.users[0]
    ad = r["findings"][0]["evidence"]["adaptive"]
    assert ad["method"] == "persona_teaming" and ad["item"] == "p1" and ad["family"] == "persona_team"


def test_lifelong_memory_is_shared_by_cases_with_the_same_items_within_a_run(env, run):
    env.target.behavior = lambda n, b, h: (200, {}, openai_json("Sorry, I cannot do that."))
    llm = FakeAttackerLLM([["a1"], ["a2"], ["b1"], ["b2"]])
    play(env, run, lib(case("c1", adaptive={"max_rounds": 2, **{k: v for k, v in PLAGUE.items() if k != "max_rounds"}}),
                       case("c2", adaptive={"max_rounds": 2, **{k: v for k, v in PLAGUE.items() if k != "max_rounds"}})),
         cfg=RunConfig(adaptive=True), attacker=attacker(llm))
    assert llm.calls == 4
    assert "s1: tried 1, refused 1, violation 0; s2: tried 1, refused 1, violation 0" in llm.users[2]      # c2 starts with what c1 learned


def test_plague_still_respects_the_scope_round_cap_and_attacker_failures_abort(env, run):
    env.target.behavior = lambda n, b, h: (200, {}, openai_json("Sorry, I cannot do that."))
    llm = FakeAttackerLLM([["x1"], ["x2"], ["x3"]])
    play(env, run, lib(case("c1", adaptive=PLAGUE)), cfg=RunConfig(adaptive=True, adaptive_max_rounds=1), attacker=attacker(llm))
    assert llm.calls == 1 and states(env)[-1] == AgentState.EXHAUSTED.value
