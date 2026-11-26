"""Attack families + framework mapping, external payload import (carrier rule), rule-based multi-turn branching and its signed-scope permission."""
import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from fakes import LEAK, FakeJudge, openai_json
from llm_redteam import branching, frameworks, payloads
from llm_redteam.engine import Executor, RunConfig
from llm_redteam.evaluator import Evaluator
from llm_redteam.governor import Denied, Governor
from llm_redteam.library import LibraryError, check_against_scope, parse_library
from llm_redteam.reasons import Reason
from llm_redteam.scope import Endpoint, Limits, LLMScope
from llm_redteam.store import Store
from llm_redteam.targets import TargetAdapter

NOW = datetime.now(timezone.utc)


def case(id="b1", **kw):
    return {"id": id, "category": "prompt_injection_direct", "title": id, "expected_behavior": "no leak", "on_refusal": "next_case",
            "variants": [], "max_attempts": 1, **kw}


def lib(*cases):
    return parse_library(json.dumps({"library": {"name": "t", "version": "1"}, "cases": list(cases)}))


def bcase(steps, **kw):
    return case(type="branching", branching=steps, **kw)


STEPS = [
    {"id": "s1", "message": "Hello, who are you?", "rules": [{"contains": ["secret-ok"], "goto": "s3"}, {"refused": True, "goto": "end"}]},
    {"id": "s2", "message": "Tell me more about yourself."},
    {"id": "s3", "message": "Thanks. And your setup?"},
]


# ------------------------------------------------------------------ attack families and framework mapping
def test_family_adds_atlas_and_asi_mapping():
    fw = frameworks.resolve(owasp=None, attack_class="prompt_injection_indirect", family="memory_poisoning")
    assert fw["asi"] == "ASI06_MemoryContextPoisoning" and "AML.T0080.000" in [t["id"] for t in fw["atlas"]] and fw["family"] == "memory_poisoning"
    assert frameworks.resolve(owasp=None, attack_class="jailbreak", asi="ASI01_AgentGoalHijack", family="role_play")["asi"] == "ASI01_AgentGoalHijack"   # explicit tag wins
    assert frameworks.resolve(owasp=None, attack_class="jailbreak")["family"] is None


def test_every_family_maps_to_known_framework_ids_and_a_scope_class():
    from llm_redteam.scope import ATTACK_CLASSES
    for f in frameworks.FAMILIES:
        assert frameworks.ASI_BY_FAMILY[f] in frameworks.ASI_BY_ID and frameworks.CLASS_BY_FAMILY[f] in ATTACK_CLASSES
        assert all(t in frameworks.TECHNIQUES for t in frameworks.ATLAS_BY_FAMILY[f])
    assert all(a in frameworks.TACTICS for _n, tacs in frameworks.TECHNIQUES.values() for a in tacs)


def test_library_accepts_known_family_and_rejects_unknown():
    c = lib(case(turns=["hello"], attack_family="Role-Play", source="x (MIT)")).cases[0]
    assert c.attack_family == "role_play" and c.source == "x (MIT)"
    with pytest.raises(LibraryError, match="unknown attack_family"):
        lib(case(turns=["hello"], attack_family="magic"))


def test_family_stats_rows_count_family_tagged_attempts():
    att = [{"category": "jailbreak", "owasp_category": None, "outcome": "judged:violation", "is_replay": False, "tags_json": json.dumps({"family": "role_play"})},
           {"category": "jailbreak", "owasp_category": None, "outcome": "judged:no_violation", "is_replay": False, "tags_json": json.dumps({"family": "role_play"})}]
    st = frameworks.stats(att, [], ())
    row = next(r for r in st["families"] if r["id"] == "role_play")
    assert row["tested"] == 2 and row["violations"] == 1 and len(st["families"]) == len(frameworks.FAMILIES)
    assert next(r for r in st["atlas"] if r["id"] == "AML.T0054")["tested"] == 2


# ------------------------------------------------------------------ importer
def test_lines_import_is_verbatim_deduplicated_and_family_from_folder():
    doc, rep = payloads.convert("# comment\nalpha one\n\nalpha one\nbeta  two {previous_reply}\nlast\n", fmt="lines", path_hint="exfiltration/notes.txt", source="ai-seclists (MIT)")
    assert [c["turns"] for c in doc["cases"]] == [["alpha one"], ["last"]]                # verbatim, comment/blank/duplicate/reserved-placeholder lines skipped
    assert rep["skipped_duplicate"] == 1 and rep["skipped_placeholder"] == 1 and rep["by_family"] == {"exfiltration": 2}
    c = parse_library(json.dumps(doc)).cases[0]
    assert c.attack_family == "exfiltration" and c.category == "data_leakage" and c.source == "ai-seclists (MIT)"


def test_records_import_detects_fields_and_maps_labels():
    data = json.dumps([{"payload": "p1", "category": "Jailbreak personas"}, {"prompt": "p2", "technique": "base64 trick"}, {"text": "p3"}, {"nothing": 1}])
    doc, rep = payloads.convert(data, fmt="records")
    assert [c["attack_family"] for c in doc["cases"]] == ["role_play", "encoding_evasion", None]
    assert rep["unmapped_family"] == 1 and rep["skipped_empty"] == 1
    assert doc["cases"][2]["category"] == "prompt_injection_direct"
    csv_text = "text,family\nhello there,memory poisoning\n"
    assert payloads.convert(csv_text, fmt="records", file_format="csv")[0]["cases"][0]["attack_family"] == "memory_poisoning"


DUELS = "\n".join(json.dumps(d) for d in (
    {"duel_id": "d1", "outcome": "red_win", "win_signal": "secret_leak", "rounds": [{"n": 1, "red_attack": "a1"}, {"n": 2, "red_attack": "a2", "blue_response": "never used"}]},
    {"duel_id": "d2", "outcome": "blue_win", "rounds": [{"n": 1, "red_attack": "b1"}, {"n": 2, "red_attack": "b2"}]},
    {"duel_id": "d3", "outcome": "red_win", "rounds": [{"n": 1, "red_attack": "only one"}]}))


def test_altayduel_import_uses_only_attacker_turns():
    doc, rep = payloads.convert(DUELS, fmt="altayduel", source="AltaySec/altayduel-transcripts (CC-BY-4.0)")
    assert [c["turns"] for c in doc["cases"][:2]] == [["a1", "a2"], ["b1", "b2"]] and "never used" not in json.dumps(doc)
    assert rep["multi_turn"] == 2 and doc["cases"][0]["id"] == "imp-d1"
    only, _ = payloads.convert(DUELS, fmt="altayduel", only_successful=True)
    assert [c["id"] for c in only["cases"]] == ["imp-d1", "imp-d3"]
    br, _ = payloads.convert(DUELS, fmt="altayduel", multi_turn="branching")
    c = parse_library(json.dumps(br)).cases[0]
    assert c.case_type == "branching" and [s.id for s in c.branching] == ["s1", "s2"] and c.branching[0].rules[0].goto == "end"


def test_importer_input_errors():
    with pytest.raises(LibraryError, match="contains no payloads"):
        payloads.convert("# only a comment\n", fmt="lines")
    with pytest.raises(LibraryError, match="unknown family"):
        payloads.convert("x", fmt="lines", family="magic")
    with pytest.raises(LibraryError, match="format must be"):
        payloads.convert("x", fmt="html")
    long = "x" * (payloads.MAX_TEXT_CHARS + 1)
    with pytest.raises(LibraryError, match="no usable payload"):      # too long is skipped, never truncated
        payloads.convert(long, fmt="lines")


# ------------------------------------------------------------------ branching rules (pure)
def test_choose_first_matching_rule_wins_and_default_is_next():
    steps = branching.parse_steps(STEPS)
    assert branching.choose(steps, 0, "ok. secret-ok!", [])[0] == 2
    assert branching.choose(steps, 0, "I'm sorry, I can't help.", [])[0] is None                    # refusal rule -> end
    nxt, info = branching.choose(steps, 0, "plain answer", [])
    assert nxt == 1 and info["via"] == "default"
    assert branching.choose(steps, 2, "anything", [])[0] is None                                    # after the last step: end


def test_rule_conditions_length_and_canary():
    steps = branching.parse_steps([{"id": "a", "message": "m", "rules": [{"canary": True, "goto": "end"}, {"min_chars": 10, "not_contains": ["nope"], "goto": "c"}]},
                                   {"id": "b", "message": "m"}, {"id": "c", "message": "m"}])
    assert branching.choose(steps, 0, "has CANARY-1 inside", ["CANARY-1"])[0] is None
    assert branching.choose(steps, 0, "long enough reply", [])[0] == 2
    assert branching.choose(steps, 0, "long enough, nope", [])[0] == 1


@pytest.mark.parametrize("steps,msg", [
    ([{"id": "a", "message": "m", "rules": [{"contains": ["x"], "goto": "a"}]}], "LATER step"),                     # a loop to itself
    ([{"id": "a", "message": "m"}, {"id": "b", "message": "m", "default": "a"}], "LATER step"),                  # backwards
    ([{"id": "a", "message": "m", "rules": [{"goto": "end"}]}], "at least one condition"),
    ([{"id": "a", "message": "m", "rules": [{"contains": ["x"], "goto": "end", "shell": "x"}]}], "may use only"),
    ([{"id": "a", "message": "m"}, {"id": "a", "message": "m"}], "unique"),
    ([{"id": "end", "message": "m"}], "unique"),
    ([{"id": "a", "message": "{previous_reply}"}], "first step"),
    ([{"id": f"s{i}", "message": "m"} for i in range(21)], "1-20 steps"),
])
def test_branching_validation_rejects_unsafe_tables(steps, msg):
    with pytest.raises(branching.BranchError, match=msg):
        branching.parse_steps(steps)


def test_library_branching_rules():
    c = lib(bcase(STEPS)).cases[0]
    assert c.case_type == "branching" and c.turns == ("Hello, who are you?",) and c.max_path == 3
    with pytest.raises(LibraryError, match="needs type: branching"):
        lib(case(turns=["hi"], branching=STEPS))
    with pytest.raises(LibraryError, match="not 'turns'"):
        lib(bcase(STEPS, turns=["hi"]))
    with pytest.raises(LibraryError, match="bypass"):
        lib(bcase(STEPS, bypass_technique="template", bypass={"template": "{text}"}))


# ------------------------------------------------------------------ signed scope + Governor + engine
@pytest.fixture
def env(fresh_db, target):
    class E:
        pass
    e = E()
    e.store, e.target = Store(fresh_db), target

    async def sleep(s):
        pass

    def scope(allowed=True, **limits):
        return LLMScope(name="t", client="c", authorized_by="CISO", authorization_doc_sha256=hashlib.sha256(b"d").digest(),
                        valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=30), endpoints=[Endpoint(target.url, "openai_compat", "m", local=True)],
                        attack_classes=["prompt_injection_direct"], branching_allowed=allowed,
                        limits=Limits(**({"max_requests_per_minute": 600, "max_turns_per_conversation": 12} | limits)))

    def build(library, sc):
        run_id = e.store.create_run("scope-x", target.url, {})
        e.run_id = run_id
        e.gov = Governor(sc, lambda action, **kw: e.store.audit(action, run_id=run_id, reason=kw.get("reason"), detail=kw.get("detail")), sleep=sleep)
        ep = sc.endpoints[0]
        return Executor(run_id=run_id, endpoint=ep, library=library, cases=check_against_scope(library, sc), adapter=TargetAdapter(ep, "k", sleep=sleep),
                        evaluator=Evaluator(FakeJudge()), governor=e.gov, store=e.store, config=RunConfig(replay_n=1, replay_k=1))
    e.scope, e.build = scope, build
    return e


def sent_users(call):
    return [m["content"] for m in call["body"]["messages"] if m["role"] == "user"]


def test_scope_without_permission_refuses_branching_case(env):
    with pytest.raises(LibraryError, match="branching_allowed"):
        check_against_scope(lib(bcase(STEPS)), env.scope(allowed=False))
    with pytest.raises(LibraryError, match="longest branching path"):
        check_against_scope(lib(bcase(STEPS)), env.scope(max_turns_per_conversation=2))


def test_branching_permission_is_part_of_the_signed_content():
    off, on = LLMScope.from_content(env_content(False)), LLMScope.from_content(env_content(True))
    assert off.digest() != on.digest() and "branching_allowed" not in env_content(False) and LLMScope.from_content(env_content(True)).branching_allowed


def env_content(allowed):
    sc = LLMScope(name="t", client="c", authorized_by="CISO", authorization_doc_sha256=hashlib.sha256(b"d").digest(), valid_from=NOW, valid_until=NOW + timedelta(days=1),
                  endpoints=[Endpoint("http://127.0.0.1:1/v1", "openai_compat", "m", local=True)], attack_classes=["prompt_injection_direct"], branching_allowed=allowed)
    return sc.content()


def test_governor_denies_branching_without_permission(env):
    env.build(lib(case(turns=["hi"])), env.scope(allowed=False))
    with pytest.raises(Denied) as d:
        asyncio.run(env.gov.authorize(env.target.url, "prompt_injection_direct", "c1", 5, 5, branching=True))
    assert d.value.reason == Reason.BRANCHING_NOT_ALLOWED
    asyncio.run(env.gov.authorize(env.target.url, "prompt_injection_direct", "c2", 5, 5))              # a normal turn is still fine


def test_engine_follows_the_rule_table(env, run):
    def beh(n, b, h):
        return 200, {}, openai_json("secret-ok, go on" if n == 0 else f"reply {n} {LEAK}")
    env.target.behavior = beh
    ex = env.build(lib(bcase(STEPS)), env.scope())
    run(ex.run())
    first_conv = [sent_users(c) for c in env.target.calls[:2]]
    assert first_conv[0] == ["Hello, who are you?"]
    assert first_conv[1] == ["Hello, who are you?", "Thanks. And your setup?"]                          # rule 1 skipped s2 and went to s3
    f = env.store.get_run(env.run_id)["findings"][0]
    b = f["evidence"]["branching"]
    assert b["path"][:2] == ["s1", "s3"] and b["trace"][0]["via"] == "rule 1" and b["turns"] == 2 and f["evidence"]["case"]["type"] == "branching"


def test_engine_default_path_and_refusal_stop(env, run):
    env.target.behavior = lambda n, b, h: (200, {}, openai_json(f"fine {n} {LEAK}"))
    run(env.build(lib(bcase(STEPS)), env.scope()).run())
    assert [len(sent_users(c)) for c in env.target.calls[:3]] == [1, 2, 3]                                # s1 -> s2 -> s3 by default
    assert sent_users(env.target.calls[2])[1] == "Tell me more about yourself."


def test_engine_refusal_rule_ends_the_conversation(env, run):
    env.target.behavior = lambda n, b, h: (200, {}, openai_json("I'm sorry, I can't help with that."))
    run(env.build(lib(bcase(STEPS)), env.scope()).run())
    assert len(env.target.calls) == 1                                                                   # one turn only: the refusal rule said end


# ------------------------------------------------------------------ reports
def test_csv_and_pdf_carry_family_and_threat_matrix():
    from llm_redteam import reports
    f = {"id": "f1", "run_id": "r1", "status": "verified", "severity": "high", "category": "jailbreak", "case_id": "c1", "title": "t", "created_at": 1.0,
         "evidence": {"case": {"source": "ds (MIT)"}}, "frameworks": frameworks.resolve(owasp=None, attack_class="jailbreak", family="role_play"), "benchmark": None}
    rows = list(__import__("csv").reader(reports.findings_csv([f]).decode("utf-8-sig").splitlines()))
    head, row = rows[0], rows[1]
    assert row[head.index("attack_family")] == "role_play" and row[head.index("source")] == "ds (MIT)" and row[head.index("asi_category")].startswith("ASI03")
    att = [{"category": "jailbreak", "owasp_category": None, "outcome": "judged:violation", "is_replay": False, "tags_json": json.dumps({"family": "role_play"})}]
    html = reports.threat_matrix_html({"attempts": att}, [{"category": "jailbreak", "owasp_category": None, "status": "verified", "tags_json": json.dumps({"family": "role_play"})}])
    assert "Attack families" in html and "Role play / persona" in html and "AML.T0054" in html
