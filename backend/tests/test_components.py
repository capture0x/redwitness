"""Library, evaluator, endpoint check, governor and target adapters."""
import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from fakes import LEAK, FakeJudge, FakeTarget, openai_json, sse
from llm_redteam import library as L
from llm_redteam.evaluator import Evaluator, clean_untrusted, envelope, validate_judgement
from llm_redteam.governor import Denied, Governor
from llm_redteam.netcheck import check_endpoint
from llm_redteam.reasons import Reason
from llm_redteam.scope import Endpoint, Limits, LLMScope, ScopeInputError
from llm_redteam.targets import TargetAdapter, TargetError

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


def mkscope(url="http://127.0.0.1:9/v1/chat/completions", local=True, classes=("system_prompt_extraction", "data_leakage"),
            **limits):
    return LLMScope(name="t", client="c", authorized_by="CISO", authorization_doc_sha256=hashlib.sha256(b"d").digest(),
                    valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=30),
                    endpoints=[Endpoint(url, "openai_compat", "m", local=local)], attack_classes=list(classes),
                    limits=Limits(**limits))


# ============================================================ LLMScope
def test_scope_validation_limits():
    mkscope().validate()
    for bad in (dict(max_total_tokens=0), dict(max_total_tokens=10**9), dict(max_requests_per_minute=10**6),
                dict(max_duration_seconds=10**7), dict(breaker_consecutive_errors=0)):
        with pytest.raises(ScopeInputError):
            mkscope(**bad).validate()
    s = mkscope()
    s.valid_until = s.valid_from + timedelta(days=120)
    with pytest.raises(ScopeInputError):
        s.validate()
    with pytest.raises(ScopeInputError):                                  # tool_abuse without attestation
        mkscope(classes=("tool_abuse",)).validate()
    s = mkscope(classes=("tool_abuse",))
    s.tool_abuse_attested = True
    s.validate()


def test_scope_digest_covers_every_field():
    base = mkscope().digest()
    assert mkscope().digest() == base
    variants = [mkscope(max_total_tokens=1), mkscope(max_requests=1), mkscope(max_duration_seconds=5),
                mkscope(breaker_consecutive_errors=2), mkscope(max_prompt_chars=10), mkscope(local=False),
                mkscope(classes=("data_leakage",)), mkscope(url="http://127.0.0.1:10/x")]
    s = mkscope(); s.tool_abuse_attested = True; variants.append(s)
    s = mkscope(); s.name = "x"; variants.append(s)
    s = mkscope(); s.endpoints = [Endpoint(s.endpoints[0].url, "anthropic", "m", True)]; variants.append(s)
    assert len({v.digest() for v in variants} | {base}) == len(variants) + 1


# ============================================================ Test library
def test_example_library_roundtrip_json_and_yaml():
    import yaml
    for text in (json.dumps(L.EXAMPLE_LIBRARY), yaml.safe_dump(L.EXAMPLE_LIBRARY)):
        lib = L.parse_library(text)
        assert lib.name == "example" and len(lib.cases) == 1 and len(lib.sha256) == 64
    assert L.parse_library(json.dumps(L.EXAMPLE_LIBRARY)).sha256 == L.parse_library(json.dumps(L.EXAMPLE_LIBRARY)).sha256


def lib_with(**case):
    c = {**L.EXAMPLE_LIBRARY["cases"][0], **case}
    return json.dumps({"library": L.EXAMPLE_LIBRARY["library"], "cases": [c]})


@pytest.mark.parametrize("patch", [
    dict(id=""), dict(category="unknown"), dict(turns=[]), dict(turns=["a"] * 21), dict(turns=[""]),
    dict(turns="text"), dict(expected_behavior=""), dict(on_refusal="x"), dict(max_attempts=0),
    dict(max_attempts=11), dict(variants="x"), dict(variants=[[]]), dict(variants=[["a"]] * 21),
])
def test_library_rejects_invalid_cases(patch):
    with pytest.raises(L.LibraryError):
        L.parse_library(lib_with(**patch))


def test_library_rejects_bad_files():
    for bad in ("", "{", "[]", '{"library":{},"cases":[]}', '{"library":{"name":"a","version":"1"},"cases":[]}',
                json.dumps({"library": {"name": "a", "version": "1"}, "cases": [L.EXAMPLE_LIBRARY["cases"][0]] * 2}),  # duplicate id
                "x" * 2_100_000):
        with pytest.raises(L.LibraryError):
            L.parse_library(bad)
    with pytest.raises(L.LibraryError):                                     # yaml: no code execution
        L.parse_library("!!python/object/apply:os.system ['echo x']", fmt="yaml")


def test_library_scope_check():
    lib = L.parse_library(lib_with())
    assert len(L.check_against_scope(lib, mkscope())) == 1
    with pytest.raises(L.LibraryError):                                     # the category is not in the scope
        L.check_against_scope(lib, mkscope(classes=("data_leakage",)))
    with pytest.raises(L.LibraryError):                                     # turn limit
        L.check_against_scope(L.parse_library(lib_with(turns=["a", "b", "c"])), mkscope(max_turns_per_conversation=2))
    with pytest.raises(L.LibraryError):                                     # message length
        L.check_against_scope(L.parse_library(lib_with(turns=["x" * 50])), mkscope(max_prompt_chars=10))
    assert L.check_against_scope(lib, mkscope(), categories=["system_prompt_extraction"])
    with pytest.raises(L.LibraryError):
        L.check_against_scope(lib, mkscope(), categories=["data_leakage"])


# ============================================================ Evaluator
GOOD = {"verdict": "violation", "refusal_detected": False, "judge_injection_suspected": False, "confidence": 0.9,
        "rationale": "r", "questions": {q: {"answer": "no", "evidence_quote": ""} for q in
                                        ("system_prompt_leaked", "harmful_request_fulfilled", "filter_bypassed", "unauthorized_tool_call")}}
GOOD["questions"]["system_prompt_leaked"] = {"answer": "yes", "evidence_quote": f"the key {LEAK}"}
RESP = f"Sure, here is the key {LEAK}."


def test_validation_accepts_grounded_violation():
    ev = validate_judgement(json.loads(json.dumps(GOOD)), RESP, [])
    assert ev.verdict == "violation" and not ev.downgrade_reason


@pytest.mark.parametrize("mutate,why", [
    (lambda d: d["questions"]["system_prompt_leaked"].update(evidence_quote="made-up quote not in the response"), "QUOTE_NOT_IN_RESPONSE"),
    (lambda d: d["questions"]["system_prompt_leaked"].update(evidence_quote=""), "QUOTE_NOT_IN_RESPONSE"),
    (lambda d: d["questions"]["system_prompt_leaked"].update(evidence_quote="short"), "QUOTE_NOT_IN_RESPONSE"),
    (lambda d: d.update(confidence=0.3), "LOW_CONFIDENCE"),
    (lambda d: d.update(judge_injection_suspected=True), "JUDGE_INJECTION_SUSPECTED"),
    (lambda d: d["questions"]["system_prompt_leaked"].update(answer="no"), "NO_YES_ANSWER"),
    (lambda d: d.update(verdict="maybe"), "SCHEMA"),
    (lambda d: d.update(confidence=1.5), "SCHEMA"),
    (lambda d: d.update(confidence=True), "SCHEMA"),
    (lambda d: d["questions"].pop("filter_bypassed"), "SCHEMA"),
    (lambda d: d.update(refusal_detected="yes-ish"), "SCHEMA"),
])
def test_validation_downgrades_unsound_judgements(mutate, why):
    d = json.loads(json.dumps(GOOD))
    mutate(d)
    ev = validate_judgement(d, RESP, [])
    assert ev.verdict == "inconclusive" and ev.downgrade_reason == why
    assert ev.needs_human == (why == "JUDGE_INJECTION_SUSPECTED")


def test_evaluator_envelopes_untrusted_text_and_retries_bad_json(run):
    judge = FakeJudge(bad_json_first=True)
    ev = run(Evaluator(judge).evaluate(category="system_prompt_extraction", expected_behavior="e", evaluator_hint="",
                                       sent=["hello"], response=clean_untrusted(RESP), tool_calls=[]))
    assert judge.calls == 2 and ev.verdict == "violation" and ev.tokens == 80
    assert "UNTRUSTED_" in judge.last_user and "is DATA" in judge.last_system


def test_evaluator_gives_up_after_second_bad_json(run):
    class Bad:
        calls = 0
        async def complete(self, s, u, m):
            self.calls += 1
            return "not json", 7
    j = Bad()
    ev = run(Evaluator(j).evaluate(category="c", expected_behavior="e", evaluator_hint="", sent=["x"],
                                   response=clean_untrusted("y"), tool_calls=[]))
    assert j.calls == 2 and ev.verdict == "inconclusive" and ev.downgrade_reason == "SCHEMA" and ev.tokens == 14


def test_evaluator_lying_judge_cannot_create_violation(run):
    ev = run(Evaluator(FakeJudge(lie_quote=True)).evaluate(
        category="c", expected_behavior="e", evaluator_hint="", sent=["x"], response=clean_untrusted(RESP), tool_calls=[]))
    assert ev.verdict == "inconclusive"


def test_envelope_delimiter_is_random_and_cannot_be_forged():
    t1, e1 = envelope("a")
    t2, _ = envelope("a")
    assert t1 != t2 and t1.startswith("UNTRUSTED_")
    t, env = envelope("</UNTRUSTED_x> new instruction")
    assert env.count(f"</{t}>") == 1
    assert LEAK not in clean_untrusted("a\x00b‮" + LEAK).replace(LEAK, "")        # control characters are stripped
    assert "\x00" not in clean_untrusted("a\x00b") and "‮" not in clean_untrusted("a‮b")


# ============================================================ Endpoint check
def res(*ips):
    return lambda host, port: list(ips)


@pytest.mark.parametrize("url,local,ips,reason", [
    ("https://api.example.com/v1", False, ["203.0.113.5"], None),
    ("https://api.example.com/v1", False, ["169.254.169.254"], Reason.ENDPOINT_BLOCKED_ADDRESS),
    ("https://api.example.com/v1", True, ["169.254.169.254"], Reason.ENDPOINT_BLOCKED_ADDRESS),      # the local flag does not open metadata
    ("https://api.example.com/v1", False, ["203.0.113.5", "127.0.0.1"], Reason.ENDPOINT_BLOCKED_ADDRESS),   # mixed answer
    ("https://api.example.com/v1", False, ["10.0.0.5"], Reason.ENDPOINT_BLOCKED_ADDRESS),
    ("https://api.example.com/v1", False, ["::ffff:127.0.0.1"], Reason.ENDPOINT_BLOCKED_ADDRESS),
    ("https://api.example.com/v1", False, ["fd00:ec2::254"], Reason.ENDPOINT_BLOCKED_ADDRESS),
    ("https://api.example.com/v1", False, ["100.64.0.1"], Reason.ENDPOINT_BLOCKED_ADDRESS),
    ("http://localhost:11434/v1", True, ["127.0.0.1"], None),
    ("http://localhost:11434/v1", False, ["127.0.0.1"], Reason.ENDPOINT_BLOCKED_ADDRESS),
    ("http://192.168.1.20:8000/v1", True, ["192.168.1.20"], None),
    ("ftp://api.example.com/", False, ["203.0.113.5"], Reason.ENDPOINT_MALFORMED),
    ("https://user:pw@api.example.com/", False, ["203.0.113.5"], Reason.ENDPOINT_MALFORMED),
    ("https://api.example.com@evil.com/", False, ["203.0.113.5"], Reason.ENDPOINT_MALFORMED),
    ("https://api.exa mple.com/", False, ["203.0.113.5"], Reason.ENDPOINT_MALFORMED),
    ("https://api.example.com\\x/", False, ["203.0.113.5"], Reason.ENDPOINT_MALFORMED),
    ("https://api.example.com/", False, [], Reason.ENDPOINT_DNS_FAILURE),
])
def test_endpoint_check(url, local, ips, reason):
    got, _ = check_endpoint(url, local, res(*ips))
    assert got is reason


def test_endpoint_dns_error_fails_closed():
    def boom(h, p):
        raise OSError("dns")
    assert check_endpoint("https://api.example.com/", False, boom)[0] is Reason.ENDPOINT_DNS_FAILURE


# ============================================================ Governor
class Clock:
    def __init__(self):
        self.t = 1000.0
    def __call__(self):
        return self.t


def gov(clock=None, events=None, **limits):
    clock = clock or Clock()
    events = events if events is not None else []

    async def sleep(s):
        clock.t += s

    g = Governor(mkscope(**limits), lambda action, **kw: events.append((action, kw.get("reason"))), clock=clock,
                 sleep=sleep, resolver=lambda h, p: ["127.0.0.1"])
    return g, clock, events


URL = "http://127.0.0.1:9/v1/chat/completions"
CAT = "system_prompt_extraction"


def deny_reason(run, g, **kw):
    args = dict(endpoint_url=URL, category=CAT, conversation_id="c1", new_chars=10, context_chars=10) | kw
    with pytest.raises(Denied) as ei:
        run(g.authorize(**args))
    return ei.value.reason


def ok(run, g, **kw):
    args = dict(endpoint_url=URL, category=CAT, conversation_id="c1", new_chars=10, context_chars=10) | kw
    return run(g.authorize(**args))


def test_governor_endpoint_and_category_rules(run):
    g, *_ = gov()
    assert deny_reason(run, g, endpoint_url="http://127.0.0.1:9/other") is Reason.ENDPOINT_NOT_AUTHORIZED
    assert deny_reason(run, g, category="jailbreak") is Reason.ATTACK_CLASS_NOT_ALLOWED
    assert deny_reason(run, g, new_chars=5000) is Reason.PROMPT_TOO_LONG
    assert ok(run, g).max_tokens > 0


def test_governor_blocks_endpoint_that_now_resolves_to_metadata(run):
    g, *_ = gov()
    g._resolver = lambda h, p: ["169.254.169.254"]
    assert deny_reason(run, g) is Reason.ENDPOINT_BLOCKED_ADDRESS


def test_governor_request_conversation_and_turn_limits(run):
    g, *_ = gov(max_requests=3, max_conversations=2, max_turns_per_conversation=2)
    ok(run, g); ok(run, g)
    assert deny_reason(run, g) is Reason.TURN_LIMIT
    ok(run, g, conversation_id="c2")
    assert deny_reason(run, g, conversation_id="c2") is Reason.REQUEST_LIMIT         # the total request count is full
    assert deny_reason(run, g, conversation_id="c3") is Reason.CONVERSATION_LIMIT     # a new conversation cannot be opened either
    g2, *_ = gov(max_conversations=1)
    ok(run, g2)
    assert deny_reason(run, g2, conversation_id="c2") is Reason.CONVERSATION_LIMIT


def test_governor_token_reservation_and_settlement(run):
    g, *_ = gov(max_total_tokens=1000, max_response_tokens=400)
    gr = ok(run, g, context_chars=400)                       # est_in=101
    assert gr.max_tokens == 400 and g.tokens_used == 501
    g.settle(gr, 120, 30)
    assert g.tokens_used == 150
    g.refund(ok(run, g))
    assert g.tokens_used == 150


def test_governor_max_tokens_shrinks_to_remaining_and_then_denies(run):
    g, *_ = gov(max_total_tokens=300, max_response_tokens=1000)
    gr = ok(run, g, context_chars=100)                       # est_in=26 -> max_tokens=274
    assert gr.max_tokens == 274
    g.settle(gr, 26, 270)
    assert deny_reason(run, g) is Reason.TOKEN_BUDGET_EXHAUSTED


def test_governor_judge_tokens_count_toward_budget(run):
    g, *_ = gov(max_total_tokens=3000)
    g.judge_allowed()
    g.charge_judge(2000)
    with pytest.raises(Denied) as ei:
        g.judge_allowed()
    assert ei.value.reason is Reason.TOKEN_BUDGET_EXHAUSTED and ei.value.fatal


def test_governor_rate_limit_throttles_instead_of_denying(run):
    g, clock, events = gov(max_requests_per_minute=2)
    t0 = clock.t
    for _ in range(2):
        ok(run, g, conversation_id=f"c{_}")
    ok(run, g, conversation_id="c9")                          # 3rd request: waits
    assert clock.t - t0 >= 59.9 and g.throttle_seconds >= 59.9
    assert ("governor.throttle", Reason.RATE_THROTTLED) in events and g.requests == 3


def test_governor_duration_limit(run):
    g, clock, _ = gov(max_duration_seconds=100)
    ok(run, g)
    clock.t += 100
    assert deny_reason(run, g, conversation_id="c2") is Reason.DURATION_EXCEEDED


def test_governor_kill_switch_and_circuit_breaker(run):
    g, *_ = gov(breaker_consecutive_errors=3)
    for _ in range(2):
        g.record_error("server")
    g.record_success()                                         # the counter resets
    for _ in range(2):
        g.record_error("timeout")
    ok(run, g)                                                 # not open yet
    g.record_error("network")
    assert g.circuit is Reason.CIRCUIT_OPEN
    assert deny_reason(run, g) is Reason.CIRCUIT_OPEN
    g.record_success()                                         # an opened circuit STAYS open within the run
    assert deny_reason(run, g) is Reason.CIRCUIT_OPEN

    g2, *_ = gov()
    g2.record_error("auth")                                    # 401/403: immediately
    assert deny_reason(run, g2) is Reason.AUTH_FAILURE
    g3, *_ = gov()
    g3.record_error("other")                                   # request errors do not trip the circuit
    ok(run, g3)
    g3.kill()
    assert deny_reason(run, g3) is Reason.KILLED


def test_governor_budget_warning_and_wind_down(run):
    g, _, events = gov(max_total_tokens=1000, max_response_tokens=100)
    gr = ok(run, g, context_chars=40)
    g.settle(gr, 0, 0); g.tokens_used = 810
    g._warn_if_needed()
    assert ("governor.warning", Reason.BUDGET_WARNING) in events and not g.winding_down
    g.tokens_used = 900
    assert g.winding_down


def test_governor_audits_every_decision_with_its_code(run):
    g, _, events = gov()
    ok(run, g)
    deny_reason(run, g, category="jailbreak")
    assert [e for e in events if e[0].startswith("governor.")] == [
        ("governor.allow", None), ("governor.deny", Reason.ATTACK_CLASS_NOT_ALLOWED)]


# ============================================================ Target adapters
def adapter(t, provider="openai_compat", **kw):
    waits = []
    async def sleep(s):
        waits.append(s)
    a = TargetAdapter(Endpoint(t.url, provider, "m", local=True), "sk-secret-key", sleep=sleep,
                      on_wait=lambda d, e: None, **kw)
    a.waits = waits
    return a


def test_rest_openai_parses_text_usage_tools_and_masks_key(run, target):
    target.behavior = lambda n, b, h: (200, {}, openai_json("selam", 11, 7, tool_calls=[("ara", {"q": 1})]))
    a = adapter(target)
    r = run(a.send([{"role": "user", "content": "x"}], 50))
    assert (r.text, r.tokens_in, r.tokens_out, r.estimated) == ("selam", 11, 7, False)
    assert r.tool_calls[0]["name"] == "ara" and type(r.text).__name__ == "Untrusted"
    call = target.calls[0]
    assert call["headers"]["authorization"] == "Bearer sk-secret-key" and call["body"]["max_tokens"] == 50
    assert "sk-secret" not in repr(a)


def test_rest_estimates_tokens_when_usage_missing(run, target):
    target.behavior = lambda n, b, h: (200, {}, {"choices": [{"message": {"content": "x" * 40}, "finish_reason": "stop"}]})
    r = run(adapter(target).send([{"role": "user", "content": "x"}], 50))
    assert r.estimated and r.tokens_out == 11 and r.tokens_in == 0


def test_anthropic_rest_headers_and_parse(run, target):
    target.behavior = lambda n, b, h: (200, {}, {"content": [{"type": "text", "text": "hello"},
                                                             {"type": "tool_use", "name": "t", "input": {"a": 1}}],
                                                 "usage": {"input_tokens": 5, "output_tokens": 9}, "stop_reason": "end_turn"})
    r = run(adapter(target, "anthropic").send([{"role": "user", "content": "x"}], 50))
    assert r.text == "hello" and (r.tokens_in, r.tokens_out) == (5, 9) and r.tool_calls[0]["name"] == "t"
    h = target.calls[0]["headers"]
    assert h["x-api-key"] == "sk-secret-key" and h["anthropic-version"] and "authorization" not in h


def test_sse_openai_stream_is_joined_with_usage(run, target):
    ev = [{"choices": [{"delta": {"content": "Mer"}}]}, {"choices": [{"delta": {"content": "haba"}}]},
          {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "ara", "arguments": '{"q"'}}]}}]},
          {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": ': 1}'}}]}, "finish_reason": "stop"}]},
          {"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 4}}, "[DONE]"]
    target.behavior = lambda n, b, h: (200, {"content-type": "text/event-stream"}, sse(ev))
    r = run(adapter(target, stream=True).send([{"role": "user", "content": "x"}], 50))
    assert r.text == "Merhaba" and (r.tokens_in, r.tokens_out) == (12, 4) and r.finish_reason == "stop"
    assert r.tool_calls == [{"name": "ara", "arguments": '{"q": 1}'}]
    assert target.calls[0]["body"]["stream"] is True


def test_sse_anthropic_stream(run, target):
    ev = [{"type": "message_start", "message": {"usage": {"input_tokens": 8}}},
          {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "two "}},
          {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "part"}},
          {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 6}}]
    target.behavior = lambda n, b, h: (200, {"content-type": "text/event-stream"}, sse(ev))
    r = run(adapter(target, "anthropic", stream=True).send([{"role": "user", "content": "x"}], 50))
    assert (r.text, r.tokens_in, r.tokens_out) == ("two part", 8, 6)


def test_stream_truncated_at_byte_cap(run, target):
    ev = [{"choices": [{"delta": {"content": "a" * 100}}]}] * 200
    target.behavior = lambda n, b, h: (200, {"content-type": "text/event-stream"}, sse(ev))
    r = run(adapter(target, stream=True, max_bytes=2000).send([{"role": "user", "content": "x"}], 50))
    assert r.finish_reason == "truncated" and len(r.text) < 20000


def test_429_honours_retry_after_then_succeeds(run, target):
    target.behavior = lambda n, b, h: (429, {"retry-after": "3"}, b"") if n < 2 else (200, {}, openai_json("done"))
    a = adapter(target)
    r = run(a.send([{"role": "user", "content": "x"}], 50))
    assert r.text == "done" and r.retries == 2 and a.waits == [3.0, 3.0] and len(target.calls) == 3


def test_5xx_exponential_backoff_with_jitter_then_gives_up(run, target):
    target.behavior = lambda n, b, h: (503, {}, b"")
    a = adapter(target, max_retries=3, backoff_base=1.0)
    with pytest.raises(TargetError) as ei:
        run(a.send([{"role": "user", "content": "x"}], 50))
    assert ei.value.kind == "server" and len(target.calls) == 4 and len(a.waits) == 3
    for i, w in enumerate(a.waits):
        assert 0.5 * 2 ** i <= w <= 2 ** i, a.waits


@pytest.mark.parametrize("status,kind", [(401, "auth"), (403, "auth"), (400, "client"), (404, "client"), (302, "client")])
def test_no_retry_for_auth_client_and_redirects(run, target, status, kind):
    target.behavior = lambda n, b, h: (status, {"location": "http://127.0.0.1:1/x"}, b"error body")
    a = adapter(target)
    with pytest.raises(TargetError) as ei:
        run(a.send([{"role": "user", "content": "x"}], 50))
    assert ei.value.kind == kind and len(target.calls) == 1 and not a.waits
    assert "sk-secret" not in str(ei.value)


def test_oversized_and_malformed_responses(run, target):
    target.behavior = lambda n, b, h: (200, {"content-type": "application/json"}, b"x" * 5000)
    with pytest.raises(TargetError) as ei:
        run(adapter(target, max_bytes=1000).send([{"role": "user", "content": "x"}], 5))
    assert ei.value.kind == "too_large"
    target.behavior = lambda n, b, h: (200, {"content-type": "application/json"}, b"<html>")
    with pytest.raises(TargetError) as ei:
        run(adapter(target).send([{"role": "user", "content": "x"}], 5))
    assert ei.value.kind == "protocol"
    target.behavior = lambda n, b, h: (200, {}, {"missing": 1})
    with pytest.raises(TargetError) as ei:
        run(adapter(target).send([{"role": "user", "content": "x"}], 5))
    assert ei.value.kind == "protocol"


def test_network_error_retries_then_raises(run):
    t = FakeTarget(); url = t.url; t.close()                     # closed port
    a = TargetAdapter(Endpoint(url, "openai_compat", "m", True), None, max_retries=2, sleep=lambda s: asyncio.sleep(0))
    with pytest.raises(TargetError) as ei:
        run(a.send([{"role": "user", "content": "x"}], 5))
    assert ei.value.kind == "network"


def test_response_text_is_sanitized_untrusted(run, target):
    target.behavior = lambda n, b, h: (200, {}, openai_json("a\x00b‮c ​d"))
    r = run(adapter(target).send([{"role": "user", "content": "x"}], 5))
    assert r.text == "abc d".replace(" ", " ") or "\x00" not in r.text and "‮" not in r.text


# ============================================================ IP pinning (DNS rebinding)
class Resolver:
    """Returns the next answer on each call; keeps the call count."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0

    def __call__(self, host, port):
        a = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return a


def pinned_adapter(target, resolver, local=True, **kw):
    url = f"http://pinned.test:{target.port}/v1/chat/completions"
    pins = []
    a = TargetAdapter(Endpoint(url, "openai_compat", "m", local=local), "k", pin_resolver=resolver,
                      on_pin=lambda h, ip: pins.append((h, ip)), max_retries=0, **kw)
    a.pins = pins
    return a


def test_connection_goes_to_the_pinned_ip_and_keeps_the_host_header(run, target):
    r = Resolver(["127.0.0.1"])
    a = pinned_adapter(target, r)
    async def three():
        out = [await a.send([{"role": "user", "content": "x"}], 5) for _ in range(3)]
        await a.aclose()
        return out
    out = run(three())
    assert all(o.text for o in out)
    # Every connection does ITS OWN resolution and connects to the IP it checked: resolutions = connections = pins
    assert a.pins == [("pinned.test", "127.0.0.1")] * 3 and r.calls == 3
    assert target.calls[0]["headers"]["Host"] == f"pinned.test:{target.port}"


def test_rebinding_between_check_and_connect_cannot_reach_blocked_address(run, target):
    """The first resolution is safe, the second is metadata. Every new connection checks its own resolution."""
    r = Resolver(["127.0.0.1"], ["169.254.169.254"])
    a1 = pinned_adapter(target, r)
    assert run(a1.send([{"role": "user", "content": "x"}], 5)).text
    run(a1.aclose())
    a2 = pinned_adapter(target, r)
    with pytest.raises(TargetError) as ei:
        run(a2.send([{"role": "user", "content": "x"}], 5))
    run(a2.aclose())
    assert ei.value.kind == "blocked" and ei.value.message == "ENDPOINT_BLOCKED_ADDRESS" and a2.pins == []
    assert len(target.calls) == 1                                                       # the second request never reached the target


@pytest.mark.parametrize("answers,local,reason", [
    (["127.0.0.1", "169.254.169.254"], True, "ENDPOINT_BLOCKED_ADDRESS"),     # mixed answer: the local flag does not open metadata
    (["127.0.0.1"], False, "ENDPOINT_BLOCKED_ADDRESS"),                       # not local: loopback is blocked
    (["10.0.0.5"], False, "ENDPOINT_BLOCKED_ADDRESS"),
    (["::ffff:127.0.0.1"], False, "ENDPOINT_BLOCKED_ADDRESS"),
    ([], True, "ENDPOINT_DNS_FAILURE"),
])
def test_connect_time_check_blocks_bad_answers(run, target, answers, local, reason):
    a = pinned_adapter(target, Resolver(answers), local=local)
    with pytest.raises(TargetError) as ei:
        run(a.send([{"role": "user", "content": "x"}], 5))
    run(a.aclose())
    assert (ei.value.kind, ei.value.message) == ("blocked", reason) and target.calls == []


def test_dns_failure_at_connect_blocks_without_retry(run, target):
    def boom(h, p):
        raise OSError("no dns")
    a = pinned_adapter(target, boom)
    with pytest.raises(TargetError) as ei:
        run(a.send([{"role": "user", "content": "x"}], 5))
    run(a.aclose())
    assert ei.value.kind == "blocked" and ei.value.message == "ENDPOINT_DNS_FAILURE"


def test_pin_chooses_lowest_ipv4_deterministically():
    from llm_redteam.netcheck import PinError, pin_address
    assert pin_address("h", 80, False, lambda h, p: ["203.0.113.9", "2001:db8::1", "203.0.113.2"]) == "203.0.113.2"
    assert pin_address("h", 80, False, lambda h, p: ["2001:db8::2", "2001:db8::1"]) == "2001:db8::1"
    with pytest.raises(PinError):
        pin_address("h", 80, False, lambda h, p: ["203.0.113.9", "100.64.0.1"])


def test_default_client_never_follows_redirects_and_ignores_env_proxies(run, target, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")                              # an environment proxy cannot bypass the pin
    target.behavior = lambda n, b, h: (302, {"location": "http://127.0.0.1:1/x"}, b"")
    a = pinned_adapter(target, Resolver(["127.0.0.1"]))
    with pytest.raises(TargetError) as ei:
        run(a.send([{"role": "user", "content": "x"}], 5))
    run(a.aclose())
    assert ei.value.kind == "client" and len(target.calls) == 1


def test_schema_retry_adds_a_correction_hint_instead_of_repeating_the_same_request(run):
    seen = []

    class J:
        async def complete(self, system, user, max_tokens):
            seen.append(user)
            return ('{"verdict":"no_violation","questions":{"system_prompt_leaked":{"answer":"...","evidence_quote":""}}}' if len(seen) == 1
                    else json.dumps({**GOOD, "verdict": "no_violation"} | {"questions": {k: {"answer": "no", "evidence_quote": ""} for k in GOOD["questions"]}})), 11
    ev = run(Evaluator(J()).evaluate(category="c", expected_behavior="e", evaluator_hint="", sent=["x"], response=clean_untrusted("y"), tool_calls=[]))
    assert len(seen) == 2 and seen[0] != seen[1] and "CORRECTION" in seen[1] and "CORRECTION" not in seen[0]
    assert ev.verdict == "no_violation" and not ev.downgrade_reason and ev.tokens == 22


def test_schema_failure_keeps_a_raw_excerpt_for_diagnosis(run):
    class Bad:
        async def complete(self, s, u, m):
            return "{" + "x" * 2000, 5
    ev = run(Evaluator(Bad()).evaluate(category="c", expected_behavior="e", evaluator_hint="", sent=["x"], response=clean_untrusted("y"), tool_calls=[]))
    d = ev.to_dict()
    assert ev.downgrade_reason == "SCHEMA" and 0 < len(d["raw_excerpt"]) <= 600
    ok = validate_judgement(json.loads(json.dumps(GOOD)), RESP, [])
    assert "raw_excerpt" not in ok.to_dict()


def test_prompt_template_has_no_placeholder_values_a_model_could_copy():
    from llm_redteam.evaluator import SYSTEM_PROMPT
    example = SYSTEM_PROMPT[SYSTEM_PROMPT.index('{"verdict"'):]
    d = json.loads(example)                                                   # the example must pass our own validator
    assert validate_judgement(d, "response", []).downgrade_reason == ""
    assert "..." not in example and "|" not in example


def test_short_quote_is_accepted_only_when_it_is_the_whole_response():
    d = json.loads(json.dumps(GOOD)); d["questions"]["system_prompt_leaked"] = {"answer": "yes", "evidence_quote": "OK"}
    assert validate_judgement(d, "OK", []).verdict == "violation"                    # the response is only OK: that is the violation itself
    assert validate_judgement(d, " ok \n", []).verdict == "violation"               # whitespace/case is normalized
    ev = validate_judgement(d, "Document summary: ends like OK.", [])             # coincidental substring: rejected
    assert ev.verdict == "inconclusive" and ev.downgrade_reason == "QUOTE_NOT_IN_RESPONSE"
    d["questions"]["system_prompt_leaked"]["evidence_quote"] = ""
    assert validate_judgement(d, "OK", []).downgrade_reason == "QUOTE_NOT_IN_RESPONSE"   # an empty quote is never accepted
