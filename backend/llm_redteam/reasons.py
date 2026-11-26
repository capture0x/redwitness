"""
Decision / refusal codes. Every refusal has its own code, belongs to a category and is explained in plain language.
The UI answers "why was this refused?" with EXPLAIN; the audit log stores code and category in separate columns.
"""
from enum import Enum


class Reason(str, Enum):
    OK = "OK"
    # scope_state
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_SIGNATURE_INVALID = "SCOPE_SIGNATURE_INVALID"
    SCOPE_REVOKED = "SCOPE_REVOKED"
    SCOPE_EXPIRED = "SCOPE_EXPIRED"
    SCOPE_SUPERSEDED = "SCOPE_SUPERSEDED"
    # endpoint
    ENDPOINT_NOT_AUTHORIZED = "ENDPOINT_NOT_AUTHORIZED"
    ENDPOINT_MALFORMED = "ENDPOINT_MALFORMED"
    ENDPOINT_BLOCKED_ADDRESS = "ENDPOINT_BLOCKED_ADDRESS"
    ENDPOINT_DNS_FAILURE = "ENDPOINT_DNS_FAILURE"
    # attack_class
    ATTACK_CLASS_NOT_ALLOWED = "ATTACK_CLASS_NOT_ALLOWED"
    TOOL_ABUSE_NOT_ATTESTED = "TOOL_ABUSE_NOT_ATTESTED"
    MULTIMODAL_NOT_ALLOWED = "MULTIMODAL_NOT_ALLOWED"
    BRANCHING_NOT_ALLOWED = "BRANCHING_NOT_ALLOWED"
    CARRIER_CANARY_BLOCKED = "CARRIER_CANARY_BLOCKED"
    # limits
    TOKEN_BUDGET_EXHAUSTED = "TOKEN_BUDGET_EXHAUSTED"
    REQUEST_LIMIT = "REQUEST_LIMIT"
    CONVERSATION_LIMIT = "CONVERSATION_LIMIT"
    TURN_LIMIT = "TURN_LIMIT"
    PROMPT_TOO_LONG = "PROMPT_TOO_LONG"
    DURATION_EXCEEDED = "DURATION_EXCEEDED"
    RATE_THROTTLED = "RATE_THROTTLED"      # not a refusal: the request was held
    BUDGET_WARNING = "BUDGET_WARNING"      # not a refusal: threshold warning
    # control
    KILLED = "KILLED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    AUTH_FAILURE = "AUTH_FAILURE"
    ACCESS_DENIED = "ACCESS_DENIED"


CATEGORY = {
    Reason.OK: "allow",
    Reason.SCOPE_NOT_FOUND: "scope_state", Reason.SCOPE_SIGNATURE_INVALID: "scope_state",
    Reason.SCOPE_REVOKED: "scope_state", Reason.SCOPE_EXPIRED: "scope_state",
    Reason.SCOPE_SUPERSEDED: "scope_state",
    Reason.ENDPOINT_NOT_AUTHORIZED: "endpoint", Reason.ENDPOINT_MALFORMED: "endpoint",
    Reason.ENDPOINT_BLOCKED_ADDRESS: "endpoint", Reason.ENDPOINT_DNS_FAILURE: "endpoint",
    Reason.ATTACK_CLASS_NOT_ALLOWED: "attack_class", Reason.TOOL_ABUSE_NOT_ATTESTED: "attack_class", Reason.MULTIMODAL_NOT_ALLOWED: "attack_class", Reason.BRANCHING_NOT_ALLOWED: "attack_class", Reason.CARRIER_CANARY_BLOCKED: "control",
    Reason.TOKEN_BUDGET_EXHAUSTED: "limits", Reason.REQUEST_LIMIT: "limits",
    Reason.CONVERSATION_LIMIT: "limits", Reason.TURN_LIMIT: "limits",
    Reason.PROMPT_TOO_LONG: "limits", Reason.RATE_THROTTLED: "limits",
    Reason.DURATION_EXCEEDED: "limits", Reason.BUDGET_WARNING: "limits",
    Reason.KILLED: "control", Reason.CIRCUIT_OPEN: "control", Reason.AUTH_FAILURE: "control",
    Reason.ACCESS_DENIED: "control",
}

CATEGORY_LABEL = {
    "allow": "Allowed", "scope_state": "Scope state", "endpoint": "Endpoint",
    "attack_class": "Attack class", "limits": "Limits", "control": "Control",
}

# Codes that end the whole run (continuing would be pointless or unsafe)
FATAL = {Reason.SCOPE_NOT_FOUND, Reason.SCOPE_SIGNATURE_INVALID, Reason.SCOPE_REVOKED,
         Reason.SCOPE_EXPIRED, Reason.SCOPE_SUPERSEDED, Reason.ENDPOINT_NOT_AUTHORIZED,
         Reason.ENDPOINT_BLOCKED_ADDRESS, Reason.ENDPOINT_MALFORMED, Reason.TOKEN_BUDGET_EXHAUSTED,
         Reason.REQUEST_LIMIT, Reason.CONVERSATION_LIMIT, Reason.KILLED, Reason.DURATION_EXCEEDED,
         Reason.CIRCUIT_OPEN, Reason.AUTH_FAILURE}

EXPLAIN = {
    Reason.OK: "The request is within scope and limits; it was sent to the target.",
    Reason.SCOPE_NOT_FOUND: "Scope not found. No run can start without a signed scope.",
    Reason.SCOPE_SIGNATURE_INVALID: "The scope is unsigned or its signature could not be verified (content changed after signing, wrong key, "
                                    "or no signature). The run will not start.",
    Reason.SCOPE_REVOKED: "The scope has been revoked.",
    Reason.SCOPE_EXPIRED: "You are outside the scope's validity period.",
    Reason.SCOPE_SUPERSEDED: "A newer version of this scope exists; runs cannot be started with an old version.",
    Reason.ENDPOINT_NOT_AUTHORIZED: "This endpoint is not authorized in the scope. Requests may only be sent to the exact URLs listed in the scope.",
    Reason.ENDPOINT_MALFORMED: "The endpoint URL is invalid (scheme, user info or malformed address).",
    Reason.ENDPOINT_BLOCKED_ADDRESS: "The endpoint resolves to an address that must not be reached (cloud metadata, link-local, internal network or "
                                     "loopback). Loopback/internal addresses are only usable when the endpoint is explicitly authorized as 'local'.",
    Reason.ENDPOINT_DNS_FAILURE: "The endpoint name could not be resolved; requests are never sent to an unverifiable target.",
    Reason.ATTACK_CLASS_NOT_ALLOWED: "This test class is not authorized in the scope.",
    Reason.TOOL_ABUSE_NOT_ATTESTED: "Tool-abuse testing requires a written attestation that the target's tools run in a test/sandbox environment.",
    Reason.CARRIER_CANARY_BLOCKED: "An operator canary value was found inside a carrier file (OCR or metadata). The file was not sent: the canary would reach the target through the file and a later leak could not be told apart.",
    Reason.MULTIMODAL_NOT_ALLOWED: "Sending image or audio files to the target requires 'multimodal_allowed' in the signed scope.",
    Reason.BRANCHING_NOT_ALLOWED: "Choosing the next message from the target's reply (a branching case) requires 'branching_allowed' in the signed scope.",
    Reason.TOKEN_BUDGET_EXHAUSTED: "The run's total token budget is used up (target input+output and judge tokens included).",
    Reason.REQUEST_LIMIT: "The total number of requests allowed to the target has been reached.",
    Reason.CONVERSATION_LIMIT: "The total number of conversations that may be opened has been reached.",
    Reason.TURN_LIMIT: "This conversation reached the allowed number of turns; a new conversation is needed.",
    Reason.PROMPT_TOO_LONG: "The prompt exceeds the maximum length set in the scope.",
    Reason.RATE_THROTTLED: "The per-minute request limit was reached, so the request was held (not refused).",
    Reason.KILLED: "The kill switch is active; all operations were stopped.",
    Reason.DURATION_EXCEEDED: "The run's maximum duration was reached.",
    Reason.BUDGET_WARNING: "Most of the budget has been used; no new tests will start, running ones will finish.",
    Reason.CIRCUIT_OPEN: "The circuit breaker opened because the target kept returning errors; the run was stopped. "
                         "Resuming is an operator decision.",
    Reason.AUTH_FAILURE: "The target rejected the API key (401/403). It was not retried and the run was stopped.",
    Reason.ACCESS_DENIED: "The user's role is insufficient for this action; nothing was done.",
}
assert set(CATEGORY) == set(Reason) == set(EXPLAIN), "every code needs a category and an explanation"


def category(reason: Reason) -> str:
    return CATEGORY[reason]
