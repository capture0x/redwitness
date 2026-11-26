"""
LLMScope: the document that authorizes an LLM target in a LIMITED and SIGNED way.
Not IP/domain based: endpoint authorization + attack class + token/request/rate/conversation limits.
The digest is computed from the canonical JSON of the content; every field that affects the scope is included.
"""
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from .signing import iso

ATTACK_CLASSES = ("prompt_injection_direct", "prompt_injection_indirect", "jailbreak",
                  "system_prompt_extraction", "tool_abuse", "data_leakage", "unsafe_output", "misinformation", "resource_consumption")
# Analysis classes (privacy / extraction / vector store). They are authorized in the signed scope like any other class, but they are NOT test-library
# categories: they run through the dedicated analysis modules, each with its own hard query/token ceiling on top of the scope limits.
ANALYSIS_CLASSES = ("model_extraction", "membership_inference", "vector_store_exposure")
VECTOR_PROVIDERS = ("chroma", "qdrant", "weaviate")
CLASS_LABEL = {
    "model_extraction": "Model extraction (budgeted)",
    "membership_inference": "Membership inference",
    "vector_store_exposure": "Vector store exposure (read-only)",
    "prompt_injection_direct": "Direct prompt injection",
    "prompt_injection_indirect": "Indirect prompt injection",
    "jailbreak": "Jailbreak",
    "system_prompt_extraction": "System prompt extraction",
    "tool_abuse": "Tool abuse",
    "data_leakage": "Data leakage",
    "unsafe_output": "Unsafe output handling",
    "misinformation": "Misinformation / hallucination",
    "resource_consumption": "Resource consumption",
}
PROVIDERS = ("openai_compat", "anthropic")
ALL_PROVIDERS = PROVIDERS + VECTOR_PROVIDERS

# Hard upper bounds: a typo must not create an "unlimited" scope
HARD_MAX = dict(max_total_tokens=5_000_000, max_requests=5000, max_requests_per_minute=600,
                max_conversations=1000, max_turns_per_conversation=50, max_prompt_chars=20_000,
                max_response_tokens=8192, max_duration_seconds=86_400, breaker_consecutive_errors=50)
MAX_VALIDITY = timedelta(days=90)
ADAPTIVE_ROUNDS_DEFAULT, ADAPTIVE_ROUNDS_MAX = 3, 5
CAMPAIGN_SESSIONS_DEFAULT, CAMPAIGN_SESSIONS_MAX = 5, 10


class ScopeInputError(ValueError):
    """The scope draft is invalid; the message is shown to the user."""


@dataclass(frozen=True)
class Endpoint:
    url: str
    provider: str = "openai_compat"
    model: str = ""
    local: bool = False                 # loopback/private-network permission: must be EXPLICITLY authorized
    api_key_env: str | None = None      # the key itself is not stored in the scope
    ingest_url: str | None = None       # the target's document/knowledge-base upload endpoint (for indirect tests; must be authorized)
    ingest_delete_url: str | None = None  # endpoint that DELETES the uploaded document (cleanup). The '{name}' placeholder is replaced with the document name; otherwise the DELETE body is {"name": ...}


@dataclass(frozen=True)
class Limits:
    max_total_tokens: int = 200_000
    max_requests: int = 200
    max_requests_per_minute: int = 30
    max_conversations: int = 40
    max_turns_per_conversation: int = 6
    max_prompt_chars: int = 4000
    max_response_tokens: int = 1024
    max_duration_seconds: int = 1800
    breaker_consecutive_errors: int = 5     # consecutive 5xx/network errors/timeouts -> circuit breaker


@dataclass
class LLMScope:
    name: str
    client: str
    authorized_by: str
    authorization_doc_sha256: bytes
    valid_from: datetime
    valid_until: datetime
    endpoints: list[Endpoint]
    attack_classes: list[str]
    limits: Limits = field(default_factory=Limits)
    tool_abuse_attested: bool = False
    adaptive_allowed: bool = False          # may the Attacker LLM rewrite refused cases in runs under this scope?
    max_adaptive_rounds: int = ADAPTIVE_ROUNDS_DEFAULT   # upper bound for rewrite rounds per case (the library's own max_rounds is capped by it)
    multimodal_allowed: bool = False        # may runs under this scope send library-supplied image/audio files to the target?
    campaign_allowed: bool = False          # may a multi-session campaign be run under this scope?
    branching_allowed: bool = False         # may a run pick the next message from the target's reply (rule-based branching cases)?
    max_campaign_sessions: int = CAMPAIGN_SESSIONS_DEFAULT   # upper bound for the sessions of one campaign
    lineage_id: str = ""
    version: int = 1

    def validate(self) -> None:
        for f in ("name", "client", "authorized_by"):
            if not str(getattr(self, f)).strip():
                raise ScopeInputError(f"'{f}' bos olamaz")
        if len(self.authorization_doc_sha256) != 32:
            raise ScopeInputError("authorization document digest (SHA-256, 32 bytes) is required")
        if self.valid_until <= self.valid_from:
            raise ScopeInputError("the end date must be after the start date")
        if self.valid_until - self.valid_from > MAX_VALIDITY:
            raise ScopeInputError("a scope can be valid for at most 90 days")
        if not self.endpoints:
            raise ScopeInputError("at least one endpoint must be authorized")
        seen = set()
        for e in self.endpoints:
            if e.provider not in ALL_PROVIDERS:
                raise ScopeInputError(f"unknown provider: {e.provider}")
            if not e.url.startswith(("http://", "https://")):
                raise ScopeInputError(f"the endpoint URL must be http(s): {e.url!r}")
            for fld in ("ingest_url", "ingest_delete_url"):
                v = getattr(e, fld)
                if v is not None and not v.startswith(("http://", "https://")):
                    raise ScopeInputError(f"{fld} must be http(s): {v!r}")
            if e.ingest_delete_url and not e.ingest_url:
                raise ScopeInputError("ingest_delete_url can only be defined together with ingest_url")
            if e.provider in VECTOR_PROVIDERS and (e.ingest_url or e.ingest_delete_url):
                raise ScopeInputError("a vector store endpoint cannot define ingest_url / ingest_delete_url")
            if e.provider not in VECTOR_PROVIDERS and not e.model.strip():
                raise ScopeInputError(f"a model name is required for the endpoint: {e.url}")
            if e.url in seen:
                raise ScopeInputError(f"endpoint defined twice: {e.url}")
            seen.add(e.url)
        if not self.attack_classes:
            raise ScopeInputError("at least one attack class must be selected")
        for c in self.attack_classes:
            if c not in ATTACK_CLASSES + ANALYSIS_CLASSES:
                raise ScopeInputError(f"unknown attack class: {c}")
        if "tool_abuse" in self.attack_classes and not self.tool_abuse_attested:
            raise ScopeInputError("tool abuse requires the 'tools run in a test environment' attestation")
        r = self.max_adaptive_rounds
        if not isinstance(r, int) or isinstance(r, bool) or not 1 <= r <= ADAPTIVE_ROUNDS_MAX:
            raise ScopeInputError(f"max_adaptive_rounds must be an integer between 1 and {ADAPTIVE_ROUNDS_MAX}")
        s = self.max_campaign_sessions
        if not isinstance(s, int) or isinstance(s, bool) or not 1 <= s <= CAMPAIGN_SESSIONS_MAX:
            raise ScopeInputError(f"max_campaign_sessions must be an integer between 1 and {CAMPAIGN_SESSIONS_MAX}")
        for k, mx in HARD_MAX.items():
            v = getattr(self.limits, k)
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= mx:
                raise ScopeInputError(f"{k} must be between 1 and {mx}")

    def content(self) -> dict:
        """The signed content. Forgetting to add a new field HERE means that field can be changed without invalidating the signature."""
        c = {
            "v": 1, "lineage_id": self.lineage_id, "version": self.version,
            "name": self.name, "client": self.client, "authorized_by": self.authorized_by,
            "authorization_doc_sha256": bytes(self.authorization_doc_sha256).hex(),
            "valid_from": iso(self.valid_from), "valid_until": iso(self.valid_until),
            "endpoints": sorted((asdict(e) for e in self.endpoints), key=lambda d: d["url"]),
            "attack_classes": sorted(self.attack_classes),
            "limits": asdict(self.limits),
            "tool_abuse_attested": bool(self.tool_abuse_attested),
        }
        # Added only when granted: a scope without them means "adaptive not allowed", so scopes signed before these fields existed keep
        # their digest and their signature stays valid. Granting adaptive mode changes the digest, so the grant is covered by the signature.
        if self.adaptive_allowed:
            c["adaptive_allowed"], c["max_adaptive_rounds"] = True, int(self.max_adaptive_rounds)
        if self.multimodal_allowed:                                   # same rule: only added when granted, so older signatures stay valid
            c["multimodal_allowed"] = True
        if self.campaign_allowed:
            c["campaign_allowed"], c["max_campaign_sessions"] = True, int(self.max_campaign_sessions)
        if self.branching_allowed:                                    # only added when granted, so older signatures stay valid
            c["branching_allowed"] = True
        return c

    def canonical(self) -> bytes:
        return json.dumps(self.content(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical()).digest()

    def endpoint(self, url: str) -> Endpoint | None:
        return next((e for e in self.endpoints if e.url == url), None)

    @classmethod
    def from_content(cls, c: dict) -> "LLMScope":
        return cls(
            name=c["name"], client=c["client"], authorized_by=c["authorized_by"],
            authorization_doc_sha256=bytes.fromhex(c["authorization_doc_sha256"]),
            valid_from=datetime.fromisoformat(c["valid_from"]), valid_until=datetime.fromisoformat(c["valid_until"]),
            endpoints=[Endpoint(**e) for e in c["endpoints"]], attack_classes=list(c["attack_classes"]),
            limits=Limits(**c["limits"]), tool_abuse_attested=c["tool_abuse_attested"],
            adaptive_allowed=bool(c.get("adaptive_allowed", False)), max_adaptive_rounds=c.get("max_adaptive_rounds", ADAPTIVE_ROUNDS_DEFAULT),
            multimodal_allowed=bool(c.get("multimodal_allowed", False)), campaign_allowed=bool(c.get("campaign_allowed", False)),
            max_campaign_sessions=c.get("max_campaign_sessions", CAMPAIGN_SESSIONS_DEFAULT), branching_allowed=bool(c.get("branching_allowed", False)),
            lineage_id=c["lineage_id"], version=c["version"])
