"""
Scope signature (Phase 0-1): server key (HMAC-SHA256) + approver identity + timestamp + scope digest.
Signing (sign) and verification (verify) are SEPARATE functions. Without a key no signature is produced: there is no silent fallback.
In Phase 2 the approver's own Ed25519 signature is added; the server signature then remains for integrity only.
"""
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

SIG_DOMAIN = "reconloop-llmscope-sig-v1"
MIN_KEY_BYTES = 32


class SigningError(Exception):
    pass


def iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        raise SigningError("the timestamp must include a time zone")
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds")


@dataclass
class Keyring:
    keys: dict[str, bytes] = field(default_factory=dict)
    active: str | None = None

    def __post_init__(self):
        for kid, key in self.keys.items():
            if len(key) < MIN_KEY_BYTES:
                raise SigningError(f"signing key '{kid}' is too short (at least {MIN_KEY_BYTES} bytes)")
        if self.active is not None and self.active not in self.keys:
            raise SigningError(f"active key '{self.active}' is not in the keyring")

    @classmethod
    def from_env(cls, env=os.environ) -> "Keyring":
        """REDWITNESS_SCOPE_KEYS='k1:<hex>,k2:<hex>'  REDWITNESS_SCOPE_ACTIVE_KEY='k2'"""
        keys = {}
        for part in filter(None, (p.strip() for p in env.get("REDWITNESS_SCOPE_KEYS", "").split(","))):
            kid, _, hexkey = part.partition(":")
            try:
                keys[kid] = bytes.fromhex(hexkey)
            except ValueError:
                raise SigningError(f"signing key '{kid}' is not valid hex") from None
        active = env.get("REDWITNESS_SCOPE_ACTIVE_KEY") or (next(iter(keys)) if len(keys) == 1 else None)
        return cls(keys, active)

    @property
    def can_sign(self) -> bool:
        return self.active is not None


def _message(key_id: str, digest: bytes, approved_by: str, approved_at: datetime) -> bytes:
    return "\x1f".join([SIG_DOMAIN, key_id, digest.hex(), str(approved_by), iso(approved_at)]).encode()


def sign(keyring: Keyring, digest: bytes, approved_by: str, approved_at: datetime) -> tuple[str, bytes]:
    if not keyring.can_sign:
        raise SigningError("the server signing key is not configured")
    if len(digest) != 32:
        raise SigningError("the scope digest must be 32 bytes")
    kid = keyring.active
    return kid, hmac.new(keyring.keys[kid], _message(kid, digest, approved_by, approved_at), hashlib.sha256).digest()


def verify(keyring: Keyring, key_id: str, signature: bytes, digest: bytes,
           approved_by: str, approved_at: datetime) -> None:
    """Returns silently when valid, otherwise raises SigningError. The caller must have RECOMPUTED `digest`."""
    key = keyring.keys.get(key_id)
    if key is None:
        raise SigningError(f"signing key '{key_id}' is not defined on this server")
    if not signature:
        raise SigningError("the scope is not signed")
    expected = hmac.new(key, _message(key_id, digest, approved_by, approved_at), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, bytes(signature)):
        raise SigningError("the signature does not match the scope content")
