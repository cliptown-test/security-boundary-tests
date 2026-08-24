from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath


class BoundaryViolation(ValueError):
    pass


PROXIMITY_ENVELOPE_FIELDS = frozenset(
    {
        "protocol",
        "message_kind",
        "message_id",
        "session_id",
        "sequence",
        "issued_at_unix_ms",
        "expires_at_unix_ms",
        "sender_device_id",
        "recipient_device_id",
        "scope",
        "ciphertext",
        "ciphertext_sha256",
        "signing_key_id",
        "signature",
    }
)
PROXIMITY_FORBIDDEN_FIELDS = frozenset(
    {
        "access_token",
        "assurance_claim",
        "biometric",
        "factor_result",
        "id_token",
        "otp",
        "password",
        "pin",
        "private_key",
        "recovery_code",
        "refresh_token",
        "seed",
        "totp",
    }
)
TRANSPORT_ONLY_AMR = frozenset({"bluetooth", "nearby", "proximity", "rssi", "pairing", "bonding"})


def _has_forbidden_proximity_field(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in PROXIMITY_FORBIDDEN_FIELDS
            or _has_forbidden_proximity_field(entry)
            for key, entry in value.items()
        )
    if isinstance(value, list):
        return any(_has_forbidden_proximity_field(entry) for entry in value)
    return False


def _decode_base64url(value: object) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise BoundaryViolation("value must be canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as error:
        raise BoundaryViolation("invalid base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise BoundaryViolation("non-canonical base64url")
    return decoded


@dataclass
class ProximityReplayState:
    recipient_device_id: str
    session_id: str
    last_sequence: int = 0
    seen_message_ids: set[str] = field(default_factory=set)


def validate_proximity_envelope(
    envelope: dict[str, object],
    state: ProximityReplayState,
    *,
    now_unix_ms: int,
    signature_verifier: Callable[[dict[str, object]], bool],
) -> bytes:
    if set(envelope) != PROXIMITY_ENVELOPE_FIELDS:
        raise BoundaryViolation("proximity envelope fields must match the closed v1 contract")
    if _has_forbidden_proximity_field(envelope):
        raise BoundaryViolation("credential-shaped proximity field is forbidden")
    if envelope["protocol"] != "cliptown.proximity.v1":
        raise BoundaryViolation("unsupported proximity protocol")
    if envelope["scope"] not in {"cliptown:clipboard:import", "shared-auth:step-up:relay"}:
        raise BoundaryViolation("unsupported proximity scope")
    if envelope["recipient_device_id"] != state.recipient_device_id:
        raise BoundaryViolation("wrong proximity recipient")
    if envelope["session_id"] != state.session_id:
        raise BoundaryViolation("wrong proximity session")

    issued_at = envelope["issued_at_unix_ms"]
    expires_at = envelope["expires_at_unix_ms"]
    sequence = envelope["sequence"]
    message_id = envelope["message_id"]
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (issued_at, expires_at, sequence)):
        raise BoundaryViolation("proximity times and sequence must be integers")
    if expires_at <= issued_at or expires_at - issued_at > 120_000:
        raise BoundaryViolation("proximity lifetime is invalid")
    if now_unix_ms < issued_at or now_unix_ms >= expires_at:
        raise BoundaryViolation("proximity envelope is not currently valid")
    if not isinstance(message_id, str) or message_id in state.seen_message_ids:
        raise BoundaryViolation("proximity message replay detected")
    if sequence <= state.last_sequence:
        raise BoundaryViolation("proximity sequence did not advance")

    ciphertext = _decode_base64url(envelope["ciphertext"])
    if len(ciphertext) > 32 * 1024:
        raise BoundaryViolation("proximity ciphertext exceeds 32 KiB")
    if not isinstance(envelope["ciphertext_sha256"], str) or not hmac.compare_digest(
        hashlib.sha256(ciphertext).hexdigest(), envelope["ciphertext_sha256"]
    ):
        raise BoundaryViolation("proximity ciphertext digest mismatch")
    _decode_base64url(envelope["signature"])
    if not signature_verifier(envelope):
        raise BoundaryViolation("proximity signature mismatch or device key is not enrolled")

    state.seen_message_ids.add(message_id)
    state.last_sequence = sequence
    return ciphertext


def accepts_threefa_assurance(amr: set[str], *, shared_auth_result_verified: bool) -> bool:
    if amr & TRANSPORT_ONLY_AMR:
        return False
    return shared_auth_result_verified and "threefa_app" in amr


def normalize_relative_path(value: str) -> str:
    decoded = urllib.parse.unquote(urllib.parse.unquote(value))
    if not decoded or "\x00" in decoded or "\\" in decoded or decoded.startswith("/"):
        raise BoundaryViolation("path must be a non-empty relative POSIX path")
    parts = PurePosixPath(decoded).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise BoundaryViolation("path traversal segment is forbidden")
    normalized = "/".join(parts)
    if normalized != decoded:
        raise BoundaryViolation("path normalization changed the request")
    return normalized


def validate_outbound_url(value: str, allowed_hosts: set[str]) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BoundaryViolation("outbound URL must use HTTPS without user info")
    host = parsed.hostname.rstrip(".").lower()
    if host not in {item.rstrip(".").lower() for item in allowed_hosts}:
        raise BoundaryViolation("outbound host is not allowlisted")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        raise BoundaryViolation("non-public IP destinations are forbidden")
    if parsed.fragment:
        raise BoundaryViolation("fragments are not sent upstream")
    return urllib.parse.urlunsplit(parsed)


def redact(value: str) -> str:
    token_pattern = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}")
    bearer_pattern = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+")
    redacted = token_pattern.sub("[REDACTED]", value)
    return bearer_pattern.sub(r"\1[REDACTED]", redacted)


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    roles: frozenset[str]


def authorize_read(principal: Principal, resource_tenant_id: str) -> None:
    if principal.tenant_id != resource_tenant_id:
        raise BoundaryViolation("cross-tenant read is forbidden")
    if not ({"reader", "admin"} & principal.roles):
        raise BoundaryViolation("read role is required")


def sign(secret: bytes, timestamp: int, nonce: str, body: bytes) -> str:
    message = f"{timestamp}.{nonce}.".encode() + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


@dataclass
class ReplayWindow:
    max_skew_seconds: int = 300
    seen: dict[str, int] = field(default_factory=dict)

    def verify(
        self,
        secret: bytes,
        timestamp: int,
        nonce: str,
        body: bytes,
        signature: str,
        now: int | None = None,
    ) -> None:
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > self.max_skew_seconds:
            raise BoundaryViolation("signature timestamp is outside the replay window")
        if nonce in self.seen:
            raise BoundaryViolation("nonce replay detected")
        expected = sign(secret, timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            raise BoundaryViolation("signature mismatch")
        self.seen[nonce] = timestamp
        cutoff = current - self.max_skew_seconds
        self.seen = {key: seen_at for key, seen_at in self.seen.items() if seen_at >= cutoff}
