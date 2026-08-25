from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import time
import urllib.parse
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import PurePosixPath


class BoundaryViolation(ValueError):
    pass


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
PROXIMITY_SCOPES = {
    "pairing_hello": "cliptown:device:pair",
    "clipboard_offer": "cliptown:clipboard:import",
    "clipboard_chunk": "cliptown:clipboard:import",
    "shared_auth_step_up": "shared-auth:step-up:relay",
}
PROXIMITY_FORBIDDEN_FIELDS = frozenset(
    {
        "access_token",
        "approval_result",
        "assurance",
        "biometric",
        "factor_proof",
        "factor_result",
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


def _decode_unpadded_base64url(value: object) -> bytes:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise BoundaryViolation("value must be unpadded base64url")
    try:
        return b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise BoundaryViolation("value must be unpadded base64url") from error


def _proximity_signing_bytes(envelope: dict[str, object]) -> bytes:
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return json.dumps(unsigned, separators=(",", ":"), ensure_ascii=False).encode()


def sign_proximity_envelope(secret: bytes, envelope: dict[str, object]) -> str:
    return hmac.new(secret, _proximity_signing_bytes(envelope), hashlib.sha256).hexdigest()


@dataclass
class ProximityEnvelopeVerifier:
    local_device_id: str
    peer_device_id: str
    session_id: str
    max_clock_skew_ms: int = 30_000
    seen_messages: set[str] = field(default_factory=set)
    last_sequence: int = 0

    def verify(self, secret: bytes, envelope: dict[str, object], now_ms: int) -> None:
        if set(envelope) != PROXIMITY_ENVELOPE_FIELDS:
            raise BoundaryViolation("proximity envelopes are closed")
        if any(key.lower() in PROXIMITY_FORBIDDEN_FIELDS for key in envelope):
            raise BoundaryViolation("credential and assurance fields are forbidden")
        if envelope["protocol"] != "cliptown.proximity.v1":
            raise BoundaryViolation("unsupported proximity protocol")
        if PROXIMITY_SCOPES.get(envelope["message_kind"]) != envelope["scope"]:
            raise BoundaryViolation("message kind and scope do not match")
        if envelope["recipient_device_id"] != self.local_device_id:
            raise BoundaryViolation("wrong proximity recipient")
        if envelope["sender_device_id"] != self.peer_device_id:
            raise BoundaryViolation("wrong proximity sender")
        if envelope["session_id"] != self.session_id:
            raise BoundaryViolation("wrong proximity session")

        issued_at = envelope["issued_at_unix_ms"]
        expires_at = envelope["expires_at_unix_ms"]
        sequence = envelope["sequence"]
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (issued_at, expires_at, sequence)):
            raise BoundaryViolation("proximity time and sequence fields must be integers")
        if sequence < 1 or sequence > 0x7FFFFFFF:
            raise BoundaryViolation("invalid proximity sequence")
        if expires_at <= issued_at or expires_at - issued_at > 120_000:
            raise BoundaryViolation("invalid proximity lifetime")
        if issued_at > now_ms + self.max_clock_skew_ms or expires_at <= now_ms:
            raise BoundaryViolation("proximity envelope is expired or from the future")

        ciphertext = _decode_unpadded_base64url(envelope["ciphertext"])
        if not ciphertext or len(ciphertext) > 32 * 1024:
            raise BoundaryViolation("proximity ciphertext exceeds the reviewed bound")
        digest = hashlib.sha256(ciphertext).hexdigest()
        if not hmac.compare_digest(digest, str(envelope["ciphertext_sha256"])):
            raise BoundaryViolation("proximity ciphertext digest mismatch")
        expected_signature = sign_proximity_envelope(secret, envelope)
        if not hmac.compare_digest(expected_signature, str(envelope["signature"])):
            raise BoundaryViolation("proximity device signature mismatch")

        message_id = str(envelope["message_id"])
        if message_id in self.seen_messages:
            raise BoundaryViolation("proximity message replay")
        if sequence <= self.last_sequence:
            raise BoundaryViolation("proximity message reordered")
        self.seen_messages.add(message_id)
        self.last_sequence = sequence
