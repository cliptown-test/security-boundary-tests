import base64
import hashlib
import re
import unittest
from pathlib import Path

from deep_tests.security_model import (
    BoundaryViolation,
    Principal,
    ProximityEnvelopeVerifier,
    ProximityReplayState,
    ReplayWindow,
    accepts_threefa_assurance,
    authorize_read,
    normalize_relative_path,
    redact,
    sign,
    sign_proximity_envelope,
    validate_outbound_url,
    validate_proximity_envelope,
)


class SecurityBoundaryTests(unittest.TestCase):
    @staticmethod
    def proximity_envelope(**overrides: object) -> dict[str, object]:
        ciphertext = b"opaque-encrypted-clipboard-offer"
        envelope: dict[str, object] = {
            "protocol": "cliptown.proximity.v1",
            "message_kind": "clipboard_offer",
            "message_id": "11111111-1111-4111-8111-111111111111",
            "session_id": "AQIDBAUGBwgJCgsMDQ4PEA",
            "sequence": 1,
            "issued_at_unix_ms": 1_000_000,
            "expires_at_unix_ms": 1_120_000,
            "sender_device_id": "22222222-2222-4222-8222-222222222222",
            "recipient_device_id": "33333333-3333-4333-8333-333333333333",
            "scope": "cliptown:clipboard:import",
            "ciphertext": base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode(),
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "signing_key_id": "enrolled-device-key",
            "signature": "A" * 86,
        }
        envelope.update(overrides)
        return envelope

    @staticmethod
    def signed_proximity_envelope(secret: bytes, *, sequence: int = 1, message_id: str = "message-1") -> dict:
        ciphertext = base64.urlsafe_b64encode(b"opaque-encrypted-clip").rstrip(b"=").decode()
        envelope = {
            "protocol": "cliptown.proximity.v1",
            "message_kind": "clipboard_offer",
            "message_id": message_id,
            "session_id": "AQIDBAUGBwgJCgsMDQ4PEA",
            "sequence": sequence,
            "issued_at_unix_ms": 1_700_000_000_000,
            "expires_at_unix_ms": 1_700_000_120_000,
            "sender_device_id": "22222222-2222-4222-8222-222222222222",
            "recipient_device_id": "33333333-3333-4333-8333-333333333333",
            "scope": "cliptown:clipboard:import",
            "ciphertext": ciphertext,
            "ciphertext_sha256": hashlib.sha256(b"opaque-encrypted-clip").hexdigest(),
            "signing_key_id": "device-key-1",
            "signature": "",
        }
        envelope["signature"] = sign_proximity_envelope(secret, envelope)
        return envelope

    @staticmethod
    def proximity_verifier() -> ProximityEnvelopeVerifier:
        return ProximityEnvelopeVerifier(
            local_device_id="33333333-3333-4333-8333-333333333333",
            peer_device_id="22222222-2222-4222-8222-222222222222",
            session_id="AQIDBAUGBwgJCgsMDQ4PEA",
        )

    def test_proximity_envelope_accepts_once_after_all_security_checks(self) -> None:
        state = ProximityReplayState(
            recipient_device_id="33333333-3333-4333-8333-333333333333",
            session_id="AQIDBAUGBwgJCgsMDQ4PEA",
        )
        envelope = self.proximity_envelope()
        plaintext = validate_proximity_envelope(
            envelope,
            state,
            now_unix_ms=1_000_001,
            signature_verifier=lambda _: True,
        )
        self.assertEqual(plaintext, b"opaque-encrypted-clipboard-offer")
        with self.assertRaises(BoundaryViolation):
            validate_proximity_envelope(
                envelope,
                state,
                now_unix_ms=1_000_002,
                signature_verifier=lambda _: True,
            )

    def test_proximity_negative_matrix_fails_before_state_mutation(self) -> None:
        mutations = (
            {"recipient_device_id": "44444444-4444-4444-8444-444444444444"},
            {"session_id": "wrong-session"},
            {"sequence": 0},
            {"expires_at_unix_ms": 1_120_001},
            {"ciphertext": base64.urlsafe_b64encode(b"tampered").rstrip(b"=").decode()},
            {"scope": "shared-auth:factor:success"},
            {"otp": "123456"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                state = ProximityReplayState(
                    recipient_device_id="33333333-3333-4333-8333-333333333333",
                    session_id="AQIDBAUGBwgJCgsMDQ4PEA",
                )
                with self.assertRaises(BoundaryViolation):
                    validate_proximity_envelope(
                        self.proximity_envelope(**mutation),
                        state,
                        now_unix_ms=1_000_001,
                        signature_verifier=lambda _: True,
                    )
                self.assertEqual(state.seen_message_ids, set())
                self.assertEqual(state.last_sequence, 0)

        unsigned_state = ProximityReplayState(
            recipient_device_id="33333333-3333-4333-8333-333333333333",
            session_id="AQIDBAUGBwgJCgsMDQ4PEA",
        )
        with self.assertRaises(BoundaryViolation):
            validate_proximity_envelope(
                self.proximity_envelope(),
                unsigned_state,
                now_unix_ms=1_000_001,
                signature_verifier=lambda _: False,
            )
        self.assertEqual(unsigned_state.seen_message_ids, set())

    def test_bluetooth_never_becomes_authentication_assurance(self) -> None:
        for observation in ("bluetooth", "nearby", "proximity", "rssi", "pairing", "bonding"):
            with self.subTest(observation=observation):
                self.assertFalse(
                    accepts_threefa_assurance(
                        {"threefa_app", observation}, shared_auth_result_verified=True
                    )
                )
        self.assertFalse(
            accepts_threefa_assurance({"threefa_app"}, shared_auth_result_verified=False)
        )
        self.assertTrue(
            accepts_threefa_assurance({"threefa_app"}, shared_auth_result_verified=True)
        )

    def test_bluetooth_envelopes_are_verified_before_replay_state_changes(self) -> None:
        secret = b"synthetic-enrolled-device-key"
        envelope = self.signed_proximity_envelope(secret)
        verifier = self.proximity_verifier()

        forged = {**envelope, "signature": "0" * 64}
        with self.assertRaisesRegex(BoundaryViolation, "signature mismatch"):
            verifier.verify(secret, forged, now_ms=1_700_000_000_001)

        verifier.verify(secret, envelope, now_ms=1_700_000_000_001)
        self.assertEqual(verifier.last_sequence, 1)
        with self.assertRaisesRegex(BoundaryViolation, "replay"):
            verifier.verify(secret, envelope, now_ms=1_700_000_000_002)

    def test_bluetooth_context_expiry_scope_and_credential_boundaries_fail_closed(self) -> None:
        secret = b"synthetic-enrolled-device-key"
        baseline = self.signed_proximity_envelope(secret)

        cases = {
            "wrong recipient": {**baseline, "recipient_device_id": "44444444-4444-4444-8444-444444444444"},
            "wrong sender": {**baseline, "sender_device_id": "44444444-4444-4444-8444-444444444444"},
            "wrong session": {**baseline, "session_id": "ERITFBUWFxgZGhscHR4fIA"},
            "scope confusion": {**baseline, "scope": "shared-auth:step-up:relay"},
            "expired": {**baseline, "expires_at_unix_ms": 1_700_000_000_001},
            "from future": {
                **baseline,
                "issued_at_unix_ms": 1_700_000_030_002,
                "expires_at_unix_ms": 1_700_000_120_000,
            },
            "digest tamper": {**baseline, "ciphertext": "AQID"},
            "credential field": {**baseline, "otp": "123456"},
        }
        for name, envelope in cases.items():
            envelope["signature"] = sign_proximity_envelope(secret, envelope)
            with self.subTest(name=name), self.assertRaises(BoundaryViolation):
                self.proximity_verifier().verify(secret, envelope, now_ms=1_700_000_000_001)

    def test_bluetooth_offline_clip_and_threefa_relay_keep_distinct_scopes(self) -> None:
        secret = b"synthetic-enrolled-device-key"
        verifier = self.proximity_verifier()
        clip = self.signed_proximity_envelope(secret)
        relay = self.signed_proximity_envelope(secret, sequence=2, message_id="message-2")
        relay.update(
            message_kind="shared_auth_step_up",
            scope="shared-auth:step-up:relay",
        )
        relay["signature"] = sign_proximity_envelope(secret, relay)

        verifier.verify(secret, clip, now_ms=1_700_000_000_001)
        verifier.verify(secret, relay, now_ms=1_700_000_000_002)
        self.assertNotEqual(relay["scope"], "shared-auth:factor:success")

    def test_path_traversal_corpus_is_rejected(self) -> None:
        traversal = [
            "../secret",
            "safe/../secret",
            "%2e%2e/secret",
            "%252e%252e/secret",
            "/absolute",
            "safe\\windows",
            "safe/%2e%2e/secret",
            "safe//double",
        ]
        for value in traversal:
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)
        self.assertEqual(normalize_relative_path("safe/nested/file.txt"), "safe/nested/file.txt")

    def test_ssrf_boundary_requires_exact_https_allowlist(self) -> None:
        allowed = {"api.example.test"}
        self.assertEqual(
            validate_outbound_url("https://api.example.test/v1", allowed),
            "https://api.example.test/v1",
        )
        for value in (
            "http://api.example.test/v1",
            "https://api.example.test.attacker.invalid/v1",
            "https://user@api.example.test/v1",
            "https://127.0.0.1/v1",
        ):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)

    def test_tenant_isolation_and_roles_fail_closed(self) -> None:
        authorize_read(Principal("tenant-a", frozenset({"reader"})), "tenant-a")
        with self.assertRaises(BoundaryViolation):
            authorize_read(Principal("tenant-a", frozenset({"reader"})), "tenant-b")
        with self.assertRaises(BoundaryViolation):
            authorize_read(Principal("tenant-a", frozenset({"writer"})), "tenant-a")

    def test_signature_tamper_replay_and_skew_are_rejected(self) -> None:
        secret = b"unit-test-secret"
        body = b"payload"
        now = 1_700_000_000
        signature = sign(secret, now, "nonce-1", body)
        window = ReplayWindow(max_skew_seconds=300)
        window.verify(secret, now, "nonce-1", body, signature, now=now)
        with self.assertRaises(BoundaryViolation):
            window.verify(secret, now, "nonce-1", body, signature, now=now)
        with self.assertRaises(BoundaryViolation):
            ReplayWindow().verify(secret, now, "nonce-2", b"tampered", signature, now=now)
        with self.assertRaises(BoundaryViolation):
            ReplayWindow(max_skew_seconds=10).verify(
                secret, now - 11, "nonce-3", body, sign(secret, now - 11, "nonce-3", body), now=now
            )

    def test_redaction_removes_token_and_bearer_shapes(self) -> None:
        github_shape = "gh" + "p_" + "A" * 32
        linear_shape = "lin_" + "api_" + "B" * 32
        value = f"Authorization: Bearer opaque {github_shape} {linear_shape}"
        result = redact(value)
        self.assertNotIn(github_shape, result)
        self.assertNotIn(linear_shape, result)
        self.assertNotIn("opaque", result)

    def test_workflow_actions_are_immutable_and_permissions_are_read_only(self) -> None:
        workflow = Path(".github/workflows/deep-tests.yml").read_text()
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("pull_request_target", workflow)
        uses = [line.split("uses:", 1)[1].strip() for line in workflow.splitlines() if "uses:" in line]
        self.assertGreaterEqual(len(uses), 2)
        for action in uses:
            self.assertRegex(action, re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$"))


if __name__ == "__main__":
    unittest.main()
