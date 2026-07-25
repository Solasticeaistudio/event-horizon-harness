from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from event_horizon.canonical import digest
from event_horizon.denial_certificate import (
    DenialCertificateBuilder,
    DenialCertificateVerifier,
)
from event_horizon.denial_cli import main as denial_cli
from event_horizon.models import ValidationError
from event_horizon.recorder import ExternalRecorder


NOW_MS = 1_700_000_000_000


class DenialCertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.recorder = ExternalRecorder(
            Path(self.tmp.name) / "evidence.jsonl",
            b"denial-recorder-public-test-key-no-authority",
        )
        self.builder = DenialCertificateBuilder(
            self.recorder,
            b"denial-certificate-public-test-key",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def arguments(self, **changes):
        values = {
            "attempt_id": "attempt-1",
            "campaign_id": "campaign-1",
            "task_id": "task-1",
            "session_id": "session-1",
            "workload_identity_hash": digest("executor-1"),
            "technique_classification": "capability-replay",
            "request_digest": digest({"request": 1}),
            "canonical_request_digest": digest({"request": 1}),
            "requested_authority": {"action": "object.read", "resource": "target"},
            "effective_authority": {"actions": []},
            "denial_reason_code": "CAPABILITY_CONSUMED",
            "effect_state": "denied-before-effect",
            "policy_version": "policy-v1",
            "policy_digest": digest({"policy": 1}),
            "policy_ceiling_digest": digest({"ceiling": 1}),
            "synthesizer_version": "static-v1",
            "compiler_version": "compiler-v1",
            "provider_attestation_digest": digest({"attestation": 1}),
            "guardian_state_digest": digest({"guardian": 1}),
            "decay_state_digest": digest({"decay": 1}),
            "code_commit": "b115d1c",
            "build_identifier": "test-build-1",
            "environment_identifier": "synthetic-range",
            "denial_timestamp_ms": NOW_MS,
        }
        values.update(changes)
        return values

    def build(self, **changes):
        return self.builder.build(**self.arguments(**changes))

    def verifier(self, **changes):
        values = {
            "trusted_signer_public_key": self.builder.public_key_pem,
            "trusted_recorder_public_key": self.recorder.public_key_pem,
        }
        values.update(changes)
        return DenialCertificateVerifier(**values)

    def test_valid_certificate_verifies_with_explicit_signer_trust(self) -> None:
        certificate = self.build()
        result = self.verifier().verify(certificate)
        self.assertTrue(result.valid)
        self.assertEqual(result.effect_state, "denied-before-effect")
        self.assertTrue(certificate["certificate"]["no_authorized_effect_committed"])

    def test_security_field_mutation_invalidates_signature(self) -> None:
        fields = {
            "denial_reason_code": "DIFFERENT_REASON",
            "request_digest": "9" * 64,
            "code_commit": "deadbeef",
            "policy_version": "policy-v2",
        }
        for field, value in fields.items():
            certificate = self.build(attempt_id=f"attempt-{field}")
            certificate["certificate"][field] = value
            with self.subTest(field=field):
                self.assertFalse(self.verifier().verify(certificate).valid)

    def test_wrong_and_revoked_signer_fail(self) -> None:
        certificate = self.build()
        other = DenialCertificateBuilder(self.recorder, b"other-denial-signer-key-material!!")
        self.assertFalse(DenialCertificateVerifier(other.public_key_pem).verify(certificate).valid)
        revoked = frozenset({self.builder.key_id})
        self.assertIn("revoked", self.verifier(revoked_signer_ids=revoked).verify(certificate).reason)

    def test_missing_evidence_and_broken_chain_link_fail(self) -> None:
        missing = self.build(attempt_id="attempt-missing")
        missing.pop("recorder_receipt")
        self.assertIn("envelope", self.verifier().verify(missing).reason)

        certificate = self.build(attempt_id="attempt-link")
        later = self.recorder.append("test.later", {"safe": True})
        certificate["recorder_receipt"] = later["receipt"]
        self.assertIn("linked", self.verifier().verify(certificate).reason)

    def test_replayed_certificate_id_is_detected(self) -> None:
        certificate = self.build()
        seen: set[str] = set()
        verifier = self.verifier(seen_certificate_ids=seen)
        self.assertTrue(verifier.verify(certificate).valid)
        replay = verifier.verify(certificate)
        self.assertFalse(replay.valid)
        self.assertIn("replayed", replay.reason)

    def test_malformed_certificate_and_private_fields_fail(self) -> None:
        self.assertFalse(self.verifier().verify({}).valid)
        with self.assertRaisesRegex(ValidationError, "private"):
            self.build(requested_authority={"api_key": "must-not-appear"})
        certificate = self.build(attempt_id="privacy-safe")
        serialized = str(certificate)
        self.assertNotIn("private prompt", serialized)
        self.assertNotIn("must-not-appear", serialized)

    def test_canary_trust_and_behavioral_denials_are_classified(self) -> None:
        for index, (technique, reason) in enumerate((
            ("canary-redemption", "CANARY_NON_EFFECT"),
            ("trust-downgrade", "TRUST_BELOW_SIGNED_CONSTRAINT"),
            ("boundary-probing", "BEHAVIORAL_QUARANTINE"),
        )):
            certificate = self.build(
                attempt_id=f"classified-{index}",
                technique_classification=technique,
                denial_reason_code=reason,
            )
            result = self.verifier().verify(certificate)
            self.assertTrue(result.valid)

    def test_ambiguous_and_committed_outcomes_never_claim_known_no_effect(self) -> None:
        for index, state in enumerate((
            "indeterminate-crash", "reconciliation-required",
        )):
            certificate = self.build(attempt_id=f"ambiguous-{index}", effect_state=state)
            self.assertIsNone(certificate["certificate"]["no_authorized_effect_committed"])
            self.assertTrue(self.verifier().verify(certificate).valid)
        committed = self.build(
            attempt_id="response-lost",
            effect_state="effect-committed-response-lost",
        )
        self.assertFalse(committed["certificate"]["no_authorized_effect_committed"])
        self.assertTrue(self.verifier().verify(committed).valid)

    def test_claiming_no_effect_for_ambiguous_state_is_rejected(self) -> None:
        certificate = self.build(effect_state="indeterminate-crash")
        certificate["certificate"]["no_authorized_effect_committed"] = True
        self.assertFalse(self.verifier().verify(certificate).valid)

    def test_valid_receipt_from_wrong_recorder_is_not_trusted(self) -> None:
        certificate = self.build()
        other_recorder = ExternalRecorder(
            Path(self.tmp.name) / "other.jsonl", b"other-recorder-public-test-key-no-authority"
        )
        other_event = other_recorder.append("denial.evaluated", {"attempt_id": "spoof"})
        changed = copy.deepcopy(certificate)
        changed["recorder_public_key_pem"] = other_recorder.public_key_pem
        changed["recorder_receipt"] = other_event["receipt"]
        self.assertIn("not trusted", self.verifier().verify(changed).reason)

    def test_standalone_cli_requires_and_uses_trusted_keys(self) -> None:
        certificate = self.build()
        directory = Path(self.tmp.name)
        certificate_path = directory / "denial.json"
        signer_path = directory / "signer.pem"
        recorder_path = directory / "recorder.pem"
        certificate_path.write_text(json.dumps(certificate), encoding="utf-8")
        signer_path.write_text(self.builder.public_key_pem, encoding="ascii")
        recorder_path.write_text(self.recorder.public_key_pem, encoding="ascii")
        self.assertEqual(denial_cli([
            str(certificate_path), "--trusted-signer", str(signer_path),
            "--trusted-recorder", str(recorder_path),
        ]), 0)


if __name__ == "__main__":
    unittest.main()
