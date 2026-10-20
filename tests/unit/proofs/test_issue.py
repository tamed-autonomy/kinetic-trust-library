"""Restricted Issuer Profile v1 tests."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
import asyncio
import copy
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
import gc
from hashlib import sha256
import inspect
import json
import unittest
from unittest.mock import patch
import warnings

from kinetic_trust_library.errors import (
    CryptoConfigurationError,
    CryptoProviderContractError,
    CryptoProviderFailureError,
    CryptoProviderUnavailableError,
    OutcomeUnknownError,
    ProofIssuanceInputError,
    SignerContractError,
    SigningProviderFailureError,
    SigningProviderUnavailableError,
)
from kinetic_trust_library.models.envelope import EvaluationBundle
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    AsyncVerifierBinding,
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofCrypto,
    ProofIntent,
    ProofToken,
    SignatureVerificationOutcome,
    TrustedVerificationKey,
    VerifierBinding,
)
from kinetic_trust_library.protocols import (
    ProviderFailure,
    ProviderUnavailable,
    SigningOutcomeUnknown,
)
from kinetic_trust_library.models.standing import RootInstrumentStatus
from kinetic_trust_library.proofs import TrustProofs
from tests.unit.proofs._fakes import SpyKeySource, SpySigner, SpyVerifier
from tests.unit.proofs._fixtures import (
    proof_intent,
    ceiling_bundle,
    complete_bundle,
    complete_bundle_at,
    es256_signature,
    non_clear_bundle,
    oracle_signing_identity,
    root_bundle,
    sponsored_bundle,
    velocity_bundle,
)


class _DatetimeSubclass(datetime):
    pass


class _ZeroOffset(tzinfo):
    def utcoffset(self, value):
        return timedelta(0)

    def dst(self, value):
        return timedelta(0)


def _payload(raw: str) -> dict[str, object]:
    segment = raw.split(".")[1]
    data = urlsafe_b64decode(segment + ("=" * (-len(segment) % 4)))
    value = json.loads(data, parse_float=Decimal)
    if type(value) is not dict:
        raise AssertionError("proof payload fixture is not an object")
    return value


def _encoded_segment(value: bytes) -> bytes:
    return urlsafe_b64encode(value).rstrip(b"=")


def _issuance(
    evaluation: EvaluationBundle,
    *,
    proof: ProofIntent | None = None,
):
    facade, signer, verifier, events = _actors()
    token = facade.issue(
        evaluation,
        proof=proof_intent() if proof is None else proof,
        signer=signer,
    )
    return token, signer, verifier, events


def _actors(
    *,
    identity: object | None = None,
    signer_effect: object | None = None,
    verifier_effect: object = SignatureVerificationOutcome.VALID,
):
    events: list[str] = []
    signer = SpySigner(
        oracle_signing_identity() if identity is None else identity,
        es256_signature(r=1, s=1) if signer_effect is None else signer_effect,
        events=events,
    )
    verifier = SpyVerifier(verifier_effect, events=events)
    crypto = ProofCrypto(
        (VerifierBinding(algorithm=ProofAlgorithm.ES256, verifier=verifier),)
    )
    return TrustProofs(crypto), signer, verifier, events


def _facade(verifier: SpyVerifier, *extra_bindings: VerifierBinding) -> TrustProofs:
    return TrustProofs(
        ProofCrypto(
            (
                VerifierBinding(ProofAlgorithm.ES256, verifier),
                *extra_bindings,
            )
        )
    )


class RestrictedIssuanceTests(unittest.TestCase):
    def test_proof_time_and_decision_id_come_from_evaluation(self) -> None:
        bundle = root_bundle(RootInstrumentStatus.NONE)
        facade, signer, _, _ = _actors(
            identity=replace(oracle_signing_identity(), signing_not_after=None)
        )
        token = facade.issue(bundle, proof=proof_intent(), signer=signer)
        payload = _payload(token.raw)
        self.assertEqual(payload["sub"], bundle.action.subject)
        self.assertEqual(payload["iat"], int(bundle.cutoff.timestamp()))
        self.assertEqual(payload["exp"], int(bundle.cutoff.timestamp()) + 10)
        self.assertEqual(payload["ktp"]["action"], bundle.action.digest)
        self.assertEqual(payload["ktp"]["decision_id"], bundle.operation_id)
        self.assertEqual(payload["ktp"]["trajectory_id"], "trajectory-1")

    def test_mutated_exact_intent_stops_before_every_provider(self) -> None:
        intent = proof_intent()
        object.__setattr__(intent, "lifetime_seconds", True)
        facade, signer, verifier, events = _actors()
        with self.assertRaises(ProofIssuanceInputError):
            facade.issue(complete_bundle(), proof=intent, signer=signer)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls, events),
            (0, 0, 0, []),
        )

    def test_success_signs_once_and_self_verifies_once(self):
        events: list[str] = []
        signature = es256_signature(r=1, s=1)
        signer = SpySigner(
            oracle_signing_identity(),
            signature,
            events=events,
        )
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID, events=events)
        crypto = ProofCrypto(
            (VerifierBinding(algorithm=ProofAlgorithm.ES256, verifier=verifier),)
        )

        token = TrustProofs(crypto).issue(
            complete_bundle(),
            proof=proof_intent(proof_id="proof-1"),
            signer=signer,
        )

        self.assertIs(type(token), ProofToken)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls), (1, 1, 1)
        )
        self.assertEqual(
            events,
            ["signer.identity", "signer.sign", "verifier.verify"],
        )
        self.assertEqual(
            token.token_digest,
            "sha256:" + sha256(token.raw.encode("ascii")).hexdigest(),
        )


class IssuanceAuthorityAndInputTests(unittest.TestCase):
    def test_non_clear_bundles_stop_before_identity_signing_and_verification(self):
        for veto in (True, False):
            with self.subTest(veto=veto):
                bundle = non_clear_bundle(veto=veto)
                events: list[str] = []
                signer = SpySigner(
                    oracle_signing_identity(),
                    es256_signature(r=1, s=1),
                    events=events,
                )
                verifier = SpyVerifier(
                    SignatureVerificationOutcome.VALID,
                    events=events,
                )
                crypto = ProofCrypto((VerifierBinding(ProofAlgorithm.ES256, verifier),))

                with self.assertRaises(ProofIssuanceInputError):
                    TrustProofs(crypto).issue(
                        bundle,
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )

                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls, events),
                    (0, 0, 0, []),
                )

    def test_incomplete_reconstructed_cross_bound_and_mutated_bundles_stop_early(self):
        valid = complete_bundle()
        incomplete = copy.copy(valid)
        object.__setattr__(incomplete, "standing", None)

        reconstructed = object.__new__(EvaluationBundle)
        for field in fields(EvaluationBundle):
            object.__setattr__(
                reconstructed,
                field.name,
                None if field.name == "_request" else getattr(valid, field.name),
            )

        cross_bound = copy.copy(valid)
        other = root_bundle(RootInstrumentStatus.NONE)
        object.__setattr__(cross_bound, "trust", other.trust)

        mutated = copy.copy(valid)
        object.__setattr__(mutated, "digest", "0" * 64)

        for name, bundle in (
            ("incomplete", incomplete),
            ("reconstructed", reconstructed),
            ("cross-bound", cross_bound),
            ("mutated", mutated),
        ):
            with self.subTest(name=name):
                events: list[str] = []
                signer = SpySigner(
                    oracle_signing_identity(),
                    es256_signature(r=1, s=1),
                    events=events,
                )
                verifier = SpyVerifier(
                    SignatureVerificationOutcome.VALID,
                    events=events,
                )
                crypto = ProofCrypto((VerifierBinding(ProofAlgorithm.ES256, verifier),))
                with self.assertRaises(ProofIssuanceInputError):
                    TrustProofs(crypto).issue(
                        bundle,
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls, events),
                    (0, 0, 0, []),
                )

    def test_nonexact_non_utc_and_subsecond_cutoffs_stop_before_providers(self):
        base = complete_bundle()
        cutoffs = (
            _DatetimeSubclass.fromtimestamp(base.cutoff.timestamp(), timezone.utc),
            base.cutoff.replace(tzinfo=_ZeroOffset()),
            base.cutoff + timedelta(microseconds=1),
        )
        for cutoff in cutoffs:
            with self.subTest(cutoff=repr(cutoff)):
                bundle = copy.copy(base)
                object.__setattr__(bundle, "cutoff", cutoff)
                facade, signer, verifier, events = _actors()
                with self.assertRaises(ProofIssuanceInputError):
                    facade.issue(
                        bundle,
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls, events),
                    (0, 0, 0, []),
                )


class IssuanceProjectionAndTimeTests(unittest.TestCase):
    def test_core_risk_and_standing_projection_is_direct_and_exact(self):
        bundle = complete_bundle()
        token, _, _, _ = _issuance(bundle)
        payload = _payload(token.raw)
        ktp = payload["ktp"]
        if type(ktp) is not dict or bundle.risk is None or bundle.standing is None:
            self.fail("fixture did not produce projected authority")

        self.assertEqual(ktp["r"], bundle.risk.risk)
        self.assertEqual(
            ktp["context"],
            {
                "adversarial_pressure": bundle.risk.context.adversarial_pressure,
                "attestation_coverage": bundle.risk.context.attestation_coverage,
                "evidence_density": bundle.risk.context.evidence_density,
                "moment_criticality": bundle.risk.context.moment_criticality,
                "trust_trend": bundle.risk.context.trust_trend,
                "update_resistance": bundle.risk.context.update_resistance,
            },
        )
        self.assertEqual(ktp["e_base"], bundle.standing.base_trust)
        self.assertEqual(ktp["e_trust"], bundle.trust.effective_trust)
        self.assertEqual(ktp["peer_share"], bundle.standing.shares.peer)
        self.assertEqual(
            ktp["applicable_ceilings"],
            [
                {"ceiling": ceiling.name, "value": ceiling.value}
                for ceiling in bundle.standing.applicable_ceilings
            ],
        )
        self.assertEqual(ktp["advancement_floor"], bundle.standing.advancement_floor)
        self.assertEqual(ktp["soul"], {"soul": 0})
        self.assertNotIn("de_dt", ktp)
        self.assertNotIn("sigma", ktp)
        self.assertNotIn("zone", ktp)
        self.assertNotIn("oracle_quorum", ktp)

    def test_resilience_hash_adds_only_the_required_prefix(self):
        bundle = complete_bundle()
        token, _, _, _ = _issuance(bundle)
        payload = _payload(token.raw)
        ktp = payload["ktp"]
        if type(ktp) is not dict or bundle.standing is None:
            self.fail("fixture did not produce projected authority")
        projected = ktp["resilience_hash"]
        self.assertEqual(projected, "sha256:" + bundle.standing.por.digest)
        self.assertEqual(projected[7:], bundle.standing.por.digest)

    def test_all_nine_root_states_project_to_the_closed_wire_profile(self):
        active = {
            RootInstrumentStatus.CURRENT: "current",
            RootInstrumentStatus.NON_RENEWABLE: "non_renewable",
        }
        for status in RootInstrumentStatus:
            with self.subTest(status=status):
                bundle = root_bundle(status)
                token, _, _, _ = _issuance(bundle)
                root = _payload(token.raw)["ktp"]["root_instrument"]
                if status in active:
                    self.assertEqual(root["status"], active[status])
                    self.assertEqual(root["end_time"], 1_787_313_600)
                    self.assertEqual(root["exposure_class"], "legal-liability")
                    self.assertEqual(root["declared_exposure"], 100)
                    self.assertEqual(root["anchored_capacity"], 100)
                    self.assertEqual(root["terminator"], "legal:root-1")
                    self.assertEqual(root["chain_length"], 1)
                else:
                    self.assertEqual(root, {"status": "none"})

    def test_root_end_is_floored_and_bounds_requested_lifetime(self):
        cases = (
            (timedelta(seconds=3, microseconds=900_000), 1_787_227_203),
            (timedelta(seconds=9, microseconds=999_999), 1_787_227_209),
            (timedelta(seconds=20), 1_787_227_210),
        )
        for root_offset, expected_exp in cases:
            with self.subTest(root_offset=root_offset):
                bundle = root_bundle(
                    RootInstrumentStatus.CURRENT,
                    end_time=complete_bundle().cutoff + root_offset,
                )
                token, _, _, _ = _issuance(bundle)
                payload = _payload(token.raw)
                self.assertEqual(payload["iat"], 1_787_227_200)
                self.assertEqual(payload["exp"], expected_exp)
                self.assertEqual(token.issued_at, bundle.cutoff)
                self.assertEqual(
                    token.expires_at,
                    datetime.fromtimestamp(expected_exp, timezone.utc),
                )

    def test_active_root_tightens_requested_expiration(self) -> None:
        cutoff = complete_bundle().cutoff
        for status in (
            RootInstrumentStatus.CURRENT,
            RootInstrumentStatus.NON_RENEWABLE,
        ):
            with self.subTest(status=status):
                bundle = root_bundle(
                    status,
                    end_time=cutoff + timedelta(seconds=4, microseconds=900_000),
                )
                token, signer, verifier, events = _issuance(bundle)
                self.assertEqual(token.issued_at, cutoff)
                self.assertEqual(token.expires_at, cutoff + timedelta(seconds=4))
                self.assertEqual((signer.calls, verifier.calls), (1, 1))
                self.assertEqual(
                    events,
                    ["signer.identity", "signer.sign", "verifier.verify"],
                )

    def test_non_positive_root_bound_stops_before_every_provider(self) -> None:
        cutoff = complete_bundle().cutoff
        for status in (
            RootInstrumentStatus.CURRENT,
            RootInstrumentStatus.NON_RENEWABLE,
        ):
            with self.subTest(status=status):
                facade, signer, verifier, events = _actors()
                bundle = root_bundle(
                    status,
                    end_time=cutoff + timedelta(microseconds=900_000),
                )
                with self.assertRaises(ProofIssuanceInputError):
                    facade.issue(bundle, proof=proof_intent(), signer=signer)
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls, events),
                    (0, 0, 0, []),
                )

    def test_root_expired_exactly_at_cutoff_projects_none_and_uses_requested_expiry(
        self,
    ):
        bundle = root_bundle(RootInstrumentStatus.EXPIRED)
        token, signer, verifier, _ = _issuance(bundle)
        payload = _payload(token.raw)
        self.assertEqual(payload["iat"], 1_787_227_200)
        self.assertEqual(payload["exp"], 1_787_227_210)
        self.assertEqual(payload["ktp"]["root_instrument"], {"status": "none"})
        self.assertEqual((signer.calls, verifier.calls), (1, 1))

    def test_subsecond_evaluation_cutoff_stops_before_every_provider(self) -> None:
        cutoff = complete_bundle().cutoff + timedelta(microseconds=1)
        bundle = complete_bundle_at(cutoff)
        facade, signer, verifier, events = _actors()
        with self.assertRaises(ProofIssuanceInputError):
            facade.issue(bundle, proof=proof_intent(), signer=signer)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls, events),
            (0, 0, 0, []),
        )

    def test_velocity_is_the_only_local_optional_score_member(self):
        bundle = velocity_bundle()
        token, _, _, _ = _issuance(bundle)
        ktp = _payload(token.raw)["ktp"]
        if type(ktp) is not dict or bundle.velocity is None:
            self.fail("velocity fixture did not produce projected authority")
        self.assertEqual(ktp["de_dt"], bundle.velocity.value)
        self.assertNotIn("sigma", ktp)
        self.assertNotIn("zone", ktp)
        self.assertNotIn("oracle_quorum", ktp)

    def test_sponsored_lineage_emits_only_sponsor_and_interpretable_root_members(self):
        bundle = sponsored_bundle()
        token, _, _, _ = _issuance(bundle)
        ktp = _payload(token.raw)["ktp"]
        if type(ktp) is not dict or bundle.standing is None:
            self.fail("sponsored fixture did not produce projected authority")
        selected = bundle.standing.root_instrument
        self.assertEqual(ktp["lineage"], "sponsored")
        self.assertEqual(ktp["generation"], 0)
        self.assertEqual(ktp["sponsor"], selected.sponsor_standing.agent_id)
        self.assertEqual(
            ktp["root_instrument"],
            {"end_time": 1_789_819_200, "status": "current"},
        )


class IssuanceWireTests(unittest.TestCase):
    def test_header_payload_numeric_dates_and_signing_input_match_hand_derived_bytes(
        self,
    ):
        expected_header = b'{"alg":"ES256","kid":"oracle-key-1","typ":"ktp+jwt"}'
        expected_payload = (
            b'{"exp":1787227210,"iat":1787227200,"iss":"https://oracle.example",'
            b'"jti":"proof-1","ktp":{"action":"cf21ed7e383c4d2dad7168ecff8433d0b6bab2150dfecb85715b04055d5ad7b0",'
            b'"advancement_floor":0,"applicable_ceilings":['
            b'{"ceiling":"generation","value":55},{"ceiling":"ial","value":95},'
            b'{"ceiling":"trajectory","value":100},{"ceiling":"adversity","value":80}],'
            b'"context":{"adversarial_pressure":0.3,"attestation_coverage":0,'
            b'"evidence_density":0.1,"moment_criticality":0.75,"trust_trend":0.2,'
            b'"update_resistance":0.4},"context_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
            b'"decision_id":"operation:envelope:one","e_base":34.77121254719662437295027903255115,'
            b'"e_trust":25.12220106534956110945657660101821,"generation":3,'
            b'"lineage":"independent","peer_share":0,"r":0.2775,'
            b'"resilience_hash":"sha256:78e74fc9e51ac245d0dd266ff338e58ad90fa559da4b14bd31444e117e6f2f03",'
            b'"resource":"urn:resource:document:42",'
            b'"root_instrument":{"anchored_capacity":100,"chain_length":1,'
            b'"declared_exposure":100,"end_time":1787313600,'
            b'"exposure_class":"legal-liability","status":"current",'
            b'"terminator":"legal:root-1"},"soul":{"soul":0},"trajectory_id":"trajectory-1"},'
            b'"sub":"agent:independent:3gen:acme-line:agent-one"}'
        )
        signature = es256_signature(r=1, s=2)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        signer = SpySigner(oracle_signing_identity(), signature)

        token = _facade(verifier).issue(
            complete_bundle(),
            proof=proof_intent(proof_id="proof-1"),
            signer=signer,
        )

        expected_signing_input = (
            _encoded_segment(expected_header)
            + b"."
            + _encoded_segment(expected_payload)
        )
        self.assertEqual(signer.arguments, [expected_signing_input])
        self.assertEqual(
            token.raw,
            (expected_signing_input + b"." + _encoded_segment(signature)).decode(
                "ascii"
            ),
        )
        self.assertEqual(
            token.issued_at, datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
        )
        self.assertEqual(
            token.expires_at,
            datetime(2026, 8, 20, 12, 0, 10, tzinfo=timezone.utc),
        )

    def test_released_profile_variants_round_trip_through_task3_verification(self):
        for name, bundle in (
            ("independent", complete_bundle()),
            ("non-renewable", root_bundle(RootInstrumentStatus.NON_RENEWABLE)),
            ("sponsored", sponsored_bundle()),
            ("velocity", velocity_bundle()),
        ):
            with self.subTest(name=name):
                identity = oracle_signing_identity()
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(identity, es256_signature(r=1, s=1))
                facade = _facade(verifier)
                token = facade.issue(
                    bundle,
                    proof=proof_intent(proof_id=f"proof-{name}"),
                    signer=signer,
                )
                key = TrustedVerificationKey(
                    issuer=identity.issuer,
                    key_id=identity.key_id,
                    algorithm=identity.algorithm,
                    purpose=identity.purpose,
                    public_key=identity.public_key,
                    signing_not_before=identity.signing_not_before,
                    signing_not_after=identity.signing_not_after,
                    verification_not_after=identity.signing_not_after,
                    revoked_at=None,
                )
                keys = SpyKeySource(key)

                verified = facade.verify(token.raw, cutoff=bundle.cutoff, keys=keys)

                self.assertEqual(verified.raw, token.raw)
                self.assertEqual(verified.claims.proof_id, token.proof_id)
                self.assertEqual(verified.claims.issued_at, token.issued_at)
                self.assertEqual(verified.claims.expires_at, token.expires_at)
                self.assertEqual((signer.calls, keys.calls, verifier.calls), (1, 1, 2))


class SignerIdentityContractTests(unittest.TestCase):
    def test_sync_issue_rejects_exact_async_configuration_before_effects(self):
        class AsyncVerifierSpy:
            def __init__(self, events: list[str]) -> None:
                self.events = events
                self.calls = 0
                self.coroutines_created = 0
                self.effects = 0

            def verify(
                self,
                *,
                public_key: bytes,
                signing_input: bytes,
                signature: bytes,
            ):
                del public_key, signing_input, signature
                self.calls += 1
                self.coroutines_created += 1
                self.events.append("verifier.verify")
                return self._outcome()

            async def _outcome(self) -> SignatureVerificationOutcome:
                self.effects += 1
                return SignatureVerificationOutcome.VALID

        events: list[str] = []
        verifier = AsyncVerifierSpy(events)
        crypto = AsyncProofCrypto(
            (AsyncVerifierBinding(ProofAlgorithm.ES256, verifier),)
        )
        signer = SpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
            events=events,
        )
        error_type: type[BaseException] | None = None

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                TrustProofs(crypto).issue(  # type: ignore[arg-type]
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,
                )
            except Exception as exc:  # noqa: BLE001 - result is the assertion input
                error_type = type(exc)
            gc.collect()

        unawaited = tuple(
            str(item.message)
            for item in caught
            if item.category is RuntimeWarning
            and "was never awaited" in str(item.message)
        )
        self.assertEqual(
            (
                error_type,
                signer.identity_reads,
                signer.calls,
                verifier.calls,
                verifier.coroutines_created,
                verifier.effects,
                tuple(events),
                unawaited,
            ),
            (CryptoConfigurationError, 0, 0, 0, 0, 0, (), ()),
        )

    def test_crypto_configuration_is_revalidated_before_identity_effects(self):
        facade = TrustProofs(object())  # type: ignore[arg-type]
        signer = SpySigner(oracle_signing_identity(), es256_signature(r=1, s=1))

        with self.assertRaises(CryptoConfigurationError):
            facade.issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,
            )

        self.assertEqual((signer.identity_reads, signer.calls), (0, 0))

    def test_identity_is_read_once_owned_and_used_after_signer_mutation(self):
        identity = oracle_signing_identity()
        original_key = identity.public_key
        original_key_id = identity.key_id
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        class MutatingSigner(SpySigner):
            def sign(self, signing_input: bytes, /) -> bytes:
                object.__setattr__(identity, "public_key", b"changed")
                object.__setattr__(identity, "key_id", "changed")
                return super().sign(signing_input)

        signer = MutatingSigner(identity, es256_signature(r=1, s=1))
        token = _facade(verifier).issue(
            complete_bundle(),
            proof=proof_intent(proof_id="proof-1"),
            signer=signer,
        )

        self.assertEqual(signer.identity_reads, 1)
        self.assertEqual(verifier.arguments[0]["public_key"], original_key)
        header_segment = token.raw.split(".")[0]
        header = json.loads(
            urlsafe_b64decode(header_segment + ("=" * (-len(header_segment) % 4)))
        )
        self.assertEqual(header["kid"], original_key_id)

    def test_wrong_or_malformed_identity_stops_before_sign_and_verifier(self):
        base = oracle_signing_identity()
        cases: list[tuple[str, object]] = [("wrong type", object())]
        undeclared_algorithm = str.__new__(ProofAlgorithm, "RS256")
        object.__setattr__(undeclared_algorithm, "_name_", "UNDECLARED")
        object.__setattr__(undeclared_algorithm, "_value_", "RS256")
        undeclared_purpose = str.__new__(KeyPurpose, "general-purpose")
        object.__setattr__(undeclared_purpose, "_name_", "UNDECLARED")
        object.__setattr__(undeclared_purpose, "_value_", "general-purpose")
        changes = (
            ("issuer", "not a URI"),
            ("issuer", "https://x/" + ("a" * 2_039)),
            ("key_id", ""),
            ("key_id", "a" * 257),
            ("algorithm", "ES256"),
            ("algorithm", undeclared_algorithm),
            ("purpose", "oracle-trust-proof"),
            ("purpose", undeclared_purpose),
            ("public_key", bytearray(base.public_key)),
            ("public_key", b"\x04" + (b"\x01" * 63)),
            ("signing_not_before", base.signing_not_after),
            ("signing_not_after", complete_bundle().cutoff),
            ("revoked_at", complete_bundle().cutoff),
        )
        for member, value in changes:
            forged = copy.copy(base)
            object.__setattr__(forged, member, value)
            cases.append((member, forged))

        for name, identity in cases:
            with self.subTest(name=name):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(identity, es256_signature(r=1, s=1))
                with self.assertRaises(SignerContractError):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls),
                    (1, 0, 0),
                )

    def test_identity_access_provider_signals_are_classified_before_dispatch(self):
        cases = (
            (ProviderUnavailable(), SigningProviderUnavailableError),
            (ProviderFailure(), SigningProviderFailureError),
            (SigningOutcomeUnknown("not-dispatched"), SignerContractError),
            (RuntimeError("undeclared"), SignerContractError),
        )
        for effect, expected in cases:
            with self.subTest(effect=type(effect).__name__):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(effect, es256_signature(r=1, s=1))
                with self.assertRaises(expected):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls),
                    (1, 0, 0),
                )

    def test_identity_access_process_control_signals_propagate(self):
        for effect in (KeyboardInterrupt(), SystemExit(3), GeneratorExit()):
            with self.subTest(effect=type(effect).__name__):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(effect, es256_signature(r=1, s=1))
                with self.assertRaises(type(effect)):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls),
                    (1, 0, 0),
                )

    def test_sync_identity_native_coroutine_is_closed_before_contract_error(self):
        body_entries = 0
        scheduling_calls = 0

        class CoroutineIdentitySigner:
            def __init__(self, identity: object) -> None:
                self.identity_result = identity
                self.identity_reads = 0
                self.sign_lookups = 0
                self.sign_dispatches = 0

            @property
            def identity(self):
                self.identity_reads += 1
                return self.identity_result

            @property
            def sign(self):
                self.sign_lookups += 1
                return self._sign

            def _sign(self, signing_input: bytes, /):
                del signing_input
                self.sign_dispatches += 1
                return es256_signature(r=1, s=1)

        async def nested_identity():
            nonlocal body_entries
            body_entries += 1
            return oracle_signing_identity()

        result = nested_identity()
        signer = CoroutineIdentitySigner(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("native coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(SignerContractError):
                _facade(verifier).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,  # type: ignore[arg-type]
                )
            state = inspect.getcoroutinestate(result)
            signer.identity_result = None
            del result
            gc.collect()

        self.assertEqual(
            (
                signer.identity_reads,
                signer.sign_lookups,
                signer.sign_dispatches,
                verifier.calls,
                body_entries,
                scheduling_calls,
            ),
            (1, 0, 0, 0, 0, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_identity_lifecycle_boundaries_are_start_inclusive_end_exclusive(self):
        cutoff = complete_bundle().cutoff
        base = oracle_signing_identity()
        accepted = OracleSigningIdentity(
            issuer=base.issuer,
            key_id=base.key_id,
            algorithm=base.algorithm,
            purpose=base.purpose,
            public_key=base.public_key,
            signing_not_before=cutoff,
            signing_not_after=cutoff + timedelta(seconds=1),
            revoked_at=cutoff + timedelta(seconds=1),
        )
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        signer = SpySigner(accepted, es256_signature(r=1, s=1))

        _facade(verifier).issue(
            complete_bundle(),
            proof=proof_intent(proof_id="proof-1", lifetime_seconds=1),
            signer=signer,
        )

        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls), (1, 1, 1)
        )

    def test_enabled_ed25519_identity_uses_only_its_captured_binding(self):
        es_verifier = SpyVerifier(AssertionError("ES256 verifier must stay unused"))
        ed_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        cutoff = complete_bundle().cutoff
        identity = OracleSigningIdentity(
            issuer="https://oracle.example",
            key_id="ed-key-1",
            algorithm=ProofAlgorithm.ED25519,
            purpose=KeyPurpose.ORACLE_TRUST_PROOF,
            public_key=b"\x02" + (b"\x00" * 31),
            signing_not_before=cutoff - timedelta(seconds=1),
            signing_not_after=cutoff + timedelta(seconds=1),
            revoked_at=None,
        )
        signature = (b"\x02" + (b"\x00" * 31)) + (1).to_bytes(32, "little")
        signer = SpySigner(identity, signature)
        facade = _facade(
            es_verifier,
            VerifierBinding(ProofAlgorithm.ED25519, ed_verifier),
        )

        token = facade.issue(
            complete_bundle(),
            proof=proof_intent(proof_id="proof-ed", lifetime_seconds=1),
            signer=signer,
        )

        self.assertEqual((es_verifier.calls, ed_verifier.calls), (0, 1))
        self.assertEqual(ed_verifier.arguments[0]["signature"], signature)
        header_segment = token.raw.split(".")[0]
        header = json.loads(
            urlsafe_b64decode(header_segment + ("=" * (-len(header_segment) % 4)))
        )
        self.assertEqual(header, {"alg": "EdDSA", "kid": "ed-key-1", "typ": "ktp+jwt"})

    def test_identity_derived_uri_and_key_id_maxima_precede_signing(self):
        cutoff = complete_bundle().cutoff
        issuer_at_max = "https://x/" + ("a" * 2_038)
        accepted = OracleSigningIdentity(
            issuer=issuer_at_max,
            key_id="k" * 256,
            algorithm=ProofAlgorithm.ES256,
            purpose=KeyPurpose.ORACLE_TRUST_PROOF,
            public_key=oracle_signing_identity().public_key,
            signing_not_before=cutoff - timedelta(seconds=1),
            signing_not_after=cutoff + timedelta(seconds=1),
            revoked_at=None,
        )
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        signer = SpySigner(accepted, es256_signature(r=1, s=1))

        token = _facade(verifier).issue(
            complete_bundle(),
            proof=proof_intent(proof_id="p" * 256, lifetime_seconds=1),
            signer=signer,
        )

        payload = _payload(token.raw)
        self.assertEqual(len(payload["iss"].encode("utf-8")), 2_048)
        self.assertEqual(len(payload["jti"].encode("utf-8")), 256)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls), (1, 1, 1)
        )


class IssuanceResourceOrderingTests(unittest.TestCase):
    def test_reachable_total_member_max_passes_and_next_shape_fails_before_identity(
        self,
    ):
        at_max = ceiling_bundle(233)
        token, signer, verifier, _ = _issuance(at_max)
        payload = _payload(token.raw)

        def member_count(value: object) -> int:
            if type(value) is dict:
                return len(value) + sum(member_count(item) for item in value.values())
            if type(value) is list:
                return sum(member_count(item) for item in value)
            return 0

        self.assertEqual(member_count(payload), 511)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls), (1, 1, 1)
        )

        above_max = ceiling_bundle(234)
        events: list[str] = []
        overflow_signer = SpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
            events=events,
        )
        overflow_verifier = SpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=events,
        )
        with self.assertRaises(ProofIssuanceInputError):
            _facade(overflow_verifier).issue(
                above_max,
                proof=proof_intent(proof_id="proof-1"),
                signer=overflow_signer,
            )
        self.assertEqual(
            (
                overflow_signer.identity_reads,
                overflow_signer.calls,
                overflow_verifier.calls,
                events,
            ),
            (0, 0, 0, []),
        )


class SigningAndSelfVerificationContractTests(unittest.TestCase):
    def test_sign_method_lookup_failures_are_not_mislabeled_as_dispatched(self):
        class LookupSigner:
            def __init__(self, effect: object) -> None:
                self.effect = effect
                self.identity_reads = 0
                self.sign_lookups = 0

            @property
            def identity(self) -> OracleSigningIdentity:
                self.identity_reads += 1
                return oracle_signing_identity()

            @property
            def sign(self):
                self.sign_lookups += 1
                if isinstance(self.effect, BaseException):
                    raise self.effect
                return self.effect

        cases = (
            (ProviderUnavailable(), SigningProviderUnavailableError),
            (ProviderFailure(), SigningProviderFailureError),
            (SigningOutcomeUnknown("not-dispatched"), SignerContractError),
            (RuntimeError("lookup"), SignerContractError),
            (object(), SignerContractError),
        )
        for effect, expected in cases:
            with self.subTest(effect=type(effect).__name__):
                signer = LookupSigner(effect)
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                with self.assertRaises(expected):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,  # type: ignore[arg-type]
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.sign_lookups, verifier.calls),
                    (1, 1, 0),
                )

    def test_signer_declared_provider_signals_map_to_definite_operational_errors(self):
        cases = (
            (ProviderUnavailable(), SigningProviderUnavailableError),
            (ProviderFailure(), SigningProviderFailureError),
        )
        for effect, expected in cases:
            with self.subTest(effect=type(effect).__name__):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(oracle_signing_identity(), effect)
                with self.assertRaises(expected):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls),
                    (1, 1, 0),
                )

    def test_unknown_signer_outcomes_carry_exact_correlation_without_retry(self):
        effects = [
            ("valid", SigningOutcomeUnknown("remote:42"), "remote:42"),
            ("timeout", TimeoutError("timeout"), None),
            ("undeclared", RuntimeError("undeclared"), None),
        ]
        for name, reference in (
            ("deleted", None),
            ("non-string", 42),
            ("overlong UTF-8", "é" * 129),
            ("invalid Unicode", "\ud800"),
        ):
            signal = SigningOutcomeUnknown()
            if name == "deleted":
                del signal.provider_reference
            else:
                signal.provider_reference = reference
            effects.append((name, signal, None))
        for name, effect, provider_reference in effects:
            with self.subTest(effect=name):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(oracle_signing_identity(), effect)
                with self.assertRaises(OutcomeUnknownError) as caught:
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-exact"),
                        signer=signer,
                    )
                error = caught.exception
                self.assertEqual(error.stage, "signing")
                self.assertEqual(error.proof_id, "proof-exact")
                self.assertEqual(error.provider_reference, provider_reference)
                self.assertIs(error.__cause__, effect)
                self.assertEqual(
                    error.signing_input_digest,
                    "sha256:" + sha256(signer.arguments[0]).hexdigest(),
                )
                self.assertEqual(
                    (signer.identity_reads, signer.calls, verifier.calls),
                    (1, 1, 0),
                )

    def test_sync_signer_process_control_signals_propagate_without_relabeling(self):
        for effect in (
            KeyboardInterrupt(),
            SystemExit(4),
            GeneratorExit(),
            asyncio.CancelledError(),
        ):
            with self.subTest(effect=type(effect).__name__):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(oracle_signing_identity(), effect)
                with self.assertRaises(type(effect)):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual((signer.calls, verifier.calls), (1, 0))

    def test_sync_signer_native_coroutine_result_is_closed_before_contract_error(self):
        body_entries = 0
        scheduling_calls = 0

        async def nested_signature():
            nonlocal body_entries
            body_entries += 1
            return es256_signature(r=1, s=1)

        result = nested_signature()
        signer = SpySigner(oracle_signing_identity(), result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("native coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(SignerContractError):
                _facade(verifier).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,
                )
            state = inspect.getcoroutinestate(result)
            signer.effect = None
            del result
            gc.collect()

        self.assertEqual(
            (
                signer.identity_reads,
                signer.calls,
                verifier.calls,
                body_entries,
                scheduling_calls,
            ),
            (1, 1, 0, 0, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_malformed_signatures_are_not_normalized_or_sent_to_verifier(self):
        half_order = int(
            "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
            16,
        )
        malformed = (
            bytearray(es256_signature(r=1, s=1)),
            b"short",
            es256_signature(r=0, s=1),
            es256_signature(r=1, s=half_order + 1),
        )
        for signature in malformed:
            with self.subTest(
                signature_type=type(signature).__name__, length=len(signature)
            ):
                verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(oracle_signing_identity(), signature)
                with self.assertRaises(SignerContractError):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual((signer.calls, verifier.calls), (1, 0))
                self.assertIs(signer.effect, signature)

    def test_noncanonical_ed25519_signatures_stop_before_verification(self):
        cutoff = complete_bundle().cutoff
        identity = OracleSigningIdentity(
            issuer="https://oracle.example",
            key_id="ed-key-1",
            algorithm=ProofAlgorithm.ED25519,
            purpose=KeyPurpose.ORACLE_TRUST_PROOF,
            public_key=b"\x02" + (b"\x00" * 31),
            signing_not_before=cutoff - timedelta(seconds=1),
            signing_not_after=cutoff + timedelta(seconds=1),
            revoked_at=None,
        )
        order = int(
            "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16,
        )
        malformed = (
            (b"\xed" + (b"\xff" * 30) + b"\x7f") + (1).to_bytes(32, "little"),
            (b"\x02" + (b"\x00" * 31)) + order.to_bytes(32, "little"),
        )
        for signature in malformed:
            with self.subTest(signature=signature.hex()[:16]):
                es_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                ed_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                signer = SpySigner(identity, signature)
                facade = _facade(
                    es_verifier,
                    VerifierBinding(ProofAlgorithm.ED25519, ed_verifier),
                )
                with self.assertRaises(SignerContractError):
                    facade.issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-ed", lifetime_seconds=1),
                        signer=signer,
                    )
                self.assertEqual(
                    (signer.calls, es_verifier.calls, ed_verifier.calls), (1, 0, 0)
                )

    def test_exact_signature_and_signing_input_reach_verifier_unchanged_once(self):
        signature = es256_signature(r=1, s=2)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        signer = SpySigner(oracle_signing_identity(), signature)

        token = _facade(verifier).issue(
            complete_bundle(),
            proof=proof_intent(proof_id="proof-1"),
            signer=signer,
        )

        self.assertEqual(signer.calls, 1)
        self.assertEqual(verifier.calls, 1)
        self.assertEqual(verifier.arguments[0]["signing_input"], signer.arguments[0])
        self.assertEqual(verifier.arguments[0]["signature"], signature)
        self.assertEqual(
            verifier.arguments[0]["public_key"], oracle_signing_identity().public_key
        )
        signature_segment = token.raw.split(".")[2]
        self.assertEqual(
            urlsafe_b64decode(
                signature_segment + ("=" * (-len(signature_segment) % 4))
            ),
            signature,
        )

    def test_invalid_or_malformed_self_verifier_outcomes_never_release_a_token(self):
        undeclared = object.__new__(SignatureVerificationOutcome)
        object.__setattr__(undeclared, "_name_", "UNDECLARED")
        object.__setattr__(undeclared, "_value_", 999)
        cases = (
            (SignatureVerificationOutcome.INVALID_SIGNATURE, SignerContractError),
            (SignatureVerificationOutcome.INVALID_PUBLIC_KEY, SignerContractError),
            (True, CryptoProviderContractError),
            (undeclared, CryptoProviderContractError),
        )
        for outcome, expected in cases:
            with self.subTest(outcome=repr(outcome)):
                verifier = SpyVerifier(outcome)
                signer = SpySigner(
                    oracle_signing_identity(),
                    es256_signature(r=1, s=1),
                )
                with self.assertRaises(expected):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual((signer.calls, verifier.calls), (1, 1))

    def test_sync_self_verifier_native_coroutine_is_closed_before_contract_error(
        self,
    ):
        body_entries = 0
        scheduling_calls = 0

        async def nested_outcome():
            nonlocal body_entries
            body_entries += 1
            return SignatureVerificationOutcome.VALID

        result = nested_outcome()
        verifier = SpyVerifier(result)
        signer = SpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
        )

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("native coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(CryptoProviderContractError):
                _facade(verifier).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,
                )
            state = inspect.getcoroutinestate(result)
            verifier.effect = None
            del result
            gc.collect()

        self.assertEqual(
            (
                signer.identity_reads,
                signer.calls,
                verifier.calls,
                body_entries,
                scheduling_calls,
            ),
            (1, 1, 1, 0, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_self_verifier_operational_signals_map_after_known_signature(self):
        cases = (
            (ProviderUnavailable(), CryptoProviderUnavailableError),
            (ProviderFailure(), CryptoProviderFailureError),
            (SigningOutcomeUnknown("wrong-seam"), CryptoProviderFailureError),
            (TimeoutError("timeout"), CryptoProviderFailureError),
            (RuntimeError("undeclared"), CryptoProviderFailureError),
        )
        for effect, expected in cases:
            with self.subTest(effect=type(effect).__name__):
                verifier = SpyVerifier(effect)
                signer = SpySigner(
                    oracle_signing_identity(),
                    es256_signature(r=1, s=1),
                )
                with self.assertRaises(expected):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual((signer.calls, verifier.calls), (1, 1))

    def test_self_verifier_process_control_signals_propagate(self):
        for effect in (
            KeyboardInterrupt(),
            SystemExit(5),
            GeneratorExit(),
            asyncio.CancelledError(),
        ):
            with self.subTest(effect=type(effect).__name__):
                verifier = SpyVerifier(effect)
                signer = SpySigner(
                    oracle_signing_identity(),
                    es256_signature(r=1, s=1),
                )
                with self.assertRaises(type(effect)):
                    _facade(verifier).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertEqual((signer.calls, verifier.calls), (1, 1))


if __name__ == "__main__":
    unittest.main()
