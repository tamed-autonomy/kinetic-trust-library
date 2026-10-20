"""Neutral Trust Proof value-model tests."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest

import kinetic_trust_library.errors as errors
import kinetic_trust_library.models.proof as proof_models
from kinetic_trust_library.errors import CryptoConfigurationError, ValidationError
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    AsyncVerifierBinding,
    CeilingClaim,
    KeyPurpose,
    ProofAlgorithm,
    ProofCrypto,
    ProofIntent,
    ProofRootStatus,
    ProofToken,
    RiskFactorClaims,
    RootInstrumentClaim,
    SignatureVerificationOutcome,
    SoulProofClaims,
    TrustProofClaims,
    VerifiedTrustProof,
    VerifierBinding,
)
from kinetic_trust_library.models.soul import SoulConstraintType


UTC_NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
PROOF_MODEL_EXPORTS = {
    "AsyncProofCrypto",
    "AsyncVerifierBinding",
    "CeilingClaim",
    "KeyLookup",
    "KeyPurpose",
    "KeyResolution",
    "OracleSigningIdentity",
    "ProofAlgorithm",
    "ProofCrypto",
    "ProofIntent",
    "ProofRootStatus",
    "ProofToken",
    "RiskFactorClaims",
    "RootInstrumentClaim",
    "SignatureVerificationOutcome",
    "SoulProofClaims",
    "TrustedVerificationKey",
    "TrustProofClaims",
    "UnknownVerificationKey",
    "UntrustedVerificationKey",
    "VerifiedTrustProof",
    "VerifierBinding",
}


class HostileDecimal(Decimal):
    pass


class HostileInt(int):
    pass


class HostileString(str):
    def encode(self, *args: object, **kwargs: object) -> bytes:
        raise AssertionError("string hook must not run")


class HostileDateTime(datetime):
    @property
    def tzinfo(self):  # type: ignore[override]
        raise AssertionError("datetime hook must not run")


class HostileTuple(tuple):
    def __iter__(self):
        raise AssertionError("tuple hook must not run")

    def __len__(self):
        raise AssertionError("tuple hook must not run")


class OpaqueVerifier:
    def __getattribute__(self, name: str) -> object:
        if name.startswith("__"):
            return object.__getattribute__(self, name)
        raise AssertionError("provider attributes must remain opaque")


class ProofIntentTests(unittest.TestCase):
    def test_intent_preserves_valid_canonical_values(self) -> None:
        value = ProofIntent(
            proof_id="proof-1",
            resource="urn:resource:document:42",
            context_hash="sha256:" + ("b" * 64),
            trajectory_id="trajectory-1",
            lifetime_seconds=10,
        )
        self.assertEqual(value.proof_id, "proof-1")
        self.assertEqual(value.resource, "urn:resource:document:42")
        self.assertEqual(value.context_hash, "sha256:" + ("b" * 64))
        self.assertEqual(value.trajectory_id, "trajectory-1")
        self.assertEqual(value.lifetime_seconds, 10)
        with self.assertRaises(AttributeError):
            value.lifetime_seconds = 1

    def test_intent_requires_exact_lifetime_in_closed_range(self) -> None:
        base = {
            "proof_id": "proof-1",
            "resource": "urn:resource:document:42",
            "context_hash": "sha256:" + ("b" * 64),
            "trajectory_id": "trajectory-1",
        }
        for value in (None, False, True, HostileInt(1), 0, 11, 1.0, "1"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProofIntent(**base, lifetime_seconds=value)  # type: ignore[arg-type]

    def test_intent_rejects_noncanonical_binding_fields(self) -> None:
        base = {
            "proof_id": "proof-1",
            "resource": "urn:resource:document:42",
            "context_hash": "sha256:" + ("b" * 64),
            "trajectory_id": "trajectory-1",
            "lifetime_seconds": 10,
        }
        identifiers = (
            None,
            HostileString("id"),
            "",
            "a" * 257,
            "e\u0301",
            "bad id",
            "bad\x00id",
            "\ud800",
        )
        invalid = {
            "proof_id": identifiers,
            "trajectory_id": identifiers,
            "resource": (
                None,
                HostileString("urn:r:1"),
                "",
                "relative",
                "urn:" + "r" * 2045,
                "\ud800",
            ),
            "context_hash": (
                None,
                HostileString("sha256:" + "b" * 64),
                "b" * 64,
                "sha256:" + "B" * 64,
                "sha256:" + "b" * 63,
                "sha256:" + "b" * 64 + "\n",
            ),
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(ValidationError):
                        ProofIntent(**{**base, field: value})  # type: ignore[arg-type]

    def test_intent_accepts_binding_and_lifetime_boundaries(self) -> None:
        for identifier in ("a", "é" * 128):
            for lifetime in (1, 10):
                with self.subTest(identifier=identifier, lifetime=lifetime):
                    value = ProofIntent(
                        proof_id=identifier,
                        resource="urn:" + "r" * 2044,
                        context_hash="sha256:" + "b" * 64,
                        trajectory_id=identifier,
                        lifetime_seconds=lifetime,
                    )
                    self.assertEqual(value.proof_id, identifier)
                    self.assertEqual(value.trajectory_id, identifier)
                    self.assertEqual(value.resource, "urn:" + "r" * 2044)
                    self.assertEqual(value.lifetime_seconds, lifetime)


class ProofBindingValidationTests(unittest.TestCase):
    def test_binding_validators_reject_subclass_hooks_before_using_values(self):
        for validator, value, kwargs in (
            (
                proof_models._require_uri,
                HostileString("urn:resource:1"),
                {"name": "resource"},
            ),
            (
                proof_models._require_key_identifier,
                HostileString("decision-1"),
                {"name": "decision ID"},
            ),
            (
                proof_models._require_sha256,
                HostileString("sha256:" + "b" * 64),
                {"name": "context hash"},
            ),
            (
                proof_models._require_proof_time,
                HostileDateTime(2026, 8, 24),
                {"name": "issued at"},
            ),
        ):
            with (
                self.subTest(validator=validator.__name__),
                self.assertRaises(ValidationError),
            ):
                validator(value, **kwargs)

    def test_binding_boundaries_preserve_values_without_normalization(self):
        resource = "urn:" + "r" * 2044
        self.assertEqual(proof_models._require_uri(resource, name="resource"), resource)
        for identifier in ("a", "é" * 128):
            self.assertEqual(
                proof_models._require_key_identifier(identifier, name="decision ID"),
                identifier,
            )
        digest = "sha256:" + "b" * 64
        self.assertEqual(
            proof_models._require_sha256(digest, name="context hash"), digest
        )
        for seconds in (1, 10):
            proof_models._require_proof_lifetime(
                UTC_NOW, UTC_NOW + timedelta(seconds=seconds)
            )
        for seconds in (-1, 0, 11):
            with self.subTest(seconds=seconds), self.assertRaises(ValidationError):
                proof_models._require_proof_lifetime(
                    UTC_NOW, UTC_NOW + timedelta(seconds=seconds)
                )


def risk_claims(**overrides: object) -> RiskFactorClaims:
    values: dict[str, object] = {
        "evidence_density": Decimal("0.1"),
        "trust_trend": Decimal("0.2"),
        "adversarial_pressure": Decimal("0.3"),
        "update_resistance": Decimal("0.4"),
        "attestation_coverage": Decimal("0.5"),
        "moment_criticality": Decimal("0.6"),
    }
    values.update(overrides)
    return RiskFactorClaims(**values)  # type: ignore[arg-type]


def soul_claims(**overrides: object) -> SoulProofClaims:
    values: dict[str, object] = {
        "soul": 0,
        "constraint_type": None,
        "constraint_id": None,
        "constraint_name": None,
        "authority": None,
        "community": None,
        "remediation": None,
    }
    values.update(overrides)
    return SoulProofClaims(**values)  # type: ignore[arg-type]


def root_claim(**overrides: object) -> RootInstrumentClaim:
    values: dict[str, object] = {
        "status": ProofRootStatus.CURRENT,
        "end_time": UTC_NOW,
        "exposure_class": "legal entity assets",
        "declared_exposure": Decimal("50"),
        "anchored_capacity": Decimal("60"),
        "terminator": "Example Holdings",
        "chain_length": 2,
    }
    values.update(overrides)
    return RootInstrumentClaim(**values)  # type: ignore[arg-type]


def undeclared_es256_algorithm() -> ProofAlgorithm:
    algorithm = str.__new__(ProofAlgorithm, ProofAlgorithm.ES256.value)
    object.__setattr__(algorithm, "_name_", "UNDECLARED_ES256_ALIAS")
    object.__setattr__(algorithm, "_value_", ProofAlgorithm.ES256.value)
    return algorithm


class ProofModelAuthorityTests(unittest.TestCase):
    def test_proof_model_module_has_exact_public_surface(self):
        namespace: dict[str, object] = {}
        exec("from kinetic_trust_library.models.proof import *", namespace)

        self.assertEqual(set(proof_models.__all__), PROOF_MODEL_EXPORTS)
        self.assertEqual(
            tuple(proof_models.__all__), tuple(sorted(PROOF_MODEL_EXPORTS))
        )
        self.assertEqual(set(namespace) - {"__builtins__"}, PROOF_MODEL_EXPORTS)

    def test_exact_builtin_enums_are_pinned(self):
        self.assertEqual(ProofAlgorithm.ES256.value, "ES256")
        self.assertEqual(ProofAlgorithm.ED25519.value, "EdDSA")
        self.assertEqual(KeyPurpose.ORACLE_TRUST_PROOF.value, "oracle-trust-proof")
        self.assertEqual(
            tuple(status.value for status in ProofRootStatus),
            ("current", "non_renewable", "none"),
        )
        self.assertEqual(
            tuple(SignatureVerificationOutcome),
            (
                SignatureVerificationOutcome.VALID,
                SignatureVerificationOutcome.INVALID_SIGNATURE,
                SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
            ),
        )

    def test_guarded_results_reject_full_field_public_construction(self):
        with self.assertRaises(TypeError):
            TrustProofClaims(
                issuer="https://oracle.example",
                subject="urn:agent:example",
                issued_at=UTC_NOW,
                expires_at=UTC_NOW,
                proof_id="proof-1",
                base_trust=Decimal("80"),
                effective_trust=Decimal("72"),
                risk=Decimal("0.1"),
                velocity=None,
                volatility=None,
                context=object(),
                soul=object(),
                lineage=object(),
                generation=1,
                sponsor=None,
                resilience_hash="sha256:" + ("a" * 64),
                zone=None,
                oracle_quorum=None,
                peer_share=Decimal("0"),
                applicable_ceilings=(),
                advancement_floor=Decimal("0"),
                root_instrument=object(),
            )
        with self.assertRaises(TypeError):
            ProofToken(
                raw="header.payload.signature",
                token_digest="sha256:" + ("a" * 64),
                proof_id="proof-1",
                issued_at=UTC_NOW,
                expires_at=UTC_NOW,
            )
        with self.assertRaises(TypeError):
            VerifiedTrustProof(
                raw="header.payload.signature",
                token_digest="sha256:" + ("a" * 64),
                claims=object(),
                verification_key=object(),
            )


class ClaimCarrierTests(unittest.TestCase):
    def test_valid_claim_carriers_preserve_exact_immutable_values(self):
        risk = risk_claims()
        soul = soul_claims(
            soul=1,
            constraint_type=SoulConstraintType.TK_LABEL,
            constraint_id="TK-NC-001",
            constraint_name="TK Non-Commercial",
            authority="https://localcontexts.org/label/tk-nc/",
            community="Example Indigenous Community",
            remediation="Contact the community data steward",
        )
        ceiling = CeilingClaim("zone_mass", Decimal("92"))
        root = root_claim()

        self.assertEqual(risk.evidence_density, Decimal("0.1"))
        self.assertEqual(soul.constraint_name, "TK Non-Commercial")
        self.assertEqual(ceiling, CeilingClaim("zone_mass", Decimal("92")))
        self.assertEqual(root.end_time, UTC_NOW)
        with self.assertRaises(AttributeError):
            risk.evidence_density = Decimal("0.9")
        with self.assertRaises(AttributeError):
            soul.community = "changed"
        with self.assertRaises(AttributeError):
            root.chain_length = 3

    def test_claim_decimals_are_exact_finite_and_schema_bounded(self):
        for invalid in (
            0,
            0.5,
            "0.5",
            HostileDecimal("0.5"),
            Decimal("NaN"),
            Decimal("Infinity"),
            Decimal("-0.1"),
            Decimal("1.1"),
        ):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                risk_claims(evidence_density=invalid)

        for invalid in (
            Decimal("NaN"),
            Decimal("-0.1"),
            Decimal("100.1"),
        ):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                CeilingClaim("generation", invalid)

        for field in ("declared_exposure", "anchored_capacity"):
            for invalid in (0, Decimal("NaN"), Decimal("-0.1")):
                with (
                    self.subTest(field=field, invalid=repr(invalid)),
                    self.assertRaises(ValidationError),
                ):
                    root_claim(**{field: invalid})

    def test_claim_decimal_carriers_enforce_core_precision_and_exponent_bounds(self):
        fractional_34_digits = Decimal("0.1234567890123456789012345678901234")
        minimum_exponent = Decimal("1e-6143")

        for field in (
            "evidence_density",
            "trust_trend",
            "adversarial_pressure",
            "update_resistance",
            "attestation_coverage",
            "moment_criticality",
        ):
            for accepted in (fractional_34_digits, minimum_exponent):
                with self.subTest(carrier="risk", field=field, accepted=accepted):
                    self.assertEqual(
                        getattr(risk_claims(**{field: accepted}), field),
                        accepted,
                    )

        for accepted in (fractional_34_digits, minimum_exponent):
            with self.subTest(carrier="ceiling", accepted=accepted):
                self.assertEqual(CeilingClaim("test", accepted).value, accepted)

        for field in ("declared_exposure", "anchored_capacity"):
            for accepted in (
                fractional_34_digits,
                minimum_exponent,
                Decimal("1e6144"),
            ):
                with self.subTest(carrier="root", field=field, accepted=accepted):
                    self.assertEqual(
                        getattr(root_claim(**{field: accepted}), field), accepted
                    )

        invalid_for_all = (
            Decimal("0.12345678901234567890123456789012345"),
            Decimal("1e-6144"),
        )
        for invalid in invalid_for_all:
            with self.subTest(carrier="risk", invalid=invalid):
                with self.assertRaises(ValidationError):
                    risk_claims(evidence_density=invalid)
            with self.subTest(carrier="ceiling", invalid=invalid):
                with self.assertRaises(ValidationError):
                    CeilingClaim("test", invalid)
            for field in ("declared_exposure", "anchored_capacity"):
                with self.subTest(carrier="root", field=field, invalid=invalid):
                    with self.assertRaises(ValidationError):
                        root_claim(**{field: invalid})

        for invalid in (Decimal("1e6145"), Decimal("1e999999")):
            for field in ("declared_exposure", "anchored_capacity"):
                with self.subTest(carrier="root", field=field, invalid=invalid):
                    with self.assertRaises(ValidationError):
                        root_claim(**{field: invalid})

    def test_all_claim_decimal_carriers_require_exact_decimal_inputs(self):
        invalid_values = (0, 0.5, "0.5", HostileDecimal("0.5"))
        for invalid in invalid_values:
            with self.subTest(carrier="risk", invalid=repr(invalid)):
                with self.assertRaises(ValidationError):
                    risk_claims(evidence_density=invalid)
            with self.subTest(carrier="ceiling", invalid=repr(invalid)):
                with self.assertRaises(ValidationError):
                    CeilingClaim("test", invalid)  # type: ignore[arg-type]
            for field in ("declared_exposure", "anchored_capacity"):
                with self.subTest(carrier="root", field=field, invalid=repr(invalid)):
                    with self.assertRaises(ValidationError):
                        root_claim(**{field: invalid})

    def test_soul_claim_enforces_exact_types_and_cross_field_shape(self):
        for invalid in (False, True, -1, 2, HostileInt(0)):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                soul_claims(soul=invalid)

        with self.assertRaises(ValidationError):
            soul_claims(soul=0, constraint_id="unexpected")
        with self.assertRaises(ValidationError):
            soul_claims(soul=1, constraint_type=SoulConstraintType.TK_LABEL)
        with self.assertRaises(ValidationError):
            soul_claims(
                soul=1,
                constraint_type="tk_label",
                authority="https://authority.example",
            )
        with self.assertRaises(ValidationError):
            soul_claims(
                soul=1,
                constraint_type=SoulConstraintType.TK_LABEL,
                authority="relative/path",
            )
        with self.assertRaises(ValidationError):
            soul_claims(
                soul=1,
                constraint_type=SoulConstraintType.TK_LABEL,
                authority="https://authority.example",
                constraint_name=HostileString("name"),
            )

    def test_human_readable_soul_fields_preserve_unicode_whitespace(self):
        name = "Caf\u00e9 ceremonial\nname"
        community = "Dine\u0301 community"
        normalized_community = "Diné community"

        claims = soul_claims(
            soul=1,
            constraint_type=SoulConstraintType.CARE,
            constraint_name=name,
            authority="https://authority.example",
            community=normalized_community,
            remediation="Ask first\tthen document consent",
        )
        self.assertEqual(claims.constraint_name, name)
        self.assertEqual(claims.community, normalized_community)
        with self.assertRaises(ValidationError):
            soul_claims(
                soul=1,
                constraint_type=SoulConstraintType.CARE,
                authority="https://authority.example",
                community=community,
            )

    def test_root_claim_enforces_status_shape_exact_utc_and_whole_seconds(self):
        self.assertEqual(
            root_claim(
                status=ProofRootStatus.NONE,
                end_time=None,
                exposure_class=None,
                declared_exposure=None,
                anchored_capacity=None,
                terminator=None,
                chain_length=None,
            ).status,
            ProofRootStatus.NONE,
        )
        with self.assertRaises(ValidationError):
            root_claim(status="current")
        with self.assertRaises(ValidationError):
            root_claim(status=ProofRootStatus.NONE)
        with self.assertRaises(ValidationError):
            root_claim(end_time=UTC_NOW.replace(tzinfo=None))
        with self.assertRaises(ValidationError):
            root_claim(end_time=UTC_NOW.replace(microsecond=1))
        with self.assertRaises(ValidationError):
            root_claim(end_time=HostileDateTime(2026, 8, 24))
        for invalid in (True, 0, HostileInt(2)):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                root_claim(chain_length=invalid)


class CryptoConfigurationTests(unittest.TestCase):
    def test_configuration_rejects_undeclared_exact_algorithm_members(self):
        for binding_type in (VerifierBinding, AsyncVerifierBinding):
            with (
                self.subTest(binding_type=binding_type.__name__),
                self.assertRaises(CryptoConfigurationError),
            ):
                binding_type(undeclared_es256_algorithm(), object())

        sync_binding = object.__new__(VerifierBinding)
        object.__setattr__(sync_binding, "algorithm", undeclared_es256_algorithm())
        object.__setattr__(sync_binding, "verifier", object())
        async_binding = object.__new__(AsyncVerifierBinding)
        object.__setattr__(async_binding, "algorithm", undeclared_es256_algorithm())
        object.__setattr__(async_binding, "verifier", object())
        for configuration_type, binding in (
            (ProofCrypto, sync_binding),
            (AsyncProofCrypto, async_binding),
        ):
            with (
                self.subTest(configuration_type=configuration_type.__name__),
                self.assertRaises(CryptoConfigurationError),
            ):
                configuration_type((binding,))

    def test_es256_only_and_es256_plus_ed25519_are_the_only_valid_shapes(self):
        es256 = VerifierBinding(ProofAlgorithm.ES256, object())
        ed25519 = VerifierBinding(ProofAlgorithm.ED25519, object())
        async_es256 = AsyncVerifierBinding(ProofAlgorithm.ES256, object())
        async_ed25519 = AsyncVerifierBinding(ProofAlgorithm.ED25519, object())

        self.assertEqual(ProofCrypto((es256,)).bindings, (es256,))
        self.assertEqual(
            ProofCrypto((es256, ed25519)).bindings,
            (es256, ed25519),
        )
        self.assertEqual(AsyncProofCrypto((async_es256,)).bindings, (async_es256,))
        self.assertEqual(
            AsyncProofCrypto((async_es256, async_ed25519)).bindings,
            (async_es256, async_ed25519),
        )

    def test_configuration_rejects_missing_and_duplicate_algorithms(self):
        es256 = VerifierBinding(ProofAlgorithm.ES256, object())
        ed25519 = VerifierBinding(ProofAlgorithm.ED25519, object())
        for bindings in ((), (ed25519,), (es256, es256)):
            with (
                self.subTest(bindings=bindings),
                self.assertRaises(CryptoConfigurationError),
            ):
                ProofCrypto(bindings)

    def test_configuration_rejects_wrong_binding_and_unknown_algorithm_types(self):
        async_binding = AsyncVerifierBinding(ProofAlgorithm.ES256, object())
        for bindings in (
            [VerifierBinding(ProofAlgorithm.ES256, object())],
            HostileTuple((VerifierBinding(ProofAlgorithm.ES256, object()),)),
            (object(),),
            (async_binding,),
        ):
            with (
                self.subTest(kind=type(bindings).__name__),
                self.assertRaises(CryptoConfigurationError),
            ):
                ProofCrypto(bindings)  # type: ignore[arg-type]

        forged = object.__new__(VerifierBinding)
        object.__setattr__(forged, "algorithm", "ES256")
        object.__setattr__(forged, "verifier", object())
        with self.assertRaises(CryptoConfigurationError):
            ProofCrypto((forged,))
        with self.assertRaises(CryptoConfigurationError):
            VerifierBinding("ES256", object())  # type: ignore[arg-type]

    def test_configuration_maps_incomplete_exact_bindings_to_configuration_error(
        self,
    ):
        missing_algorithm = object.__new__(VerifierBinding)
        object.__setattr__(missing_algorithm, "verifier", OpaqueVerifier())
        missing_verifier = object.__new__(VerifierBinding)
        object.__setattr__(missing_verifier, "algorithm", ProofAlgorithm.ES256)

        for slot, binding in (
            ("algorithm", missing_algorithm),
            ("verifier", missing_verifier),
        ):
            with (
                self.subTest(missing_slot=slot),
                self.assertRaises(CryptoConfigurationError),
            ):
                ProofCrypto((binding,))

    def test_async_configuration_repeats_closed_binding_validation(self):
        es256 = AsyncVerifierBinding(ProofAlgorithm.ES256, object())
        ed25519 = AsyncVerifierBinding(ProofAlgorithm.ED25519, object())
        for bindings in ((), (ed25519,), (es256, es256)):
            with (
                self.subTest(bindings=bindings),
                self.assertRaises(CryptoConfigurationError),
            ):
                AsyncProofCrypto(bindings)

        sync_binding = VerifierBinding(ProofAlgorithm.ES256, object())
        for bindings in (
            [es256],
            HostileTuple((es256,)),
            (object(),),
            (sync_binding,),
        ):
            with (
                self.subTest(kind=type(bindings).__name__),
                self.assertRaises(CryptoConfigurationError),
            ):
                AsyncProofCrypto(bindings)  # type: ignore[arg-type]

        forged = object.__new__(AsyncVerifierBinding)
        object.__setattr__(forged, "algorithm", "ES256")
        object.__setattr__(forged, "verifier", object())
        with self.assertRaises(CryptoConfigurationError):
            AsyncProofCrypto((forged,))
        with self.assertRaises(CryptoConfigurationError):
            AsyncVerifierBinding("ES256", object())  # type: ignore[arg-type]

    def test_async_configuration_maps_incomplete_exact_bindings_to_configuration_error(
        self,
    ):
        missing_algorithm = object.__new__(AsyncVerifierBinding)
        object.__setattr__(missing_algorithm, "verifier", OpaqueVerifier())
        missing_verifier = object.__new__(AsyncVerifierBinding)
        object.__setattr__(missing_verifier, "algorithm", ProofAlgorithm.ES256)

        for slot, binding in (
            ("algorithm", missing_algorithm),
            ("verifier", missing_verifier),
        ):
            with (
                self.subTest(missing_slot=slot),
                self.assertRaises(CryptoConfigurationError),
            ):
                AsyncProofCrypto((binding,))

    def test_configurations_are_frozen_and_provider_instances_remain_opaque(self):
        provider = OpaqueVerifier()
        binding = VerifierBinding(ProofAlgorithm.ES256, provider)
        crypto = ProofCrypto((binding,))

        self.assertIs(binding.verifier, provider)
        self.assertIs(crypto.bindings[0].verifier, provider)
        with self.assertRaises(AttributeError):
            binding.algorithm = ProofAlgorithm.ED25519
        with self.assertRaises(AttributeError):
            crypto.bindings += ()


class ProofErrorTests(unittest.TestCase):
    def test_public_error_tree_preserves_invalid_and_operational_categories(self):
        direct_bases = {
            errors.ProofIssuanceInputError: errors.ValidationError,
            errors.InvalidProofError: errors.KTPError,
            errors.ProofFormatError: errors.InvalidProofError,
            errors.UnsupportedProofAlgorithmError: errors.InvalidProofError,
            errors.DisabledProofAlgorithmError: errors.InvalidProofError,
            errors.UnknownVerificationKeyError: errors.InvalidProofError,
            errors.UntrustedVerificationKeyError: errors.InvalidProofError,
            errors.RevokedVerificationKeyError: errors.InvalidProofError,
            errors.InactiveVerificationKeyError: errors.InvalidProofError,
            errors.InvalidSignatureError: errors.InvalidProofError,
            errors.ProofLifetimeError: errors.InvalidProofError,
            errors.ProofClaimsError: errors.InvalidProofError,
            errors.ProofOperationError: errors.KTPError,
            errors.CryptoConfigurationError: errors.ProofOperationError,
            errors.CryptoProviderUnavailableError: errors.ProofOperationError,
            errors.CryptoProviderFailureError: errors.ProofOperationError,
            errors.CryptoProviderContractError: errors.ProofOperationError,
            errors.VerificationKeySourceUnavailableError: errors.ProofOperationError,
            errors.VerificationKeySourceFailureError: errors.ProofOperationError,
            errors.VerificationKeySourceContractError: errors.ProofOperationError,
            errors.SigningProviderUnavailableError: errors.ProofOperationError,
            errors.SigningProviderFailureError: errors.ProofOperationError,
            errors.SignerContractError: errors.ProofOperationError,
            errors.OutcomeUnknownError: errors.ProofOperationError,
        }
        for exception_type, direct_base in direct_bases.items():
            with self.subTest(exception_type=exception_type.__name__):
                self.assertEqual(exception_type.__bases__, (direct_base,))

        self.assertEqual(errors.ConfigurationError.__bases__, (errors.KTPError,))
        self.assertFalse(
            issubclass(errors.CryptoConfigurationError, errors.ConfigurationError)
        )

    def test_outcome_unknown_error_exposes_bounded_correlation_metadata(self):
        digest = "sha256:" + ("a" * 64)
        error = errors.OutcomeUnknownError(
            proof_id="proof-Δ",
            signing_input_digest=digest,
            provider_reference="request-123",
            operation_id="operation-123",
        )

        self.assertEqual(error.stage, "signing")
        self.assertEqual(error.proof_id, "proof-Δ")
        self.assertEqual(error.signing_input_digest, digest)
        self.assertEqual(error.provider_reference, "request-123")
        self.assertEqual(error.operation_id, "operation-123")

    def test_outcome_unknown_error_rejects_malformed_metadata(self):
        digest = "sha256:" + ("a" * 64)
        invalid_arguments = (
            {"proof_id": "bad proof", "signing_input_digest": digest},
            {"proof_id": "proof-1", "signing_input_digest": "sha256:abc"},
            {
                "proof_id": "proof-1",
                "signing_input_digest": digest,
                "provider_reference": "é" * 129,
            },
            {
                "proof_id": "proof-1",
                "signing_input_digest": digest,
                "operation_id": 1,
            },
        )
        for arguments in invalid_arguments:
            with (
                self.subTest(arguments=arguments),
                self.assertRaises((TypeError, ValueError)),
            ):
                errors.OutcomeUnknownError(**arguments)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
