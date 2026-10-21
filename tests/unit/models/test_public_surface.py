"""Public KTP model API and immutable-value boundary tests."""

import copy
from collections.abc import Mapping
from decimal import Decimal
import importlib
from importlib.util import find_spec
import kinetic_trust_library.models
import kinetic_trust_library.models.action
import kinetic_trust_library.models.evidence
import kinetic_trust_library.models.envelope
import kinetic_trust_library.models.profile
import kinetic_trust_library.models.proof
import kinetic_trust_library.models.risk
import kinetic_trust_library.models.soul
import kinetic_trust_library.models.standing
import kinetic_trust_library.models.trust
from kinetic_trust_library.models._uri import (
    validate_absolute_uri as _implementation_validate_absolute_uri,
)
from kinetic_trust_library.models.profile import FactorName, RiskDomain
from types import MappingProxyType
import unittest

import kinetic_trust_library

ROOT_EXPORTS = (
    "DeploymentProfile",
    "EvaluationBundle",
    "EvaluationRequest",
    "KTPError",
    "KTP_SPEC_TAG",
    "KTP_SPEC_COMMIT",
    "RejectedRequest",
    "ValidatedActionDemand",
    "ValidationError",
    "validate_absolute_uri",
    "__version__",
)
CORE_EXPORTS = ("evaluate",)
PROOF_EXPORTS = ("AsyncTrustProofs", "TrustProofs")
ERROR_EXPORTS = (
    "KTPError",
    "ValidationError",
    "ProofIssuanceInputError",
    "ConfigurationError",
    "ProofOperationError",
    "CryptoConfigurationError",
    "InvalidProofError",
    "ProofFormatError",
    "UnsupportedProofAlgorithmError",
    "DisabledProofAlgorithmError",
    "UnknownVerificationKeyError",
    "UntrustedVerificationKeyError",
    "RevokedVerificationKeyError",
    "InactiveVerificationKeyError",
    "InvalidSignatureError",
    "ProofLifetimeError",
    "ProofClaimsError",
    "CryptoProviderUnavailableError",
    "CryptoProviderFailureError",
    "CryptoProviderContractError",
    "VerificationKeySourceUnavailableError",
    "VerificationKeySourceFailureError",
    "VerificationKeySourceContractError",
    "SigningProviderUnavailableError",
    "SigningProviderFailureError",
    "SignerContractError",
    "OutcomeUnknownError",
)
ROOT_TYPE_OWNERS = {
    "DeploymentProfile": "kinetic_trust_library.models.profile",
    "EvaluationBundle": "kinetic_trust_library.models.envelope",
    "EvaluationRequest": "kinetic_trust_library.models.envelope",
    "RejectedRequest": "kinetic_trust_library.models.envelope",
    "ValidatedActionDemand": "kinetic_trust_library.models.action",
}
EXPECTED_FOCUSED_EXPORTS = {
    "kinetic_trust_library.models.capacity": (
        "CapacityRelation", "CoreCapacityResult",
    ),
    "kinetic_trust_library.core.capacity": (
        "require_validated_core_capacity_result",
    ),
    "kinetic_trust_library.models.action": (
        "ActionDemandDeclaration", "CapabilityDeclaration", "MomentCriticality",
        "MomentCriticalityDeclaration", "NormativeGateDecision",
        "NormativeGateToken", "ValidatedActionDemand", "ValidatedCapability",
        "require_validated_action", "require_validated_capability",
    ),
    "kinetic_trust_library.models.evidence": (
        "AdjudicatedMeasurementEnvelope", "DerivedStateMeasurementEnvelope",
        "DirectMeasurementEnvelope", "EnumeratedMeasurementEnvelope",
        "EvaluatedObservation", "EvidenceEntry", "EvidenceSnapshot",
        "FeedEvidenceOutcome", "FeedOutcomeState", "MeasurementEnvelope",
        "ObservationClass", "ObservationDeclaration", "ObservationValue",
        "ObservationWindow", "OnDemandQueryBinding", "PopulationState",
        "PublishedMeasurementEnvelope", "PublishedObservationPeriod",
        "SelectedFeedOutcome", "SelectedObservation", "UndefinedFeedOutcome",
        "UndefinedReason",
    ),
    "kinetic_trust_library.models.envelope": (
        "ConstraintCeiling", "EvaluationBundle",
        "EvaluationRequest", "EvaluationStage", "KineticEnvelopeResult",
        "NormativeGateOutcome", "NormativeGateState", "RejectedRequest",
        "RejectionReason", "Supervision", "TightenedConstraints",
        "UndefinedInput", "UndefinedInputLayer",
    ),
    "kinetic_trust_library.models.profile": (
        "ActionPolicy", "DeploymentProfile", "DeploymentProfileDeclaration",
        "EnvelopeThresholds", "FeedDeclaration", "FactorAggregationDeclaration",
        "FactorName", "IdentityNormalization", "LabelSetDeclaration",
        "MinMaxNormalization", "MomentCriticalityFactorDeclaration",
        "MomentCriticalityFactorProfile", "NormativeGatePolicy", "ProfileRef",
        "RiskDomain", "RiskFactorsDeclaration", "RiskFactorsProfile",
        "SignalRouteDeclaration", "SignalRiskFactorDeclaration",
        "SignalRiskFactorProfile", "require_validated_profile",
    ),
    "kinetic_trust_library.models.proof": (
        "AsyncProofCrypto", "AsyncVerifierBinding", "CeilingClaim", "KeyLookup",
        "KeyPurpose", "KeyResolution", "OracleSigningIdentity", "ProofAlgorithm",
        "ProofCrypto", "ProofIntent", "ProofRootStatus", "ProofToken", "RiskFactorClaims",
        "RootInstrumentClaim", "SignatureVerificationOutcome", "SoulProofClaims",
        "TrustProofClaims", "TrustedVerificationKey", "UnknownVerificationKey",
        "UntrustedVerificationKey", "VerifiedTrustProof", "VerifierBinding",
    ),
    "kinetic_trust_library.models.risk": (
        "DomainFactorResult", "DomainRiskResult", "MomentCriticalityResult",
        "RiskContext", "RiskInput", "RiskResult", "SignalFactorResult",
    ),
    "kinetic_trust_library.models.soul": (
        "SoulAssessment", "SoulAssessmentState", "SoulConstraint",
        "SoulConstraintType", "SoulFrameworkOutcome", "SoulResponseDeclaration",
        "SoulUndeterminedReason",
    ),
    "kinetic_trust_library.models.standing": (
        "AdjudicationFindingOutcome", "CeilingDeclaration",
        "ExternalTerminatorDeclaration", "ExternalTerminatorKind",
        "FrictionCategory", "LineagePhase", "NoRootInstrumentDeclaration",
        "PeerScoreDeclaration", "PoRAttestationDeclaration", "PoRResult",
        "RootAdjudicationFinding", "RootDeclaration",
        "RootInstrumentDeclaration", "RootInstrumentStatus",
        "RootIssuanceDeclaration", "RootWithdrawalClaim", "ShareAllocation",
        "StandingDeclaration", "StandingSnapshot", "WithdrawalCause",
    ),
    "kinetic_trust_library.models.trust": (
        "TrustSnapshot", "TrustTier", "TrustVelocity",
    ),
    "kinetic_trust_library.core.evaluate": (
        "evaluate", "require_validated_evaluation_bundle",
        "require_validated_rejected_request",
    ),
    "kinetic_trust_library.core.evidence": (
        "MAX_EVIDENCE_CANDIDATES_PER_ROUTE", "MAX_EVIDENCE_DECLARATIONS",
        "prepare_evidence", "require_validated_evidence_snapshot",
    ),
    "kinetic_trust_library.core.envelope": (
        "compute_envelope", "require_validated_envelope_result",
    ),
    "kinetic_trust_library.core.por": (
        "calculate_por", "require_validated_por_result",
    ),
    "kinetic_trust_library.core.risk": ("calculate_risk",),
    "kinetic_trust_library.core.soul": (
        "assess_soul", "require_validated_soul_assessment",
    ),
    "kinetic_trust_library.core.standing": (
        "MAX_PEER_EVIDENCE_IDS", "MAX_PEER_PROVENANCE_REFS",
        "prepare_standing", "require_validated_standing_snapshot",
    ),
    "kinetic_trust_library.core.trust": (
        "calculate_effective_trust", "calculate_velocity",
        "require_validated_trust_snapshot", "require_validated_trust_velocity",
    ),
}


class PublicSurfaceTests(unittest.TestCase):
    def test_soul_constraint_contract_is_public_only_from_focused_module(self):
        soul_constraint = importlib.import_module(
            "kinetic_trust_library.soul_constraint"
        )
        expected = {
            "SoulConstraintDocument", "SoulConstraintType",
            "parse_soul_constraint",
        }
        self.assertEqual(set(soul_constraint.__all__), expected)
        self.assertIs(
            soul_constraint.SoulConstraintType,
            kinetic_trust_library.models.soul.SoulConstraintType,
        )
        self.assertTrue(callable(soul_constraint.parse_soul_constraint))

        core = importlib.import_module("kinetic_trust_library.core")
        for facade in (kinetic_trust_library, core):
            for name in expected:
                with self.subTest(facade=facade.__name__, name=name):
                    self.assertFalse(hasattr(facade, name))
        for name in ("SoulConstraintDocument", "parse_soul_constraint"):
            with self.subTest(facade="models", name=name):
                self.assertFalse(hasattr(kinetic_trust_library.models, name))

    def test_trajectory_contract_is_public_only_from_focused_module(self):
        trajectory = importlib.import_module("kinetic_trust_library.trajectory")
        expected = {
            "TrajectoryAction", "TrajectoryAgentState", "TrajectoryLinkFinding",
            "TrajectoryOracleAttestation", "TrajectoryTransaction",
            "assess_trajectory_link", "parse_trajectory_transaction",
        }
        self.assertEqual(set(trajectory.__all__), expected)
        self.assertTrue(callable(trajectory.parse_trajectory_transaction))
        self.assertTrue(callable(trajectory.assess_trajectory_link))
        for facade in (
            kinetic_trust_library,
            kinetic_trust_library.models,
            importlib.import_module("kinetic_trust_library.core"),
        ):
            for name in expected:
                with self.subTest(facade=facade.__name__, name=name):
                    self.assertFalse(hasattr(facade, name))

    def test_capacity_contract_is_public_only_from_focused_leaf_modules(self):
        models = importlib.import_module("kinetic_trust_library.models.capacity")
        operations = importlib.import_module("kinetic_trust_library.core.capacity")
        self.assertEqual(models.__all__, ["CapacityRelation", "CoreCapacityResult"])
        self.assertEqual(
            operations.__all__, ["require_validated_core_capacity_result"]
        )
        for facade in (
            kinetic_trust_library,
            kinetic_trust_library.core,
            kinetic_trust_library.models,
        ):
            for name in (
                "CapacityRelation", "CoreCapacityResult",
                "require_validated_core_capacity_result", "derive_core_capacity",
            ):
                with self.subTest(facade=facade.__name__, name=name):
                    self.assertFalse(hasattr(facade, name))

    def test_protocol_provenance_is_explicit_beside_library_version(self):
        self.assertEqual(kinetic_trust_library.__version__, "2.1.0")
        self.assertEqual(kinetic_trust_library.KTP_SPEC_TAG, "v2.1.0")
        self.assertEqual(
            kinetic_trust_library.KTP_SPEC_COMMIT,
            "15520035267546e1035aad7beea0cc3cf9ef8f2c",
        )

    def test_obsolete_observation_module_is_absent(self):
        self.assertIsNone(find_spec("kinetic_trust_library.models.observation"))

    def test_record_contract_is_public_only_from_focused_leaf_modules(self):
        record_models = importlib.import_module("kinetic_trust_library.models.record")
        record_operations = importlib.import_module("kinetic_trust_library.core.record")
        self.assertEqual(record_models.__all__, ["DecisionRecord"])
        self.assertEqual(
            record_operations.__all__,
            ["build_decision_record", "require_validated_decision_record"],
        )
        self.assertFalse(hasattr(kinetic_trust_library, "DecisionRecord"))
        self.assertFalse(hasattr(kinetic_trust_library.models, "DecisionRecord"))
        self.assertFalse(hasattr(kinetic_trust_library.core, "build_decision_record"))

    def test_validated_profile_repr_is_stable_and_implementation_neutral(self):
        """Catches private mapping types or process addresses in public repr."""
        from tests.unit.models.test_profile import complete_profile_declaration

        first = kinetic_trust_library.DeploymentProfile.validate(complete_profile_declaration())
        second = kinetic_trust_library.DeploymentProfile.validate(
            complete_profile_declaration()
        )

        rendered = repr(first)
        self.assertEqual(rendered, repr(second))
        self.assertNotIn("_OwnedMapping", rendered)
        self.assertNotRegex(rendered, r"object at 0x[0-9a-fA-F]+")
        self.assertIn("RiskDomain.NODE", rendered)
        self.assertIn("action_class='deploy'", rendered)

    def test_package_root_facade_is_exact(self):
        """Catches an aggregate alias leaking through the package-root facade."""
        namespace: dict[str, object] = {}
        exec("from kinetic_trust_library import *", namespace)

        self.assertEqual(tuple(kinetic_trust_library.__all__), ROOT_EXPORTS)
        self.assertNotIn("_common", kinetic_trust_library.__all__)
        self.assertEqual(set(namespace) - {"__builtins__"}, set(ROOT_EXPORTS))
        self.assertEqual(kinetic_trust_library.__version__, "2.1.0")
        self.assertEqual(len(kinetic_trust_library.__all__), len(set(kinetic_trust_library.__all__)))

    def test_root_uri_validator_preserves_valid_values_and_rejects_malformed_values(self):
        validator = getattr(kinetic_trust_library, "validate_absolute_uri", None)
        self.assertIs(validator, _implementation_validate_absolute_uri)

        valid = (
            "urn:agent:example",
            "https://example.test/a%20b?mode=1#fragment",
            "urn:" + "a" * 2044,
        )
        for value in valid:
            with self.subTest(value=value):
                self.assertEqual(
                    validator(value, name="evidence subject"),
                    value,
                )

        invalid = (
            "urn:%ZZ",
            "urn:a\\b",
            "urn:é",
            "http://999.999.999.999",
            "https://example.test:",
            "https://user@@example.test",
            "urn:" + "a" * 2045,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(
                kinetic_trust_library.ValidationError
            ):
                validator(value, name="evidence subject")

    def test_root_uri_validator_remains_scheme_neutral_for_authority_forms(self):
        for value in ("urn://", "urn://authority/path", "did://", "did://authority/path"):
            with self.subTest(value=value):
                self.assertEqual(
                    kinetic_trust_library.validate_absolute_uri(
                        value, name="evidence subject"
                    ),
                    value,
                )

    def test_root_types_are_exact_leaf_objects(self):
        """Catches a wrapper or copied type in the package-root facade."""
        for name, module_name in ROOT_TYPE_OWNERS.items():
            owner = importlib.import_module(module_name)
            exported = getattr(kinetic_trust_library, name)
            with self.subTest(name=name):
                self.assertIs(exported, getattr(owner, name))
                self.assertEqual(exported.__module__, module_name)

        errors = importlib.import_module("kinetic_trust_library.errors")
        self.assertIs(kinetic_trust_library.KTPError, errors.KTPError)
        self.assertIs(kinetic_trust_library.ValidationError, errors.ValidationError)

    def test_core_facade_exports_only_evaluate(self):
        """Catches a Core helper leaking through the single-operation facade."""
        core = importlib.import_module("kinetic_trust_library.core")
        evaluate_module = importlib.import_module("kinetic_trust_library.core.evaluate")

        self.assertEqual(tuple(core.__all__), CORE_EXPORTS)
        self.assertIs(core.evaluate, evaluate_module.evaluate)

    def test_models_and_adapters_are_namespace_only(self):
        """Catches model or adapter values leaking out of namespace packages."""
        models = kinetic_trust_library.models
        adapters = importlib.import_module("kinetic_trust_library.adapters")

        self.assertEqual(tuple(models.__all__), ())
        self.assertNotIn("_common", models.__all__)
        self.assertEqual(tuple(adapters.__all__), ())
        self.assertIs(
            models.profile, importlib.import_module("kinetic_trust_library.models.profile")
        )
        self.assertIs(
            models.action, importlib.import_module("kinetic_trust_library.models.action")
        )
        self.assertIs(
            models.evidence, importlib.import_module("kinetic_trust_library.models.evidence")
        )
        self.assertIs(
            models.standing, importlib.import_module("kinetic_trust_library.models.standing")
        )
        self.assertIs(models.soul, importlib.import_module("kinetic_trust_library.models.soul"))
        self.assertIs(models.risk, importlib.import_module("kinetic_trust_library.models.risk"))
        self.assertIs(
            models.trust, importlib.import_module("kinetic_trust_library.models.trust")
        )
        self.assertIs(
            models.envelope, importlib.import_module("kinetic_trust_library.models.envelope")
        )
        self.assertIs(
            models.proof, importlib.import_module("kinetic_trust_library.models.proof")
        )
        adapter_cryptography = importlib.import_module(
            "kinetic_trust_library.adapters.cryptography"
        )
        self.assertIs(adapters.cryptography, adapter_cryptography)


    def test_proof_facade_exports_only_operations(self):
        """Catches proof values or optional adapters leaking through proofs."""
        proofs = importlib.import_module("kinetic_trust_library.proofs")
        namespace: dict[str, object] = {}
        exec("from kinetic_trust_library.proofs import *", namespace)

        self.assertEqual(tuple(proofs.__all__), PROOF_EXPORTS)
        self.assertEqual(set(namespace) - {"__builtins__"}, set(PROOF_EXPORTS))
        self.assertIs(namespace["AsyncTrustProofs"], proofs.AsyncTrustProofs)
        self.assertIs(namespace["TrustProofs"], proofs.TrustProofs)

    def test_focused_module_exports_are_unchanged(self):
        """Catches a supported leaf interface changing while facades narrow."""
        for module_name, expected in EXPECTED_FOCUSED_EXPORTS.items():
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                self.assertEqual(tuple(module.__all__), expected)

    def test_errors_export_the_complete_unchanged_hierarchy(self):
        """Catches a missing error export or changed error inheritance."""
        errors = importlib.import_module("kinetic_trust_library.errors")

        self.assertEqual(tuple(errors.__all__), ERROR_EXPORTS)
        for name in ERROR_EXPORTS:
            with self.subTest(name=name):
                self.assertIn(name, vars(errors))
        self.assertEqual(errors.ConfigurationError.__bases__, (errors.KTPError,))
        self.assertEqual(
            errors.CryptoConfigurationError.__bases__, (errors.ProofOperationError,)
        )
        for name in (
            "ProofFormatError",
            "UnsupportedProofAlgorithmError",
            "DisabledProofAlgorithmError",
            "UnknownVerificationKeyError",
            "UntrustedVerificationKeyError",
            "RevokedVerificationKeyError",
            "InactiveVerificationKeyError",
            "InvalidSignatureError",
            "ProofLifetimeError",
            "ProofClaimsError",
        ):
            with self.subTest(presented_proof_error=name):
                self.assertTrue(issubclass(getattr(errors, name), errors.InvalidProofError))
        for name in (
            "CryptoProviderUnavailableError",
            "CryptoProviderFailureError",
            "CryptoProviderContractError",
            "VerificationKeySourceUnavailableError",
            "VerificationKeySourceFailureError",
            "VerificationKeySourceContractError",
            "SigningProviderUnavailableError",
            "SigningProviderFailureError",
            "SignerContractError",
            "OutcomeUnknownError",
        ):
            with self.subTest(provider_operation_error=name):
                self.assertTrue(
                    issubclass(getattr(errors, name), errors.ProofOperationError)
                )


    def test_validated_profile_accessors_are_owned_immutable_values(self):
        """Catches a mutable nested public value or a digest changed by mutation attempts."""
        from tests.unit.models.test_profile import complete_profile_declaration

        declaration = complete_profile_declaration()
        profile = kinetic_trust_library.DeploymentProfile.validate(declaration)
        original_digest = profile.digest
        factor = profile.factor(FactorName.EVIDENCE_DENSITY)
        aggregation = factor.aggregation
        policy = profile.action_policy("deploy")

        self.assertIsInstance(profile.risk_domain_weights, Mapping)
        self.assertIsNone(aggregation.signal_weights)
        self.assertIsInstance(policy.constraint_units, Mapping)
        self.assertIsInstance(profile.soul_frameworks, tuple)
        with self.assertRaises(TypeError):
            profile.risk_domain_weights[RiskDomain.NODE] = object()
        with self.assertRaises(AttributeError):
            factor.weight = object()
        with self.assertRaises(TypeError):
            policy.constraint_units["rate"] = "changed"
        with self.assertRaises(AttributeError):
            profile.peer_share = object()
        with self.assertRaises(AttributeError):
            profile.soul_frameworks += ("soul.framework.secondary",)

        declaration.risk_domain_weights.clear()
        declaration.actions.clear()
        self.assertEqual(profile.digest, original_digest)
        self.assertEqual(
            profile.domain_weight(RiskDomain.NODE),
            Decimal("0.30"),
        )
        self.assertEqual(profile.action_policy("deploy"), policy)
        self.assertEqual(copy.copy(profile).digest, original_digest)


    def test_validated_action_values_cannot_be_constructed_or_mutated(self):
        """Catches bypassable validated-value constructors or mutable action snapshots."""
        from tests.unit.models.test_profile import (
            UTC_NOW,
            complete_action,
            complete_capability,
            complete_profile_declaration,
        )

        profile = kinetic_trust_library.DeploymentProfile.validate(
            complete_profile_declaration()
        )
        action = kinetic_trust_library.ValidatedActionDemand.validate(
            complete_action(),
            profile=profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        original_digest = action.digest

        with self.assertRaises(TypeError):
            kinetic_trust_library.DeploymentProfile()
        with self.assertRaises(TypeError):
            kinetic_trust_library.ValidatedActionDemand()
        self.assertIsInstance(action.granted_constraints, MappingProxyType)
        self.assertIsInstance(action.requested_constraints, MappingProxyType)
        self.assertIsInstance(action.capability.constraint_ceiling, MappingProxyType)
        self.assertIsInstance(action.capability.action_classes, tuple)
        self.assertIsInstance(action.normative_gate_tokens, tuple)
        with self.assertRaises(TypeError):
            action.granted_constraints["rate"] = object()
        with self.assertRaises(TypeError):
            action.requested_constraints["rate"] = object()
        with self.assertRaises(TypeError):
            action.capability.constraint_ceiling["rate"] = object()
        with self.assertRaises(AttributeError):
            action.demand = object()
        with self.assertRaises(AttributeError):
            action.normative_gate_tokens += ()

        self.assertEqual(action.digest, original_digest)
        self.assertEqual(copy.copy(action).digest, original_digest)


if __name__ == "__main__":
    unittest.main()
