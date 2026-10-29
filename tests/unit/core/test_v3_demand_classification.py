"""Bind installed A classification to verified demand evidence and invocation."""
import json
import unittest
from importlib.util import find_spec
from decimal import Decimal

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.installed_demand import InstalledDemandVerifier
from kinetic_trust_library.v3.demand_classification import InstalledDemandClassifier
from kinetic_trust_library.v3.core_projection import project_classified_native_core, NativeCoreContext
from tests.unit.core.test_v3_native_core_projection import soul, standing, factors, FACTORS
from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier, AuthenticatedStandingEvidence
from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
from kinetic_trust_library.v3.demand_supplier import _digest
from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier, AuthenticatedSoulResponse
from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier, AuthenticatedEnvironmentEvidence
from tests.unit.core.test_v3_installed_demand_verifier import FixtureAdapter, VECTORS


@unittest.skipUnless(all(find_spec(name) for name in ("rfc8785", "jsonschema", "cryptography")),
                     "install v3-proofs for classification integration tests")
class DemandClassificationTests(unittest.TestCase):
    def test_observed_and_unavailable_inputs_are_operation_bound(self):
        import rfc8785
        vectors = json.loads(VECTORS.read_text())
        raw_profile = rfc8785.dumps(vectors["deployment_profile"])
        verifier = InstalledDemandVerifier(
            raw_profile, rfc8785.dumps(vectors["supplier_profile_payload"]),
            rfc8785.dumps(vectors["verification_profile_payload"]),
            FixtureAdapter(vectors, vectors["context"]), "sha256",
        )
        class Classifier:
            def classify(self, operation_bytes, *, criticality):
                return Decimal(10) + criticality * 10
        classifier = InstalledDemandClassifier(raw_profile, Classifier(), "sha256")
        class SoulAdapter:
            def query(self, *, required_frameworks, **kwargs):
                return tuple(AuthenticatedSoulResponse(f, "clear", b"authenticated clear") for f in required_frameworks)
        verified_soul = InstalledSoulVerifier(raw_profile, SoulAdapter(), "sha256").evaluate(
            actual_operation=vectors["operation"], evaluated_at=1030)
        profile = vectors["deployment_profile"]
        class EnvironmentAdapter:
            def verify(self, *args, **kwargs):
                return AuthenticatedEnvironmentEvidence(rfc8785.dumps({"factors": {
                    name: {"signals": dict.fromkeys(config["signals"], 0), "measured_stress": 0}
                    for name, config in profile["risk_factors"].items()}}))
        environment_verifier = InstalledEnvironmentVerifier(raw_profile, EnvironmentAdapter(), "sha256")
        verified_environment = environment_verifier.evaluate(b"environment", actual_operation=vectors["operation"], evaluated_at=1030)
        other_environment = environment_verifier.evaluate(b"environment", actual_operation=vectors["operation"], evaluated_at=1031)
        root_context = rfc8785.dumps(dict(subject=vectors["operation"]["actor"], subject_profile="software",
            generation=7, lineage="guarantor", hop_bound=profile["external_root"]["hop_bound"], deployment_digest=_digest(profile,"sha256")))
        roots = select_assessed_roots((), context_bytes=root_context, evaluated_at=1030, algorithm="sha256")
        class StandingAdapter:
            def verify(self, *args, **kwargs):
                return AuthenticatedStandingEvidence(rfc8785.dumps(dict(
                    subject=vectors["operation"]["actor"], generation=7, identity_assurance_level=3,
                    trajectory_length=20000, por_contribution=70, peer_score=0,
                    maximum_adversity_friction=.9, crisis_exposure=True, additional_ceilings={})))
        verified_standing = InstalledStandingVerifier(raw_profile, StandingAdapter(), "sha256").evaluate(
            b"standing", roots=roots, actual_operation=vectors["operation"], evaluated_at=1030)
        other_standing = InstalledStandingVerifier(raw_profile, StandingAdapter(), "sha256").evaluate(
            b"standing", roots=roots, actual_operation={**vectors["operation"], "resource": "urn:other"}, evaluated_at=1030)
        for case_id, expected in (("valid-value", 18), ("wrong-signature", 20)):
            case = next(c for c in vectors["cases"] if c["id"] == case_id)
            assessment = verifier.evaluate(case["jws"].encode(), actual_operation=vectors["operation"],
                                           evaluated_at=1030, clock_healthy=True)
            result = classifier.classify(assessment, actual_operation=vectors["operation"], evaluated_at=1030)
            self.assertEqual(result.demand, expected)
            self.assertEqual(result.operation_digest, assessment.operation_digest)
            self.assertEqual(result.conservative, case_id != "valid-value")
            core = project_classified_native_core(
                verified_soul, standing=verified_standing, environment=verified_environment,
                context=NativeCoreContext(raw_profile, rfc8785.dumps(vectors["operation"]), 1030, "sha256"), demand=result,
            )
            self.assertEqual(core.capacity.demand, expected)
            self.assertIs(core.classified_demand, result)
            self.assertIs(core.standing_assessment, verified_standing)
            self.assertIs(core.environment_assessment, verified_environment)
            with self.assertRaisesRegex(ValidationError, "environment belongs"):
                project_classified_native_core(verified_soul, standing=verified_standing, environment=other_environment, demand=result,
                    context=NativeCoreContext(raw_profile, rfc8785.dumps(vectors["operation"]), 1030, "sha256"))
            with self.assertRaisesRegex(ValidationError, "standing belongs"):
                project_classified_native_core(verified_soul, standing=other_standing, environment=verified_environment, demand=result,
                    context=NativeCoreContext(raw_profile, rfc8785.dumps(vectors["operation"]), 1030, "sha256"))
            with self.assertRaises(ValidationError):
                project_classified_native_core(verified_soul, standing=standing(), environment=verified_environment, demand=result,
                    context=NativeCoreContext(raw_profile, rfc8785.dumps(vectors["operation"]), 1030, "sha256"))
            with self.assertRaises(ValidationError):
                project_classified_native_core(
                    verified_soul, standing=verified_standing, environment=verified_environment, demand=result,
                    context=NativeCoreContext(raw_profile, rfc8785.dumps(vectors["operation"]), 1031, "sha256"),
                )
            with self.assertRaises(ValidationError):
                classifier.classify(assessment, actual_operation={**vectors["operation"], "resource": "urn:other"}, evaluated_at=1030)
            with self.assertRaises(ValidationError):
                classifier.classify(assessment, actual_operation=vectors["operation"], evaluated_at=1031)
        class LoweringClassifier:
            def classify(self, operation_bytes, *, criticality):
                return 100 - criticality * 10
        with self.assertRaises(ValidationError):
            InstalledDemandClassifier(raw_profile, LoweringClassifier(), "sha256").classify(
                assessment, actual_operation=vectors["operation"], evaluated_at=1030)


if __name__ == "__main__":
    unittest.main()
