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
        for case_id, expected in (("valid-value", 18), ("wrong-signature", 20)):
            case = next(c for c in vectors["cases"] if c["id"] == case_id)
            assessment = verifier.evaluate(case["jws"].encode(), actual_operation=vectors["operation"],
                                           evaluated_at=1030, clock_healthy=True)
            result = classifier.classify(assessment, actual_operation=vectors["operation"], evaluated_at=1030)
            self.assertEqual(result.demand, expected)
            self.assertEqual(result.operation_digest, assessment.operation_digest)
            self.assertEqual(result.conservative, case_id != "valid-value")
            core = project_classified_native_core(
                soul("clear"), standing=standing(), factors=factors(),
                context=NativeCoreContext(raw_profile, rfc8785.dumps(vectors["operation"]), 1030, "sha256"), demand=result,
            )
            self.assertEqual(core.capacity.demand, expected)
            self.assertIs(core.classified_demand, result)
            with self.assertRaises(ValidationError):
                project_classified_native_core(
                    soul("clear"), standing=standing(), factors=factors(), demand=result,
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
