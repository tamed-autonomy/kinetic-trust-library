import json
import unittest
from kinetic_trust_library.errors import ValidationError
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier, AuthenticatedEnvironmentEvidence


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"), "install v3-proofs")
class InstalledEnvironmentTests(unittest.TestCase):
    def test_missing_required_signal_overrides_candidate_aggregate(self):
        import rfc8785
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/demand-supplier-v1.json").read_text())
        profile = vectors["deployment_profile"]
        from tests.unit.core._v3_declaration_fixture import declare_bmc_labels
        declare_bmc_labels(profile)
        body = {"factors": {name: {"signals": dict.fromkeys(config["signals"], 0), "measured_stress": 0, "feed_undefined": []}
                           for name, config in profile["risk_factors"].items()}}
        class Adapter:
            dependencies=("body.hardware.bmc_reachable",)
            def verify(self, *args, **kwargs):
                return AuthenticatedEnvironmentEvidence(rfc8785.dumps(body),self.dependencies)
        adapter=Adapter()
        verifier = InstalledEnvironmentVerifier(rfc8785.dumps(profile), adapter, "sha256")
        complete = verifier.evaluate(b"source evidence", actual_operation=vectors["operation"], evaluated_at=1030)
        self.assertTrue(all(f.state == "observable" for f in complete.factors))
        self.assertEqual(complete.label_set_dependencies,("body.hardware.bmc_reachable",))
        for dependencies in ((),("body.hardware.bmc_reachable",)*2,["body.hardware.bmc_reachable"],
                             ("body.hardware.bmc_reachable","soul.temporal.action_rate")):
            adapter.dependencies=dependencies
            with self.subTest(dependencies=dependencies),self.assertRaises(ValidationError):
                verifier.evaluate(b"source evidence",actual_operation=vectors["operation"],evaluated_at=1030)
        adapter.dependencies=("body.hardware.bmc_reachable",)
        name = "evidence_density"
        body["factors"][name]["signals"].pop(profile["risk_factors"][name]["signals"][0])
        missing = verifier.evaluate(b"source evidence", actual_operation=vectors["operation"], evaluated_at=1030)
        factor = next(f for f in missing.factors if f.factor == name)
        self.assertIsNone(factor.value)
        self.assertEqual(factor.decision_stress, 1)
        self.assertEqual(missing.original_evidence, b"source evidence")
        body["factors"]["adversarial_pressure"]["feed_undefined"] = [
            {"input": "feed-01", "layer": "feed", "state": "unanswered"}]
        backup = verifier.evaluate(b"source evidence", actual_operation=vectors["operation"], evaluated_at=1030)
        backed_factor = next(f for f in backup.factors if f.factor == "adversarial_pressure")
        self.assertEqual(backed_factor.state, "observable")
        self.assertEqual(backed_factor.undefined_inputs[0].input, "feed-01")


if __name__ == "__main__": unittest.main()
