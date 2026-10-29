"""Ordered verifier integration using the explicitly composed fixture profile."""
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from dataclasses import replace
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier, InstalledSchemaBundle


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785", "jsonschema", "cryptography")), "install v3-proofs")
class CompleteProofVerifierTests(unittest.TestCase):
    def test_all_published_ordered_outcomes_under_fixture_schema_composition(self):
        import rfc8785
        root = Path(__file__).parents[3]
        vectors = json.loads((root / "spec/proposals/trust-proof-v3.json").read_text())
        schema = json.loads((root / "spec/proposals/trust-proof-schema-v3.json").read_text())
        risk = json.loads((root / "src/kinetic_trust_library/v3/schemas/risk-factors-v2.json").read_text())
        # Fixture-only composition of #195 with #164's five-factor context.
        risk["required"].remove("moment_criticality")
        risk["properties"].pop("moment_criticality")
        soul = json.loads((root / "src/kinetic_trust_library/v3/schemas/soul-constraint-v2.json").read_text())
        bundle = InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in (schema, risk, soul)), schema["$id"])
        for case in vectors["cases"]:
            with self.subTest(case=case["id"]):
                context = {**vectors["context"], **case.get("context", {})}
                verifier = InstalledProofVerifier(
                    schema_bundle=bundle, trusted_keys_bytes=rfc8785.dumps({k["kid"]:k for k in vectors["keys"]}),
                    expected_context_bytes=rfc8785.dumps(context),
                    installed_algorithms=("ES256", "EdDSA") if context["crypto_profile"] == "fixture-es256-ed25519" else ("ES256",),
                    root_verifier=lambda payload, now: True,
                )
                result = verifier.verify(case["jws"], now=context["now"], clock_healthy=context["clock_healthy"])
                self.assertEqual(result.reason, case["expected"]["reason"])
                self.assertEqual(result.compact, case["jws"])
                if case["id"] == "clear":
                    rejected = replace(verifier, root_verifier=lambda payload, now: False).verify(
                        case["jws"], now=context["now"], clock_healthy=True)
                    self.assertEqual((rejected.stage, rejected.reason), (7, "TP_INVARIANT"))


if __name__ == "__main__": unittest.main()
