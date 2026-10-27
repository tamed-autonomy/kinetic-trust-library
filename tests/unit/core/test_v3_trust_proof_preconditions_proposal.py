"""Provisional ordered precondition stages 1–5 from RFC PR #195."""

import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.v3._trust_proof_preconditions import first_precondition_failure


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
EARLY_REASONS = {
    "TP_FORMAT", "TP_TYPE", "TP_ALGORITHM", "TP_HEADER",
    "TP_KEY_UNTRUSTED", "TP_KEY_REVOKED", "TP_KEY_ROLE",
    "TP_KEY_ALGORITHM", "TP_SIGNATURE", "TP_ISSUER", "TP_AUDIENCE",
    "TP_TIME",
}


@unittest.skipUnless(find_spec("rfc8785"), "install the v3-proofs extra for JCS tests")
class ProposedTrustProofPreconditions(unittest.TestCase):
    def test_all_published_cases_respect_first_five_stages(self):
        vectors = json.loads(VECTORS.read_text())
        keys = {key["kid"]: key for key in vectors["keys"]}
        self.assertGreaterEqual(len(vectors["cases"]), 90)
        for case in vectors["cases"]:
            with self.subTest(case=case["id"]):
                context = {**vectors["context"], **case.get("context", {})}
                algorithms = ("ES256", "EdDSA") if context["crypto_profile"] == (
                    "fixture-es256-ed25519"
                ) else ("ES256",)
                actual = first_precondition_failure(
                    case["jws"],
                    expected_issuer=context["issuer"],
                    expected_audience=context["audience"],
                    expected_zone=context["zone"],
                    now=context["now"],
                    clock_healthy=context["clock_healthy"],
                    installed_algorithms=algorithms,
                    trusted_keys=keys,
                )
                expected = case["expected"]["reason"]
                self.assertEqual(actual, expected if expected in EARLY_REASONS else None)


if __name__ == "__main__":
    unittest.main()
