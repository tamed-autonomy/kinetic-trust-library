"""Provisional stage-4 signature checks from RFC PR #195 test keys."""

import base64
import json
import unittest
from pathlib import Path

from kinetic_trust_library.v3.trust_proof_signature import trust_proof_signature_valid


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
CASES = {
    "clear", "eddsa-named-profile", "wrong-signing-key",
    "damaged-signature", "high-s", "der-signature",
    "signature-before-expiry",
}


class ProposedTrustProofSignature(unittest.TestCase):
    def test_published_signature_cases_after_prior_stages(self):
        vectors = json.loads(VECTORS.read_text())
        keys = {key["kid"]: key for key in vectors["keys"]}
        observed = set()
        for case in vectors["cases"]:
            if case["id"] not in CASES:
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                segment = case["jws"].split(".")[0]
                header = json.loads(base64.urlsafe_b64decode(
                    segment + "=" * (-len(segment) % 4)
                ))
                self.assertEqual(
                    trust_proof_signature_valid(
                        case["jws"], algorithm=header["alg"],
                        trusted_key=keys[header["kid"]],
                    ),
                    case["expected"]["reason"] != "TP_SIGNATURE",
                )
        self.assertEqual(observed, CASES)

    def test_no_key_or_wrong_key_fails_closed(self):
        vectors = json.loads(VECTORS.read_text())
        proof = next(c["jws"] for c in vectors["cases"] if c["id"] == "clear")
        self.assertFalse(trust_proof_signature_valid(
            proof, algorithm="ES256", trusted_key=None
        ))


if __name__ == "__main__":
    unittest.main()
