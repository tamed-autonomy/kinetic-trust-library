"""Provisional stage-3 trusted-key metadata checks from RFC PR #195."""

import base64
import json
import unittest
from pathlib import Path

from kinetic_trust_library.v3.trust_proof_key import trust_proof_stage3_reason


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
CASES = {
    "clear", "eddsa-named-profile", "untrusted-key", "revoked-key",
    "wrong-key-role", "wrong-key-curve", "algorithm-key-mismatch",
}


class ProposedTrustProofKey(unittest.TestCase):
    def test_published_stage3_metadata_cases(self):
        vectors = json.loads(VECTORS.read_text())
        trusted_keys = {key["kid"]: key for key in vectors["keys"]}
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
                context = {**vectors["context"], **case.get("context", {})}
                reason = trust_proof_stage3_reason(
                    header,
                    trusted_key=trusted_keys.get(header["kid"]),
                    expected_issuer=context["issuer"],
                    expected_zone=context["zone"],
                )
                wanted = case["expected"]["reason"]
                self.assertEqual(
                    reason,
                    wanted if wanted.startswith("TP_KEY_") else None,
                )
        self.assertEqual(observed, CASES)

    def test_untrusted_key_cannot_be_appointed_by_header(self):
        header = {"alg": "ES256", "kid": "attacker", "typ": "ktp-trust-proof+jwt"}
        self.assertEqual(trust_proof_stage3_reason(
            header, trusted_key=None, expected_issuer="issuer", expected_zone="zone"
        ), "TP_KEY_UNTRUSTED")


if __name__ == "__main__":
    unittest.main()
