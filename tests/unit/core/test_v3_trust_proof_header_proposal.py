"""Provisional stage-2 protected-header checks from RFC PR #195."""

import base64
import json
import unittest
from pathlib import Path

from kinetic_trust_library.v3.trust_proof_header import trust_proof_stage2_reason


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
CASES = {
    "clear", "wrong-typ", "none-algorithm", "hmac-confusion",
    "curve-name-as-alg", "extra-header", "embedded-key", "remote-key",
    "b64-extension", "crit-header", "eddsa-disabled",
    "eddsa-named-profile", "type-before-expiry",
}


class ProposedTrustProofHeader(unittest.TestCase):
    def test_published_stage2_cases_after_structural_parsing(self):
        vectors = json.loads(VECTORS.read_text())
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
                algorithms = ("ES256", "EdDSA") if context["crypto_profile"] == (
                    "fixture-es256-ed25519"
                ) else ("ES256",)
                reason = trust_proof_stage2_reason(
                    header, installed_algorithms=algorithms
                )
                wanted = case["expected"]["reason"]
                self.assertEqual(
                    reason,
                    wanted if wanted in {"TP_TYPE", "TP_ALGORITHM", "TP_HEADER"}
                    else None,
                )
        self.assertEqual(observed, CASES)

    def test_caller_cannot_install_unsupported_algorithm(self):
        header = {"typ": "ktp-trust-proof+jwt", "alg": "none", "kid": "K"}
        self.assertEqual(
            trust_proof_stage2_reason(header, installed_algorithms=("none",)),
            "TP_ALGORITHM",
        )
        self.assertEqual(
            trust_proof_stage2_reason(header, installed_algorithms=("ES256",)),
            "TP_ALGORITHM",
        )


if __name__ == "__main__":
    unittest.main()
