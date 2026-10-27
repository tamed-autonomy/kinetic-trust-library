"""Provisional strict JSON/JCS portion of RFC PR #195 stage 1."""

import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.errors import ProofFormatError
from kinetic_trust_library.v3.trust_proof_framing import parse_compact_framing
from kinetic_trust_library.v3.trust_proof_json import parse_proof_json_objects


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
JSON_CASES = {
    "clear": True,
    "duplicate-header": False,
    "duplicate-payload": False,
    "noncanonical-json": False,
    "nonfinite-json": False,
    "unsafe-integer": False,
    "integer-decimal-token": False,
    "excessive-depth": False,
}


@unittest.skipUnless(find_spec("rfc8785"), "install the v3-proofs extra for JCS tests")
class ProposedTrustProofJSON(unittest.TestCase):
    def test_published_json_cases(self):
        vectors = json.loads(VECTORS.read_text())
        observed = set()
        for case in vectors["cases"]:
            if case["id"] not in JSON_CASES:
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                framing = parse_compact_framing(case["jws"])
                if JSON_CASES[case["id"]]:
                    header, payload = parse_proof_json_objects(framing)
                    self.assertEqual(header["typ"], "ktp-trust-proof+jwt")
                    self.assertEqual(payload["iss"], vectors["context"]["issuer"])
                else:
                    with self.assertRaises(ProofFormatError):
                        parse_proof_json_objects(framing)
        self.assertEqual(observed, set(JSON_CASES))


if __name__ == "__main__":
    unittest.main()
