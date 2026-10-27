"""Provisional compact-framing subset of RFC PR #195 stage 1."""

import json
import unittest
from pathlib import Path

from kinetic_trust_library.errors import ProofFormatError
from kinetic_trust_library.v3.trust_proof_framing import parse_compact_framing


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
CASES = {
    "clear": True,
    "invalid-compact": False,
    "padding": False,
    "oversized-envelope": False,
    "oversized-header": False,
    "invalid-utf8": False,
}


class ProposedTrustProofFraming(unittest.TestCase):
    def test_published_compact_cases(self):
        vectors = json.loads(VECTORS.read_text())
        observed = set()
        for case in vectors["cases"]:
            if case["id"] not in CASES:
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                if CASES[case["id"]]:
                    parsed = parse_compact_framing(case["jws"])
                    self.assertEqual(parsed.signing_input, case["jws"].rsplit(".", 1)[0].encode("ascii"))
                else:
                    with self.assertRaises(ProofFormatError):
                        parse_compact_framing(case["jws"])
        self.assertEqual(observed, set(CASES))

    def test_non_ascii_empty_and_noncanonical_segments(self):
        for invalid in ("é.a.b", "a..b", "a.b.", "a.b.c=", "a.b.c/d", "a.b.c+d"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ProofFormatError):
                    parse_compact_framing(invalid)


if __name__ == "__main__":
    unittest.main()
