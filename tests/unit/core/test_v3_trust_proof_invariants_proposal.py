"""Provisional stage-7 invariant and ingress checks from RFC PR #195."""

import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.v3.trust_proof_framing import parse_compact_framing
from kinetic_trust_library.v3.trust_proof_invariants import trust_proof_stage7_reason
from kinetic_trust_library.v3.trust_proof_json import parse_proof_json_objects


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
REASONS = {"TP_INVARIANT", "TP_INGRESS", "TP_CLEAR", "TP_VETO", "TP_UNDETERMINED"}


@unittest.skipUnless(find_spec("rfc8785"), "install the v3-proofs extra for JCS tests")
class ProposedTrustProofInvariants(unittest.TestCase):
    def test_published_stage7_and_gate_cases(self):
        vectors = json.loads(VECTORS.read_text())
        observed = set()
        for case in vectors["cases"]:
            expected = case["expected"]["reason"]
            if expected not in REASONS:
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                _, payload = parse_proof_json_objects(parse_compact_framing(case["jws"]))
                context = {**vectors["context"], **case.get("context", {})}
                actual = trust_proof_stage7_reason(
                    payload,
                    expected_subject=context["subject"],
                    expected_zone=context["zone"],
                    required_ceilings=context["required_ceilings"],
                    ring_depth=context["ring_depth"],
                    ingress_verifier=None,
                )
                self.assertEqual(
                    actual,
                    expected if expected in {"TP_INVARIANT", "TP_INGRESS"} else None,
                )
        self.assertGreaterEqual(len(observed), 28)


if __name__ == "__main__":
    unittest.main()
