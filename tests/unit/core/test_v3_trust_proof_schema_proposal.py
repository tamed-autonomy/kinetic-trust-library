"""Provisional stage-6 closed schema checks from RFC PR #195."""

import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.v3.trust_proof_framing import parse_compact_framing
from kinetic_trust_library.v3.trust_proof_json import parse_proof_json_objects
from kinetic_trust_library.v3.trust_proof_schema import trust_proof_schema_valid


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
@unittest.skipUnless(
    find_spec("rfc8785") and find_spec("jsonschema"),
    "install the v3-proofs extra for schema tests",
)
class ProposedTrustProofSchema(unittest.TestCase):
    def test_all_published_schema_failures_are_rejected(self):
        vectors = json.loads(VECTORS.read_text())
        observed = set()
        for case in vectors["cases"]:
            if case["expected"]["reason"] != "TP_SCHEMA":
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                _, payload = parse_proof_json_objects(parse_compact_framing(case["jws"]))
                self.assertFalse(trust_proof_schema_valid(payload))
        self.assertEqual(len(observed), 22)

    def test_proposal_schema_conflicts_with_its_clear_vector(self):
        vectors = json.loads(VECTORS.read_text())
        clear = next(case for case in vectors["cases"] if case["id"] == "clear")
        _, payload = parse_proof_json_objects(parse_compact_framing(clear["jws"]))
        risk_schema = json.loads((VECTORS.parents[2] / (
            "spec/v2.1.0/schemas/risk-factors.json"
        )).read_text())
        self.assertEqual(clear["expected"]["reason"], "TP_CLEAR")
        self.assertEqual(len(payload["ktp"]["context"]), 5)
        self.assertIn("moment_criticality", risk_schema["required"])
        self.assertFalse(trust_proof_schema_valid(payload))


if __name__ == "__main__":
    unittest.main()
