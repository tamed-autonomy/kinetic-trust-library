"""Provisional checks against RFC PR #194, head 9889cabcf4eb."""

import json
import unittest
from pathlib import Path

from kinetic_trust_library.agent_identity import (
    validate_agent_uri,
    validate_sponsorship_binding,
)
from kinetic_trust_library.errors import ValidationError


VECTORS = Path(__file__).parents[2] / "spec/proposals/agent-identifiers-v3.json"


class ProposedAgentIdentifiers(unittest.TestCase):
    def test_all_proposed_parse_vectors(self):
        cases = json.loads(VECTORS.read_text())["parse_cases"]
        for case in cases:
            with self.subTest(case=case["id"]):
                if case["expected_valid"]:
                    self.assertEqual(
                        validate_agent_uri(case["identifier"]), case["identifier"]
                    )
                else:
                    with self.assertRaises(ValidationError):
                        validate_agent_uri(case["identifier"])

    def test_all_proposed_binding_vectors(self):
        cases = json.loads(VECTORS.read_text())["binding_cases"]
        for case in cases:
            with self.subTest(case=case["id"]):
                values = (
                    case["subject"],
                    case["bond_sponsored_id"],
                    case["bond_sponsor_id"],
                    case["proof_sub"],
                    case["proof_sponsor"],
                )
                if case["expected_valid"]:
                    self.assertIsNone(validate_sponsorship_binding(*values))
                else:
                    with self.assertRaises(ValidationError):
                        validate_sponsorship_binding(*values)


if __name__ == "__main__":
    unittest.main()
