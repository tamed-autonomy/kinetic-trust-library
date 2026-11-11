"""Provisional checks against RFC PR #194, head a85e198a1736."""

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
                persons = frozenset(value for value in values if isinstance(value, str) and value.startswith("person:"))
                if case["expected_valid"]:
                    self.assertIsNone(validate_sponsorship_binding(*values, authenticated_person_ids=persons))
                else:
                    with self.assertRaises(ValidationError):
                        validate_sponsorship_binding(*values, authenticated_person_ids=persons)

    def test_person_id_requires_independent_authentication(self):
        with self.assertRaises(ValidationError):
            validate_sponsorship_binding(
                "person:alex", "person:alex", "person:robin", "person:alex", "person:robin"
            )


if __name__ == "__main__":
    unittest.main()
