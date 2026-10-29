"""Provisional strongest-single root selection from RFC PR #201."""

import json
import unittest
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.external_root_selection import (
    EligibleRoot,
    select_strongest_root,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/external-root-v1.json"


class ProposedExternalRootSelection(unittest.TestCase):
    def test_decimal_context_cannot_turn_near_scores_into_a_tie(self):
        weaker = EligibleRoot("weak", "sha256:" + "0" * 64, "0.1234567890123456789012345678901234")
        stronger = EligibleRoot("strong", "sha256:" + "f" * 64, "0.1234567890123456789012345678901235")
        self.assertIs(select_strongest_root((weaker, stronger), algorithm="sha256"), stronger)

    def test_root_strength_cannot_exceed_core_score_range(self):
        with self.assertRaises(ValidationError):
            EligibleRoot("root", "sha256:" + "a" * 64, 101)

    def test_published_selection_cases(self):
        vectors = json.loads(VECTORS.read_text())
        self.assertEqual(len(vectors["selection_cases"]), 4)
        for case in vectors["selection_cases"]:
            with self.subTest(case=case["id"]):
                candidates = tuple(
                    EligibleRoot(
                        instrument_id=name,
                        complete_digest=vectors["projection_examples"][name][
                            "attestation_digest"
                        ],
                        strength=vectors["selection_strength_answers"][name],
                    )
                    for name in case["candidates"]
                    if name not in case.get("ineligible", ())
                )
                selected = select_strongest_root(candidates, algorithm="sha256")
                self.assertEqual(selected.instrument_id, case["expected_selected"])
                self.assertEqual(
                    vectors["projection_examples"][selected.instrument_id],
                    case["expected_projection"],
                )
                self.assertFalse(case["aggregatePermitted"])

    def test_no_eligible_root_and_mixed_algorithms(self):
        self.assertIsNone(select_strongest_root((), algorithm="sha256"))
        with self.assertRaises(ValidationError):
            EligibleRoot("a", "sha256:" + "0" * 64, 0)
        root = EligibleRoot("a", "sha256:" + "a" * 64, 1)
        with self.assertRaises(ValidationError):
            select_strongest_root((root,), algorithm="sha384")


if __name__ == "__main__":
    unittest.main()
