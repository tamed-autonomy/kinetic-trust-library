"""Provisional checks against RFC PR #193, head b698f82e02c4."""

import json
import unittest
from decimal import Decimal
from pathlib import Path

from kinetic_trust_library.core.por import calculate_por, classify_friction
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.standing import FrictionCategory
from tests.unit.core.test_por import CUTOFF, attestation


VECTORS = Path(__file__).parents[3] / "spec/proposals/por-friction-boundaries-v3.json"


class ProposedFrictionBoundaries(unittest.TestCase):
    def test_tagged_v2_elevated_label_at_point_three_is_not_native_v3(self):
        with self.assertRaisesRegex(ValidationError, "friction category"):
            calculate_por(
                [attestation(friction="0.3", friction_category=FrictionCategory.ELEVATED)],
                "agent:one",
                CUTOFF,
            )

    def test_all_official_proposal_boundaries_have_one_exact_category(self):
        cases = json.loads(VECTORS.read_text())["cases"]
        for case in cases:
            with self.subTest(case=case["id"]):
                friction = Decimal(case["friction"])
                expected = case["expected"]
                if not expected["valid"]:
                    with self.assertRaises(ValidationError):
                        classify_friction(friction)
                else:
                    self.assertEqual(
                        classify_friction(friction),
                        FrictionCategory[expected["category"]],
                    )

    def test_proposal_contribution_and_category_mismatch_cases(self):
        cases = json.loads(VECTORS.read_text())["cases"]
        for case in cases:
            with self.subTest(case=case["id"]):
                expected = case["expected"]
                if not expected["valid"]:
                    continue
                category = FrictionCategory[expected["category"]]
                declaration = attestation(
                    friction=case["friction"],
                    friction_category=category,
                    action_risk=case["action_risk"],
                )
                result = calculate_por([declaration], "agent:one", CUTOFF)
                self.assertEqual(
                    bool(result.eligible_attestation_ids),
                    expected["ordinary_success_eligible"],
                )
                self.assertEqual(
                    result.resilience_score,
                    Decimal(expected["resilience_score_contribution"]),
                )
                if expected["mismatched_declared_category"] is not None:
                    mismatch = FrictionCategory[
                        expected["mismatched_declared_category"]
                    ]
                    with self.assertRaises(ValidationError):
                        calculate_por(
                            [attestation(
                                friction=case["friction"],
                                friction_category=mismatch,
                            )],
                            "agent:one",
                            CUTOFF,
                        )


if __name__ == "__main__":
    unittest.main()
