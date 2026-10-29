"""Native v3 E_base composition from Core §5.1."""

import unittest
from decimal import Decimal

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.base_trust import calculate_native_base_trust


CEILINGS = {"generation": 100, "ial": 95, "trajectory": 100, "adversity": 100}


class NativeV3BaseTrust(unittest.TestCase):
    def test_full_shares_and_ceiling(self):
        result = calculate_native_base_trust(
            por_contribution=70, root_score=100, peer_share=0,
            peer_score=0, ceilings={**CEILINGS, "deployment": 85},
        )
        self.assertEqual(result.raw_base, Decimal(100))
        self.assertEqual(result.base_trust, Decimal(85))
        self.assertEqual(result.binding_ceilings, ("deployment",))
        self.assertEqual(dict(result.ceilings)["ial"], Decimal(95))
        self.assertEqual(dict(result.ceilings)["deployment"], Decimal(85))

    def test_peer_share_reallocates_without_double_counting(self):
        result = calculate_native_base_trust(
            por_contribution=35, root_score=50, peer_share=20,
            peer_score=100, ceilings=CEILINGS,
        )
        self.assertEqual(result.raw_base, Decimal(60))
        self.assertEqual(result.base_trust, Decimal(60))

    def test_zero_root_enforces_missing_root_cap(self):
        result = calculate_native_base_trust(
            por_contribution=70, root_score=0, peer_share=20,
            peer_score=100, ceilings=CEILINGS,
        )
        self.assertEqual(result.raw_base, Decimal(76))
        self.assertEqual(result.base_trust, Decimal(70))
        self.assertIn("external_root_missing", result.binding_ceilings)

    def test_incomplete_or_invalid_declaration_rejected(self):
        for kwargs in (
            {"peer_share": 5}, {"peer_share": 21}, {"peer_share": True},
            {"por_contribution": 71}, {"root_score": 101},
            {"peer_score": 1}, {"ceilings": {"generation": 100}},
            {"ceilings": {**CEILINGS, "ial": 100}},
            {"ceilings": {**CEILINGS, "generation": 30}},
            {"ceilings": {**CEILINGS, "trajectory": 75}},
            {"ceilings": {**CEILINGS, "adversity": 75}},
        ):
            values = dict(por_contribution=70, root_score=100, peer_share=0,
                          peer_score=0, ceilings=CEILINGS)
            values.update(kwargs)
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValidationError):
                    calculate_native_base_trust(**values)


if __name__ == "__main__":
    unittest.main()
