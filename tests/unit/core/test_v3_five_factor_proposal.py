"""Provisional five-factor checks against RFC PR #164, head 7e4a3c9."""

import json
import unittest
from decimal import Context, Decimal, localcontext
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.risk import calculate_five_factor_risk


VECTORS = Path(__file__).parents[3] / "spec/proposals/demand-input-v1.json"


class ProposedFiveFactorRisk(unittest.TestCase):
    def test_stadium_vector_has_exact_five_factor_arithmetic(self):
        cases = json.loads(VECTORS.read_text())["vectors"]
        kickoff = next(case for case in cases if case["id"].startswith("DI10-"))
        given = kickoff["given"]
        result = calculate_five_factor_risk(
            given["normalized_inputs"], given["weights"]
        )
        self.assertEqual(result, Decimal("0.53975"))
        self.assertEqual(result.quantize(Decimal("0.01")), Decimal("0.54"))
        self.assertEqual(result, Decimal(str(kickoff["expect"]["R"])))
        self.assertEqual(Decimal(95) * (1-result), Decimal(str(kickoff["expect"]["E_trust"])))

    def test_sixth_factor_and_non_unit_weights_are_rejected(self):
        values = dict.fromkeys(
            (
                "evidence_density", "trust_trend", "adversarial_pressure",
                "update_resistance", "attestation_coverage",
            ),
            "0.5",
        )
        weights = dict.fromkeys(values, "0.20")
        with self.assertRaises(ValidationError):
            calculate_five_factor_risk(
                {**values, "moment_criticality": "0.99"}, weights
            )
        with self.assertRaises(ValidationError):
            calculate_five_factor_risk(values, {**weights, "trust_trend": "0.21"})

    def test_bool_nonfinite_and_out_of_range_values_are_rejected(self):
        values = dict.fromkeys(
            (
                "evidence_density", "trust_trend", "adversarial_pressure",
                "update_resistance", "attestation_coverage",
            ),
            "0.5",
        )
        weights = dict.fromkeys(values, "0.20")
        for invalid in (True, "NaN", "Infinity", "-0.01", "1.01"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValidationError):
                    calculate_five_factor_risk(
                        {**values, "trust_trend": invalid}, weights
                    )

    def test_decimal_products_are_not_rounded_to_v2_local_precision(self):
        names = (
            "evidence_density", "trust_trend", "adversarial_pressure",
            "update_resistance", "attestation_coverage",
        )
        first = Decimal("0.1234567890123456789012345678901234")
        values = dict.fromkeys(names, Decimal(0))
        values[names[0]] = first
        weights = dict(zip(names, (
            first, Decimal("0.2"), Decimal("0.2"), Decimal("0.2"),
            Decimal("0.2765432109876543210987654321098766"),
        )))
        with localcontext(Context(prec=70)):
            expected = first * first
        self.assertEqual(calculate_five_factor_risk(values, weights), expected)


if __name__ == "__main__":
    unittest.main()
