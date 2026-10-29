import unittest
from decimal import Decimal, localcontext
from fractions import Fraction
from kinetic_trust_library.v3._exact import finite_decimal
from kinetic_trust_library.v3.risk import calculate_five_factor_risk
from kinetic_trust_library.v3.base_trust import calculate_native_base_trust
from kinetic_trust_library.v3.core import preflight_core
from kinetic_trust_library.v3.core_capacity import project_native_capacity
from kinetic_trust_library.v3.soul import assess_soul_queries, SoulQueryState
from kinetic_trust_library.v3.evidence_state import assess_required_factor

FACTORS = ("evidence_density","trust_trend","adversarial_pressure","update_resistance","attestation_coverage")


class ExactNativeArithmeticTests(unittest.TestCase):
    def test_terminating_conversion_at_extreme_exponents_and_repeating_rejection(self):
        with localcontext() as context:
            context.prec = 3
            for text in ("1e-6143", "1e6144", "-.125", "0", "12.34567890123456789"):
                value = Decimal(text)
                self.assertEqual(finite_decimal(Fraction(value)), value)
        with self.assertRaises(ValueError):
            finite_decimal(Fraction(1, 3))

    def test_small_contribution_survives_risk_and_capacity(self):
        values = dict.fromkeys(FACTORS, 0)
        values[FACTORS[0]], values[FACTORS[1]] = 1, "1e-100"
        weights = dict.fromkeys(FACTORS, ".2")
        with localcontext() as context:
            context.prec = 6
            risk = calculate_five_factor_risk(values, weights)
        self.assertGreater(risk, Decimal(".2"))
        factors = tuple(assess_required_factor(factor=n, required_signals=(n,), populated_signals={n:values[n]}, measured_stress=values[n]) for n in FACTORS)
        soul = assess_soul_queries(required_frameworks=("f",), responses=(SoulQueryState("f","clear"),))
        base = calculate_native_base_trust(por_contribution=70, root_score=100, peer_share=0, peer_score=0,
            ceilings=dict(generation=100,ial=95,trajectory=100,adversity=100))
        projected = project_native_capacity(preflight_core(soul,factors=factors,weights=weights), standing=base, demand=76)
        self.assertLess(projected.decision_effective_trust, Decimal(76))
        self.assertEqual(projected.relation,"above")

    def test_small_base_contribution_survives_share_composition(self):
        result = calculate_native_base_trust(por_contribution=1, root_score="1e-100",peer_share=0,peer_score=0,
            ceilings=dict(generation=100,ial=95,trajectory=100,adversity=100))
        self.assertGreater(result.raw_base, Decimal(1))


if __name__ == "__main__": unittest.main()
