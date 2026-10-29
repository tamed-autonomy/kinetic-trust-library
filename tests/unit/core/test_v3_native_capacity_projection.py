"""Exact, non-authorizing v3 capacity projection."""

import unittest
from decimal import Decimal

from kinetic_trust_library import v3
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.base_trust import calculate_native_base_trust
from kinetic_trust_library.v3.core import preflight_core
from kinetic_trust_library.v3.core_capacity import (
    NativeCapacityProjection, project_native_capacity,
)
from kinetic_trust_library.v3.evidence_state import assess_required_factor
from kinetic_trust_library.v3.soul import SoulQueryState, assess_soul_queries


FACTORS = (
    "evidence_density", "trust_trend", "adversarial_pressure",
    "update_resistance", "attestation_coverage",
)
WEIGHTS = dict.fromkeys(FACTORS, "0.2")


def standing95():
    return calculate_native_base_trust(
        por_contribution=70, root_score=100, peer_share=0, peer_score=0,
        ceilings={"generation": 100, "ial": 95, "trajectory": 100, "adversity": 100},
    )


def preflight(*, veto=False, missing=False):
    soul = assess_soul_queries(
        required_frameworks=("framework",),
        responses=(SoulQueryState("framework", "veto" if veto else "clear"),),
    )
    factors = tuple(
        assess_required_factor(
            factor=name,
            required_signals=(f"signal:{name}",),
            populated_signals={f"signal:{name}": None if missing and name == FACTORS[0] else 0},
            measured_stress=None if missing and name == FACTORS[0] else 0,
        )
        for name in FACTORS
    )
    return preflight_core(soul, factors=factors, weights=WEIGHTS)


class NativeV3CapacityProjection(unittest.TestCase):
    def test_v3_namespace_exposes_projection_without_authorization(self):
        self.assertIs(v3.project_native_capacity, project_native_capacity)

    def test_rfc_demand_input_worked_example_keeps_unrounded_intermediate(self):
        soul = assess_soul_queries(
            required_frameworks=("framework",),
            responses=(SoulQueryState("framework", "clear"),),
        )
        values = {
            "evidence_density": "0.875", "trust_trend": "0.920",
            "adversarial_pressure": "0.020", "update_resistance": "0.100",
            "attestation_coverage": "0.040",
        }
        weights = {
            "evidence_density": "0.29", "trust_trend": "0.29",
            "adversarial_pressure": "0.24", "update_resistance": "0.12",
            "attestation_coverage": "0.06",
        }
        factors = tuple(
            assess_required_factor(
                factor=name, required_signals=(f"signal:{name}",),
                populated_signals={f"signal:{name}": values[name]},
                measured_stress=values[name],
            ) for name in FACTORS
        )
        result = project_native_capacity(
            preflight_core(soul, factors=factors, weights=weights),
            standing=standing95(), demand="43.72",
        )
        self.assertEqual(result.measured_effective_trust, Decimal("43.72375"))
        self.assertEqual(result.relation, "below")

    def test_exact_complete_measurement_and_relation(self):
        result = project_native_capacity(preflight(), standing=standing95(), demand=80)
        self.assertEqual(result.measured_effective_trust, Decimal(95))
        self.assertEqual(result.decision_effective_trust, Decimal(95))
        self.assertEqual(result.relation, "below")
        self.assertEqual(project_native_capacity(preflight(), standing=standing95(), demand=95).relation, "at")
        self.assertEqual(project_native_capacity(preflight(), standing=standing95(), demand=96).relation, "above")

    def test_missing_factor_preserves_unknownness_and_restricts_capacity(self):
        result = project_native_capacity(preflight(missing=True), standing=standing95(), demand=77)
        self.assertIsNone(result.measured_effective_trust)
        self.assertEqual(result.decision_effective_trust, Decimal(76))
        self.assertEqual(result.relation, "above")
        self.assertFalse(result.capacity_known)

    def test_soul_veto_stops_before_capacity_and_invalid_inputs_are_rejected(self):
        self.assertIsNone(project_native_capacity(preflight(veto=True), standing=object(), demand=object()))
        with self.assertRaises(TypeError):
            NativeCapacityProjection()
        for standing, demand in ((object(), 0), (standing95(), -1), (standing95(), 101), (standing95(), True)):
            with self.subTest(standing=standing, demand=demand):
                with self.assertRaises(ValidationError):
                    project_native_capacity(preflight(), standing=standing, demand=demand)


if __name__ == "__main__":
    unittest.main()
