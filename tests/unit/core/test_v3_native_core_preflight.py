"""Native v3 Soul-first Core stage ordering from RFC PR #203."""

import unittest
from decimal import Decimal

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library import v3
from kinetic_trust_library.v3.core import preflight_core
from kinetic_trust_library.v3.evidence_state import assess_required_factor
from kinetic_trust_library.v3.soul import (
    SoulGateState,
    SoulQueryState,
    assess_soul_queries,
)


FACTORS = (
    "evidence_density", "trust_trend", "adversarial_pressure",
    "update_resistance", "attestation_coverage",
)


def calm_factors():
    return tuple(
        assess_required_factor(
            factor=name, required_signals=(f"signal:{name}",),
            populated_signals={f"signal:{name}": 0}, measured_stress=0,
        )
        for name in FACTORS
    )


class NativeV3CorePreflight(unittest.TestCase):
    def test_candidate_v3_namespace_exposes_preflight(self):
        self.assertIs(v3.preflight_core, preflight_core)
        self.assertIs(v3.assess_soul_queries, assess_soul_queries)

    def test_known_veto_stops_before_risk_even_with_unknown_query(self):
        soul = assess_soul_queries(
            required_frameworks=("a", "b"),
            responses=(SoulQueryState("a", "veto"),),
        )
        self.assertEqual(soul.state, SoulGateState.VETO)
        self.assertEqual(
            tuple(entry.record() for entry in soul.undefined_inputs),
            ({"input": "b", "layer": "query", "state": "absent"},),
        )
        result = preflight_core(soul, factors=object(), weights=object())
        self.assertEqual(result.soul.state, SoulGateState.VETO)
        self.assertIsNone(result.risk)

    def test_unanswered_required_framework_stops_before_risk(self):
        soul = assess_soul_queries(
            required_frameworks=("a", "b"),
            responses=(SoulQueryState("a", "clear"), SoulQueryState("b", "unanswered")),
        )
        self.assertEqual(soul.state, SoulGateState.UNDETERMINED)
        result = preflight_core(soul, factors=object(), weights=object())
        self.assertIsNone(result.risk)
        self.assertEqual(result.soul.undefined_inputs[0].state, "unanswered")

    def test_clear_soul_allows_five_factor_risk_stage(self):
        soul = assess_soul_queries(
            required_frameworks=("a", "b"),
            responses=(SoulQueryState("a", "clear"), SoulQueryState("b", "clear")),
        )
        result = preflight_core(
            soul, factors=calm_factors(), weights=dict.fromkeys(FACTORS, "0.2")
        )
        self.assertEqual(result.soul.state, SoulGateState.CLEAR)
        self.assertEqual(result.risk.measured_risk, Decimal(0))

    def test_empty_duplicate_or_undeclared_frameworks_rejected(self):
        for required, responses in (
            ((), ()),
            (("a", "a"), (SoulQueryState("a", "clear"),)),
            (("a",), (SoulQueryState("b", "clear"),)),
            (("a",), (SoulQueryState("a", "clear"), SoulQueryState("a", "veto"))),
        ):
            with self.subTest(required=required, responses=responses):
                with self.assertRaises(ValidationError):
                    assess_soul_queries(required_frameworks=required, responses=responses)


if __name__ == "__main__":
    unittest.main()
