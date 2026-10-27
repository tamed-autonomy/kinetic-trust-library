"""Native v3 composition of the five-factor and missing-evidence proposals."""

import json
import unittest
from decimal import Decimal
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library import v3
from kinetic_trust_library.v3.core_risk import (
    NativeRiskAssessment,
    assess_five_factor_risk,
)
from kinetic_trust_library.v3.evidence_state import assess_required_factor


VECTORS = Path(__file__).parents[3] / "spec/proposals/demand-input-v1.json"
FACTORS = (
    "evidence_density", "trust_trend", "adversarial_pressure",
    "update_resistance", "attestation_coverage",
)


def observed(name: str, value: object):
    signal = f"signal:{name}"
    return assess_required_factor(
        factor=name, required_signals=(signal,),
        populated_signals={signal: value}, measured_stress=value,
    )


class NativeV3RiskAssessment(unittest.TestCase):
    def test_candidate_v3_namespace_exposes_native_risk_path(self):
        self.assertIs(v3.assess_five_factor_risk, assess_five_factor_risk)
        self.assertIs(v3.NativeRiskAssessment, NativeRiskAssessment)

    def test_complete_five_factor_stadium_case(self):
        vectors = json.loads(VECTORS.read_text())["vectors"]
        case = next(item for item in vectors if item["id"].startswith("DI10-"))
        given = case["given"]
        states = tuple(observed(name, given["normalized_inputs"][name]) for name in FACTORS)
        result = assess_five_factor_risk(states, weights=given["weights"])
        self.assertEqual(result.measured_risk, Decimal("0.53975"))
        self.assertEqual(result.decision_risk, Decimal("0.53975"))
        self.assertEqual(result.undefined_inputs, ())
        self.assertTrue(result.has_complete_measurement)
        self.assertEqual(tuple(state.factor for state in result.factors), FACTORS)

    def test_missing_factor_retains_unknownness_with_restrictive_reading(self):
        states = [observed(name, 0) for name in FACTORS]
        states[0] = assess_required_factor(
            factor=FACTORS[0], required_signals=("signal:missing",),
            populated_signals={"signal:missing": None}, measured_stress=None,
        )
        result = assess_five_factor_risk(tuple(states), weights=dict.fromkeys(FACTORS, "0.2"))
        self.assertIsNone(result.measured_risk)
        self.assertEqual(result.decision_risk, Decimal("0.2"))
        self.assertFalse(result.has_complete_measurement)
        self.assertEqual(
            tuple((entry.input, entry.layer) for entry in result.undefined_inputs),
            (("signal:missing", "signal"), (FACTORS[0], "term")),
        )
        self.assertIsNone(result.factors[0].value)

    def test_rejects_missing_duplicate_and_sixth_factor(self):
        states = tuple(observed(name, 0) for name in FACTORS)
        weights = dict.fromkeys(FACTORS, "0.2")
        for invalid in (states[:-1], states[:-1] + states[:1], states + (
            observed("moment_criticality", 0),
        )):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(ValidationError):
                    assess_five_factor_risk(invalid, weights=weights)

    def test_result_cannot_be_fabricated_or_mutated(self):
        with self.assertRaises(TypeError):
            NativeRiskAssessment()
        result = assess_five_factor_risk(
            tuple(observed(name, 0) for name in FACTORS),
            weights=dict.fromkeys(FACTORS, "0.2"),
        )
        with self.assertRaises((AttributeError, TypeError)):
            result.decision_risk = Decimal(0)


if __name__ == "__main__":
    unittest.main()
