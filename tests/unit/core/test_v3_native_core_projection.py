"""Native Core projection stage order without an authorization result."""

import unittest

from kinetic_trust_library import v3
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.base_trust import calculate_native_base_trust
from kinetic_trust_library.v3.core_projection import project_native_core
from kinetic_trust_library.v3.evidence_state import assess_required_factor
from kinetic_trust_library.v3.soul import SoulQueryState, assess_soul_queries


FACTORS = (
    "evidence_density", "trust_trend", "adversarial_pressure",
    "update_resistance", "attestation_coverage",
)


def soul(value):
    return assess_soul_queries(
        required_frameworks=("framework",),
        responses=(SoulQueryState("framework", value),),
    )


def standing():
    return calculate_native_base_trust(
        por_contribution=70, root_score=100, peer_share=0, peer_score=0,
        ceilings={"generation": 100, "ial": 95, "trajectory": 100, "adversity": 100},
    )


def factors():
    return tuple(
        assess_required_factor(
            factor=name, required_signals=(f"signal:{name}",),
            populated_signals={f"signal:{name}": 0}, measured_stress=0,
        ) for name in FACTORS
    )


class NativeCoreProjectionTests(unittest.TestCase):
    def test_v3_namespace_exposes_native_composition(self):
        self.assertIs(v3.project_native_core, project_native_core)
        self.assertIs(v3.calculate_native_base_trust, calculate_native_base_trust)

    def test_veto_and_unknown_stop_before_standing_risk_and_capacity(self):
        for state in ("veto", "unanswered"):
            with self.subTest(state=state):
                result = project_native_core(
                    soul(state), standing=object(), factors=object(),
                    weights=object(), demand=object(),
                )
                self.assertIsNone(result.standing)
                self.assertIsNone(result.risk)
                self.assertIsNone(result.capacity)
                if state == "unanswered":
                    self.assertEqual(result.undefined_inputs[0].layer, "query")

    def test_standing_is_validated_before_risk(self):
        with self.assertRaisesRegex(ValidationError, "standing"):
            project_native_core(
                soul("clear"), standing=object(), factors=object(),
                weights=object(), demand=object(),
            )

    def test_clear_path_reaches_conservative_capacity_projection(self):
        result = project_native_core(
            soul("clear"), standing=standing(), factors=factors(),
            weights=dict.fromkeys(FACTORS, "0.2"), demand=90,
        )
        self.assertEqual(result.standing.base_trust, 95)
        self.assertEqual(result.risk.decision_risk, 0)
        self.assertEqual(result.capacity.relation, "below")
        self.assertFalse(hasattr(result, "authorized"))
        self.assertEqual(result.undefined_inputs, ())


if __name__ == "__main__":
    unittest.main()
