import unittest
from decimal import Decimal
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.core_capacity import project_native_capacity
from kinetic_trust_library.v3.native_envelope import project_native_envelope, NativeEnvelopeThresholds
from tests.unit.core.test_v3_native_capacity_projection import preflight, standing95


class NativeEnvelopeTests(unittest.TestCase):
    def test_tiny_positive_demand_remains_strictly_below_margin_one(self):
        capacity = project_native_capacity(preflight(), standing=standing95(), demand="1e-6143")
        result = project_native_envelope(capacity, thresholds=NativeEnvelopeThresholds(0, ".2", ".3", 1))
        self.assertEqual(result.supervision, "metacognitive")

    def test_capacity_and_equality_veto_precede_profile(self):
        for demand in (95, 96):
            capacity = project_native_capacity(preflight(), standing=standing95(), demand=demand)
            result = project_native_envelope(capacity)
            self.assertEqual(result.supervision, "silent_veto")
            self.assertEqual(result.margin, Decimal(0) if demand == 95 else None)

    def test_declared_bands_and_unknown_capacity_floor(self):
        profile = NativeEnvelopeThresholds("0.1", "0.2", "0.3", "0.4")
        for demand, expected in ((50, "stable"), (60, "metacognitive"), (70, "assisted"), (80, "regulated"), (90, "silent_veto")):
            result = project_native_envelope(project_native_capacity(preflight(), standing=standing95(), demand=demand), thresholds=profile)
            self.assertEqual(result.supervision, expected)
        unknown = project_native_capacity(preflight(missing=True), standing=standing95(), demand=1)
        self.assertEqual(project_native_envelope(unknown).supervision, "assisted")
        with self.assertRaises(ValidationError):
            NativeEnvelopeThresholds(0, 0, 0, 0)


if __name__ == "__main__": unittest.main()
