"""Provisional, pure calculations from KTP-CELESTIAL and RFC PR #222."""

import unittest
from decimal import Decimal

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.celestial_profile import (
    latest_verifiable_event_time,
    projected_validity_seconds,
    degraded_trust,
    step_tier_ceiling,
)


class CelestialProfileTests(unittest.TestCase):
    def test_mars_validity_example_and_class_cap(self):
        self.assertEqual(projected_validity_seconds(
            latency_class=2, light_time_seconds=750, departure_tier_value="0.85"
        ), Decimal("21375.0000"))
        self.assertEqual(projected_validity_seconds(
            latency_class=2, light_time_seconds=3000, departure_tier_value="1"
        ), Decimal(86400))

    def test_class_five_requires_declared_mission_duration(self):
        with self.assertRaises(ValidationError):
            projected_validity_seconds(latency_class=5, light_time_seconds=1_000_000,
                                       departure_tier_value="0.85")
        self.assertEqual(projected_validity_seconds(
            latency_class=5, light_time_seconds=1_000_000,
            departure_tier_value="0.85", mission_duration_seconds=12345
        ), Decimal(12345))

    def test_causality_does_not_call_remote_state_current(self):
        self.assertEqual(latest_verifiable_event_time(1000, 750), Decimal(250))
        with self.assertRaises(ValidationError):
            latest_verifiable_event_time(1000, -1)

    def test_linear_and_corrected_exponential_half_life(self):
        self.assertEqual(degraded_trust(80, elapsed_seconds=5, validity_seconds=10,
                                        curve="linear"), Decimal(40))
        self.assertAlmostEqual(degraded_trust(80, elapsed_seconds=6, validity_seconds=24,
                                              curve="exponential", half_life_seconds=6),
                               Decimal(40), places=20)
        self.assertEqual(degraded_trust(80, elapsed_seconds=10, validity_seconds=10,
                                        curve="linear"), Decimal(0))
        with self.assertRaises(ValidationError):
            degraded_trust(80, elapsed_seconds=11, validity_seconds=10, curve="linear")

    def test_step_thresholds_are_ceilings_only(self):
        self.assertIsNone(step_tier_ceiling(elapsed_seconds=49, validity_seconds=100))
        self.assertEqual(step_tier_ceiling(elapsed_seconds=50, validity_seconds=100), "analyst")
        self.assertEqual(step_tier_ceiling(elapsed_seconds=75, validity_seconds=100), "observer")
        self.assertEqual(step_tier_ceiling(elapsed_seconds=90, validity_seconds=100), "hibernation")
