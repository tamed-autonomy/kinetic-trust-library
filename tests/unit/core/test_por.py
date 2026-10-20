"""Proof-of-Resilience calculation tests derived from KTP Identity 5."""

import copy
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Context, Decimal, getcontext, setcontext

from kinetic_trust_library.core.por import (
    _por_contribution,
    calculate_por,
    require_validated_por_result,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.standing import (
    FrictionCategory,
    PoRAttestationDeclaration,
    PoRResult,
)


UTC = timezone.utc
CUTOFF = datetime(2026, 8, 20, 12, tzinfo=UTC)


class ObservableZeroOffsetTimezone(tzinfo):
    def __init__(self):
        self.calls = 0

    def utcoffset(self, value):
        self.calls += 1
        return timedelta(0)

    def dst(self, value):
        self.calls += 1
        return timedelta(0)


def attestation(index=1, **changes):
    values = {
        "attestation_id": f"attestation:{index}",
        "agent_id": "agent:one",
        "transaction_ref": f"transaction:{index}",
        "friction": "0.4",
        "friction_category": FrictionCategory.ELEVATED,
        "action_risk": "0.5",
        "outcome": "success",
        "timestamp": CUTOFF - timedelta(seconds=index),
        "oracle_id": f"oracle:{index}",
        "verification_ref": f"verification:{index}",
    }
    values.update(changes)
    return PoRAttestationDeclaration(**values)


class PoRTests(unittest.TestCase):
    def test_missing_attestation_slot_is_a_validation_error(self):
        declaration = attestation()
        object.__delattr__(declaration, "verification_ref")

        with self.assertRaises(ValidationError):
            calculate_por([declaration], agent_id="agent:one", cutoff=CUTOFF)

    def test_weighted_score_and_log_contribution(self):
        declarations = [
            *(attestation(index, friction="0.4") for index in range(1, 501)),
            *(
                attestation(
                    index,
                    friction="0.6",
                    friction_category=FrictionCategory.HIGH,
                )
                for index in range(501, 551)
            ),
            *(
                attestation(
                    index,
                    friction="0.95",
                    friction_category=FrictionCategory.CRISIS,
                )
                for index in range(551, 556)
            ),
        ]

        result = calculate_por(declarations, agent_id="agent:one", cutoff=CUTOFF)

        self.assertEqual(result.resilience_score, Decimal("325.0"))
        self.assertEqual(result.contribution.quantize(Decimal("0.1")), Decimal("25.1"))
        self.assertEqual(len(result.eligible_attestation_ids), 555)

    def test_contribution_has_the_published_seventy_point_cap(self):
        self.assertLess(_por_contribution(Decimal("9999998")), Decimal(70))
        self.assertEqual(_por_contribution(Decimal("9999999")), Decimal(70))
        self.assertEqual(_por_contribution(Decimal("1000000000")), Decimal(70))

    def test_friction_equal_point_three_gets_no_credit(self):
        result = calculate_por(
            [attestation(friction="0.3")],
            agent_id="agent:one",
            cutoff=CUTOFF,
        )
        self.assertEqual(result.resilience_score, Decimal(0))
        self.assertEqual(result.contribution, Decimal(0))
        self.assertEqual(result.eligible_attestation_ids, ())

    def test_category_boundaries_are_non_overlapping(self):
        cases = (
            ("0.3000001", FrictionCategory.ELEVATED),
            ("0.4999999", FrictionCategory.ELEVATED),
            ("0.5", FrictionCategory.HIGH),
            ("0.6999999", FrictionCategory.HIGH),
            ("0.7", FrictionCategory.SEVERE),
            ("0.8999999", FrictionCategory.SEVERE),
            ("0.9", FrictionCategory.CRISIS),
            ("1", FrictionCategory.CRISIS),
        )
        for index, (friction, category) in enumerate(cases, start=1):
            with self.subTest(friction=friction):
                result = calculate_por(
                    [attestation(index, friction=friction, friction_category=category)],
                    agent_id="agent:one",
                    cutoff=CUTOFF,
                )
                self.assertGreater(result.resilience_score, 0)

    def test_category_and_friction_must_agree(self):
        with self.assertRaisesRegex(ValidationError, "friction category"):
            calculate_por(
                [attestation(friction="0.7", friction_category=FrictionCategory.HIGH)],
                agent_id="agent:one",
                cutoff=CUTOFF,
            )

    def test_wrong_agent_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "agent"):
            calculate_por(
                [attestation(agent_id="agent:other")],
                agent_id="agent:one",
                cutoff=CUTOFF,
            )

    def test_duplicate_attestation_and_transaction_references_are_rejected(self):
        for second in (
            attestation(2, attestation_id="attestation:1"),
            attestation(2, transaction_ref="transaction:1"),
        ):
            with self.subTest(second=second):
                with self.assertRaisesRegex(ValidationError, "duplicate"):
                    calculate_por(
                        [attestation(), second],
                        agent_id="agent:one",
                        cutoff=CUTOFF,
                    )

    def test_future_attestation_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "future"):
            calculate_por(
                [attestation(timestamp=CUTOFF + timedelta(microseconds=1))],
                agent_id="agent:one",
                cutoff=CUTOFF,
            )

    def test_authoritative_por_times_require_owned_utc_without_timezone_hooks(self):
        custom_timezone = ObservableZeroOffsetTimezone()
        custom_time = datetime(2026, 8, 20, 11, 59, tzinfo=custom_timezone)
        with self.assertRaises(ValidationError):
            calculate_por(
                [attestation(timestamp=custom_time)],
                agent_id="agent:one",
                cutoff=CUTOFF,
            )
        self.assertEqual(custom_timezone.calls, 0)

        result = calculate_por([attestation()], "agent:one", CUTOFF)
        retained_timezone = ObservableZeroOffsetTimezone()
        retained_time = datetime(2026, 8, 20, 11, 59, tzinfo=retained_timezone)
        forged = copy.copy(result)
        object.__setattr__(
            forged,
            "_attestations",
            (replace(result._attestations[0], timestamp=retained_time),),
        )
        with self.assertRaises(ValidationError):
            require_validated_por_result(forged)
        self.assertEqual(retained_timezone.calls, 0)

    def test_attestation_has_no_invented_expiry_or_decay(self):
        old = attestation(timestamp=CUTOFF - timedelta(days=3650))
        result = calculate_por([old], agent_id="agent:one", cutoff=CUTOFF)
        self.assertEqual(result.eligible_attestation_ids, ("attestation:1",))

    def test_invalid_outcome_and_incomplete_verification_provenance_are_rejected(self):
        cases = (
            attestation(outcome="failure"),
            attestation(oracle_id=""),
            attestation(verification_ref=""),
        )
        for declaration in cases:
            with self.subTest(declaration=declaration):
                with self.assertRaises(ValidationError):
                    calculate_por([declaration], agent_id="agent:one", cutoff=CUTOFF)

    def test_action_risk_and_friction_are_bounded(self):
        for declaration in (
            attestation(action_risk="-0.0001"),
            attestation(action_risk="1.0001"),
            attestation(friction="1.0001"),
        ):
            with self.subTest(declaration=declaration):
                with self.assertRaises(ValidationError):
                    calculate_por([declaration], agent_id="agent:one", cutoff=CUTOFF)

    def test_graceful_degrade_requires_high_or_greater_friction_for_credit(self):
        elevated = calculate_por(
            [attestation(outcome="graceful_degrade")],
            agent_id="agent:one",
            cutoff=CUTOFF,
        )
        high = calculate_por(
            [
                attestation(
                    friction="0.5",
                    friction_category=FrictionCategory.HIGH,
                    outcome="graceful_degrade",
                )
            ],
            agent_id="agent:one",
            cutoff=CUTOFF,
        )
        self.assertEqual(elevated.resilience_score, 0)
        self.assertEqual(high.resilience_score, Decimal("1.0"))

    def test_zero_risk_attestation_remains_eligible_but_adds_zero(self):
        result = calculate_por([attestation(action_risk="0")], "agent:one", CUTOFF)
        self.assertEqual(result.eligible_attestation_ids, ("attestation:1",))
        self.assertEqual(result.resilience_score, 0)
        self.assertEqual(result.contribution, 0)

    def test_deterministic_logarithm_ignores_ambient_decimal_context(self):
        original = getcontext().copy()
        try:
            first = calculate_por([attestation()], "agent:one", CUTOFF)
            setcontext(Context(prec=7))
            second = calculate_por([attestation()], "agent:one", CUTOFF)
        finally:
            setcontext(original)
        self.assertEqual(first.contribution, second.contribution)
        self.assertEqual(first.digest, second.digest)

    def test_result_is_owned_guarded_and_structurally_revalidated(self):
        source = [attestation()]
        result = calculate_por(source, "agent:one", CUTOFF)
        original = copy.copy(result)
        source.clear()

        with self.assertRaises(TypeError):
            PoRResult()
        with self.assertRaises(FrozenInstanceError):
            result.contribution = Decimal(70)
        self.assertIs(require_validated_por_result(result), result)
        self.assertEqual(result, original)

        forged = object.__new__((PoRResult))
        for name in result.__slots__:
            object.__setattr__(forged, name, getattr(result, name))
        object.__setattr__(forged, "contribution", Decimal(70))
        with self.assertRaisesRegex(ValidationError, "integrity"):
            require_validated_por_result(forged)

    def test_input_order_does_not_change_result(self):
        values = [
            attestation(2, friction="0.6", friction_category=FrictionCategory.HIGH),
            attestation(1),
        ]
        forward = calculate_por(values, "agent:one", CUTOFF)
        reverse = calculate_por(tuple(reversed(values)), "agent:one", CUTOFF)
        self.assertEqual(forward, reverse)
        self.assertEqual(forward.digest, reverse.digest)

    def test_unbounded_iterable_is_rejected_without_a_product_history_quota(self):
        with self.assertRaisesRegex(ValidationError, "finite built-in"):
            calculate_por(
                (attestation(index) for index in range(1, 3)),
                "agent:one",
                CUTOFF,
            )

    def test_finite_history_beyond_the_old_batch_limit_is_accepted(self):
        values = [attestation(index, friction="0.3") for index in range(1, 65_538)]
        result = calculate_por(values, "agent:one", CUTOFF)
        self.assertEqual(result.resilience_score, 0)
        self.assertEqual(result.eligible_attestation_ids, ())


if __name__ == "__main__":
    unittest.main()
