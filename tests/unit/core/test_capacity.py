from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import kinetic_trust_library.core.capacity as capacity_module
import kinetic_trust_library.models.profile as profile_module
from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.core.capacity import (
    _derive_core_capacity_with_context,
    _require_validated_core_capacity_result_with_context,
    require_validated_core_capacity_result,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.capacity import CapacityRelation, CoreCapacityResult
from kinetic_trust_library.models.profile import ProfileRef
from tests.unit.core.test_envelope import CAPACITY, OPERATION_ID, full_state


def capacity_fixture(demand: Decimal = CAPACITY - Decimal("0.000001")):
    profile, action, _, trust = full_state(demand)
    context = profile_module._validated_profile_context(profile)
    value = _derive_core_capacity_with_context(
        context, action, trust, operation_id=OPERATION_ID
    )
    return profile, action, trust, value


class CoreCapacityTests(unittest.TestCase):
    def test_derived_value_binds_exact_validated_inputs(self):
        profile, action, trust, value = capacity_fixture()

        self.assertIs(require_validated_core_capacity_result(value), value)
        self.assertEqual(value.operation_id, OPERATION_ID)
        self.assertEqual(value.profile_ref, profile.ref)
        self.assertEqual(value.profile_digest, profile.digest)
        self.assertEqual(value.action_id, action.action_id)
        self.assertEqual(value.action_digest, action.digest)
        self.assertEqual(value.trust_digest, trust.digest)
        self.assertEqual(value.cutoff, action.validation_cutoff)
        self.assertEqual(value.autonomy_demand, action.demand)
        self.assertEqual(value.effective_trust, trust.effective_trust)
        self.assertRegex(value.digest, r"^[0-9a-f]{64}$")
        self.assertIs(
            _require_validated_core_capacity_result_with_context(
                value,
                profile_module._validated_profile_context(profile),
                action=action,
                trust=trust,
                operation_id=OPERATION_ID,
            ),
            value,
        )
        self.assertEqual(
            value.digest,
            canonical_sha256(
                {
                    "operation_id": OPERATION_ID,
                    "profile_ref": profile.ref,
                    "profile_digest": profile.digest,
                    "action_id": action.action_id,
                    "action_digest": action.digest,
                    "trust_digest": trust.digest,
                    "cutoff": action.validation_cutoff,
                    "autonomy_demand": action.demand,
                    "effective_trust": trust.effective_trust,
                    "relation": "below_capacity",
                }
            ),
        )

    def test_constructor_and_mutation_are_closed(self):
        with self.assertRaises(TypeError):
            CoreCapacityResult()
        with self.assertRaises(TypeError):
            CoreCapacityResult(operation_id=OPERATION_ID)
        value = capacity_fixture()[3]
        with self.assertRaises(FrozenInstanceError):
            value.digest = "0" * 64

    def test_revalidation_rejects_resealed_out_of_domain_terms(self):
        original = capacity_fixture()[3]
        cases = (
            ("autonomy_demand", Decimal("-0.000001")),
            ("autonomy_demand", Decimal("100.000001")),
            ("effective_trust", Decimal("-0.000001")),
            ("effective_trust", Decimal("100.000001")),
        )
        for member, replacement in cases:
            with self.subTest(member=member, replacement=replacement):
                hostile = copy.copy(original)
                object.__setattr__(hostile, member, replacement)
                object.__setattr__(
                    hostile, "digest", capacity_module._core_capacity_digest(hostile)
                )
                with self.assertRaisesRegex(
                    ValidationError, "Core capacity integrity is invalid"
                ):
                    require_validated_core_capacity_result(hostile)

    def test_revalidation_rejects_nonfinite_terms_before_digest_work(self):
        original = capacity_fixture()[3]
        for member in ("autonomy_demand", "effective_trust"):
            for replacement in (
                Decimal("NaN"), Decimal("sNaN"),
                Decimal("Infinity"), Decimal("-Infinity"),
            ):
                with self.subTest(member=member, replacement=replacement):
                    hostile = copy.copy(original)
                    object.__setattr__(hostile, member, replacement)
                    object.__setattr__(hostile, "digest", "0" * 64)
                    with patch.object(
                        capacity_module,
                        "_core_capacity_digest",
                        side_effect=AssertionError("digest work reached"),
                    ) as digest:
                        with self.assertRaisesRegex(
                            ValidationError, "Core capacity integrity is invalid"
                        ):
                            require_validated_core_capacity_result(hostile)
                        digest.assert_not_called()

    def test_equal_inputs_have_a_deterministic_digest(self):
        self.assertEqual(capacity_fixture()[3].digest, capacity_fixture()[3].digest)

    def test_changed_digest_and_resealed_relation_are_rejected(self):
        original = capacity_fixture()[3]
        changed_digest = copy.copy(original)
        object.__setattr__(changed_digest, "digest", "0" * 64)
        with self.assertRaises(ValidationError):
            require_validated_core_capacity_result(changed_digest)

        changed_relation = copy.copy(original)
        object.__setattr__(
            changed_relation, "relation", CapacityRelation.ABOVE_CAPACITY
        )
        object.__setattr__(
            changed_relation, "digest",
            capacity_module._core_capacity_digest(changed_relation),
        )
        with self.assertRaises(ValidationError):
            require_validated_core_capacity_result(changed_relation)
        with self.assertRaises(ValidationError):
            _ = changed_relation.within_capacity

    def test_context_validation_rejects_another_action_or_trust(self):
        profile, action, trust, original = capacity_fixture()
        _, alternate_action, alternate_trust, _ = capacity_fixture(
            CAPACITY - Decimal("0.000002")
        )
        context = profile_module._validated_profile_context(profile)
        for replacement_action, replacement_trust in (
            (alternate_action, trust), (action, alternate_trust),
        ):
            with self.subTest(
                action=replacement_action.digest, trust=replacement_trust.digest
            ):
                with self.assertRaises(ValidationError):
                    _require_validated_core_capacity_result_with_context(
                        original, context,
                        action=replacement_action,
                        trust=replacement_trust,
                        operation_id=OPERATION_ID,
                    )
        with self.assertRaises(ValidationError):
            _derive_core_capacity_with_context(
                context, alternate_action, trust, operation_id=OPERATION_ID
            )
        with self.assertRaises(ValidationError):
            _derive_core_capacity_with_context(
                context, action, trust, operation_id="operation:other"
            )

    def test_context_validation_rejects_resealed_identity_and_cutoff_changes(self):
        profile, action, trust, original = capacity_fixture()
        context = profile_module._validated_profile_context(profile)
        cases = (
            ("operation_id", "operation:other"),
            ("profile_ref", ProfileRef("profile:other", 1)),
            ("profile_digest", "1" * 64),
            ("action_id", "action:other"),
            ("action_digest", "1" * 64),
            ("trust_digest", "1" * 64),
            ("cutoff", original.cutoff + timedelta(microseconds=1)),
            ("autonomy_demand", original.autonomy_demand - Decimal("0.000001")),
            ("effective_trust", original.effective_trust + Decimal("0.000001")),
        )
        for member, replacement in cases:
            with self.subTest(member=member):
                hostile = copy.copy(original)
                object.__setattr__(hostile, member, replacement)
                object.__setattr__(
                    hostile, "digest", capacity_module._core_capacity_digest(hostile)
                )
                with self.assertRaises(ValidationError):
                    _require_validated_core_capacity_result_with_context(
                        hostile, context,
                        action=action, trust=trust, operation_id=OPERATION_ID,
                    )

    def test_decimal_subclasses_are_rejected_without_hooks(self):
        class DecimalSubclass(Decimal):
            def is_finite(self):
                raise AssertionError("Decimal subclass hook reached")

        original = capacity_fixture()[3]
        for member in ("autonomy_demand", "effective_trust"):
            for replacement in (DecimalSubclass("1"), 1, 1.0, "1", True):
                with self.subTest(member=member, replacement_type=type(replacement)):
                    hostile = copy.copy(original)
                    object.__setattr__(hostile, member, replacement)
                    with self.assertRaisesRegex(
                        ValidationError, "Core capacity integrity is invalid"
                    ):
                        require_validated_core_capacity_result(hostile)

    def test_structural_validation_rejects_malformed_and_incomplete_values(self):
        original = capacity_fixture()[3]
        cases = (
            ("operation_id", ""), ("action_id", "Bad ID"),
            ("profile_ref", "profile"), ("profile_digest", "g" * 64),
            ("action_digest", "A" * 64), ("trust_digest", 1),
            ("cutoff", original.cutoff.replace(tzinfo=None)),
            ("relation", "below_capacity"), ("digest", "short"),
        )
        for member, replacement in cases:
            with self.subTest(member=member):
                hostile = copy.copy(original)
                object.__setattr__(hostile, member, replacement)
                with self.assertRaisesRegex(
                    ValidationError, "Core capacity integrity is invalid"
                ):
                    require_validated_core_capacity_result(hostile)
        for hostile in (None, object(), object.__new__(CoreCapacityResult)):
            with self.subTest(hostile_type=type(hostile)):
                with self.assertRaises(ValidationError):
                    require_validated_core_capacity_result(hostile)
