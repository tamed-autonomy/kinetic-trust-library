"""Adversarial integrity seal for the public Library evaluation result values."""

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
import sys
import unittest
import kinetic_trust_library.models.profile as profile_module
import kinetic_trust_library.core.capacity as capacity_module
from kinetic_trust_library.models.capacity import CapacityRelation, CoreCapacityResult

from kinetic_trust_library import (
    EvaluationBundle,
    EvaluationRequest,
    ValidatedActionDemand,
    ValidationError,
)
from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.core import evaluate
from kinetic_trust_library.core.evidence import (
    prepare_evidence,
    require_validated_evidence_snapshot,
)
from kinetic_trust_library.core.envelope import (
    compute_envelope,
    require_validated_envelope_result,
)
from kinetic_trust_library.core.evaluate import require_validated_evaluation_bundle
from kinetic_trust_library.core.risk import calculate_risk
from kinetic_trust_library.core.soul import assess_soul, require_validated_soul_assessment
from kinetic_trust_library.core.standing import (
    prepare_standing,
    require_validated_standing_snapshot,
)
from kinetic_trust_library.core.trust import (
    calculate_effective_trust,
    require_validated_trust_snapshot,
)
from kinetic_trust_library.models.envelope import (
    KineticEnvelopeResult,
    Supervision,
    UndefinedInputLayer,
)
from kinetic_trust_library.models.trust import TrustTier
from kinetic_trust_library.core.envelope import (
    _constraints_projection,
    _result_projection,
)
from kinetic_trust_library.core.evaluate import _bundle_projection
from tests.unit.core.test_pinned_vectors import _build_case
from tests.unit.core.test_evidence_review import (
    profile_with_counted_one_route_feeds,
)
from tests.unit.core.test_standing_contract import (
    INDEPENDENT_ID,
    declaration as standing_declaration,
)
from kinetic_trust_library.models.soul import SoulResponseDeclaration
from tests.unit.models.test_profile import (
    UTC_NOW,
    complete_action,
    complete_capability,
)


class _PassiveString(str):
    pass


class _ArmedString(str):
    calls = 0

    @classmethod
    def _explode(cls):
        cls.calls += 1
        raise AssertionError("hostile string hook executed")

    def __eq__(self, other):
        return type(self)._explode()

    def __ne__(self, other):
        return type(self)._explode()

    def __hash__(self):
        return type(self)._explode()

    def __str__(self):
        return type(self)._explode()

    def encode(self, *args, **kwargs):
        return type(self)._explode()


class _PassiveDecimal(Decimal):
    pass


class _ArmedDecimal(Decimal):
    calls = 0

    @classmethod
    def _explode(cls):
        cls.calls += 1
        raise AssertionError("hostile Decimal hook executed")

    def is_finite(self):
        return type(self)._explode()

    def as_tuple(self):
        return type(self)._explode()

    def __eq__(self, other):
        return type(self)._explode()

    def __lt__(self, other):
        return type(self)._explode()


class _PassiveDatetime(datetime):
    pass


class _ArmedDatetime(datetime):
    calls = 0

    @classmethod
    def _explode(cls):
        cls.calls += 1
        raise AssertionError("hostile datetime hook executed")

    def __eq__(self, other):
        return type(self)._explode()

    def isoformat(self, *args, **kwargs):
        return type(self)._explode()

    def utcoffset(self):
        return type(self)._explode()


class _ArmedTimezone(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def _explode(self):
        self.calls += 1
        raise AssertionError("hostile timezone hook executed")

    def utcoffset(self, value):
        return self._explode()

    def dst(self, value):
        return self._explode()

    def tzname(self, value):
        return self._explode()

    def fromutc(self, value):
        return self._explode()


class _IgnoredMutableList(list):
    calls = 0

    @classmethod
    def _explode(cls):
        cls.calls += 1
        raise AssertionError("ignored caller list was consulted")

    def __iter__(self):
        return type(self)._explode()

    def __len__(self):
        return type(self)._explode()

    def __getitem__(self, key):
        return type(self)._explode()

    def __bool__(self):
        return type(self)._explode()

    def __eq__(self, other):
        return type(self)._explode()


class _IgnoredMutableDict(dict):
    calls = 0

    @classmethod
    def _explode(cls):
        cls.calls += 1
        raise AssertionError("ignored caller mapping was consulted")

    def __iter__(self):
        return type(self)._explode()

    def __len__(self):
        return type(self)._explode()

    def __getitem__(self, key):
        return type(self)._explode()

    def get(self, key, default=None):
        return type(self)._explode()

    def items(self):
        return type(self)._explode()

    def __bool__(self):
        return type(self)._explode()

    def __eq__(self, other):
        return type(self)._explode()


def _bundle_for(index: int) -> EvaluationBundle:
    case = _build_case(index)
    value = evaluate(
        EvaluationRequest(
            operation_id=case.operation_id,
            profile=case.profile,
            action=case.action,
            standing=case.standing_declaration,
            observations=case.observations,
            soul_responses=case.soul_declarations,
            cutoff=case.action.validation_cutoff,
        )
    )
    if type(value) is not EvaluationBundle:
        raise AssertionError(f"reference request was rejected: {value!r}")
    return value


def _reseal_envelope(value: KineticEnvelopeResult) -> None:
    object.__setattr__(
        value,
        "digest",
        canonical_sha256(_result_projection(value, include_digest=False)),
    )


def _reseal_capacity(value: CoreCapacityResult) -> None:
    object.__setattr__(value, "digest", capacity_module._core_capacity_digest(value))


def _reseal_constraints(value: object) -> None:
    object.__setattr__(
        value,
        "digest",
        canonical_sha256(_constraints_projection(value, include_digest=False)),
    )


def _reseal_bundle(value: EvaluationBundle) -> None:
    object.__setattr__(
        value,
        "digest",
        canonical_sha256(_bundle_projection(value, include_digest=False)),
    )


class KineticEnvelopeIntegrityTests(unittest.TestCase):
    def assert_result_invalid(self, value: object) -> None:
        with self.assertRaises(ValidationError):
            require_validated_envelope_result(value)

    def test_every_result_field_is_frozen_and_collections_are_not_mutable(self):
        result = _build_case(0).envelope

        for field in fields(KineticEnvelopeResult):
            with self.subTest(field=field.name), self.assertRaises(FrozenInstanceError):
                setattr(result, field.name, getattr(result, field.name))

        for collection in (
            result.rationale,
            result.tightened_constraints.ceilings,
            result.normative_gate_outcomes,
            result.undefined_inputs,
            result.trace,
            result._soul.outcomes,
            result._trust._risk_result.domains,
        ):
            with self.subTest(collection=collection), self.assertRaises(AttributeError):
                collection.append(object())

        with self.assertRaises(TypeError):
            result._action.requested_constraints["maxVelocityMps"] = Decimal("0")
        with self.assertRaises(TypeError):
            result._profile.actions["publish"] = object()

    def test_every_result_field_rejects_semantic_mutation_even_when_resealed(self):
        case = _build_case(0)
        alternate = _build_case(1)
        undefined = _build_case(6).envelope.undefined_inputs
        original = case.envelope
        changed_ref = copy.copy(original.profile_ref)
        object.__setattr__(changed_ref, "version", original.profile_ref.version + 1)
        mutations = {
            "operation_id": "operation:mutated",
            "profile_ref": changed_ref,
            "profile_digest": "0" * 64,
            "action_id": "action:mutated",
            "action_digest": "0" * 64,
            "core_capacity_digest": "0" * 64,
            "cutoff": original.cutoff + timedelta(microseconds=1),
            "autonomy_demand": original.autonomy_demand + Decimal("1"),
            "environmental_capacity": original.environmental_capacity + Decimal("1"),
            "margin": original.margin - Decimal("0.01"),
            "capacity_known": False,
            "tightened_constraints": alternate.envelope.tightened_constraints,
            "supervision": Supervision.ASSISTED,
            "policy_code": "KINETIC_CAPACITY_EXCEEDED",
            "rationale": ("semantically mutated rationale",),
            "tier": TrustTier.ADMIN,
            "normative_gate_outcomes": None,
            "undefined_inputs": undefined,
            "trace": original.trace[:-1],
            "digest": "0" * 64,
            "_profile": object(),
            "_action": alternate.action,
            "_soul": alternate.soul,
            "_trust": alternate.trust,
        }
        self.assertEqual(set(mutations), {field.name for field in fields(original)})

        for name, replacement in mutations.items():
            with self.subTest(field=name):
                candidate = copy.copy(original)
                object.__setattr__(candidate, name, replacement)
                if name != "digest":
                    try:
                        _reseal_envelope(candidate)
                    except (AttributeError, TypeError, ValidationError):
                        pass
                self.assert_result_invalid(candidate)

    def test_nested_constraint_fields_and_collections_are_fully_sealed(self):
        result = _build_case(0).envelope
        constraints = result.tightened_constraints
        first = constraints.ceilings[0]
        changed_ref = copy.copy(constraints.profile_ref)
        object.__setattr__(changed_ref, "version", changed_ref.version + 1)
        mutations = {
            "profile_ref": changed_ref,
            "profile_digest": "0" * 64,
            "action_class": "mutated",
            "ceilings": constraints.ceilings[:-1],
            "digest": "0" * 64,
        }
        self.assertEqual(set(mutations), {field.name for field in fields(constraints)})
        for name, replacement in mutations.items():
            with self.subTest(constraint_field=name):
                nested = copy.copy(constraints)
                object.__setattr__(nested, name, replacement)
                if name != "digest":
                    try:
                        _reseal_constraints(nested)
                    except ValidationError:
                        pass
                candidate = copy.copy(result)
                object.__setattr__(candidate, "tightened_constraints", nested)
                try:
                    _reseal_envelope(candidate)
                except ValidationError:
                    pass
                self.assert_result_invalid(candidate)

        ceiling_mutations = {
            "magnitude": "maxVelocityMps:mutated",
            "unit": "m/s2",
            "maximum": first.maximum - Decimal("0.01"),
        }
        self.assertEqual(
            set(ceiling_mutations), {field.name for field in fields(first)}
        )
        for name, replacement in ceiling_mutations.items():
            with self.subTest(ceiling_field=name):
                changed_ceiling = copy.copy(first)
                object.__setattr__(changed_ceiling, name, replacement)
                nested = copy.copy(constraints)
                object.__setattr__(
                    nested,
                    "ceilings",
                    (changed_ceiling, *constraints.ceilings[1:]),
                )
                try:
                    _reseal_constraints(nested)
                except ValidationError:
                    pass
                candidate = copy.copy(result)
                object.__setattr__(candidate, "tightened_constraints", nested)
                try:
                    _reseal_envelope(candidate)
                except ValidationError:
                    pass
                self.assert_result_invalid(candidate)

        candidate = copy.copy(result)
        nested = copy.copy(constraints)
        object.__setattr__(nested, "ceilings", list(nested.ceilings))
        object.__setattr__(candidate, "tightened_constraints", nested)
        self.assert_result_invalid(candidate)

    def test_nested_undefined_input_fields_are_fully_sealed(self):
        result = _build_case(6).envelope
        item = result.undefined_inputs[0]
        mutations = {
            "input_id": "feed:mutated",
            "layer": UndefinedInputLayer.GATE,
            "reason": "mutated",
            "provenance_ids": ("provenance:mutated",),
        }
        self.assertEqual(set(mutations), {field.name for field in fields(item)})
        for name, replacement in mutations.items():
            with self.subTest(undefined_field=name):
                changed = copy.copy(item)
                object.__setattr__(changed, name, replacement)
                candidate = copy.copy(result)
                object.__setattr__(
                    candidate,
                    "undefined_inputs",
                    (changed, *result.undefined_inputs[1:]),
                )
                try:
                    _reseal_envelope(candidate)
                except ValidationError:
                    pass
                self.assert_result_invalid(candidate)

        candidate = copy.copy(result)
        object.__setattr__(candidate, "undefined_inputs", list(result.undefined_inputs))
        self.assert_result_invalid(candidate)

    def test_invalid_unicode_is_a_controlled_integrity_failure(self):
        result = _build_case(0).envelope
        for name, replacement in (
            ("operation_id", "operation:\ud800"),
            ("policy_code", "POLICY\ud800"),
            ("rationale", ("rationale\ud800",)),
        ):
            with self.subTest(field=name):
                candidate = copy.copy(result)
                object.__setattr__(candidate, name, replacement)
                self.assert_result_invalid(candidate)

        nested = copy.copy(result.tightened_constraints)
        ceiling = copy.copy(nested.ceilings[0])
        object.__setattr__(ceiling, "magnitude", "magnitude\ud800")
        object.__setattr__(nested, "ceilings", (ceiling, *nested.ceilings[1:]))
        candidate = copy.copy(result)
        object.__setattr__(candidate, "tightened_constraints", nested)
        self.assert_result_invalid(candidate)

    def test_passive_and_armed_primitive_subclasses_reject_before_hooks(self):
        result = _build_case(0).envelope
        passive_time = _PassiveDatetime(
            result.cutoff.year,
            result.cutoff.month,
            result.cutoff.day,
            result.cutoff.hour,
            result.cutoff.minute,
            result.cutoff.second,
            result.cutoff.microsecond,
            tzinfo=timezone.utc,
        )
        cases = (
            ("operation_id", _PassiveString(result.operation_id)),
            ("autonomy_demand", _PassiveDecimal(str(result.autonomy_demand))),
            ("cutoff", passive_time),
            ("operation_id", _ArmedString(result.operation_id)),
            ("autonomy_demand", _ArmedDecimal(str(result.autonomy_demand))),
            (
                "cutoff",
                _ArmedDatetime(
                    result.cutoff.year,
                    result.cutoff.month,
                    result.cutoff.day,
                    result.cutoff.hour,
                    result.cutoff.minute,
                    result.cutoff.second,
                    result.cutoff.microsecond,
                    tzinfo=timezone.utc,
                ),
            ),
        )
        _ArmedString.calls = 0
        _ArmedDecimal.calls = 0
        _ArmedDatetime.calls = 0
        for name, replacement in cases:
            with self.subTest(field=name, kind=type(replacement).__name__):
                candidate = copy.copy(result)
                object.__setattr__(candidate, name, replacement)
                self.assert_result_invalid(candidate)
        self.assertEqual(_ArmedString.calls, 0)
        self.assertEqual(_ArmedDecimal.calls, 0)
        self.assertEqual(_ArmedDatetime.calls, 0)

    def test_numeric_equivalence_is_not_misclassified_as_semantic_mutation(self):
        result = _build_case(0).envelope
        scaled_capacity = copy.copy(result)
        object.__setattr__(
            scaled_capacity,
            "environmental_capacity",
            Decimal("20.0000"),
        )
        self.assertIs(
            require_validated_envelope_result(scaled_capacity),
            scaled_capacity,
        )

        scaled_ceiling = copy.copy(result.tightened_constraints.ceilings[0])
        object.__setattr__(
            scaled_ceiling,
            "maximum",
            scaled_ceiling.maximum.quantize(Decimal("0.0000")),
        )
        scaled_constraints = copy.copy(result.tightened_constraints)
        object.__setattr__(
            scaled_constraints,
            "ceilings",
            (scaled_ceiling, *scaled_constraints.ceilings[1:]),
        )
        candidate = copy.copy(result)
        object.__setattr__(candidate, "tightened_constraints", scaled_constraints)
        self.assertIs(require_validated_envelope_result(candidate), candidate)

        equality = _build_case(0, demand_override=Decimal("20")).envelope
        self.assertEqual(equality.margin, Decimal(0))
        signed_scaled_zero = copy.copy(equality)
        object.__setattr__(signed_scaled_zero, "margin", Decimal("-0E-999999"))
        self.assertIs(
            require_validated_envelope_result(signed_scaled_zero),
            signed_scaled_zero,
        )

    def test_coherent_copy_and_reconstruction_revalidate_without_claiming_transfer(
        self,
    ):
        result = _build_case(0).envelope
        shallow = copy.copy(result)
        self.assertIs(require_validated_envelope_result(shallow), shallow)

        reconstructed = object.__new__(KineticEnvelopeResult)
        for field in fields(result):
            object.__setattr__(reconstructed, field.name, getattr(result, field.name))
        self.assertIs(
            require_validated_envelope_result(reconstructed),
            reconstructed,
        )
        self.assertFalse(hasattr(result, "to_json"))
        self.assertFalse(hasattr(result, "from_json"))

        mutated = copy.copy(reconstructed)
        object.__setattr__(mutated, "rationale", ("coherent-looking mutation",))
        _reseal_envelope(mutated)
        self.assert_result_invalid(mutated)

    def test_digest_corruption_is_rejected_by_structural_revalidation(self):
        result = copy.copy(_build_case(0).envelope)
        object.__setattr__(result, "digest", "0" * 64)
        self.assert_result_invalid(result)


class EvaluationBundleIntegrityTests(unittest.TestCase):
    def test_bundle_gates_envelope_capacity_digest_before_caller_hooks(self):
        bundle = _bundle_for(0)
        _ArmedString.calls = 0
        object.__setattr__(
            bundle.envelope,
            "core_capacity_digest",
            _ArmedString(bundle.core_capacity.digest),
        )
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(bundle)
        self.assertEqual(_ArmedString.calls, 0)

    def test_bundle_rejects_resealed_capacity_relation(self):
        bundle = _bundle_for(0)
        capacity = copy.copy(bundle.core_capacity)
        object.__setattr__(capacity, "relation", CapacityRelation.ABOVE_CAPACITY)
        _reseal_capacity(capacity)
        envelope = copy.copy(bundle.envelope)
        object.__setattr__(envelope, "core_capacity_digest", capacity.digest)
        _reseal_envelope(envelope)
        candidate = copy.copy(bundle)
        object.__setattr__(candidate, "core_capacity", capacity)
        object.__setattr__(candidate, "envelope", envelope)
        _reseal_bundle(candidate)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(candidate)

    def test_bundle_rejects_resealed_envelope_capacity_digest(self):
        bundle = _bundle_for(0)
        envelope = copy.copy(bundle.envelope)
        object.__setattr__(envelope, "core_capacity_digest", "0" * 64)
        _reseal_envelope(envelope)
        candidate = copy.copy(bundle)
        object.__setattr__(candidate, "envelope", envelope)
        _reseal_bundle(candidate)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(candidate)

    def test_bundle_rejects_cross_evaluation_capacity_and_envelope(self):
        original = _bundle_for(0)
        alternate = _bundle_for(1)
        envelope = copy.copy(original.envelope)
        object.__setattr__(
            envelope, "core_capacity_digest", alternate.core_capacity.digest
        )
        _reseal_envelope(envelope)
        changed_capacity = copy.copy(original)
        object.__setattr__(changed_capacity, "core_capacity", alternate.core_capacity)
        object.__setattr__(changed_capacity, "envelope", envelope)
        _reseal_bundle(changed_capacity)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(changed_capacity)
        changed_envelope = copy.copy(original)
        object.__setattr__(changed_envelope, "envelope", alternate.envelope)
        _reseal_bundle(changed_envelope)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(changed_envelope)

    def test_unknown_evidence_retains_numeric_core_capacity(self):
        bundle = _bundle_for(6)
        self.assertIsNotNone(bundle.core_capacity)
        self.assertFalse(bundle.envelope.capacity_known)
        self.assertEqual(
            bundle.envelope.core_capacity_digest, bundle.core_capacity.digest
        )

    def test_public_core_profile_surfaces_reject_exact_private_context(self):
        case = _build_case(0)
        context = profile_module._validated_profile_context(case.profile)
        risk = case.trust._risk_result
        evidence = risk._evidence
        standing = case.trust._standing
        cutoff = case.action.validation_cutoff
        calls = {
            "assess_soul": lambda: assess_soul(
                context,
                case.soul_declarations,
                case.action,
                cutoff,
            ),
            "require_validated_soul_assessment": lambda: (
                require_validated_soul_assessment(case.soul, profile=context)
            ),
            "prepare_standing": lambda: prepare_standing(
                context,
                case.standing_declaration,
                cutoff,
            ),
            "require_validated_standing_snapshot": lambda: (
                require_validated_standing_snapshot(standing, profile=context)
            ),
            "prepare_evidence": lambda: prepare_evidence(
                context,
                case.observations,
                cutoff,
                operation_id=case.operation_id,
            ),
            "require_validated_evidence_snapshot": lambda: (
                require_validated_evidence_snapshot(evidence, profile=context)
            ),
            "calculate_risk": lambda: calculate_risk(
                context,
                evidence,
                case.soul,
                case.action,
                cutoff,
            ),
            "calculate_effective_trust": lambda: calculate_effective_trust(
                context,
                standing,
                risk,
                case.soul,
                case.action,
                cutoff,
            ),
            "require_validated_trust_snapshot": lambda: (
                require_validated_trust_snapshot(case.trust, profile=context)
            ),
            "compute_envelope": lambda: compute_envelope(
                context,
                case.action,
                case.soul,
                case.trust,
                operation_id=case.operation_id,
            ),
            "require_validated_envelope_result": lambda: (
                require_validated_envelope_result(case.envelope, profile=context)
            ),
        }

        for name, call in calls.items():
            with self.subTest(name=name), self.assertRaises(ValidationError):
                call()

    def test_bundle_fully_validates_the_effective_profile_once(self):
        bundle = _bundle_for(0)
        validation_code = profile_module.require_validated_profile.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is validation_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            self.assertIs(require_validated_evaluation_bundle(bundle), bundle)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)

    def test_high_fanout_soul_veto_bundle_validates_profile_once(self):
        profile, _source_mapping = profile_with_counted_one_route_feeds(2_100)
        action = ValidatedActionDemand.validate(
            complete_action(),
            profile=profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        bundle = evaluate(
            EvaluationRequest(
                operation_id="operation:high-fanout-veto",
                profile=profile,
                action=action,
                standing=object(),
                observations=object(),
                soul_responses=(),
                cutoff=UTC_NOW,
                previous_trust=object(),
            )
        )
        self.assertIs(type(bundle), EvaluationBundle)
        self.assertIsNone(bundle._request)
        validation_code = profile_module.require_validated_profile.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is validation_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            self.assertIs(require_validated_evaluation_bundle(bundle), bundle)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)

    def test_high_fanout_complete_bundle_validates_profile_once(self):
        profile, _source_mapping = profile_with_counted_one_route_feeds(2_100)
        action = ValidatedActionDemand.validate(
            complete_action(subject=INDEPENDENT_ID),
            profile=profile,
            capability=complete_capability(subject=INDEPENDENT_ID),
            cutoff=UTC_NOW,
        )
        soul_responses = tuple(
            SoulResponseDeclaration(
                framework_id=framework,
                profile_ref=profile.ref,
                profile_digest=profile.digest,
                action_id=action.action_id,
                action_digest=action.digest,
                query_cutoff=UTC_NOW,
                state="clear",
                observed_at=UTC_NOW,
                provenance_id=f"soul:{framework}",
            )
            for framework in profile.soul_frameworks
        )
        bundle = evaluate(
            EvaluationRequest(
                operation_id="operation:high-fanout-complete",
                profile=profile,
                action=action,
                standing=standing_declaration(),
                observations=(),
                soul_responses=soul_responses,
                cutoff=UTC_NOW,
            )
        )
        self.assertIs(type(bundle), EvaluationBundle)
        self.assertIsNotNone(bundle.trust)
        validation_code = profile_module.require_validated_profile.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is validation_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            self.assertIs(require_validated_evaluation_bundle(bundle), bundle)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)

    def test_bundle_preflights_each_distinct_equivalent_retained_profile_once(self):
        bundle = _bundle_for(0)
        evidence_profile = _build_case(0).profile
        standing_profile = _build_case(0).profile
        self.assertIsNot(evidence_profile, bundle.soul._profile)
        self.assertIsNot(standing_profile, bundle.soul._profile)
        self.assertIsNot(evidence_profile, standing_profile)
        object.__setattr__(bundle.evidence, "_profile", evidence_profile)
        object.__setattr__(bundle.standing, "_profile", standing_profile)

        ownership_code = profile_module._require_owned_profile_structure.__code__
        preflighted: list[int] = []

        def record_preflight(frame, event, _argument):
            if event == "call" and frame.f_code is ownership_code:
                preflighted.append(id(frame.f_locals["value"]))

        sys.setprofile(record_preflight)
        try:
            self.assertIs(require_validated_evaluation_bundle(bundle), bundle)
        finally:
            sys.setprofile(None)

        expected = {
            id(bundle.soul._profile),
            id(evidence_profile),
            id(standing_profile),
        }
        self.assertEqual(set(preflighted), expected)
        for identity in expected:
            self.assertEqual(preflighted.count(identity), 1)

    def test_soul_veto_neither_consults_nor_retains_ignored_caller_objects(self):
        case = _build_case(0)
        standing = _IgnoredMutableList([object()])
        observations = _IgnoredMutableList([object()])
        previous_trust = _IgnoredMutableDict({"ignored": object()})
        _IgnoredMutableList.calls = 0
        _IgnoredMutableDict.calls = 0
        request = EvaluationRequest(
            operation_id=case.operation_id,
            profile=case.profile,
            action=case.action,
            standing=standing,
            observations=observations,
            soul_responses=(),
            cutoff=case.action.validation_cutoff,
            previous_trust=previous_trust,
        )

        bundle = evaluate(request)

        self.assertIs(type(bundle), EvaluationBundle)
        self.assertIsNone(bundle._request)
        self.assertEqual(_IgnoredMutableList.calls, 0)
        self.assertEqual(_IgnoredMutableDict.calls, 0)
        digest = bundle.digest
        list.append(standing, object())
        list.clear(observations)
        dict.__setitem__(previous_trust, "mutated", object())
        self.assertEqual(bundle.digest, digest)
        self.assertIs(require_validated_evaluation_bundle(bundle), bundle)
        self.assertEqual(_IgnoredMutableList.calls, 0)
        self.assertEqual(_IgnoredMutableDict.calls, 0)

        corrupted_digest = copy.copy(bundle)
        object.__setattr__(corrupted_digest, "digest", "0" * 64)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(corrupted_digest)

    def test_soul_veto_rejects_injected_even_valid_full_request(self):
        case = _build_case(0)
        veto_bundle = evaluate(
            EvaluationRequest(
                operation_id=case.operation_id,
                profile=case.profile,
                action=case.action,
                standing=object(),
                observations=[],
                soul_responses=(),
                cutoff=case.action.validation_cutoff,
                previous_trust={},
            )
        )
        self.assertIs(type(veto_bundle), EvaluationBundle)

        candidate = copy.copy(veto_bundle)
        object.__setattr__(candidate, "_request", _bundle_for(0)._request)

        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(candidate)

        clear_without_replay_authority = copy.copy(_bundle_for(0))
        object.__setattr__(clear_without_replay_authority, "_request", None)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(clear_without_replay_authority)

    def test_every_bundle_field_is_frozen_and_owned_collections_are_not_mutable(self):
        bundle = _bundle_for(0)
        for field in fields(EvaluationBundle):
            with self.subTest(field=field.name), self.assertRaises(FrozenInstanceError):
                setattr(bundle, field.name, getattr(bundle, field.name))

        for collection in (
            bundle._request.observations,
            bundle._request.soul_responses,
            bundle.envelope.trace,
            bundle.envelope.tightened_constraints.ceilings,
        ):
            with self.subTest(collection=collection), self.assertRaises(AttributeError):
                collection.append(object())
        with self.assertRaises(TypeError):
            bundle.action.granted_constraints["maxVelocityMps"] = Decimal("0")

    def test_every_bundle_field_rejects_semantic_mutation_even_when_resealed(self):
        original = _bundle_for(0)
        alternate = _bundle_for(1)
        changed_ref = copy.copy(original.profile_ref)
        object.__setattr__(changed_ref, "version", changed_ref.version + 1)
        mutations = {
            "profile_ref": changed_ref,
            "profile_digest": "0" * 64,
            "operation_id": "operation:mutated",
            "cutoff": original.cutoff + timedelta(microseconds=1),
            "action": alternate.action,
            "soul": alternate.soul,
            "standing": None,
            "evidence": None,
            "risk": None,
            "trust": None,
            "velocity": object(),
            "core_capacity": alternate.core_capacity,
            "envelope": alternate.envelope,
            "digest": "0" * 64,
            "_request": object(),
        }
        self.assertEqual(set(mutations), {field.name for field in fields(original)})
        for name, replacement in mutations.items():
            with self.subTest(field=name):
                candidate = copy.copy(original)
                object.__setattr__(candidate, name, replacement)
                if name != "digest":
                    try:
                        _reseal_bundle(candidate)
                    except (AttributeError, TypeError, ValidationError):
                        pass
                with self.assertRaises(ValidationError):
                    require_validated_evaluation_bundle(candidate)

    def test_bundle_rejects_lists_invalid_unicode_and_primitive_subclasses(self):
        bundle = _bundle_for(0)
        list_cases = (
            replace(
                bundle._request,
                observations=list(bundle._request.observations),
            ),
            replace(
                bundle._request,
                soul_responses=list(bundle._request.soul_responses),
            ),
        )
        for request in list_cases:
            candidate = copy.copy(bundle)
            object.__setattr__(candidate, "_request", request)
            with self.assertRaises(ValidationError):
                require_validated_evaluation_bundle(candidate)

        primitive_cases = (
            ("operation_id", "operation:\ud800"),
            ("operation_id", _PassiveString(bundle.operation_id)),
            ("operation_id", _ArmedString(bundle.operation_id)),
            (
                "cutoff",
                _PassiveDatetime(
                    bundle.cutoff.year,
                    bundle.cutoff.month,
                    bundle.cutoff.day,
                    bundle.cutoff.hour,
                    bundle.cutoff.minute,
                    bundle.cutoff.second,
                    bundle.cutoff.microsecond,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                "cutoff",
                _ArmedDatetime(
                    bundle.cutoff.year,
                    bundle.cutoff.month,
                    bundle.cutoff.day,
                    bundle.cutoff.hour,
                    bundle.cutoff.minute,
                    bundle.cutoff.second,
                    bundle.cutoff.microsecond,
                    tzinfo=timezone.utc,
                ),
            ),
        )
        _ArmedString.calls = 0
        _ArmedDatetime.calls = 0
        for name, replacement in primitive_cases:
            with self.subTest(field=name, kind=type(replacement).__name__):
                candidate = copy.copy(bundle)
                object.__setattr__(candidate, name, replacement)
                with self.assertRaises(ValidationError):
                    require_validated_evaluation_bundle(candidate)
        self.assertEqual(_ArmedString.calls, 0)
        self.assertEqual(_ArmedDatetime.calls, 0)

    def test_bundle_rejects_noncanonical_timezone_without_executing_hooks(self):
        bundle = _bundle_for(0)
        hostile_timezone = _ArmedTimezone()
        hostile_cutoff = datetime(
            bundle.cutoff.year,
            bundle.cutoff.month,
            bundle.cutoff.day,
            bundle.cutoff.hour,
            bundle.cutoff.minute,
            bundle.cutoff.second,
            bundle.cutoff.microsecond,
            tzinfo=hostile_timezone,
        )
        candidate = copy.copy(bundle)
        object.__setattr__(candidate, "cutoff", hostile_cutoff)

        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(candidate)
        self.assertEqual(hostile_timezone.calls, 0)

    def test_bundle_rejects_passive_primitive_in_retained_selected_evidence(self):
        bundle = _bundle_for(0)
        evidence = copy.copy(bundle.evidence)
        entries = list(evidence.entries)
        entry_index = next(
            index for index, entry in enumerate(entries) if entry.selected_observations
        )
        entry = entries[entry_index]
        outcomes = list(entry.feed_outcomes)
        outcome_index = next(
            index
            for index, outcome in enumerate(outcomes)
            if hasattr(outcome, "observation")
        )
        outcome = outcomes[outcome_index]
        selected = copy.copy(outcome.observation)
        object.__setattr__(
            selected,
            "provenance_digest",
            _PassiveString(selected.provenance_digest),
        )
        outcomes[outcome_index] = replace(outcome, observation=selected)
        entries[entry_index] = replace(entry, feed_outcomes=tuple(outcomes))
        object.__setattr__(evidence, "entries", tuple(entries))
        candidate = copy.copy(bundle)
        object.__setattr__(candidate, "evidence", evidence)

        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(candidate)

    def test_bundle_rejects_armed_retained_profile_tree_before_hooks(self):
        bundle = _bundle_for(0)
        hostile_profile = copy.copy(bundle.evidence._profile)
        _ArmedString.calls = 0
        object.__setattr__(
            hostile_profile,
            "misattestation_adjudicator",
            _ArmedString(hostile_profile.misattestation_adjudicator),
        )
        hostile_evidence = copy.copy(bundle.evidence)
        object.__setattr__(hostile_evidence, "_profile", hostile_profile)
        candidate = copy.copy(bundle)
        object.__setattr__(candidate, "evidence", hostile_evidence)

        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(candidate)
        self.assertEqual(_ArmedString.calls, 0)
        self.assertEqual(candidate, bundle)
        self.assertEqual(_ArmedString.calls, 0)

    def test_bundle_binds_every_retained_profile_branch_before_hooks(self):
        for branch in ("soul", "risk", "trust", "envelope", "_request"):
            with self.subTest(branch=branch):
                bundle = _bundle_for(0)
                candidate = copy.copy(bundle)
                hostile_profile = copy.copy(bundle.soul._profile)
                object.__setattr__(
                    hostile_profile,
                    "misattestation_adjudicator",
                    _ArmedString(hostile_profile.misattestation_adjudicator),
                )
                retained = copy.copy(getattr(bundle, branch))
                object.__setattr__(
                    retained,
                    "profile" if branch == "_request" else "_profile",
                    hostile_profile,
                )
                object.__setattr__(candidate, branch, retained)
                _ArmedString.calls = 0

                with self.assertRaises(ValidationError):
                    require_validated_evaluation_bundle(candidate)
                self.assertEqual(_ArmedString.calls, 0)

    def test_bundle_copy_and_exact_reconstruction_revalidate(self):
        bundle = _bundle_for(0)
        shallow = copy.copy(bundle)
        self.assertIs(require_validated_evaluation_bundle(shallow), shallow)

        reconstructed = object.__new__(EvaluationBundle)
        for field in fields(bundle):
            object.__setattr__(reconstructed, field.name, getattr(bundle, field.name))
        self.assertIs(
            require_validated_evaluation_bundle(reconstructed),
            reconstructed,
        )
        self.assertFalse(hasattr(bundle, "to_json"))
        self.assertFalse(hasattr(bundle, "from_json"))

    def test_bundle_digest_and_nested_result_are_independently_sealed(self):
        bundle = _bundle_for(0)
        digest_mutation = copy.copy(bundle)
        object.__setattr__(digest_mutation, "digest", "0" * 64)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(digest_mutation)

        nested_result = copy.copy(bundle.envelope)
        object.__setattr__(nested_result, "supervision", Supervision.ASSISTED)
        _reseal_envelope(nested_result)
        nested_mutation = copy.copy(bundle)
        object.__setattr__(nested_mutation, "envelope", nested_result)
        _reseal_bundle(nested_mutation)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(nested_mutation)


if __name__ == "__main__":
    unittest.main()
