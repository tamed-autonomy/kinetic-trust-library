"""Task 5 complete pure evaluation-order and rejection tests."""

from __future__ import annotations

import copy
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from importlib import import_module
from unittest.mock import patch

import kinetic_trust_library.models.action as action_module
import kinetic_trust_library.core.capacity as capacity_module
import kinetic_trust_library.models.profile as profile_module
from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.core.evaluate import (
    evaluate,
    require_validated_evaluation_bundle,
    require_validated_rejected_request,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import (
    MomentCriticalityDeclaration,
    NormativeGateDecision,
    NormativeGateToken,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.envelope import (
    EvaluationBundle,
    EvaluationRequest,
    EvaluationStage,
    RejectedRequest,
    RejectionReason,
    Supervision,
)
from kinetic_trust_library.models.evidence import OnDemandQueryBinding
from kinetic_trust_library.models.capacity import CapacityRelation
from tests.unit.core.test_pinned_vectors import _build_case
from kinetic_trust_library.models.soul import SoulResponseDeclaration
from tests.unit.core.test_envelope import (
    CURRENT_STRESSES,
    OPERATION_ID,
    configured_profile,
    gate_policy,
    gate_token,
)
from tests.unit.core.test_evidence import CUTOFF
from tests.unit.core.test_risk import evidence_declarations
from tests.unit.core.test_standing_contract import (
    INDEPENDENT_ID,
    declaration as standing_declaration,
)
from tests.unit.models.test_profile import complete_action, complete_capability


evaluation_module = import_module("kinetic_trust_library.core.evaluate")


def _reference_request(demand: Decimal) -> EvaluationRequest:
    case = _build_case(0, demand_override=demand)
    return EvaluationRequest(
        operation_id=case.operation_id,
        profile=case.profile,
        action=case.action,
        standing=case.standing_declaration,
        observations=case.observations,
        soul_responses=case.soul_declarations,
        cutoff=case.action.validation_cutoff,
    )


class _HostileString(str):
    def __hash__(self):
        raise AssertionError("hostile string hashing executed")

    def __eq__(self, other):
        raise AssertionError("hostile string equality executed")


class _HostileTimezone(tzinfo):
    def __init__(self):
        self.calls = 0

    def _explode(self):
        self.calls += 1
        raise AssertionError("timezone hook executed")

    def utcoffset(self, dt):
        return self._explode()

    def dst(self, dt):
        return self._explode()

    def tzname(self, dt):
        return self._explode()

    def fromutc(self, dt):
        return self._explode()


def validated_action(
    profile,
    *,
    demand="1",
    normative_gate_tokens: tuple[NormativeGateToken, ...] = (),
):
    return ValidatedActionDemand.validate(
        complete_action(
            action_id="action:evaluate:one",
            subject=INDEPENDENT_ID,
            demand=demand,
            moment_criticality=MomentCriticalityDeclaration(
                value="0.75",
                supplier="action-api",
                unit="stress-0-1",
                observed_at=CUTOFF,
                provenance_id="moment:evaluate:one",
            ),
            normative_gate_tokens=normative_gate_tokens,
        ),
        profile=profile,
        capability=complete_capability(
            subject=INDEPENDENT_ID,
            not_before=CUTOFF - timedelta(minutes=1),
            not_after=CUTOFF + timedelta(minutes=1),
        ),
        cutoff=CUTOFF,
    )


def soul_responses(profile, action):
    return tuple(
        SoulResponseDeclaration(
            framework_id=framework,
            profile_ref=profile.ref,
            profile_digest=profile.digest,
            action_id=action.action_id,
            action_digest=action.digest,
            query_cutoff=CUTOFF,
            state="clear",
            observed_at=CUTOFF,
            provenance_id=f"soul:{framework}",
        )
        for framework in profile.soul_frameworks
    )


def request(
    *,
    soul_clear=True,
    operation_id=OPERATION_ID,
    profile=None,
    normative_gate_tokens: tuple[NormativeGateToken, ...] = (),
):
    profile = configured_profile() if profile is None else profile
    action = validated_action(
        profile,
        normative_gate_tokens=normative_gate_tokens,
    )
    return EvaluationRequest(
        operation_id=operation_id,
        profile=profile,
        action=action,
        standing=standing_declaration(),
        observations=evidence_declarations(CUTOFF, CURRENT_STRESSES),
        soul_responses=soul_responses(profile, action) if soul_clear else (),
        cutoff=CUTOFF,
    )


def _retarget_action_profile_digest(action, profile_digest):
    capability = copy.copy(action.capability)
    object.__setattr__(capability, "profile_digest", profile_digest)
    object.__setattr__(
        capability,
        "digest",
        action_module._capability_digest(capability),
    )
    result = copy.copy(action)
    object.__setattr__(result, "profile_digest", profile_digest)
    object.__setattr__(result, "capability", capability)
    object.__setattr__(result, "digest", action_module._action_digest(result))
    return result


class _StageSpy:
    def __init__(self, name, function, trace):
        self.name = name
        self.function = function
        self.trace = trace

    def __call__(self, *args, **kwargs):
        self.trace.append(self.name)
        return self.function(*args, **kwargs)


class CompleteEvaluationTests(unittest.TestCase):
    def test_core_capacity_and_envelope_matrix(self):
        soul_nonclear = replace(_reference_request(Decimal("10")), soul_responses=())
        gate_profile = configured_profile(normative_gates=(gate_policy(),))
        required_gate_veto_below = request(
            profile=gate_profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.VETO),),
        )
        invalid_declaration = _reference_request(Decimal("10"))
        object.__setattr__(invalid_declaration.action, "digest", "0" * 64)
        cases = (
            (
                "below",
                _reference_request(Decimal("10")),
                CapacityRelation.BELOW_CAPACITY,
                True,
                Supervision.STABLE,
            ),
            (
                "equal",
                _reference_request(Decimal("20")),
                CapacityRelation.AT_CAPACITY,
                True,
                Supervision.SILENT_VETO,
            ),
            (
                "above",
                _reference_request(Decimal("21")),
                CapacityRelation.ABOVE_CAPACITY,
                False,
                Supervision.SILENT_VETO,
            ),
            ("soul_nonclear", soul_nonclear, None, None, Supervision.SILENT_VETO),
            (
                "required_gate_veto_below",
                required_gate_veto_below,
                CapacityRelation.BELOW_CAPACITY,
                True,
                Supervision.SILENT_VETO,
            ),
            ("invalid_declaration", invalid_declaration, None, None, None),
        )
        for name, value, relation, within, supervision in cases:
            with self.subTest(case=name):
                outcome = evaluate(value)
                if name == "invalid_declaration":
                    self.assertIs(type(outcome), RejectedRequest)
                    self.assertIs(
                        outcome.reason_code,
                        RejectionReason.INVALID_DECLARATION,
                    )
                    self.assertIs(outcome.failed_stage, EvaluationStage.CAPABILITY)
                    for member in (
                        "standing", "evidence", "risk", "trust",
                        "core_capacity", "envelope",
                    ):
                        self.assertFalse(hasattr(outcome, member))
                    continue
                self.assertIs(type(outcome), EvaluationBundle)
                self.assertIs(outcome.envelope.supervision, supervision)
                if relation is None:
                    self.assertIsNone(outcome.core_capacity)
                    self.assertIsNone(outcome.envelope.core_capacity_digest)
                    self.assertEqual(
                        outcome.envelope.trace,
                        (
                            EvaluationStage.CAPABILITY,
                            EvaluationStage.SOUL,
                            EvaluationStage.ENVELOPE,
                        ),
                    )
                    continue
                self.assertIsNotNone(outcome.core_capacity)
                self.assertIs(outcome.core_capacity.relation, relation)
                self.assertIs(outcome.core_capacity.within_capacity, within)
                self.assertEqual(outcome.core_capacity.profile_ref, outcome.profile_ref)
                self.assertEqual(
                    outcome.core_capacity.profile_digest, outcome.profile_digest
                )
                self.assertEqual(
                    outcome.core_capacity.action_digest, outcome.action.digest
                )
                self.assertEqual(
                    outcome.core_capacity.trust_digest, outcome.trust.digest
                )
                self.assertEqual(
                    outcome.core_capacity.operation_id, outcome.operation_id
                )
                self.assertEqual(outcome.core_capacity.cutoff, outcome.cutoff)
                self.assertEqual(
                    outcome.envelope.core_capacity_digest,
                    outcome.core_capacity.digest,
                )
                self.assertEqual(
                    outcome.envelope.environmental_capacity,
                    outcome.core_capacity.effective_trust,
                )
                if name == "equal":
                    self.assertEqual(outcome.envelope.margin, Decimal(0))
                    self.assertEqual(
                        outcome.envelope.policy_code, "KINETIC_CAPACITY_EXCEEDED"
                    )

    def test_request_profile_context_is_rejected_at_capability_stage(self):
        value = request()
        context = profile_module._validated_profile_context(value.profile)

        result = evaluate(replace(value, profile=context))

        self.assertIs(type(result), RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.CAPABILITY)
        self.assertEqual(result.trace, ())

    def test_mutated_resealed_context_cannot_authorize_public_evaluation(self):
        value = request()
        profile = value.profile
        context = profile_module._validated_profile_context(profile)
        object.__setattr__(profile, "standing_decay_rate", Decimal("101"))
        object.__setattr__(
            profile,
            "digest",
            canonical_sha256(profile_module._profile_digest_input(profile)),
        )
        action = _retarget_action_profile_digest(value.action, profile.digest)
        forged_request = replace(
            value,
            profile=context,
            action=action,
            soul_responses=soul_responses(profile, action),
        )
        with self.assertRaises(ValidationError):
            profile_module.require_validated_profile(profile)

        result = evaluate(forged_request)

        self.assertIs(type(result), RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.CAPABILITY)
        self.assertEqual(result.trace, ())

    def test_normative_gate_is_carried_at_envelope_after_full_trust_order(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        value = request(
            profile=profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.VETO),),
        )

        result = evaluate(value)

        self.assertIsInstance(result, EvaluationBundle)
        self.assertIsNotNone(result.standing)
        self.assertIsNotNone(result.risk)
        self.assertIsNotNone(result.trust)
        self.assertEqual(result.envelope.trace, tuple(EvaluationStage))
        self.assertEqual(
            result.envelope.environmental_capacity, result.trust.effective_trust
        )
        self.assertIs(result.envelope.supervision, Supervision.SILENT_VETO)

    def test_successful_evaluation_uses_the_exact_stage_order(self):
        trace = []
        targets = (
            ("validate_capability", "_require_action"),
            ("assess_soul", "_assess_soul_with_context"),
            ("prepare_standing", "_prepare_standing_with_context"),
            ("prepare_evidence", "_prepare_evidence_with_context"),
            ("calculate_risk", "_calculate_risk_with_context"),
            (
                "calculate_effective_trust",
                "_calculate_effective_trust_with_context",
            ),
            ("derive_core_capacity", "_derive_core_capacity_with_context"),
            ("compute_envelope", "_compute_envelope_with_context"),
        )
        stack = []
        try:
            for label, attribute in targets:
                original = getattr(evaluation_module, attribute)
                manager = patch.object(
                    evaluation_module,
                    attribute,
                    _StageSpy(label, original, trace),
                )
                manager.start()
                stack.append(manager)
            result = evaluate(request())
        finally:
            for manager in reversed(stack):
                manager.stop()

        self.assertIsInstance(result, EvaluationBundle)
        self.assertEqual(
            trace,
            [
                "validate_capability",
                "assess_soul",
                "prepare_standing",
                "prepare_evidence",
                "calculate_risk",
                "calculate_effective_trust",
                "derive_core_capacity",
                "compute_envelope",
            ],
        )
        self.assertEqual(
            result.envelope.trace,
            tuple(EvaluationStage),
        )
        self.assertEqual(result.operation_id, OPERATION_ID)
        self.assertEqual(result.evidence.operation_id, OPERATION_ID)
        self.assertEqual(result.cutoff, CUTOFF)
        self.assertIs(
            require_validated_evaluation_bundle(result),
            result,
        )

    def test_successful_evaluation_constructs_core_capacity_exactly_once(self):
        value = request()
        derivation_code = capacity_module._derive_core_capacity_with_context.__code__
        derivations = 0

        def count_derivations(frame, event, _argument):
            nonlocal derivations
            if event == "call" and frame.f_code is derivation_code:
                derivations += 1

        previous_profiler = sys.getprofile()
        sys.setprofile(count_derivations)
        try:
            bundle = evaluate(value)
        finally:
            sys.setprofile(previous_profiler)

        self.assertIs(type(bundle), EvaluationBundle)
        self.assertEqual(derivations, 1)
        self.assertEqual(
            bundle.envelope.core_capacity_digest, bundle.core_capacity.digest
        )

    def test_successful_bundle_retains_exact_stage_results(self):
        produced = []
        capacities = []
        consumed_capacities = []
        calculate = evaluation_module._calculate_risk_with_context
        derive = evaluation_module._derive_core_capacity_with_context
        compute = evaluation_module._compute_envelope_with_context

        def capture_risk(*args, **kwargs):
            result = calculate(*args, **kwargs)
            produced.append(result)
            return result

        def capture_capacity(*args, **kwargs):
            result = derive(*args, **kwargs)
            capacities.append(result)
            return result

        def capture_envelope(*args, **kwargs):
            consumed_capacities.append(kwargs["core_capacity"])
            return compute(*args, **kwargs)

        with (
            patch.object(evaluation_module, "_calculate_risk_with_context", capture_risk),
            patch.object(
                evaluation_module, "_derive_core_capacity_with_context", capture_capacity
            ),
            patch.object(
                evaluation_module, "_compute_envelope_with_context", capture_envelope
            ),
        ):
            bundle = evaluate(request())

        self.assertIsInstance(bundle, EvaluationBundle)
        self.assertEqual(len(produced), 1)
        self.assertIs(bundle.risk, produced[0])
        self.assertIs(bundle.risk.context, produced[0].context)
        self.assertIs(bundle.trust._risk_result, bundle.risk)
        self.assertEqual(bundle.trust.risk, bundle.risk.risk)
        self.assertEqual(len(capacities), 1)
        self.assertIs(bundle.core_capacity, capacities[0])
        self.assertEqual(len(consumed_capacities), 1)
        self.assertIs(bundle.core_capacity, consumed_capacities[0])
        self.assertEqual(
            bundle.envelope.core_capacity_digest, bundle.core_capacity.digest
        )

    def test_soul_veto_stops_before_all_later_authority(self):
        value = request(soul_clear=False)
        value = EvaluationRequest(
            operation_id=value.operation_id,
            profile=value.profile,
            action=value.action,
            standing=object(),
            observations=object(),
            soul_responses=value.soul_responses,
            cutoff=value.cutoff,
            previous_trust=object(),
        )

        with (
            patch.object(
                evaluation_module,
                "_prepare_standing_with_context",
                side_effect=AssertionError("standing must not run"),
            ),
            patch.object(
                evaluation_module,
                "_prepare_evidence_with_context",
                side_effect=AssertionError("evidence must not run"),
            ),
            patch.object(
                evaluation_module,
                "_calculate_risk_with_context",
                side_effect=AssertionError("risk must not run"),
            ),
        ):
            result = evaluate(value)

        self.assertIsInstance(result, EvaluationBundle)
        self.assertIs(result.envelope.supervision, Supervision.SILENT_VETO)
        self.assertIsNone(result.standing)
        self.assertIsNone(result.evidence)
        self.assertIsNone(result.risk)
        self.assertIsNone(result.trust)
        self.assertIsNone(result.velocity)
        self.assertEqual(
            result.envelope.trace,
            (
                EvaluationStage.CAPABILITY,
                EvaluationStage.SOUL,
                EvaluationStage.ENVELOPE,
            ),
        )

    def test_invalid_action_stops_before_soul_and_returns_typed_rejection(self):
        value = request()
        object.__setattr__(value.action, "digest", "0" * 64)
        with patch.object(
            evaluation_module,
            "_assess_soul_with_context",
            side_effect=AssertionError("Soul must not run"),
        ):
            result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.reason_code, RejectionReason.INVALID_DECLARATION)
        self.assertIs(result.failed_stage, EvaluationStage.CAPABILITY)
        self.assertEqual(result.trace, ())
        self.assertIs(require_validated_rejected_request(result), result)

    def test_invalid_evidence_returns_no_partial_authoritative_bundle(self):
        value = request(operation_id="operation:evaluate:expected")
        value = replace(
            value,
            observations=(
                replace(value.observations[0], unit="wrong-unit"),
                *value.observations[1:],
            ),
        )
        result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.EVIDENCE)
        self.assertEqual(
            result.trace,
            (
                EvaluationStage.CAPABILITY,
                EvaluationStage.SOUL,
                EvaluationStage.STANDING,
            ),
        )
        self.assertFalse(hasattr(result, "standing"))
        self.assertFalse(hasattr(result, "envelope"))

    def test_on_demand_evidence_bound_to_another_operation_is_rejected(self):
        source = "feed:node:0"
        profile = configured_profile(on_demand_source=source)
        value = request(
            profile=profile,
            operation_id="operation:evaluate:expected",
        )
        observations = list(value.observations)
        observations[0] = replace(
            observations[0],
            observed_at=CUTOFF,
            ingested_at=CUTOFF + timedelta(milliseconds=1),
            on_demand_binding=OnDemandQueryBinding(
                "operation:evaluate:other",
                CUTOFF,
            ),
        )
        value = replace(value, observations=tuple(observations))

        result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.EVIDENCE)

    def test_request_cutoff_must_equal_the_action_owned_cutoff(self):
        value = replace(request(), cutoff=CUTOFF + timedelta(microseconds=1))

        result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.CAPABILITY)
        self.assertEqual(result.trace, ())

    def test_request_operation_and_cutoff_require_exact_owned_primitives(self):
        operation = _HostileString(OPERATION_ID)
        operation_result = evaluate(replace(request(), operation_id=operation))
        self.assertIsInstance(operation_result, RejectedRequest)
        self.assertIs(operation_result.failed_stage, EvaluationStage.CAPABILITY)

        hostile_timezone = _HostileTimezone()
        cutoff = datetime(2026, 8, 20, 12, tzinfo=hostile_timezone)
        cutoff_result = evaluate(replace(request(), cutoff=cutoff))
        self.assertIsInstance(cutoff_result, RejectedRequest)
        self.assertIs(cutoff_result.failed_stage, EvaluationStage.CAPABILITY)
        self.assertEqual(hostile_timezone.calls, 0)

        exact = evaluate(request())
        self.assertIsInstance(exact, EvaluationBundle)
        self.assertIs(exact.cutoff.tzinfo, timezone.utc)

    def test_request_fact_collections_must_be_replayable_owned_tuples(self):
        soul_value = request()
        soul_value = replace(
            soul_value,
            soul_responses=iter(soul_value.soul_responses),
        )
        soul_result = evaluate(soul_value)
        self.assertIsInstance(soul_result, RejectedRequest)
        self.assertIs(soul_result.failed_stage, EvaluationStage.SOUL)

        evidence_value = request()
        evidence_value = replace(
            evidence_value,
            observations=iter(evidence_value.observations),
        )
        evidence_result = evaluate(evidence_value)
        self.assertIsInstance(evidence_result, RejectedRequest)
        self.assertIs(evidence_result.failed_stage, EvaluationStage.EVIDENCE)

    def test_invalid_soul_stops_before_standing(self):
        value = request()
        value = replace(
            value,
            soul_responses=(replace(value.soul_responses[0], action_digest="0" * 64),),
        )
        with patch.object(
            evaluation_module,
            "_prepare_standing_with_context",
            side_effect=AssertionError("standing must not run"),
        ):
            result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.SOUL)
        self.assertEqual(result.trace, (EvaluationStage.CAPABILITY,))

    def test_invalid_standing_stops_before_evidence(self):
        value = replace(request(), standing=object())
        with patch.object(
            evaluation_module,
            "_prepare_evidence_with_context",
            side_effect=AssertionError("evidence must not run"),
        ):
            result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.failed_stage, EvaluationStage.STANDING)
        self.assertEqual(
            result.trace,
            (EvaluationStage.CAPABILITY, EvaluationStage.SOUL),
        )

    def test_validation_failures_name_the_exact_later_stage(self):
        cases = (
            (
                "_calculate_risk_with_context",
                EvaluationStage.RISK,
                (
                    EvaluationStage.CAPABILITY,
                    EvaluationStage.SOUL,
                    EvaluationStage.STANDING,
                    EvaluationStage.EVIDENCE,
                ),
            ),
            (
                "_calculate_effective_trust_with_context",
                EvaluationStage.TRUST,
                (
                    EvaluationStage.CAPABILITY,
                    EvaluationStage.SOUL,
                    EvaluationStage.STANDING,
                    EvaluationStage.EVIDENCE,
                    EvaluationStage.RISK,
                ),
            ),
            (
                "_compute_envelope_with_context",
                EvaluationStage.ENVELOPE,
                tuple(EvaluationStage)[:-1],
            ),
            (
                "_derive_core_capacity_with_context",
                EvaluationStage.CORE_CAPACITY,
                tuple(EvaluationStage)[:-2],
            ),
        )
        for function, failed_stage, trace in cases:
            with (
                self.subTest(stage=failed_stage),
                patch.object(
                    evaluation_module,
                    function,
                    side_effect=ValidationError("deterministic invalid declaration"),
                ),
            ):
                result = evaluate(request())
            self.assertIsInstance(result, RejectedRequest)
            self.assertIs(result.failed_stage, failed_stage)
            self.assertEqual(result.trace, trace)

    def test_operational_exception_propagates_without_fabricated_decision(self):
        with patch.object(
            evaluation_module,
            "_prepare_standing_with_context",
            side_effect=RuntimeError("application provider failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "provider failed"):
                evaluate(request())

    def test_missing_declaration_slots_are_deterministic_stage_rejections(self):
        cases = (
            (
                "capability",
                "operation_id",
                EvaluationStage.CAPABILITY,
                (),
            ),
            (
                "soul",
                "framework_id",
                EvaluationStage.SOUL,
                (EvaluationStage.CAPABILITY,),
            ),
            (
                "standing",
                "generation",
                EvaluationStage.STANDING,
                (EvaluationStage.CAPABILITY, EvaluationStage.SOUL),
            ),
            (
                "evidence",
                "observation_id",
                EvaluationStage.EVIDENCE,
                (
                    EvaluationStage.CAPABILITY,
                    EvaluationStage.SOUL,
                    EvaluationStage.STANDING,
                ),
            ),
        )
        for location, member, failed_stage, expected_trace in cases:
            value = request()
            if location == "capability":
                object.__delattr__(value, member)
            elif location == "soul":
                declaration = value.soul_responses[0]
                object.__delattr__(declaration, member)
            elif location == "standing":
                object.__delattr__(value.standing, member)
            else:
                object.__delattr__(value.observations[0], member)

            with self.subTest(location=location):
                result = evaluate(value)
                self.assertIsInstance(result, RejectedRequest)
                self.assertIs(result.failed_stage, failed_stage)
                self.assertEqual(result.trace, expected_trace)

    def test_missing_nested_evidence_slots_are_deterministic_stage_rejections(self):
        value = request()
        object.__delattr__(value.observations[0].measurement_envelope, "subject")

        result = evaluate(value)

        self.assertIsInstance(result, RejectedRequest)
        self.assertIs(result.reason_code, RejectionReason.INVALID_DECLARATION)
        self.assertIs(result.failed_stage, EvaluationStage.EVIDENCE)
        self.assertEqual(
            result.trace,
            (
                EvaluationStage.CAPABILITY,
                EvaluationStage.SOUL,
                EvaluationStage.STANDING,
            ),
        )

    def test_missing_nested_soul_and_standing_slots_are_stage_rejections(self):
        cases = (
            ("soul", EvaluationStage.SOUL, (EvaluationStage.CAPABILITY,)),
            (
                "standing", EvaluationStage.STANDING,
                (EvaluationStage.CAPABILITY, EvaluationStage.SOUL),
            ),
        )
        for location, failed_stage, expected_trace in cases:
            value = request()
            if location == "soul":
                reference = copy.copy(value.soul_responses[0].profile_ref)
                object.__setattr__(value.soul_responses[0], "profile_ref", reference)
                object.__delattr__(reference, "version")
            else:
                object.__delattr__(
                    value.standing.root_instruments[0].issuance, "verification_ref"
                )

            with self.subTest(location=location):
                result = evaluate(value)
                self.assertIs(type(result), RejectedRequest)
                self.assertIs(result.reason_code, RejectionReason.INVALID_DECLARATION)
                self.assertIs(result.failed_stage, failed_stage)
                self.assertEqual(result.trace, expected_trace)

    def test_missing_request_slots_are_deterministic_stage_rejections(self):
        cases = (
            ("operation_id", EvaluationStage.CAPABILITY, ()),
            ("profile", EvaluationStage.CAPABILITY, ()),
            ("action", EvaluationStage.CAPABILITY, ()),
            ("cutoff", EvaluationStage.CAPABILITY, ()),
            (
                "soul_responses",
                EvaluationStage.SOUL,
                (EvaluationStage.CAPABILITY,),
            ),
            (
                "standing",
                EvaluationStage.STANDING,
                (EvaluationStage.CAPABILITY, EvaluationStage.SOUL),
            ),
            (
                "observations",
                EvaluationStage.EVIDENCE,
                (
                    EvaluationStage.CAPABILITY,
                    EvaluationStage.SOUL,
                    EvaluationStage.STANDING,
                ),
            ),
            (
                "previous_trust",
                EvaluationStage.TRUST,
                (
                    EvaluationStage.CAPABILITY,
                    EvaluationStage.SOUL,
                    EvaluationStage.STANDING,
                    EvaluationStage.EVIDENCE,
                    EvaluationStage.RISK,
                ),
            ),
        )
        for member, failed_stage, expected_trace in cases:
            value = request()
            object.__delattr__(value, member)

            with self.subTest(member=member):
                result = evaluate(value)
                self.assertIsInstance(result, RejectedRequest)
                self.assertIs(result.failed_stage, failed_stage)
                self.assertEqual(result.trace, expected_trace)

    def test_result_shaped_input_is_a_non_authoritative_rejection(self):
        complete = evaluate(request())
        self.assertIsInstance(complete, EvaluationBundle)

        rejected = evaluate(complete.envelope)

        self.assertIsInstance(rejected, RejectedRequest)
        self.assertIs(rejected.failed_stage, EvaluationStage.CAPABILITY)

    def test_request_has_one_action_authority_not_a_second_capability(self):
        value = request()

        self.assertNotIn("capability", EvaluationRequest.__dataclass_fields__)
        self.assertIsNotNone(value.action.capability)

    def test_evaluation_is_byte_deterministic(self):
        first = evaluate(request())
        second = evaluate(request())

        self.assertIsInstance(first, EvaluationBundle)
        self.assertIsInstance(second, EvaluationBundle)
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.envelope.digest, second.envelope.digest)

    def test_bundle_and_rejection_are_immutable_and_structurally_checked(self):
        bundle = evaluate(request())
        self.assertIsInstance(bundle, EvaluationBundle)
        with self.assertRaises(TypeError):
            EvaluationBundle()
        with self.assertRaises(FrozenInstanceError):
            bundle.envelope = object()
        object.__setattr__(bundle, "digest", "0" * 64)
        with self.assertRaises(ValidationError):
            require_validated_evaluation_bundle(bundle)

        invalid = request()
        object.__setattr__(invalid.action, "digest", "0" * 64)
        rejected = evaluate(invalid)
        self.assertIsInstance(rejected, RejectedRequest)
        with self.assertRaises(TypeError):
            RejectedRequest()
        object.__setattr__(rejected, "rationale", ("",))
        object.__setattr__(
            rejected,
            "digest",
            canonical_sha256(
                {
                    "reason_code": rejected.reason_code,
                    "failed_stage": rejected.failed_stage,
                    "trace": rejected.trace,
                    "rationale": rejected.rationale,
                }
            ),
        )
        with self.assertRaises(ValidationError):
            require_validated_rejected_request(rejected)

        other = request()
        object.__setattr__(other.action, "digest", "0" * 64)
        malformed_trace = evaluate(other)
        self.assertIsInstance(malformed_trace, RejectedRequest)
        object.__setattr__(
            malformed_trace,
            "trace",
            (EvaluationStage.ENVELOPE,),
        )
        object.__setattr__(
            malformed_trace,
            "digest",
            canonical_sha256(
                {
                    "reason_code": malformed_trace.reason_code,
                    "failed_stage": malformed_trace.failed_stage,
                    "trace": malformed_trace.trace,
                    "rationale": malformed_trace.rationale,
                }
            ),
        )
        with self.assertRaises(ValidationError):
            require_validated_rejected_request(malformed_trace)


if __name__ == "__main__":
    unittest.main()
