"""Authoritative Task 5 Kinetic Envelope tests."""

from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT, as_decimal
from kinetic_trust_library.core.capacity import _capacity_relation
import kinetic_trust_library.core.envelope as envelope_module
from kinetic_trust_library.core.envelope import (
    _supervision,
    compute_envelope,
    require_validated_envelope_result,
)
from kinetic_trust_library.core.evaluate import evaluate, require_validated_evaluation_bundle
from kinetic_trust_library.core.evidence import prepare_evidence
from kinetic_trust_library.core.risk import calculate_risk
from kinetic_trust_library.core.soul import assess_soul
from kinetic_trust_library.core.standing import prepare_standing
from kinetic_trust_library.core.trust import calculate_effective_trust
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import (
    MomentCriticalityDeclaration,
    NormativeGateDecision,
    NormativeGateToken,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.capacity import CapacityRelation
from kinetic_trust_library.models.envelope import (
    ConstraintCeiling,
    EvaluationBundle,
    EvaluationRequest,
    KineticEnvelopeResult,
    NormativeGateOutcome,
    NormativeGateState,
    Supervision,
    TightenedConstraints,
    UndefinedInput,
    UndefinedInputLayer,
)
from kinetic_trust_library.models.profile import (
    ActionPolicy,
    DeploymentProfile,
    EnvelopeThresholds,
    NormativeGatePolicy,
)
from kinetic_trust_library.models.soul import (
    SoulConstraintType,
    SoulResponseDeclaration,
    SoulUndeterminedReason,
)
from kinetic_trust_library.models.standing import CeilingDeclaration
from kinetic_trust_library.models.trust import TrustTier
from tests.unit.core.test_evidence import CUTOFF, profile_declaration
from tests.unit.core.test_risk import evidence_declarations, uniform_vectors
from tests.unit.core.test_standing_contract import (
    INDEPENDENT_ID,
    declaration as standing_declaration,
)
from tests.unit.models.test_profile import complete_action, complete_capability


CAPACITY = Decimal("25.12220106534956110945657660101821")
OPERATION_ID = "operation:envelope:one"
CURRENT_STRESSES = uniform_vectors(("0.1", "0.2", "0.3", "0.4", "0"))
ROS2_REFERENCE_CONSTRAINT_UNITS = {
    "maxVelocityMps": "m/s",
    "maxForceNewtons": "N",
    "maxTorqueNm": "N·m",
    "maxJerkMps3": "m/s³",
    "maxAngularVelocityRps": "rad/s",
    "proximityMinMeters": "m",
    "joint:elbow:maxPositionRad": "rad",
    "joint:elbow:maxVelocityRps": "rad/s",
    "joint:elbow:maxEffortNm": "N·m",
}


class _HostileGateString(str):
    calls = 0

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("hostile gate equality executed")

    def __ne__(self, other):
        type(self).calls += 1
        raise AssertionError("hostile gate inequality executed")


def configured_profile(
    *,
    thresholds: EnvelopeThresholds | None = EnvelopeThresholds(
        veto=Decimal("0"),
        allow=Decimal("0.40"),
        metacognitive_floor=Decimal("0.20"),
        assisted_floor=Decimal("0.10"),
    ),
    two_constraints: bool = False,
    on_demand_source: str | None = None,
    normative_gates: tuple[NormativeGatePolicy, ...] = (),
    constraint_units: dict[str, str] | None = None,
) -> DeploymentProfile:
    declaration = profile_declaration(on_demand_source=on_demand_source)
    actions = declaration.actions
    if constraint_units is not None:
        actions = {
            "deploy": ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units=constraint_units,
                normative_gates=normative_gates,
            )
        }
    elif two_constraints:
        actions = {
            "deploy": ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units={
                    "rate": "ops-per-minute",
                    "volume": "records",
                },
                normative_gates=normative_gates,
            )
        }
    elif normative_gates:
        policy = actions["deploy"]
        actions = {
            "deploy": replace(policy, normative_gates=normative_gates),
        }
    return DeploymentProfile.validate(
        replace(
            declaration,
            envelope_thresholds=thresholds,
            actions=actions,
        )
    )


def validated_action(
    profile: DeploymentProfile,
    *,
    demand: str | Decimal,
    requested: dict[str, str] | None = None,
    granted: dict[str, str] | None = None,
    ceilings: dict[str, str] | None = None,
    moment: str | Decimal = "0.75",
    normative_gate_tokens: tuple[NormativeGateToken, ...] = (),
) -> ValidatedActionDemand:
    requested = {"rate": "10"} if requested is None else requested
    granted = {"rate": "20"} if granted is None else granted
    ceilings = {"rate": "25"} if ceilings is None else ceilings
    return ValidatedActionDemand.validate(
        complete_action(
            action_id="action:envelope:one",
            subject=INDEPENDENT_ID,
            demand=demand,
            granted_constraints=granted,
            requested_constraints=requested,
            moment_criticality=MomentCriticalityDeclaration(
                value=moment,
                supplier="action-api",
                unit="stress-0-1",
                observed_at=CUTOFF,
                provenance_id="moment:envelope:one",
            ),
            normative_gate_tokens=normative_gate_tokens,
        ),
        profile=profile,
        capability=complete_capability(
            subject=INDEPENDENT_ID,
            constraint_ceiling=ceilings,
            not_before=CUTOFF - timedelta(minutes=1),
            not_after=CUTOFF + timedelta(minutes=1),
        ),
        cutoff=CUTOFF,
    )


def clear_soul(profile: DeploymentProfile, action: ValidatedActionDemand):
    return assess_soul(
        profile,
        tuple(
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
        ),
        action,
        CUTOFF,
    )


def full_state(
    demand: str | Decimal,
    *,
    profile: DeploymentProfile | None = None,
    observations=None,
    requested: dict[str, str] | None = None,
    granted: dict[str, str] | None = None,
    ceilings: dict[str, str] | None = None,
    normative_gate_tokens: tuple[NormativeGateToken, ...] = (),
):
    profile = configured_profile() if profile is None else profile
    action = validated_action(
        profile,
        demand=demand,
        requested=requested,
        granted=granted,
        ceilings=ceilings,
        normative_gate_tokens=normative_gate_tokens,
    )
    soul = clear_soul(profile, action)
    observations = (
        evidence_declarations(CUTOFF, CURRENT_STRESSES)
        if observations is None
        else observations
    )
    evidence = prepare_evidence(
        profile,
        observations,
        CUTOFF,
        operation_id=OPERATION_ID,
    )
    risk = calculate_risk(profile, evidence, soul, action, CUTOFF)
    standing = prepare_standing(profile, standing_declaration(), CUTOFF)
    trust = calculate_effective_trust(
        profile,
        standing,
        risk,
        soul,
        action,
        CUTOFF,
    )
    return profile, action, soul, trust


GATE_SCHEMA = "https://schemas.example/ktp/change-control/v1"
GATE_AUTHORITY = "https://policy.example/authorities/change-control"


def gate_policy(*, required: bool = True) -> NormativeGatePolicy:
    return NormativeGatePolicy(
        gate_id="gate:change-control",
        schema_uri=GATE_SCHEMA,
        required=required,
    )


def gate_token(decision: NormativeGateDecision) -> NormativeGateToken:
    return NormativeGateToken(
        gate_id="gate:change-control",
        schema_uri=GATE_SCHEMA,
        decision=decision,
        authority=GATE_AUTHORITY,
        observed_at=CUTOFF,
        provenance_id="gate-token:change-control:one",
    )


class NormativeGateEnvelopeTests(unittest.TestCase):
    def test_clear_required_gate_is_typed_carriage_and_nonrestrictive(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        profile, action, soul, trust = full_state(
            "1",
            profile=profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.CLEAR),),
        )

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertIs(result.supervision, Supervision.STABLE)
        self.assertEqual(len(result.normative_gate_outcomes), 1)
        outcome = result.normative_gate_outcomes[0]
        self.assertIsInstance(outcome, NormativeGateOutcome)
        self.assertIs(outcome.state, NormativeGateState.CLEAR)
        self.assertEqual(outcome.schema_uri, GATE_SCHEMA)
        self.assertEqual(outcome.token, action.normative_gate_tokens[0])

    def test_veto_gate_only_tightens_envelope_and_never_rewrites_trust(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        clear_state = full_state(
            "1",
            profile=profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.CLEAR),),
        )
        veto_state = full_state(
            "1",
            profile=profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.VETO),),
        )
        clear = compute_envelope(*clear_state, operation_id=OPERATION_ID)
        veto = compute_envelope(*veto_state, operation_id=OPERATION_ID)

        self.assertEqual(veto.environmental_capacity, clear.environmental_capacity)
        self.assertEqual(veto.margin, clear.margin)
        self.assertEqual(veto.tier, clear.tier)
        self.assertTrue(veto.capacity_known)
        self.assertIs(veto.normative_gate_outcomes[0].state, NormativeGateState.VETO)
        self.assertIs(veto.supervision, Supervision.SILENT_VETO)
        self.assertEqual(veto.policy_code, "KINETIC_CAPACITY_EXCEEDED")
        self.assertEqual(
            veto.rationale,
            ("normative gate constrained the Kinetic Envelope",),
        )

    def test_undetermined_and_missing_required_gates_fail_closed_with_provenance(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        cases = (
            (
                (gate_token(NormativeGateDecision.UNDETERMINED),),
                NormativeGateState.UNDETERMINED,
                ("gate-token:change-control:one",),
            ),
            ((), NormativeGateState.MISSING, (profile.digest,)),
        )
        for tokens, expected_state, provenance in cases:
            with self.subTest(expected_state=expected_state):
                state = full_state(
                    "1",
                    profile=profile,
                    normative_gate_tokens=tokens,
                )
                result = compute_envelope(*state, operation_id=OPERATION_ID)
                self.assertIs(result.supervision, Supervision.SILENT_VETO)
                self.assertIs(
                    result.normative_gate_outcomes[0].state,
                    expected_state,
                )
                undefined = tuple(
                    item
                    for item in result.undefined_inputs
                    if item.layer is UndefinedInputLayer.GATE
                )
                self.assertEqual(len(undefined), 1)
                self.assertEqual(undefined[0].input_id, "gate:change-control")
                self.assertEqual(undefined[0].provenance_ids, provenance)

    def test_optional_missing_gate_is_explicit_but_nonrestrictive(self):
        profile = configured_profile(normative_gates=(gate_policy(required=False),))
        state = full_state("1", profile=profile)

        result = compute_envelope(*state, operation_id=OPERATION_ID)

        self.assertIs(
            result.normative_gate_outcomes[0].state, NormativeGateState.MISSING
        )
        self.assertIs(result.supervision, Supervision.STABLE)
        self.assertFalse(
            any(
                item.layer is UndefinedInputLayer.GATE
                for item in result.undefined_inputs
            )
        )

    def test_gate_inventory_exactly_rejects_unknown_schema_authority_and_time(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        valid = gate_token(NormativeGateDecision.CLEAR)
        cases = (
            replace(valid, gate_id="gate:unknown"),
            replace(valid, schema_uri="https://schemas.example/other/v1"),
            replace(valid, authority="not-an-absolute-uri"),
            replace(valid, observed_at=CUTOFF - timedelta(microseconds=1)),
            replace(valid, provenance_id=""),
        )
        for token in cases:
            with self.subTest(token=token), self.assertRaises(ValidationError):
                validated_action(
                    profile,
                    demand="1",
                    normative_gate_tokens=(token,),
                )

    def test_gate_schema_rejects_string_subclasses_before_comparison_hooks(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        token = replace(
            gate_token(NormativeGateDecision.CLEAR),
            schema_uri=_HostileGateString(GATE_SCHEMA),
        )
        _HostileGateString.calls = 0

        with self.assertRaises(ValidationError):
            validated_action(
                profile,
                demand="1",
                normative_gate_tokens=(token,),
            )
        self.assertEqual(_HostileGateString.calls, 0)

    def test_gate_result_and_source_mutation_are_detected(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        state = full_state(
            "1",
            profile=profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.CLEAR),),
        )
        result = compute_envelope(*state, operation_id=OPERATION_ID)
        outcome = result.normative_gate_outcomes[0]
        object.__setattr__(outcome, "state", NormativeGateState.VETO)
        object.__setattr__(result, "digest", canonical_sha256({"forged": True}))

        with self.assertRaises(ValidationError):
            require_validated_envelope_result(result)

    def test_gate_outcome_revalidation_rejects_hostile_nested_primitives_first(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        state = full_state(
            "1",
            profile=profile,
            normative_gate_tokens=(gate_token(NormativeGateDecision.CLEAR),),
        )
        result = compute_envelope(*state, operation_id=OPERATION_ID)
        outcome = result.normative_gate_outcomes[0]
        token = copy.copy(outcome.token)
        object.__setattr__(token, "gate_id", _HostileGateString(token.gate_id))
        object.__setattr__(outcome, "token", token)
        _HostileGateString.calls = 0

        with self.assertRaises(ValidationError):
            require_validated_envelope_result(result)
        self.assertEqual(_HostileGateString.calls, 0)

    def test_soul_veto_leaves_normative_gates_explicitly_unevaluated(self):
        profile = configured_profile(normative_gates=(gate_policy(),))
        action = validated_action(
            profile,
            demand="1",
            normative_gate_tokens=(gate_token(NormativeGateDecision.VETO),),
        )
        soul = assess_soul(profile, (), action, CUTOFF)

        result = compute_envelope(
            profile, action, soul, None, operation_id=OPERATION_ID
        )

        self.assertIsNone(result.normative_gate_outcomes)
        self.assertIsNone(result.environmental_capacity)
        self.assertIsNone(result.margin)
        self.assertIsNone(result.tier)


class EnvelopeArithmeticTests(unittest.TestCase):
    def test_negative_ordered_thresholds_cannot_relax_exact_capacity(self):
        thresholds = EnvelopeThresholds(
            veto=Decimal("-0.40"),
            assisted_floor=Decimal("-0.30"),
            metacognitive_floor=Decimal("-0.20"),
            allow=Decimal("-0.10"),
        )
        profile = configured_profile(thresholds=thresholds)
        profile, action, soul, trust = full_state(str(CAPACITY), profile=profile)

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertIs(
            _capacity_relation(action.demand, trust.effective_trust),
            CapacityRelation.AT_CAPACITY,
        )
        self.assertEqual(result.margin, Decimal(0))
        self.assertIs(result.supervision, Supervision.SILENT_VETO)
        self.assertEqual(result.policy_code, "KINETIC_CAPACITY_EXCEEDED")

    def test_valid_extreme_inputs_are_closed_under_exact_margin_derivation(self):
        profile = configured_profile()
        action = validated_action(profile, demand="100", moment="0.97")
        request = EvaluationRequest(
            operation_id=OPERATION_ID,
            profile=profile,
            action=action,
            standing=replace(
                standing_declaration(),
                additional_ceilings=(
                    CeilingDeclaration(
                        name="extreme-envelope-limit",
                        value="1E-6141",
                        provenance_id="ceiling:extreme-envelope-limit",
                    ),
                ),
            ),
            observations=evidence_declarations(
                CUTOFF,
                uniform_vectors(("0.99", "0.99", "1", "0.99", "1")),
            ),
            soul_responses=tuple(
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
            ),
            cutoff=CUTOFF,
        )

        evaluated = evaluate(request)

        self.assertIsInstance(evaluated, EvaluationBundle)
        self.assertEqual(evaluated.standing.base_trust, Decimal("1E-6141"))
        self.assertEqual(evaluated.risk.risk, Decimal("0.990000"))
        self.assertEqual(evaluated.trust.effective_trust, Decimal("1E-6143"))
        self.assertEqual(evaluated.envelope.margin.adjusted(), 6145)
        self.assertIs(evaluated.envelope.supervision, Supervision.SILENT_VETO)
        self.assertIs(
            require_validated_envelope_result(evaluated.envelope),
            evaluated.envelope,
        )
        self.assertIs(require_validated_evaluation_bundle(evaluated), evaluated)
        with self.assertRaises(ValidationError):
            as_decimal("1E6145", name="caller input")

    def test_derived_margin_bounds_and_exact_recomputation_are_structural(self):
        profile, action, soul, trust = full_state("1")
        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        outside = copy.copy(result)
        object.__setattr__(outside, "margin", Decimal("-1E6146"))
        with self.assertRaises(ValidationError):
            require_validated_envelope_result(outside)

        resealed = copy.copy(result)
        object.__setattr__(resealed, "margin", Decimal("0"))
        object.__setattr__(
            resealed,
            "digest",
            canonical_sha256(
                envelope_module._result_projection(resealed, include_digest=False)
            ),
        )
        with self.assertRaises(ValidationError):
            require_validated_envelope_result(resealed)

    def test_every_threshold_is_exact_on_both_sides(self):
        thresholds = EnvelopeThresholds(
            veto=Decimal("0"),
            allow=Decimal("0.40"),
            metacognitive_floor=Decimal("0.20"),
            assisted_floor=Decimal("0.10"),
        )
        cases = (
            (thresholds.allow.next_minus(KTP_CONTEXT), Supervision.METACOGNITIVE),
            (thresholds.allow, Supervision.STABLE),
            (thresholds.allow.next_plus(KTP_CONTEXT), Supervision.STABLE),
            (
                thresholds.metacognitive_floor.next_minus(KTP_CONTEXT),
                Supervision.ASSISTED,
            ),
            (thresholds.metacognitive_floor, Supervision.METACOGNITIVE),
            (
                thresholds.metacognitive_floor.next_plus(KTP_CONTEXT),
                Supervision.METACOGNITIVE,
            ),
            (
                thresholds.assisted_floor.next_minus(KTP_CONTEXT),
                Supervision.REGULATED,
            ),
            (thresholds.assisted_floor, Supervision.ASSISTED),
            (
                thresholds.assisted_floor.next_plus(KTP_CONTEXT),
                Supervision.ASSISTED,
            ),
            (Decimal("-1e-33"), Supervision.SILENT_VETO),
            (thresholds.veto, Supervision.SILENT_VETO),
            (Decimal("1e-33"), Supervision.REGULATED),
        )
        for margin, expected in cases:
            with self.subTest(margin=margin):
                with localcontext(KTP_CONTEXT):
                    demand = Decimal(1) - margin
                self.assertIs(
                    _supervision(
                        relation=(
                            CapacityRelation.ABOVE_CAPACITY if demand > 1
                            else CapacityRelation.AT_CAPACITY if demand == 1
                            else CapacityRelation.BELOW_CAPACITY
                        ),
                        margin=margin,
                        thresholds=thresholds,
                        capacity_known=True,
                    ),
                    expected,
                )

    def test_all_declared_supervision_bands_use_exact_boundaries(self):
        # Division is performed at the pinned KTP decimal precision. These
        # literal margins are therefore the exact results represented by the
        # corresponding demand and capacity literals, not rounded aliases.
        cases = (
            (
                "15.07332063920973666567394596061093",
                "0.3999999999999999999999999999999998",
                "allow",
                Supervision.STABLE,
            ),
            (
                "17.58554074574469277661960362071275",
                "0.2999999999999999999999999999999999",
                "metacognitive",
                Supervision.METACOGNITIVE,
            ),
            (
                "21.35387090554712694303809011086548",
                "0.1499999999999999999999999999999999",
                "assisted",
                Supervision.ASSISTED,
            ),
            (
                "23.86609101208208305398374777096730",
                "0.0500000000000000000000000000000000",
                "regulated",
                Supervision.REGULATED,
            ),
            (
                "25.12220106534956110945657660101821",
                "0",
                "veto",
                Supervision.SILENT_VETO,
            ),
        )
        for demand, margin, boundary, supervision in cases:
            with self.subTest(supervision=supervision):
                exact = Decimal(margin)
                thresholds = {
                    "allow": EnvelopeThresholds(
                        veto=Decimal("0"),
                        allow=exact,
                        metacognitive_floor=Decimal("0.20"),
                        assisted_floor=Decimal("0.10"),
                    ),
                    "metacognitive": EnvelopeThresholds(
                        veto=Decimal("0"),
                        allow=Decimal("0.40"),
                        metacognitive_floor=exact,
                        assisted_floor=Decimal("0.10"),
                    ),
                    "assisted": EnvelopeThresholds(
                        veto=Decimal("0"),
                        allow=Decimal("0.40"),
                        metacognitive_floor=Decimal("0.20"),
                        assisted_floor=exact,
                    ),
                    "regulated": EnvelopeThresholds(
                        veto=Decimal("0"),
                        allow=Decimal("0.40"),
                        metacognitive_floor=Decimal("0.20"),
                        assisted_floor=Decimal("0.10"),
                    ),
                    "veto": EnvelopeThresholds(
                        veto=exact,
                        allow=Decimal("0.40"),
                        metacognitive_floor=Decimal("0.20"),
                        assisted_floor=Decimal("0.10"),
                    ),
                }[boundary]
                profile, action, soul, trust = full_state(
                    demand,
                    profile=configured_profile(thresholds=thresholds),
                )
                self.assertEqual(trust.effective_trust, CAPACITY)
                result = compute_envelope(
                    profile,
                    action,
                    soul,
                    trust,
                    operation_id=OPERATION_ID,
                )
                self.assertEqual(result.margin, Decimal(margin))
                self.assertIs(result.supervision, supervision)

    def test_zero_capacity_is_an_exact_silent_veto(self):
        profile = configured_profile()
        action = validated_action(profile, demand="0", moment="1")
        soul = clear_soul(profile, action)
        evidence = prepare_evidence(
            profile,
            evidence_declarations(
                CUTOFF,
                uniform_vectors(("1", "1", "1", "1", "1")),
            ),
            CUTOFF,
            operation_id=OPERATION_ID,
        )
        risk = calculate_risk(profile, evidence, soul, action, CUTOFF)
        trust = calculate_effective_trust(
            profile,
            prepare_standing(profile, standing_declaration(), CUTOFF),
            risk,
            soul,
            action,
            CUTOFF,
        )

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertEqual(trust.effective_trust, Decimal(0))
        self.assertEqual(result.margin, Decimal(0))
        self.assertIs(result.supervision, Supervision.SILENT_VETO)
        self.assertEqual(result.policy_code, "KINETIC_CAPACITY_EXCEEDED")

    def test_unknown_capacity_clamps_a_safe_margin_to_assisted(self):
        profile, action, soul, trust = full_state("0", observations=())

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertEqual(result.margin, Decimal(1))
        self.assertFalse(result.capacity_known)
        self.assertIs(result.supervision, Supervision.ASSISTED)
        self.assertTrue(
            any(
                item.layer is UndefinedInputLayer.FEED
                for item in result.undefined_inputs
            )
        )
        self.assertTrue(
            any(
                item.layer is UndefinedInputLayer.SIGNAL
                for item in result.undefined_inputs
            )
        )
        self.assertTrue(
            any(
                item.layer is UndefinedInputLayer.TERM
                for item in result.undefined_inputs
            )
        )
        self.assertTrue(all(item.provenance_ids for item in result.undefined_inputs))

    def test_unknown_capacity_floor_never_loosens_a_stricter_result(self):
        thresholds = configured_profile().envelope_thresholds
        self.assertIsNotNone(thresholds)
        cases = (
            (Decimal("0.50"), Supervision.ASSISTED),
            (Decimal("0.30"), Supervision.ASSISTED),
            (Decimal("0.15"), Supervision.ASSISTED),
            (Decimal("0.05"), Supervision.REGULATED),
            (Decimal("-0.01"), Supervision.SILENT_VETO),
        )
        for margin, expected in cases:
            with self.subTest(margin=margin):
                self.assertIs(
                    _supervision(
                        relation=(
                            CapacityRelation.ABOVE_CAPACITY if margin < 0
                            else CapacityRelation.BELOW_CAPACITY
                        ),
                        margin=margin,
                        thresholds=thresholds,
                        capacity_known=False,
                    ),
                    expected,
                )

    def test_binary_profile_is_stable_below_capacity_and_vetoes_equality(self):
        profile = configured_profile(thresholds=None)
        profile, action, soul, trust = full_state("1", profile=profile)
        stable = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )
        self.assertIs(stable.supervision, Supervision.STABLE)

        profile, action, soul, trust = full_state(str(CAPACITY), profile=profile)
        equality = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )
        self.assertIs(equality.supervision, Supervision.SILENT_VETO)

    def test_capacity_exceeded_retains_tightened_constraints(self):
        profile, action, soul, trust = full_state("26")

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertLess(result.margin, Decimal(0))
        self.assertIs(result.supervision, Supervision.SILENT_VETO)
        self.assertLess(
            result.tightened_constraints.ceilings[0].maximum,
            action.granted_constraints["rate"],
        )

    def test_nonstable_supervision_retains_tightened_constraints(self):
        profile, action, soul, trust = full_state("23.86609101208208305398374777096730")

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertIs(result.supervision, Supervision.REGULATED)
        self.assertLess(
            result.tightened_constraints.ceilings[0].maximum,
            action.granted_constraints["rate"],
        )

    def test_exact_tier_is_retained_but_never_replaces_the_envelope(self):
        observations = evidence_declarations(
            CUTOFF,
            uniform_vectors(("0.4", "0.4", "0.4", "0.4", "0")),
        )
        profile, action, soul, trust = full_state("0", observations=observations)

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertIs(trust.tier, TrustTier.HIBERNATION)
        self.assertIs(result.tier, trust.tier)
        self.assertIs(result.supervision, Supervision.STABLE)

    def test_undefined_inventory_preserves_every_feed_signal_and_term(self):
        profile, action, soul, trust = full_state("0", observations=())

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertEqual(
            {
                layer: sum(item.layer is layer for item in result.undefined_inputs)
                for layer in UndefinedInputLayer
            },
            {
                UndefinedInputLayer.FEED: 15,
                UndefinedInputLayer.SIGNAL: 15,
                UndefinedInputLayer.TERM: 15,
                UndefinedInputLayer.QUERY: 0,
                UndefinedInputLayer.GATE: 0,
            },
        )
        self.assertTrue(all(item.provenance_ids for item in result.undefined_inputs))

    def test_threshold_bands_must_be_strictly_ordered(self):
        declaration = profile_declaration()
        with self.assertRaisesRegex(ValidationError, "threshold"):
            DeploymentProfile.validate(
                replace(
                    declaration,
                    envelope_thresholds=EnvelopeThresholds(
                        veto=Decimal("0"),
                        allow=Decimal("0.4"),
                        metacognitive_floor=Decimal("0.1"),
                        assisted_floor=Decimal("0.2"),
                    ),
                )
            )


class EnvelopeConstraintAndIntegrityTests(unittest.TestCase):
    def test_ros2_reference_constraint_vocabulary_is_publicly_constructible(self):
        profile = configured_profile(
            constraint_units=ROS2_REFERENCE_CONSTRAINT_UNITS,
        )
        values = {
            name: str(index)
            for index, name in enumerate(ROS2_REFERENCE_CONSTRAINT_UNITS, start=1)
        }
        grants = {
            name: str(100 + index)
            for index, name in enumerate(ROS2_REFERENCE_CONSTRAINT_UNITS, start=1)
        }
        ceilings = {name: "1000" for name in ROS2_REFERENCE_CONSTRAINT_UNITS}
        profile, action, soul, trust = full_state(
            "1",
            profile=profile,
            requested=values,
            granted=grants,
            ceilings=ceilings,
        )

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        expected = tuple(
            (name, ROS2_REFERENCE_CONSTRAINT_UNITS[name], Decimal(values[name]))
            for name in sorted(ROS2_REFERENCE_CONSTRAINT_UNITS)
        )
        self.assertEqual(
            tuple(
                (item.magnitude, item.unit, item.maximum)
                for item in result.tightened_constraints.ceilings
            ),
            expected,
        )
        self.assertIs(
            require_validated_envelope_result(result),
            result,
        )

    def test_constraint_vocabulary_rejects_malformed_and_confusable_forms(self):
        invalid = (
            {"max VelocityMps": "m/s"},
            {"ｍaxVelocityMps": "m/s"},
            {"joint::maxPositionRad": "rad"},
            {"joint:elbow:": "rad"},
            {"maxTorqueNm": "N*m"},
            {"maxTorqueNm": "N · m"},
            {"maxForceNewtons": "Ｎ"},
            {"maxJerkMps3": "m/s3"},
        )
        for units in invalid:
            with self.subTest(units=units), self.assertRaises(ValidationError):
                configured_profile(constraint_units=units)

    def test_tightened_constraints_preserve_names_units_and_maxima(self):
        profile = configured_profile(two_constraints=True)
        profile, action, soul, trust = full_state(
            "1",
            profile=profile,
            requested={"rate": "10", "volume": "50"},
            granted={"rate": "20", "volume": "75"},
            ceilings={"rate": "25", "volume": "100"},
        )

        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )

        self.assertEqual(
            tuple(
                (item.magnitude, item.unit, item.maximum)
                for item in result.tightened_constraints.ceilings
            ),
            (
                ("rate", "ops-per-minute", Decimal("10")),
                ("volume", "records", Decimal("50")),
            ),
        )
        self.assertIs(result.supervision, Supervision.STABLE)

    def test_result_and_nested_constraints_are_guarded_and_structurally_rederived(self):
        profile, action, soul, trust = full_state("1")
        result = compute_envelope(
            profile, action, soul, trust, operation_id=OPERATION_ID
        )
        self.assertIs(
            require_validated_envelope_result(
                result,
                profile=profile,
                action=action,
                soul=soul,
                trust=trust,
            ),
            result,
        )
        with self.assertRaises(TypeError):
            KineticEnvelopeResult()
        with self.assertRaises(TypeError):
            ConstraintCeiling()
        with self.assertRaises(TypeError):
            TightenedConstraints()
        with self.assertRaises(TypeError):
            UndefinedInput()
        with self.assertRaises(FrozenInstanceError):
            result.margin = Decimal(0)

        ceiling = result.tightened_constraints.ceilings[0]
        object.__setattr__(ceiling, "unit", "requests-per-second")
        object.__setattr__(
            result,
            "digest",
            canonical_sha256({"forged": "coherently-resealed-by-caller"}),
        )
        with self.assertRaises(ValidationError):
            require_validated_envelope_result(result)

    def test_result_shaped_caller_values_never_supply_capacity(self):
        profile, action, soul, _trust = full_state("1")
        with self.assertRaises(ValidationError):
            compute_envelope(
                profile,
                action,
                soul,
                object(),
                operation_id=OPERATION_ID,
            )


class SoulVetoEnvelopeTests(unittest.TestCase):
    def test_soul_veto_retains_explicitly_unevaluated_capacity_and_tier(self):
        profile = configured_profile()
        action = validated_action(profile, demand="1")
        soul = assess_soul(profile, (), action, CUTOFF)

        result = compute_envelope(
            profile,
            action,
            soul,
            None,
            operation_id=OPERATION_ID,
        )

        self.assertIsNone(result.environmental_capacity)
        self.assertIsNone(result.margin)
        self.assertIsNone(result.tier)
        self.assertFalse(result.capacity_known)
        self.assertIs(result.supervision, Supervision.SILENT_VETO)
        self.assertEqual(result.policy_code, "SOVEREIGNTY_CONSTRAINT")
        self.assertEqual(
            tuple(item.layer for item in result.undefined_inputs),
            (UndefinedInputLayer.QUERY,),
        )
        self.assertEqual(
            result.undefined_inputs[0].reason,
            SoulUndeterminedReason.MISSING.value,
        )

    def test_real_soul_veto_has_no_fabricated_undefined_or_capacity(self):
        profile = configured_profile()
        action = validated_action(profile, demand="1")
        framework = profile.soul_frameworks[0]
        soul = assess_soul(
            profile,
            (
                SoulResponseDeclaration(
                    framework_id=framework,
                    profile_ref=profile.ref,
                    profile_digest=profile.digest,
                    action_id=action.action_id,
                    action_digest=action.digest,
                    query_cutoff=CUTOFF,
                    state="veto",
                    observed_at=CUTOFF,
                    provenance_id="soul:veto:one",
                    constraint_type=SoulConstraintType.TK_LABEL,
                    constraint_id="TK-NC-001",
                    authority="https://localcontexts.org/label/tk-nc/",
                ),
            ),
            action,
            CUTOFF,
        )

        result = compute_envelope(
            profile, action, soul, None, operation_id=OPERATION_ID
        )

        self.assertIsNone(result.environmental_capacity)
        self.assertIsNone(result.margin)
        self.assertIsNone(result.tier)
        self.assertEqual(result.undefined_inputs, ())


if __name__ == "__main__":
    unittest.main()
