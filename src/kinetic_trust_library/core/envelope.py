"""Derive the normative KTP supervision and tighten-only envelope."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import (
    _canonical_derived_margin,
    canonical_json_bytes,
    canonical_sha256,
)
from kinetic_trust_library._decimal import KTP_CONTEXT, require_derived_margin
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._uri import validate_absolute_uri
from kinetic_trust_library.models.action import (
    NormativeGateDecision,
    NormativeGateToken,
    ValidatedActionDemand,
    _require_validated_action_with_context,
)
from kinetic_trust_library.models._common import (
    validate_constraint_magnitude,
    validate_engineering_unit,
    validate_identifier,
)
from kinetic_trust_library.models.envelope import (
    ConstraintCeiling,
    EvaluationStage,
    KineticEnvelopeResult,
    NormativeGateOutcome,
    NormativeGateState,
    Supervision,
    TightenedConstraints,
    UndefinedInput,
    UndefinedInputLayer,
)
from kinetic_trust_library.models.evidence import (
    EvidenceSnapshot,
    SelectedFeedOutcome,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    EnvelopeThresholds,
    ProfileRef,
    _bind_profile_to_context,
    _profile_from_context,
    _validated_profile_context,
)
from kinetic_trust_library.models.risk import RiskResult, SignalFactorResult
from kinetic_trust_library.models.soul import (
    SoulAssessment,
    SoulAssessmentState,
)
from kinetic_trust_library.models.trust import TrustSnapshot, TrustTier
from kinetic_trust_library.models.capacity import CapacityRelation, CoreCapacityResult

from .capacity import (
    _derive_core_capacity_with_context,
    _require_validated_core_capacity_result_with_context,
)
from .risk import _require_validated_risk_result_with_context
from .soul import _require_validated_soul_assessment_with_context
from .trust import _require_validated_trust_snapshot_with_context


_FULL_TRACE = tuple(EvaluationStage)
_SOUL_TRACE = (
    EvaluationStage.CAPABILITY,
    EvaluationStage.SOUL,
    EvaluationStage.ENVELOPE,
)
_SUPERVISION_ORDER = {
    Supervision.STABLE: 0,
    Supervision.METACOGNITIVE: 1,
    Supervision.ASSISTED: 2,
    Supervision.REGULATED: 3,
    Supervision.SILENT_VETO: 4,
}


def compute_envelope(
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
    soul: SoulAssessment,
    trust: TrustSnapshot | None,
    *,
    operation_id: str,
) -> KineticEnvelopeResult:
    """Derive decision data without executing or blocking a product action."""
    return _compute_envelope_with_context(
        _validated_profile_context(profile),
        action,
        soul,
        trust,
        operation_id=operation_id,
        core_capacity=None,
    )


def _compute_envelope_with_context(
    context: object,
    action: ValidatedActionDemand,
    soul: SoulAssessment,
    trust: TrustSnapshot | None,
    *,
    operation_id: str,
    core_capacity: CoreCapacityResult | None,
) -> KineticEnvelopeResult:
    effective_profile = _profile_from_context(context)
    effective_operation = validate_identifier(operation_id, name="operation ID")
    effective_action = _require_validated_action_with_context(action, context)
    effective_soul = _require_validated_soul_assessment_with_context(
        soul,
        context,
        action=effective_action,
    )
    if effective_soul.cutoff != effective_action.validation_cutoff:
        raise ValidationError("Soul and action cutoffs must exactly match")

    constraints = _tightened_constraints(effective_profile, effective_action)
    if effective_soul.state is not SoulAssessmentState.CLEAR:
        if trust is not None or core_capacity is not None:
            raise ValidationError("Soul-veto evaluation must not carry trust authority")
        return _build_result(
            operation_id=effective_operation,
            profile=effective_profile,
            action=effective_action,
            soul=effective_soul,
            trust=None,
            core_capacity=None,
            environmental_capacity=None,
            margin=None,
            capacity_known=False,
            constraints=constraints,
            supervision=Supervision.SILENT_VETO,
            policy_code="SOVEREIGNTY_CONSTRAINT",
            rationale=("Soul veto stopped environmental capacity evaluation",),
            tier=None,
            normative_gate_outcomes=None,
            undefined_inputs=_soul_undefined_inputs(effective_soul),
            trace=_SOUL_TRACE,
        )

    effective_trust = _require_validated_trust_snapshot_with_context(trust, context)
    if (
        effective_trust.action_id != effective_action.action_id
        or effective_trust.action_digest != effective_action.digest
        or effective_trust.soul_digest != effective_soul.digest
        or effective_trust.observed_at != effective_action.validation_cutoff
    ):
        raise ValidationError("trust snapshot belongs to another evaluation")
    effective_risk = _require_validated_risk_result_with_context(
        effective_trust._risk_result,
        context,
        soul=effective_soul,
        action=effective_action,
    )
    if effective_risk.evidence_operation_id != effective_operation:
        raise ValidationError("operation ID does not match prepared evidence")

    if core_capacity is None:
        effective_core_capacity = _derive_core_capacity_with_context(
            context,
            effective_action,
            effective_trust,
            operation_id=effective_operation,
        )
    else:
        effective_core_capacity = _require_validated_core_capacity_result_with_context(
            core_capacity,
            context,
            action=effective_action,
            trust=effective_trust,
            operation_id=effective_operation,
        )

    capacity = effective_core_capacity.effective_trust
    margin = _margin(effective_action.demand, capacity)
    gate_outcomes = _normative_gate_outcomes(effective_action)
    gate_undefined = _gate_undefined_inputs(
        effective_profile,
        gate_outcomes,
    )
    risk_undefined = _risk_undefined_inputs(
        effective_risk,
        effective_risk._evidence,
    )
    undefined_inputs = risk_undefined + gate_undefined
    capacity_known = not risk_undefined
    supervision = _supervision(
        relation=effective_core_capacity.relation,
        margin=margin,
        thresholds=effective_profile.envelope_thresholds,
        capacity_known=capacity_known,
    )
    gate_constrained = _gate_constrained(gate_outcomes)
    if gate_constrained:
        supervision = Supervision.SILENT_VETO
        policy_code = "KINETIC_CAPACITY_EXCEEDED"
    else:
        policy_code = (
            "KINETIC_CAPACITY_EXCEEDED"
            if supervision is Supervision.SILENT_VETO
            else None
        )
    rationale = _rationale(
        supervision,
        capacity_known=capacity_known,
        gate_constrained=gate_constrained,
    )
    return _build_result(
        operation_id=effective_operation,
        profile=effective_profile,
        action=effective_action,
        soul=effective_soul,
        trust=effective_trust,
        core_capacity=effective_core_capacity,
        environmental_capacity=capacity,
        margin=margin,
        capacity_known=capacity_known,
        constraints=constraints,
        supervision=supervision,
        policy_code=policy_code,
        rationale=rationale,
        tier=effective_trust.tier,
        normative_gate_outcomes=gate_outcomes,
        undefined_inputs=undefined_inputs,
        trace=_FULL_TRACE,
    )


def require_validated_envelope_result(
    value: object,
    *,
    profile: DeploymentProfile | None = None,
    action: ValidatedActionDemand | None = None,
    soul: SoulAssessment | None = None,
    trust: TrustSnapshot | None = None,
) -> KineticEnvelopeResult:
    """Structurally rederive an envelope from its represented inputs."""

    if type(value) is not KineticEnvelopeResult:
        raise ValidationError("value is not a validated Kinetic Envelope result")
    try:
        context = _validated_profile_context(
            value._profile if profile is None else profile
        )
    except (AttributeError, KeyError, RuntimeError, TypeError, ValidationError) as exc:
        raise ValidationError("Kinetic Envelope integrity is invalid") from exc
    return _require_validated_envelope_result_with_context(
        value,
        context,
        profile_supplied=profile is not None,
        action=action,
        soul=soul,
        trust=trust,
    )


def _require_validated_envelope_result_with_context(
    value: object,
    context: object,
    *,
    profile_supplied: bool = True,
    action: ValidatedActionDemand | None = None,
    soul: SoulAssessment | None = None,
    trust: TrustSnapshot | None = None,
) -> KineticEnvelopeResult:
    """Private envelope rederivation against one already validated profile."""
    if type(value) is not KineticEnvelopeResult:
        raise ValidationError("value is not a validated Kinetic Envelope result")
    try:
        effective_profile = _bind_profile_to_context(context, value._profile)
        _require_result_structure(value)
        rederived = _compute_envelope_with_context(
            context,
            value._action,
            value._soul,
            value._trust,
            operation_id=value.operation_id,
            core_capacity=None,
        )
        if canonical_json_bytes(_result_projection(value)) != canonical_json_bytes(
            _result_projection(rederived)
        ):
            raise ValidationError("envelope does not match represented inputs")
    except (AttributeError, KeyError, RuntimeError, TypeError, ValidationError) as exc:
        raise ValidationError("Kinetic Envelope integrity is invalid") from exc

    if profile_supplied:
        if (
            value.profile_ref != effective_profile.ref
            or value.profile_digest != effective_profile.digest
        ):
            raise ValidationError("envelope belongs to another profile")
    if action is not None:
        effective_action = _require_validated_action_with_context(action, context)
        if (
            value.action_id != effective_action.action_id
            or value.action_digest != effective_action.digest
        ):
            raise ValidationError("envelope belongs to another action")
    if soul is not None:
        effective_soul = _require_validated_soul_assessment_with_context(
            soul, context, action=action
        )
        if value._soul.digest != effective_soul.digest:
            raise ValidationError("envelope belongs to another Soul assessment")
    if trust is not None:
        effective_trust = _require_validated_trust_snapshot_with_context(trust, context)
        if value._trust is None or value._trust.digest != effective_trust.digest:
            raise ValidationError("envelope belongs to another trust snapshot")
    return value


def _margin(demand: Decimal, capacity: Decimal) -> Decimal:
    if (
        type(demand) is not Decimal
        or type(capacity) is not Decimal
        or not demand.is_finite()
        or not capacity.is_finite()
        or demand < 0
        or capacity < 0
    ):
        raise ValidationError("envelope terms must be exact nonnegative Decimals")
    if capacity == 0:
        return Decimal(0)
    with localcontext(KTP_CONTEXT):
        return Decimal(1) - demand / capacity


def _supervision(
    *,
    relation: CapacityRelation,
    margin: Decimal,
    thresholds: EnvelopeThresholds | None,
    capacity_known: bool,
) -> Supervision:
    if type(relation) is not CapacityRelation:
        raise ValidationError("capacity relation is invalid")
    if type(capacity_known) is not bool:
        raise ValidationError("capacity-known must be an exact boolean")
    if relation is not CapacityRelation.BELOW_CAPACITY:
        result = Supervision.SILENT_VETO
    elif margin <= (Decimal(0) if thresholds is None else thresholds.veto):
        result = Supervision.SILENT_VETO
    elif thresholds is None:
        result = Supervision.STABLE
    elif margin >= thresholds.allow:
        result = Supervision.STABLE
    elif margin >= thresholds.metacognitive_floor:
        result = Supervision.METACOGNITIVE
    elif margin >= thresholds.assisted_floor:
        result = Supervision.ASSISTED
    else:
        result = Supervision.REGULATED
    if (
        not capacity_known
        and _SUPERVISION_ORDER[result] < _SUPERVISION_ORDER[Supervision.ASSISTED]
    ):
        return Supervision.ASSISTED
    return result


def _tightened_constraints(
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
) -> TightenedConstraints:
    ceilings: list[ConstraintCeiling] = []
    for magnitude in sorted(action.requested_constraints):
        value = object.__new__(ConstraintCeiling)
        object.__setattr__(value, "magnitude", magnitude)
        object.__setattr__(
            value, "unit", action.action_policy.constraint_units[magnitude]
        )
        object.__setattr__(value, "maximum", action.requested_constraints[magnitude])
        ceilings.append(value)
    result = object.__new__(TightenedConstraints)
    for name, member in (
        ("profile_ref", profile.ref),
        ("profile_digest", profile.digest),
        ("action_class", action.action_class),
        ("ceilings", tuple(ceilings)),
    ):
        object.__setattr__(result, name, member)
    object.__setattr__(
        result,
        "digest",
        canonical_sha256(_constraints_projection(result, include_digest=False)),
    )
    return result


def _soul_undefined_inputs(soul: SoulAssessment) -> tuple[UndefinedInput, ...]:
    values: list[UndefinedInput] = []
    for outcome in soul.outcomes:
        if outcome.undetermined_reason is None:
            continue
        provenance = () if outcome.provenance_id is None else (outcome.provenance_id,)
        values.append(
            _undefined_input(
                outcome.framework_id,
                UndefinedInputLayer.QUERY,
                outcome.undetermined_reason.value,
                provenance,
            )
        )
    return tuple(values)


def _risk_undefined_inputs(
    risk: RiskResult,
    evidence: EvidenceSnapshot,
) -> tuple[UndefinedInput, ...]:
    values: list[UndefinedInput] = []
    for entry in evidence.entries:
        for outcome in entry.feed_outcomes:
            if type(outcome) is SelectedFeedOutcome:
                continue
            values.append(
                _undefined_input(
                    outcome.source_id,
                    UndefinedInputLayer.FEED,
                    outcome.state.value,
                    (outcome.provenance_digest,),
                )
            )
        if entry.undefined_reason is not None:
            values.append(
                _undefined_input(
                    f"{entry.domain.value}/{entry.signal_id}",
                    UndefinedInputLayer.SIGNAL,
                    entry.undefined_reason.value,
                    tuple(item.provenance_digest for item in entry.feed_outcomes),
                )
            )
    for factor in risk.factors:
        if type(factor) is not SignalFactorResult:
            continue
        for domain in factor.domains:
            if not domain.defaulted:
                continue
            provenance = tuple(
                digest
                for factor_input in domain.inputs
                for digest in factor_input.feed_outcome_digests
            )
            reasons = {item.undefined_reason for item in domain.inputs}
            reason = (
                next(iter(reasons)).value
                if len(reasons) == 1 and None not in reasons
                else "undefined"
            )
            values.append(
                _undefined_input(
                    f"{domain.domain.value}/{factor.name.value}",
                    UndefinedInputLayer.TERM,
                    reason,
                    provenance,
                )
            )
    return tuple(values)


def _normative_gate_outcomes(
    action: ValidatedActionDemand,
) -> tuple[NormativeGateOutcome, ...]:
    supplied = {token.gate_id: token for token in action.normative_gate_tokens}
    values: list[NormativeGateOutcome] = []
    for policy in action.action_policy.normative_gates:
        token = supplied.get(policy.gate_id)
        if token is None:
            state = NormativeGateState.MISSING
        else:
            state = {
                NormativeGateDecision.CLEAR: NormativeGateState.CLEAR,
                NormativeGateDecision.VETO: NormativeGateState.VETO,
                NormativeGateDecision.UNDETERMINED: NormativeGateState.UNDETERMINED,
            }[token.decision]
        value = object.__new__(NormativeGateOutcome)
        for name, member in (
            ("gate_id", policy.gate_id),
            ("schema_uri", policy.schema_uri),
            ("required", policy.required),
            ("state", state),
            ("token", token),
        ):
            object.__setattr__(value, name, member)
        values.append(value)
    return tuple(values)


def _gate_constrained(outcomes: tuple[NormativeGateOutcome, ...]) -> bool:
    return any(
        outcome.state in (NormativeGateState.VETO, NormativeGateState.UNDETERMINED)
        or (outcome.required and outcome.state is NormativeGateState.MISSING)
        for outcome in outcomes
    )


def _gate_undefined_inputs(
    profile: DeploymentProfile,
    outcomes: tuple[NormativeGateOutcome, ...],
) -> tuple[UndefinedInput, ...]:
    values: list[UndefinedInput] = []
    for outcome in outcomes:
        if outcome.state is NormativeGateState.UNDETERMINED:
            if outcome.token is None:
                raise ValidationError("undetermined gate outcome must retain its token")
            values.append(
                _undefined_input(
                    outcome.gate_id,
                    UndefinedInputLayer.GATE,
                    "undetermined",
                    (outcome.token.provenance_id,),
                )
            )
        elif outcome.required and outcome.state is NormativeGateState.MISSING:
            values.append(
                _undefined_input(
                    outcome.gate_id,
                    UndefinedInputLayer.GATE,
                    "missing_required",
                    (profile.digest,),
                )
            )
    return tuple(values)


def _undefined_input(
    input_id: str,
    layer: UndefinedInputLayer,
    reason: str,
    provenance_ids: tuple[str, ...],
) -> UndefinedInput:
    value = object.__new__(UndefinedInput)
    for name, member in (
        ("input_id", input_id),
        ("layer", layer),
        ("reason", reason),
        ("provenance_ids", provenance_ids),
    ):
        object.__setattr__(value, name, member)
    return value


def _rationale(
    supervision: Supervision,
    *,
    capacity_known: bool,
    gate_constrained: bool = False,
) -> tuple[str, ...]:
    values: list[str] = []
    if not capacity_known:
        values.append("undefined evidence constrained environmental capacity")
    if gate_constrained:
        values.append("normative gate constrained the Kinetic Envelope")
        return tuple(values)
    values.append(
        {
            Supervision.STABLE: "margin permits stable operation under the envelope",
            Supervision.METACOGNITIVE: "margin requires metacognitive supervision",
            Supervision.ASSISTED: "margin or unknown capacity requires assistance",
            Supervision.REGULATED: "margin requires external regulation",
            Supervision.SILENT_VETO: "margin is at or below the veto boundary",
        }[supervision]
    )
    return tuple(values)


def _build_result(
    *,
    operation_id: str,
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
    soul: SoulAssessment,
    trust: TrustSnapshot | None,
    core_capacity: CoreCapacityResult | None,
    environmental_capacity: Decimal | None,
    margin: Decimal | None,
    capacity_known: bool,
    constraints: TightenedConstraints,
    supervision: Supervision,
    policy_code: str | None,
    rationale: tuple[str, ...],
    tier: TrustTier | None,
    normative_gate_outcomes: tuple[NormativeGateOutcome, ...] | None,
    undefined_inputs: tuple[UndefinedInput, ...],
    trace: tuple[EvaluationStage, ...],
) -> KineticEnvelopeResult:
    result = object.__new__(KineticEnvelopeResult)
    for name, member in (
        ("operation_id", operation_id),
        ("profile_ref", profile.ref),
        ("profile_digest", profile.digest),
        ("action_id", action.action_id),
        ("action_digest", action.digest),
        (
            "core_capacity_digest",
            None if core_capacity is None else core_capacity.digest,
        ),
        ("cutoff", action.validation_cutoff),
        ("autonomy_demand", action.demand),
        ("environmental_capacity", environmental_capacity),
        ("margin", margin),
        ("capacity_known", capacity_known),
        ("tightened_constraints", constraints),
        ("supervision", supervision),
        ("policy_code", policy_code),
        ("rationale", rationale),
        ("tier", tier),
        ("normative_gate_outcomes", normative_gate_outcomes),
        ("undefined_inputs", undefined_inputs),
        ("trace", trace),
        ("_profile", profile),
        ("_action", action),
        ("_soul", soul),
        ("_trust", trust),
    ):
        object.__setattr__(result, name, member)
    object.__setattr__(
        result,
        "digest",
        canonical_sha256(_result_projection(result, include_digest=False)),
    )
    return result


def _require_result_structure(value: KineticEnvelopeResult) -> None:
    if (
        type(value.operation_id) is not str
        or type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.action_id) is not str
        or type(value.action_digest) is not str
        or type(value.cutoff) is not datetime
        or value.cutoff.tzinfo is not timezone.utc
        or type(value.autonomy_demand) is not Decimal
        or type(value.capacity_known) is not bool
        or type(value.tightened_constraints) is not TightenedConstraints
        or type(value.supervision) is not Supervision
        or (value.policy_code is not None and type(value.policy_code) is not str)
        or type(value.rationale) is not tuple
        or type(value.undefined_inputs) is not tuple
        or type(value.trace) is not tuple
        or type(value.digest) is not str
        or type(value._profile) is not DeploymentProfile
        or type(value._action) is not ValidatedActionDemand
        or type(value._soul) is not SoulAssessment
    ):
        raise ValidationError("Kinetic Envelope structure is invalid")
    if value.environmental_capacity is None:
        if (
            value.core_capacity_digest is not None
            or value.margin is not None
            or value.tier is not None
            or value.capacity_known
            or value._trust is not None
            or value.normative_gate_outcomes is not None
        ):
            raise ValidationError("unevaluated capacity must remain explicitly absent")
    elif (
        type(value.core_capacity_digest) is not str
        or type(value.environmental_capacity) is not Decimal
        or type(value.margin) is not Decimal
        or type(value.tier) is not TrustTier
        or type(value._trust) is not TrustSnapshot
        or type(value.normative_gate_outcomes) is not tuple
    ):
        raise ValidationError("evaluated capacity structure is invalid")
    if value.core_capacity_digest is not None:
        _digest(value.core_capacity_digest, name="envelope Core capacity digest")
    validate_identifier(value.operation_id, name="envelope operation ID")
    validate_identifier(value.profile_ref.profile_id, name="envelope profile ID")
    validate_identifier(value.action_id, name="envelope action ID")
    for name, digest in (
        ("envelope profile digest", value.profile_digest),
        ("envelope action digest", value.action_digest),
        ("envelope digest", value.digest),
    ):
        _digest(digest, name=name)
    if not value.autonomy_demand.is_finite() or value.autonomy_demand < 0:
        raise ValidationError("envelope demand is invalid")
    if value.environmental_capacity is not None and (
        not value.environmental_capacity.is_finite()
        or value.environmental_capacity < 0
        or not value.margin.is_finite()
    ):
        raise ValidationError("envelope capacity or margin is invalid")
    if value.margin is not None:
        require_derived_margin(value.margin)
    _require_constraints_structure(value.tightened_constraints)
    if value.normative_gate_outcomes is not None:
        for outcome in value.normative_gate_outcomes:
            _require_gate_outcome_structure(outcome, cutoff=value.cutoff)
    if any(type(item) is not str for item in value.rationale):
        raise ValidationError("envelope rationale is invalid")
    for item in value.undefined_inputs:
        _require_undefined_structure(item)
    if any(type(stage) is not EvaluationStage for stage in value.trace):
        raise ValidationError("envelope trace is invalid")


def _require_constraints_structure(value: TightenedConstraints) -> None:
    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.action_class) is not str
        or type(value.ceilings) is not tuple
        or type(value.digest) is not str
    ):
        raise ValidationError("tightened constraint structure is invalid")
    validate_identifier(value.profile_ref.profile_id, name="constraint profile ID")
    validate_identifier(value.action_class, name="constraint action class")
    _digest(value.profile_digest, name="constraint profile digest")
    _digest(value.digest, name="tightened constraint digest")
    names: list[str] = []
    for ceiling in value.ceilings:
        if (
            type(ceiling) is not ConstraintCeiling
            or type(ceiling.magnitude) is not str
            or type(ceiling.unit) is not str
            or type(ceiling.maximum) is not Decimal
            or not ceiling.maximum.is_finite()
            or ceiling.maximum < 0
        ):
            raise ValidationError("constraint ceiling structure is invalid")
        names.append(
            validate_constraint_magnitude(
                ceiling.magnitude, name="constraint magnitude"
            )
        )
        validate_engineering_unit(ceiling.unit, name="constraint unit")
    if tuple(names) != tuple(sorted(names)) or len(set(names)) != len(names):
        raise ValidationError("constraint ceilings must be unique and ordered")
    if value.digest != canonical_sha256(
        _constraints_projection(value, include_digest=False)
    ):
        raise ValidationError("tightened constraint integrity is invalid")


def _require_undefined_structure(value: object) -> None:
    if (
        type(value) is not UndefinedInput
        or type(value.input_id) is not str
        or type(value.layer) is not UndefinedInputLayer
        or type(value.reason) is not str
        or type(value.provenance_ids) is not tuple
    ):
        raise ValidationError("undefined input structure is invalid")
    if not value.input_id or len(value.input_id) > 512:
        raise ValidationError("undefined input ID is invalid")
    if not value.reason or len(value.reason) > 128:
        raise ValidationError("undefined input reason is invalid")
    for provenance in value.provenance_ids:
        if type(provenance) is not str:
            raise ValidationError("undefined provenance is invalid")
        if len(provenance) == 64 and all(
            character in "0123456789abcdef" for character in provenance
        ):
            continue
        validate_identifier(provenance, name="undefined provenance ID")


def _require_gate_outcome_structure(
    value: object,
    *,
    cutoff: datetime,
) -> None:
    if (
        type(value) is not NormativeGateOutcome
        or type(value.gate_id) is not str
        or type(value.schema_uri) is not str
        or type(value.required) is not bool
        or type(value.state) is not NormativeGateState
        or (value.token is not None and type(value.token) is not NormativeGateToken)
    ):
        raise ValidationError("normative gate outcome structure is invalid")
    validate_identifier(value.gate_id, name="normative gate outcome ID")
    validate_absolute_uri(value.schema_uri, name="normative gate outcome schema URI")
    if value.state is NormativeGateState.MISSING:
        if value.token is not None:
            raise ValidationError("missing gate outcome must not carry a token")
    elif value.token is None:
        raise ValidationError("resolved gate outcome must carry its token")
    else:
        if (
            type(value.token.gate_id) is not str
            or type(value.token.schema_uri) is not str
            or type(value.token.decision) is not NormativeGateDecision
            or type(value.token.authority) is not str
            or type(value.token.observed_at) is not datetime
            or value.token.observed_at.tzinfo is not timezone.utc
            or type(value.token.provenance_id) is not str
        ):
            raise ValidationError("normative gate outcome token structure is invalid")
        validate_identifier(value.token.gate_id, name="normative gate token ID")
        validate_absolute_uri(
            value.token.schema_uri, name="normative gate token schema URI"
        )
        validate_absolute_uri(
            value.token.authority, name="normative gate token authority URI"
        )
        validate_identifier(
            value.token.provenance_id, name="normative gate token provenance ID"
        )
        expected_state = {
            NormativeGateDecision.CLEAR: NormativeGateState.CLEAR,
            NormativeGateDecision.VETO: NormativeGateState.VETO,
            NormativeGateDecision.UNDETERMINED: NormativeGateState.UNDETERMINED,
        }[value.token.decision]
        if (
            value.token.gate_id != value.gate_id
            or value.token.schema_uri != value.schema_uri
            or value.token.observed_at != cutoff
            or value.state is not expected_state
        ):
            raise ValidationError("normative gate outcome token is incoherent")


def _constraints_projection(
    value: TightenedConstraints, *, include_digest: bool = True
) -> dict[str, object]:
    projection: dict[str, object] = {
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "action_class": value.action_class,
        "ceilings": value.ceilings,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _result_projection(
    value: KineticEnvelopeResult, *, include_digest: bool = True
) -> dict[str, object]:
    projection: dict[str, object] = {
        "operation_id": value.operation_id,
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "action_id": value.action_id,
        "action_digest": value.action_digest,
        "core_capacity_digest": value.core_capacity_digest,
        "cutoff": value.cutoff,
        "autonomy_demand": value.autonomy_demand,
        "environmental_capacity": value.environmental_capacity,
        "margin": (
            None if value.margin is None else _canonical_derived_margin(value.margin)
        ),
        "capacity_known": value.capacity_known,
        "tightened_constraints": value.tightened_constraints,
        "supervision": value.supervision,
        "policy_code": value.policy_code,
        "rationale": value.rationale,
        "tier": value.tier,
        "normative_gate_outcomes": value.normative_gate_outcomes,
        "undefined_inputs": value.undefined_inputs,
        "trace": value.trace,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _digest(value: str, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


__all__ = ["compute_envelope", "require_validated_envelope_result"]
