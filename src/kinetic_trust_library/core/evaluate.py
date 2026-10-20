"""Run the pure Library evaluation pipeline without product enforcement."""

from __future__ import annotations

from datetime import datetime, timezone

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import (
    ValidatedActionDemand,
    _require_owned_utc_datetime,
    _require_validated_action_with_context,
)
from kinetic_trust_library.models._common import validate_identifier
from kinetic_trust_library.models.envelope import (
    EvaluationBundle,
    EvaluationRequest,
    EvaluationStage,
    KineticEnvelopeResult,
    RejectedRequest,
    RejectionReason,
)
from kinetic_trust_library.models.evidence import EvidenceSnapshot
from kinetic_trust_library.models.capacity import CoreCapacityResult
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    ProfileRef,
    _ValidatedProfileContext,
    _bind_profile_to_context,
    _profile_from_context,
    _validated_profile_context,
)
from kinetic_trust_library.models.risk import RiskResult
from kinetic_trust_library.models.soul import SoulAssessment, SoulAssessmentState
from kinetic_trust_library.models.standing import StandingSnapshot
from kinetic_trust_library.models.trust import TrustSnapshot, TrustVelocity

from .capacity import (
    _derive_core_capacity_with_context,
    _require_validated_core_capacity_result_with_context,
)
from .envelope import (
    _compute_envelope_with_context,
    _require_validated_envelope_result_with_context,
)
from .evidence import (
    _prepare_evidence_with_context,
    _require_validated_evidence_snapshot_with_context,
)
from .risk import (
    _calculate_risk_with_context,
    _require_validated_risk_result_with_context,
)
from .soul import (
    _assess_soul_with_context,
    _require_validated_soul_assessment_with_context,
)
from .standing import (
    _prepare_standing_with_context,
    _require_validated_standing_snapshot_with_context,
)
from .trust import (
    _calculate_effective_trust_with_context,
    _calculate_velocity_with_context,
    _require_validated_trust_snapshot_with_context,
    _require_validated_trust_velocity_with_context,
)


def evaluate(request: object) -> EvaluationBundle | RejectedRequest:
    """Return decision data or deterministic request-validation rejection.

    This function does no provider I/O and catches only ``ValidationError``.
    Operational/application failures therefore propagate without being recast as
    a KTP decision or recovery policy.
    """

    trace: list[EvaluationStage] = []
    try:
        required = _require_action(request)
    except ValidationError as exc:
        return _rejected(EvaluationStage.CAPABILITY, trace, exc)
    return _evaluate_after_action(*required, trace=trace)


def _evaluate_with_context(
    request: object,
    context: _ValidatedProfileContext,
) -> EvaluationBundle | RejectedRequest:
    """Replay under an existing call-local profile capability."""
    trace: list[EvaluationStage] = []
    try:
        required = _require_action_with_context(request, context)
    except ValidationError as exc:
        return _rejected(EvaluationStage.CAPABILITY, trace, exc)
    return _evaluate_after_action(*required, trace=trace)


def _evaluate_after_action(
    effective_request: EvaluationRequest,
    context: _ValidatedProfileContext,
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
    operation_id: str,
    cutoff: datetime,
    *,
    trace: list[EvaluationStage],
) -> EvaluationBundle | RejectedRequest:
    """Run later stages after strict or replay capability validation."""
    trace.append(EvaluationStage.CAPABILITY)

    try:
        soul_responses = _request_member(effective_request, "soul_responses")
        if type(soul_responses) is not tuple:
            raise ValidationError("evaluation Soul responses must be an owned tuple")
        soul = _assess_soul_with_context(
            context,
            soul_responses,
            action,
            cutoff,
        )
    except ValidationError as exc:
        return _rejected(EvaluationStage.SOUL, trace, exc)
    trace.append(EvaluationStage.SOUL)

    if soul.state is not SoulAssessmentState.CLEAR:
        try:
            envelope = _compute_envelope_with_context(
                context,
                action,
                soul,
                None,
                operation_id=operation_id,
                core_capacity=None,
            )
        except ValidationError as exc:
            return _rejected(EvaluationStage.ENVELOPE, trace, exc)
        return _bundle(
            effective_request,
            profile=profile,
            action=action,
            soul=soul,
            standing=None,
            evidence=None,
            risk=None,
            trust=None,
            velocity=None,
            core_capacity=None,
            envelope=envelope,
        )

    try:
        standing_declaration = _request_member(effective_request, "standing")
        standing = _prepare_standing_with_context(context, standing_declaration, cutoff)
    except ValidationError as exc:
        return _rejected(EvaluationStage.STANDING, trace, exc)
    trace.append(EvaluationStage.STANDING)

    try:
        observations = _request_member(effective_request, "observations")
        if type(observations) is not tuple:
            raise ValidationError("evaluation observations must be an owned tuple")
        evidence = _prepare_evidence_with_context(
            context,
            observations,
            cutoff,
            operation_id=operation_id,
        )
    except ValidationError as exc:
        return _rejected(EvaluationStage.EVIDENCE, trace, exc)
    trace.append(EvaluationStage.EVIDENCE)

    try:
        risk = _calculate_risk_with_context(context, evidence, soul, action, cutoff)
    except ValidationError as exc:
        return _rejected(EvaluationStage.RISK, trace, exc)
    trace.append(EvaluationStage.RISK)

    try:
        previous_trust = _request_member(effective_request, "previous_trust")
        trust = _calculate_effective_trust_with_context(
            context,
            standing,
            risk,
            soul,
            action,
            cutoff,
        )
        velocity = (
            None
            if previous_trust is None
            else _calculate_velocity_with_context(context, previous_trust, trust)
        )
    except ValidationError as exc:
        return _rejected(EvaluationStage.TRUST, trace, exc)
    trace.extend((EvaluationStage.TRUST, EvaluationStage.TIER))

    try:
        core_capacity = _derive_core_capacity_with_context(
            context,
            action,
            trust,
            operation_id=operation_id,
        )
    except ValidationError as exc:
        return _rejected(EvaluationStage.CORE_CAPACITY, trace, exc)
    trace.append(EvaluationStage.CORE_CAPACITY)

    try:
        envelope = _compute_envelope_with_context(
            context,
            action,
            soul,
            trust,
            operation_id=operation_id,
            core_capacity=core_capacity,
        )
    except ValidationError as exc:
        return _rejected(EvaluationStage.ENVELOPE, trace, exc)
    return _bundle(
        effective_request,
        profile=profile,
        action=action,
        soul=soul,
        standing=standing,
        evidence=evidence,
        risk=risk,
        trust=trust,
        velocity=velocity,
        core_capacity=core_capacity,
        envelope=envelope,
    )


def require_validated_evaluation_bundle(value: object) -> EvaluationBundle:
    """Revalidate a Soul short path or replay a complete pure request."""

    if type(value) is not EvaluationBundle:
        raise ValidationError("value is not a validated evaluation bundle")
    try:
        context = _require_bundle_structure(value)
        if value._request is not None:
            rederived = _evaluate_with_context(value._request, context)
            if type(rederived) is not EvaluationBundle:
                raise ValidationError("bundle request no longer evaluates")
            if canonical_json_bytes(_bundle_projection(value)) != canonical_json_bytes(
                _bundle_projection(rederived)
            ):
                raise ValidationError("bundle does not match represented request")
    except (AttributeError, KeyError, RuntimeError, TypeError, ValidationError) as exc:
        raise ValidationError("evaluation bundle integrity is invalid") from exc
    return value


def require_validated_rejected_request(value: object) -> RejectedRequest:
    """Validate the immutable non-authoritative rejection outcome."""

    if type(value) is not RejectedRequest:
        raise ValidationError("value is not a rejected request")
    try:
        if (
            type(value.reason_code) is not RejectionReason
            or type(value.failed_stage) is not EvaluationStage
            or type(value.trace) is not tuple
            or type(value.rationale) is not tuple
            or type(value.digest) is not str
            or any(type(stage) is not EvaluationStage for stage in value.trace)
            or value.trace not in _rejection_traces(value.failed_stage)
            or len(value.rationale) != 1
        ):
            raise ValidationError("rejected request structure is invalid")
        rationale = value.rationale[0]
        if type(rationale) is not str or not rationale or len(rationale) > 512:
            raise ValidationError("rejected request rationale is invalid")
        try:
            rationale.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValidationError("rejected request rationale is invalid") from exc
        _digest(value.digest, name="rejected request digest")
        if value.digest != canonical_sha256(
            _rejection_projection(value, include_digest=False)
        ):
            raise ValidationError("rejected request integrity is invalid")
    except (AttributeError, TypeError, ValidationError) as exc:
        raise ValidationError("rejected request integrity is invalid") from exc
    return value


def _require_action(
    value: object,
) -> tuple[
    EvaluationRequest,
    _ValidatedProfileContext,
    DeploymentProfile,
    ValidatedActionDemand,
    str,
    datetime,
]:
    if type(value) is not EvaluationRequest:
        raise ValidationError("evaluation must use the explicit request")
    try:
        request_operation_id = value.operation_id
        request_cutoff = value.cutoff
        request_profile = value.profile
        request_action = value.action
    except AttributeError as exc:
        raise ValidationError("evaluation request structure is invalid") from exc
    operation_id = validate_identifier(request_operation_id, name="operation ID")
    cutoff = _require_owned_utc_datetime(request_cutoff, name="evaluation cutoff")
    context = _validated_profile_context(request_profile)
    return _require_action_members_with_context(
        value,
        context,
        request_profile=request_profile,
        request_action=request_action,
        operation_id=operation_id,
        cutoff=cutoff,
    )


def _require_action_with_context(
    value: object,
    context: _ValidatedProfileContext,
) -> tuple[
    EvaluationRequest,
    _ValidatedProfileContext,
    DeploymentProfile,
    ValidatedActionDemand,
    str,
    datetime,
]:
    if type(value) is not EvaluationRequest:
        raise ValidationError("evaluation must use the explicit request")
    try:
        request_operation_id = value.operation_id
        request_cutoff = value.cutoff
        request_profile = value.profile
        request_action = value.action
    except AttributeError as exc:
        raise ValidationError("evaluation request structure is invalid") from exc
    operation_id = validate_identifier(request_operation_id, name="operation ID")
    cutoff = _require_owned_utc_datetime(request_cutoff, name="evaluation cutoff")
    return _require_action_members_with_context(
        value,
        context,
        request_profile=request_profile,
        request_action=request_action,
        operation_id=operation_id,
        cutoff=cutoff,
    )


def _require_action_members_with_context(
    value: EvaluationRequest,
    context: _ValidatedProfileContext,
    *,
    request_profile: object,
    request_action: object,
    operation_id: str,
    cutoff: datetime,
) -> tuple[
    EvaluationRequest,
    _ValidatedProfileContext,
    DeploymentProfile,
    ValidatedActionDemand,
    str,
    datetime,
]:
    _bind_profile_to_context(context, request_profile)
    profile = _profile_from_context(context)
    action = _require_validated_action_with_context(request_action, context)
    if action.validation_cutoff != cutoff:
        raise ValidationError("evaluation cutoff must exactly match action cutoff")
    return value, context, profile, action, operation_id, cutoff


def _request_member(value: EvaluationRequest, member: str) -> object:
    try:
        return object.__getattribute__(value, member)
    except AttributeError as exc:
        raise ValidationError("evaluation request structure is invalid") from exc


def _bundle(
    request: EvaluationRequest,
    *,
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
    soul: SoulAssessment,
    standing: StandingSnapshot | None,
    evidence: EvidenceSnapshot | None,
    risk: RiskResult | None,
    trust: TrustSnapshot | None,
    velocity: TrustVelocity | None,
    core_capacity: CoreCapacityResult | None,
    envelope: KineticEnvelopeResult,
) -> EvaluationBundle:
    value = object.__new__(EvaluationBundle)
    for name, member in (
        ("profile_ref", profile.ref),
        ("profile_digest", profile.digest),
        ("operation_id", request.operation_id),
        ("cutoff", request.cutoff),
        ("action", action),
        ("soul", soul),
        ("standing", standing),
        ("evidence", evidence),
        ("risk", risk),
        ("trust", trust),
        ("velocity", velocity),
        ("core_capacity", core_capacity),
        ("envelope", envelope),
        (
            "_request",
            request if soul.state is SoulAssessmentState.CLEAR else None,
        ),
    ):
        object.__setattr__(value, name, member)
    object.__setattr__(
        value,
        "digest",
        canonical_sha256(_bundle_projection(value, include_digest=False)),
    )
    return value


def _rejected(
    failed_stage: EvaluationStage,
    trace: list[EvaluationStage],
    error: ValidationError,
) -> RejectedRequest:
    message = str(error)
    try:
        message.encode("utf-8")
    except UnicodeEncodeError:
        message = "invalid declaration"
    message = message[:512] or "invalid declaration"
    value = object.__new__(RejectedRequest)
    for name, member in (
        ("reason_code", RejectionReason.INVALID_DECLARATION),
        ("failed_stage", failed_stage),
        ("trace", tuple(trace)),
        ("rationale", (message,)),
    ):
        object.__setattr__(value, name, member)
    object.__setattr__(
        value,
        "digest",
        canonical_sha256(_rejection_projection(value, include_digest=False)),
    )
    return value


def _require_bundle_structure(
    value: EvaluationBundle,
) -> _ValidatedProfileContext:
    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.operation_id) is not str
        or type(value.cutoff) is not datetime
        or value.cutoff.tzinfo is not timezone.utc
        or type(value.action) is not ValidatedActionDemand
        or type(value.soul) is not SoulAssessment
        or type(value.envelope) is not KineticEnvelopeResult
        or type(value.digest) is not str
        or (
            value._request is not None and type(value._request) is not EvaluationRequest
        )
    ):
        raise ValidationError("evaluation bundle structure is invalid")
    context = _validated_profile_context(value.soul._profile)
    profile = _bind_profile_to_context(context, value.soul._profile)
    action = _require_validated_action_with_context(value.action, context)
    soul = _require_validated_soul_assessment_with_context(
        value.soul, context, action=action
    )
    if (
        soul.state is SoulAssessmentState.CLEAR
        and type(value._request) is not EvaluationRequest
    ) or (soul.state is not SoulAssessmentState.CLEAR and value._request is not None):
        raise ValidationError("evaluation bundle rederivation authority is invalid")
    if soul.state is not SoulAssessmentState.CLEAR:
        if any(
            item is not None
            for item in (
                value.standing,
                value.evidence,
                value.risk,
                value.trust,
                value.velocity,
                value.core_capacity,
            )
        ):
            raise ValidationError("Soul-veto bundle carries downstream authority")
        if value.envelope.core_capacity_digest is not None:
            raise ValidationError("Soul-veto bundle carries a capacity digest")
    else:
        if (
            type(value.standing) is not StandingSnapshot
            or type(value.evidence) is not EvidenceSnapshot
            or type(value.risk) is not RiskResult
            or type(value.trust) is not TrustSnapshot
            or type(value.core_capacity) is not CoreCapacityResult
        ):
            raise ValidationError("complete evaluation bundle is incomplete")
        _require_validated_standing_snapshot_with_context(value.standing, context)
        _require_validated_evidence_snapshot_with_context(value.evidence, context)
        _require_validated_risk_result_with_context(
            value.risk, context, soul=soul, action=action
        )
        _require_validated_trust_snapshot_with_context(value.trust, context)
        if value.velocity is not None:
            _require_validated_trust_velocity_with_context(value.velocity, context)
        _require_validated_core_capacity_result_with_context(
            value.core_capacity,
            context,
            action=action,
            trust=value.trust,
            operation_id=value.operation_id,
        )
    _require_validated_envelope_result_with_context(
        value.envelope,
        context,
        action=action,
        soul=soul,
        trust=value.trust,
    )
    if (
        value.core_capacity is not None
        and value.envelope.core_capacity_digest != value.core_capacity.digest
    ):
        raise ValidationError("Envelope Core capacity binding is invalid")
    _digest(value.profile_digest, name="bundle profile digest")
    _digest(value.digest, name="bundle digest")
    if value.digest != canonical_sha256(
        _bundle_projection(value, include_digest=False)
    ):
        raise ValidationError("bundle digest does not match represented values")
    if value.profile_ref != profile.ref or value.profile_digest != profile.digest:
        raise ValidationError("bundle profile binding is invalid")
    if (
        value.operation_id != value.envelope.operation_id
        or value.cutoff != value.envelope.cutoff
    ):
        raise ValidationError("bundle operation binding is invalid")
    return context


def _bundle_projection(
    value: EvaluationBundle, *, include_digest: bool = True
) -> dict[str, object]:
    projection: dict[str, object] = {
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "operation_id": value.operation_id,
        "cutoff": value.cutoff,
        "action_digest": value.action.digest,
        "soul_digest": value.soul.digest,
        "standing_digest": None if value.standing is None else value.standing.digest,
        "evidence_digest": None if value.evidence is None else value.evidence.digest,
        "risk_digest": None if value.risk is None else value.risk.digest,
        "trust_digest": None if value.trust is None else value.trust.digest,
        "velocity_digest": None if value.velocity is None else value.velocity.digest,
        "core_capacity_digest": (
            None if value.core_capacity is None else value.core_capacity.digest
        ),
        "envelope_digest": value.envelope.digest,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _rejection_projection(
    value: RejectedRequest, *, include_digest: bool = True
) -> dict[str, object]:
    projection: dict[str, object] = {
        "reason_code": value.reason_code,
        "failed_stage": value.failed_stage,
        "trace": value.trace,
        "rationale": value.rationale,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _rejection_traces(
    failed_stage: EvaluationStage,
) -> tuple[tuple[EvaluationStage, ...], ...]:
    ordered = tuple(EvaluationStage)
    index = ordered.index(failed_stage)
    ordinary = ordered[:index]
    if failed_stage is EvaluationStage.ENVELOPE:
        return (
            (
                EvaluationStage.CAPABILITY,
                EvaluationStage.SOUL,
            ),
            ordinary,
        )
    return (ordinary,)


def _digest(value: str, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "evaluate",
    "require_validated_evaluation_bundle",
    "require_validated_rejected_request",
]
