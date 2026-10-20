"""Derive KTP effective trust, trust tier, and optional trust velocity."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import (
    ValidatedActionDemand,
    _require_validated_action_with_context,
)
from kinetic_trust_library.models._common import utc_time, validate_identifier
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
from kinetic_trust_library.models.trust import TrustSnapshot, TrustTier, TrustVelocity

from .risk import _require_validated_risk_result_with_context
from .soul import _require_validated_soul_assessment_with_context
from .standing import _require_validated_standing_snapshot_with_context


def calculate_effective_trust(
    profile: DeploymentProfile,
    standing: StandingSnapshot,
    risk: RiskResult,
    soul: SoulAssessment,
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> TrustSnapshot:
    """Derive E_trust from standing-owned E_base and represented risk."""
    return _calculate_effective_trust_with_context(
        _validated_profile_context(profile), standing, risk, soul, action, cutoff
    )


def _calculate_effective_trust_with_context(
    context: object,
    standing: StandingSnapshot,
    risk: RiskResult,
    soul: SoulAssessment,
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> TrustSnapshot:
    effective_profile = _profile_from_context(context)
    effective_cutoff = utc_time(cutoff, name="effective-trust cutoff")
    effective_action = _require_validated_action_with_context(action, context)
    if effective_action.validation_cutoff != effective_cutoff:
        raise ValidationError(
            "effective-trust cutoff must exactly match the action cutoff"
        )
    effective_soul = _require_validated_soul_assessment_with_context(
        soul,
        context,
        action=effective_action,
    )
    if effective_soul.cutoff != effective_cutoff:
        raise ValidationError(
            "effective-trust cutoff must exactly match the Soul cutoff"
        )
    if effective_soul.state is not SoulAssessmentState.CLEAR:
        raise ValidationError(
            "Soul assessment must be clear before effective-trust calculation"
        )

    effective_standing = _require_validated_standing_snapshot_with_context(
        standing, context
    )
    if effective_standing._cutoff != effective_cutoff:
        raise ValidationError(
            "effective-trust cutoff must exactly match the standing cutoff"
        )
    if effective_standing.agent_id != effective_action.subject:
        raise ValidationError("standing subject does not match the action subject")
    effective_risk = _require_validated_risk_result_with_context(
        risk,
        context,
        soul=effective_soul,
        action=effective_action,
    )
    if effective_risk.cutoff != effective_cutoff:
        raise ValidationError("risk cutoff does not match effective-trust cutoff")

    value = _effective_trust(effective_standing.base_trust, effective_risk.risk)
    tier = _trust_tier(value)

    result = object.__new__(TrustSnapshot)
    for name, member in (
        ("profile_ref", effective_profile.ref),
        ("profile_digest", effective_profile.digest),
        ("subject", effective_action.subject),
        ("action_id", effective_action.action_id),
        ("action_digest", effective_action.digest),
        ("action_class", effective_action.action_class),
        ("standing_digest", effective_standing.digest),
        ("risk_digest", effective_risk.digest),
        ("soul_digest", effective_soul.digest),
        ("observed_at", effective_cutoff),
        ("base_trust", effective_standing.base_trust),
        ("risk", effective_risk.risk),
        ("effective_trust", value),
        ("tier", tier),
        ("_profile", effective_profile),
        ("_standing", effective_standing),
        ("_risk_result", effective_risk),
        ("_soul", effective_soul),
        ("_action", effective_action),
    ):
        object.__setattr__(result, name, member)
    object.__setattr__(
        result,
        "digest",
        canonical_sha256(_trust_projection(result, include_digest=False)),
    )
    return result


def require_validated_trust_snapshot(
    value: object, *, profile: DeploymentProfile | None = None
) -> TrustSnapshot:
    """Structurally rederive effective trust from represented snapshots."""

    if type(value) is not TrustSnapshot:
        raise ValidationError("value is not a validated trust snapshot")
    try:
        context = _validated_profile_context(
            value._profile if profile is None else profile
        )
    except Exception as exc:
        raise ValidationError("trust snapshot integrity is invalid") from exc
    return _require_validated_trust_snapshot_with_context(
        value, context, profile_supplied=profile is not None
    )


def _require_validated_trust_snapshot_with_context(
    value: object,
    context: object,
    *,
    profile_supplied: bool = True,
) -> TrustSnapshot:
    """Private trust rederivation against one already validated profile."""
    if type(value) is not TrustSnapshot:
        raise ValidationError("value is not a validated trust snapshot")
    try:
        effective_profile = _bind_profile_to_context(context, value._profile)
        _require_trust_structure(value)
        rederived = _calculate_effective_trust_with_context(
            context,
            value._standing,
            value._risk_result,
            value._soul,
            value._action,
            value.observed_at,
        )
        if canonical_json_bytes(_trust_projection(value)) != canonical_json_bytes(
            _trust_projection(rederived)
        ):
            raise ValidationError("trust snapshot does not match represented inputs")
    except Exception as exc:
        raise ValidationError("trust snapshot integrity is invalid") from exc
    if profile_supplied:
        if (
            value.profile_ref != effective_profile.ref
            or value.profile_digest != effective_profile.digest
        ):
            raise ValidationError("trust snapshot belongs to another profile")
    return value


def calculate_velocity(
    previous: TrustSnapshot,
    current: TrustSnapshot,
) -> TrustVelocity:
    """Derive optional dE/dt between two coherent snapshots of one subject."""

    if type(previous) is not TrustSnapshot:
        raise ValidationError("value is not a validated trust snapshot")
    try:
        _require_trust_structure(previous)
        context = _validated_profile_context(previous._profile)
    except (AttributeError, ValidationError) as exc:
        raise ValidationError("trust snapshot integrity is invalid") from exc
    return _calculate_velocity_with_context(context, previous, current)


def _calculate_velocity_with_context(
    context: _ValidatedProfileContext,
    previous: TrustSnapshot,
    current: TrustSnapshot,
) -> TrustVelocity:
    """Derive velocity under an existing call-local profile capability."""

    earlier = _require_validated_trust_snapshot_with_context(previous, context)
    later = _require_validated_trust_snapshot_with_context(current, context)
    if (
        earlier.profile_ref != later.profile_ref
        or earlier.profile_digest != later.profile_digest
    ):
        raise ValidationError("trust velocity snapshots use different profiles")
    if earlier.subject != later.subject:
        raise ValidationError("trust velocity snapshots use different subjects")
    if earlier.action_class != later.action_class:
        raise ValidationError("trust velocity snapshots use different action classes")
    elapsed_microseconds = _elapsed_microseconds(earlier.observed_at, later.observed_at)
    if elapsed_microseconds <= 0:
        raise ValidationError("trust velocity requires positive elapsed time")
    with localcontext(KTP_CONTEXT):
        elapsed_seconds = Decimal(elapsed_microseconds) / Decimal(1_000_000)
        velocity = (later.effective_trust - earlier.effective_trust) / elapsed_seconds

    result = object.__new__(TrustVelocity)
    for name, member in (
        ("subject", earlier.subject),
        ("profile_ref", earlier.profile_ref),
        ("profile_digest", earlier.profile_digest),
        ("action_class", earlier.action_class),
        ("value", velocity),
        ("previous_digest", earlier.digest),
        ("current_digest", later.digest),
        ("previous_at", earlier.observed_at),
        ("current_at", later.observed_at),
        ("elapsed_seconds", elapsed_seconds),
        ("_previous", earlier),
        ("_current", later),
    ):
        object.__setattr__(result, name, member)
    object.__setattr__(
        result,
        "digest",
        canonical_sha256(_velocity_projection(result, include_digest=False)),
    )
    return result


def require_validated_trust_velocity(value: object) -> TrustVelocity:
    """Structurally rederive dE/dt from both represented trust snapshots."""

    if type(value) is not TrustVelocity:
        raise ValidationError("value is not a validated trust velocity")
    try:
        _require_velocity_structure(value)
        context = _validated_profile_context(value._previous._profile)
    except Exception as exc:
        raise ValidationError("trust velocity integrity is invalid") from exc
    return _require_validated_trust_velocity_with_context(value, context)


def _require_validated_trust_velocity_with_context(
    value: object,
    context: _ValidatedProfileContext,
) -> TrustVelocity:
    """Rederive velocity under an existing call-local profile capability."""

    if type(value) is not TrustVelocity:
        raise ValidationError("value is not a validated trust velocity")
    try:
        _require_velocity_structure(value)
        rederived = _calculate_velocity_with_context(
            context, value._previous, value._current
        )
        if canonical_json_bytes(_velocity_projection(value)) != canonical_json_bytes(
            _velocity_projection(rederived)
        ):
            raise ValidationError("trust velocity does not match represented inputs")
    except Exception as exc:
        raise ValidationError("trust velocity integrity is invalid") from exc
    return value


def _trust_tier(value: Decimal) -> TrustTier:
    if (
        type(value) is not Decimal
        or not value.is_finite()
        or not Decimal(0) <= value <= Decimal(100)
    ):
        raise ValidationError("trust tier requires exact effective trust in [0, 100]")
    if value >= Decimal(85):
        return TrustTier.ADMIN
    if value >= Decimal(72):
        return TrustTier.OPERATOR
    if value >= Decimal(58):
        return TrustTier.ANALYST
    if value >= Decimal(22):
        return TrustTier.OBSERVER
    return TrustTier.HIBERNATION


def _effective_trust(base_trust: Decimal, risk: Decimal) -> Decimal:
    """Apply the published multiplicative equation to exact validated terms."""
    if (
        type(base_trust) is not Decimal
        or type(risk) is not Decimal
        or not base_trust.is_finite()
        or not risk.is_finite()
        or not Decimal(0) <= base_trust <= Decimal(100)
        or not Decimal(0) <= risk <= Decimal(1)
    ):
        raise ValidationError("effective-trust terms are outside their exact bounds")
    with localcontext(KTP_CONTEXT):
        return base_trust * (Decimal(1) - risk)


def _elapsed_microseconds(previous: datetime, current: datetime) -> int:
    earlier = utc_time(previous, name="previous trust time")
    later = utc_time(current, name="current trust time")
    difference = later - earlier
    return (
        difference.days * 86_400_000_000
        + difference.seconds * 1_000_000
        + difference.microseconds
    )


def _trust_projection(
    value: TrustSnapshot, *, include_digest: bool = True
) -> dict[str, object]:
    projection: dict[str, object] = {
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "subject": value.subject,
        "action_id": value.action_id,
        "action_digest": value.action_digest,
        "action_class": value.action_class,
        "standing_digest": value.standing_digest,
        "risk_digest": value.risk_digest,
        "soul_digest": value.soul_digest,
        "observed_at": value.observed_at,
        "base_trust": value.base_trust,
        "risk": value.risk,
        "effective_trust": value.effective_trust,
        "tier": value.tier,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _velocity_projection(
    value: TrustVelocity, *, include_digest: bool = True
) -> dict[str, object]:
    projection: dict[str, object] = {
        "subject": value.subject,
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "action_class": value.action_class,
        "value": value.value,
        "previous_digest": value.previous_digest,
        "current_digest": value.current_digest,
        "previous_at": value.previous_at,
        "current_at": value.current_at,
        "elapsed_seconds": value.elapsed_seconds,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _require_trust_structure(value: TrustSnapshot) -> None:
    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.subject) is not str
        or type(value.action_id) is not str
        or type(value.action_digest) is not str
        or type(value.action_class) is not str
        or type(value.standing_digest) is not str
        or type(value.risk_digest) is not str
        or type(value.soul_digest) is not str
        or type(value.observed_at) is not datetime
        or value.observed_at.tzinfo is not timezone.utc
        or type(value.base_trust) is not Decimal
        or type(value.risk) is not Decimal
        or type(value.effective_trust) is not Decimal
        or type(value.tier) is not TrustTier
        or type(value.digest) is not str
        or type(value._profile) is not DeploymentProfile
        or type(value._standing) is not StandingSnapshot
        or type(value._risk_result) is not RiskResult
        or type(value._soul) is not SoulAssessment
        or type(value._action) is not ValidatedActionDemand
    ):
        raise ValidationError("trust snapshot structure is invalid")
    validate_identifier(value.profile_ref.profile_id, name="trust profile ID")
    validate_identifier(value.subject, name="trust subject")
    validate_identifier(value.action_id, name="trust action ID")
    validate_identifier(value.action_class, name="trust action class")
    for name, digest in (
        ("trust profile digest", value.profile_digest),
        ("trust action digest", value.action_digest),
        ("trust standing digest", value.standing_digest),
        ("trust risk digest", value.risk_digest),
        ("trust Soul digest", value.soul_digest),
        ("trust snapshot digest", value.digest),
    ):
        _digest(digest, name=name)
    utc_time(value.observed_at, name="trust snapshot time")
    if (
        not value.base_trust.is_finite()
        or not Decimal(0) <= value.base_trust <= Decimal(100)
        or not value.risk.is_finite()
        or not Decimal(0) <= value.risk <= Decimal(1)
        or not value.effective_trust.is_finite()
        or not Decimal(0) <= value.effective_trust <= Decimal(100)
    ):
        raise ValidationError("trust snapshot numeric range is invalid")


def _require_velocity_structure(value: TrustVelocity) -> None:
    if (
        type(value.subject) is not str
        or type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.action_class) is not str
        or type(value.value) is not Decimal
        or type(value.previous_digest) is not str
        or type(value.current_digest) is not str
        or type(value.elapsed_seconds) is not Decimal
        or type(value.previous_at) is not datetime
        or value.previous_at.tzinfo is not timezone.utc
        or type(value.current_at) is not datetime
        or value.current_at.tzinfo is not timezone.utc
        or type(value.digest) is not str
        or type(value._previous) is not TrustSnapshot
        or type(value._current) is not TrustSnapshot
        or not value.value.is_finite()
        or not value.elapsed_seconds.is_finite()
        or value.elapsed_seconds <= 0
    ):
        raise ValidationError("trust velocity structure is invalid")
    validate_identifier(value.subject, name="trust velocity subject")
    validate_identifier(value.profile_ref.profile_id, name="trust velocity profile ID")
    validate_identifier(value.action_class, name="trust velocity action class")
    for name, digest in (
        ("trust velocity profile digest", value.profile_digest),
        ("trust velocity previous digest", value.previous_digest),
        ("trust velocity current digest", value.current_digest),
        ("trust velocity digest", value.digest),
    ):
        _digest(digest, name=name)
    utc_time(value.previous_at, name="previous trust time")
    utc_time(value.current_at, name="current trust time")


def _digest(value: str, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "calculate_effective_trust",
    "calculate_velocity",
    "require_validated_trust_snapshot",
    "require_validated_trust_velocity",
]
