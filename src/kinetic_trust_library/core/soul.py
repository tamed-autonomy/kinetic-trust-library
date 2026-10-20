"""Deterministic, fail-closed assessment of the independent Soul veto."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from unicodedata import category, normalize

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._uri import validate_absolute_uri
from kinetic_trust_library.models.action import (
    ValidatedActionDemand,
    _require_validated_action_with_context,
)
from kinetic_trust_library.models._common import utc_time, validate_identifier
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    ProfileRef,
    _bind_profile_to_context,
    _profile_from_context,
    _validated_profile_context,
)
from kinetic_trust_library.models.soul import (
    SoulAssessment,
    SoulAssessmentState,
    SoulConstraint,
    SoulConstraintType,
    SoulFrameworkOutcome,
    SoulResponseDeclaration,
    SoulUndeterminedReason,
)


_SOUL_REASON_CODE = "SOVEREIGNTY_CONSTRAINT"
_MAX_CONSTRAINT_ID_LENGTH = 256


def assess_soul(
    profile: DeploymentProfile,
    declarations: Iterable[SoulResponseDeclaration],
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> SoulAssessment:
    """Assess one current response per configured framework, failing closed."""
    return _assess_soul_with_context(
        _validated_profile_context(profile), declarations, action, cutoff
    )


def _assess_soul_with_context(
    context: object,
    declarations: Iterable[SoulResponseDeclaration],
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> SoulAssessment:
    effective_profile = _profile_from_context(context)
    effective_cutoff = utc_time(cutoff, name="Soul cutoff")
    effective_action = _require_validated_action_with_context(action, context)
    profile_ref = _profile_ref(effective_profile.ref)
    profile_digest = _digest(
        effective_profile.digest, name="Soul assessment profile digest"
    )
    action_id = _identifier(
        effective_action.action_id, name="Soul assessment action ID"
    )
    action_digest = _digest(
        effective_action.digest, name="Soul assessment action digest"
    )
    if effective_action.validation_cutoff != effective_cutoff:
        raise ValidationError("Soul cutoff must exactly match the action cutoff")

    frameworks = _framework_inventory(effective_profile.soul_frameworks)
    supplied = _bounded_responses(declarations, maximum=len(frameworks))
    configured = frozenset(frameworks)
    by_framework: dict[str, SoulResponseDeclaration] = {}
    for declaration in supplied:
        normalized = _validate_response(
            declaration,
            profile=effective_profile,
            action=effective_action,
            cutoff=effective_cutoff,
        )
        if normalized.framework_id not in configured:
            raise ValidationError(
                f"Soul response names an unconfigured framework: "
                f"{normalized.framework_id}"
            )
        if normalized.framework_id in by_framework:
            raise ValidationError(
                f"duplicate Soul response framework: {normalized.framework_id}"
            )
        by_framework[normalized.framework_id] = normalized

    outcomes: list[SoulFrameworkOutcome] = []
    constraints: list[SoulConstraint] = []
    undetermined_frameworks: list[str] = []
    ordered_declarations: list[SoulResponseDeclaration] = []
    for framework_id in frameworks:
        declaration = by_framework.get(framework_id)
        if declaration is None:
            outcome = _build_outcome(
                framework_id=framework_id,
                state=SoulAssessmentState.UNDETERMINED,
                observed_at=None,
                provenance_id=None,
                constraint=None,
                undetermined_reason=SoulUndeterminedReason.MISSING,
            )
            undetermined_frameworks.append(framework_id)
        else:
            ordered_declarations.append(declaration)
            outcome = _outcome_from_response(declaration)
            if outcome.constraint is not None:
                constraints.append(outcome.constraint)
            if outcome.state is SoulAssessmentState.UNDETERMINED:
                undetermined_frameworks.append(framework_id)
        outcomes.append(outcome)

    if constraints:
        state = SoulAssessmentState.VETO
    elif undetermined_frameworks:
        state = SoulAssessmentState.UNDETERMINED
    else:
        state = SoulAssessmentState.CLEAR
    vetoed = state is not SoulAssessmentState.CLEAR

    result = object.__new__(SoulAssessment)
    for name, value in (
        ("profile_ref", profile_ref),
        ("profile_digest", profile_digest),
        ("action_id", action_id),
        ("action_digest", action_digest),
        ("cutoff", effective_cutoff),
        ("state", state),
        ("vetoed", vetoed),
        ("reason_code", _SOUL_REASON_CODE if vetoed else None),
        ("outcomes", tuple(outcomes)),
        ("constraints", tuple(constraints)),
        ("undetermined_frameworks", tuple(undetermined_frameworks)),
        ("_profile", effective_profile),
        ("_action", effective_action),
        ("_declarations", tuple(ordered_declarations)),
    ):
        object.__setattr__(result, name, value)
    object.__setattr__(
        result,
        "digest",
        canonical_sha256(_assessment_projection(result, include_digest=False)),
    )
    return result


def require_validated_soul_assessment(
    value: object,
    *,
    profile: DeploymentProfile | None = None,
    action: ValidatedActionDemand | None = None,
) -> SoulAssessment:
    """Structurally rederive a represented Soul assessment and its digest."""
    if type(value) is not SoulAssessment:
        raise ValidationError("value is not a validated Soul assessment")
    try:
        _require_assessment_structure(value)
        context = _validated_profile_context(
            value._profile if profile is None else profile
        )
    except Exception as exc:
        raise ValidationError("Soul assessment integrity is invalid") from exc
    return _require_validated_soul_assessment_with_context(
        value,
        context,
        profile_supplied=profile is not None,
        action=action,
    )


def _require_validated_soul_assessment_with_context(
    value: object,
    context: object,
    *,
    profile_supplied: bool = True,
    action: ValidatedActionDemand | None = None,
) -> SoulAssessment:
    """Private Soul rederivation against one already validated profile."""
    if type(value) is not SoulAssessment:
        raise ValidationError("value is not a validated Soul assessment")
    try:
        _require_assessment_structure(value)
    except Exception as exc:
        raise ValidationError("Soul assessment integrity is invalid") from exc
    try:
        effective_profile = _bind_profile_to_context(context, value._profile)
    except Exception as exc:
        if profile_supplied:
            raise ValidationError("Soul assessment belongs to another profile") from exc
        raise ValidationError("Soul assessment integrity is invalid") from exc
    try:
        rederived = _assess_soul_with_context(
            context,
            value._declarations,
            value._action,
            value.cutoff,
        )
        if canonical_json_bytes(_assessment_projection(value)) != (
            canonical_json_bytes(_assessment_projection(rederived))
        ):
            raise ValidationError(
                "Soul assessment does not match represented responses"
            )
    except Exception as exc:
        raise ValidationError("Soul assessment integrity is invalid") from exc

    if profile_supplied:
        if (
            value.profile_ref != effective_profile.ref
            or value.profile_digest != effective_profile.digest
        ):
            raise ValidationError("Soul assessment belongs to another profile")
    if action is not None:
        effective_action = _require_validated_action_with_context(action, context)
        if (
            value.action_id != effective_action.action_id
            or value.action_digest != effective_action.digest
            or value.cutoff != effective_action.validation_cutoff
        ):
            raise ValidationError("Soul assessment belongs to another action")
    return value


def _framework_inventory(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise ValidationError("Soul framework inventory must be a non-empty tuple")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        framework_id = _identifier(item, name="Soul framework ID")
        if framework_id in seen:
            raise ValidationError(f"duplicate Soul framework ID: {framework_id}")
        seen.add(framework_id)
        result.append(framework_id)
    return tuple(result)


def _bounded_responses(
    values: Iterable[SoulResponseDeclaration], *, maximum: int
) -> tuple[object, ...]:
    try:
        iterator = iter(values)
    except Exception as exc:
        raise ValidationError("Soul responses must be an iterable") from exc
    result: list[object] = []
    for index in range(maximum + 1):
        try:
            item = next(iterator)
        except StopIteration:
            return tuple(result)
        except Exception as exc:
            raise ValidationError("Soul response iterable failed") from exc
        if index == maximum:
            raise ValidationError(
                "Soul response iterable supplied more responses than configured "
                "frameworks"
            )
        result.append(item)
    raise AssertionError("bounded Soul response iteration did not terminate")


def _validate_response(
    value: object,
    *,
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> SoulResponseDeclaration:
    if type(value) is not SoulResponseDeclaration:
        raise ValidationError("Soul response must use the explicit declaration")
    try:
        value = SoulResponseDeclaration(
            framework_id=value.framework_id,
            profile_ref=value.profile_ref,
            profile_digest=value.profile_digest,
            action_id=value.action_id,
            action_digest=value.action_digest,
            query_cutoff=value.query_cutoff,
            state=value.state,
            observed_at=value.observed_at,
            provenance_id=value.provenance_id,
            constraint_type=value.constraint_type,
            constraint_id=value.constraint_id,
            authority=value.authority,
            undetermined_reason=value.undetermined_reason,
        )
    except AttributeError as exc:
        raise ValidationError("Soul response declaration structure is invalid") from exc
    framework_id = _identifier(value.framework_id, name="Soul framework ID")
    profile_ref = _profile_ref(value.profile_ref)
    profile_digest = _digest(value.profile_digest, name="Soul profile digest")
    action_id = _identifier(value.action_id, name="Soul action ID")
    action_digest = _digest(value.action_digest, name="Soul action digest")
    query_cutoff = utc_time(value.query_cutoff, name="Soul query cutoff")
    observed_at = utc_time(value.observed_at, name="Soul response observed-at")
    provenance_id = _identifier(value.provenance_id, name="Soul response provenance ID")
    if profile_ref != profile.ref or profile_digest != profile.digest:
        raise ValidationError("Soul response belongs to another profile")
    if action_id != action.action_id or action_digest != action.digest:
        raise ValidationError("Soul response belongs to another action")
    if query_cutoff != cutoff:
        raise ValidationError("Soul query cutoff must exactly match the current cutoff")
    if observed_at != cutoff:
        raise ValidationError("Soul response must be current at the exact cutoff")
    if type(value.state) is not str or value.state not in {
        "clear",
        "veto",
        "undetermined",
    }:
        raise ValidationError("Soul response state is invalid")

    constraint_type: SoulConstraintType | None = None
    constraint_id: str | None = None
    authority: str | None = None
    undetermined_reason: SoulUndeterminedReason | None = None
    if value.state == "veto":
        if type(value.constraint_type) is not SoulConstraintType:
            raise ValidationError("Soul veto requires a typed constraint type")
        constraint_type = value.constraint_type
        constraint_id = _constraint_id(value.constraint_id)
        authority = _authority_uri(value.authority)
        if value.undetermined_reason is not None:
            raise ValidationError("Soul veto must not carry an undetermined reason")
    elif value.state == "undetermined":
        if any(
            member is not None
            for member in (
                value.constraint_type,
                value.constraint_id,
                value.authority,
            )
        ):
            raise ValidationError(
                "undetermined Soul response must not fabricate constraint authority"
            )
        if (
            type(value.undetermined_reason) is not SoulUndeterminedReason
            or value.undetermined_reason is SoulUndeterminedReason.MISSING
        ):
            raise ValidationError(
                "undetermined Soul response requires a provider failure reason"
            )
        undetermined_reason = value.undetermined_reason
    else:
        if any(
            member is not None
            for member in (
                value.constraint_type,
                value.constraint_id,
                value.authority,
            )
        ):
            raise ValidationError("clear Soul response must not carry a constraint")
        if value.undetermined_reason is not None:
            raise ValidationError("clear Soul response must not be undetermined")

    return SoulResponseDeclaration(
        framework_id=framework_id,
        profile_ref=profile_ref,
        profile_digest=profile_digest,
        action_id=action_id,
        action_digest=action_digest,
        query_cutoff=query_cutoff,
        state=value.state,
        observed_at=observed_at,
        provenance_id=provenance_id,
        constraint_type=constraint_type,
        constraint_id=constraint_id,
        authority=authority,
        undetermined_reason=undetermined_reason,
    )


def _outcome_from_response(value: SoulResponseDeclaration) -> SoulFrameworkOutcome:
    constraint: SoulConstraint | None = None
    undetermined_reason: SoulUndeterminedReason | None = None
    if value.state == "veto":
        constraint = _build_constraint(value)
        state = SoulAssessmentState.VETO
    elif value.state == "undetermined":
        state = SoulAssessmentState.UNDETERMINED
        undetermined_reason = value.undetermined_reason
    else:
        state = SoulAssessmentState.CLEAR
    return _build_outcome(
        framework_id=value.framework_id,
        state=state,
        observed_at=value.observed_at,
        provenance_id=value.provenance_id,
        constraint=constraint,
        undetermined_reason=undetermined_reason,
    )


def _build_constraint(value: SoulResponseDeclaration) -> SoulConstraint:
    result = object.__new__(SoulConstraint)
    for name in (
        "framework_id",
        "constraint_type",
        "constraint_id",
        "authority",
        "provenance_id",
    ):
        object.__setattr__(result, name, getattr(value, name))
    return result


def _build_outcome(
    *,
    framework_id: str,
    state: SoulAssessmentState,
    observed_at: datetime | None,
    provenance_id: str | None,
    constraint: SoulConstraint | None,
    undetermined_reason: SoulUndeterminedReason | None,
) -> SoulFrameworkOutcome:
    result = object.__new__(SoulFrameworkOutcome)
    for name, value in (
        ("framework_id", framework_id),
        ("state", state),
        ("observed_at", observed_at),
        ("provenance_id", provenance_id),
        ("constraint", constraint),
        ("undetermined_reason", undetermined_reason),
    ):
        object.__setattr__(result, name, value)
    return result


def _require_assessment_structure(value: SoulAssessment) -> None:
    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_digest) is not str
        or type(value.action_id) is not str
        or type(value.action_digest) is not str
        or type(value.cutoff) is not datetime
        or type(value.state) is not SoulAssessmentState
        or type(value.vetoed) is not bool
        or (value.reason_code is not None and type(value.reason_code) is not str)
        or type(value.outcomes) is not tuple
        or type(value.constraints) is not tuple
        or type(value.undetermined_frameworks) is not tuple
        or type(value.digest) is not str
        or type(value._profile) is not DeploymentProfile
        or type(value._action) is not ValidatedActionDemand
        or type(value._declarations) is not tuple
    ):
        raise ValidationError("Soul assessment structure is invalid")
    _profile_ref(value.profile_ref)
    _digest(value.profile_digest, name="Soul assessment profile digest")
    _identifier(value.action_id, name="Soul assessment action ID")
    _digest(value.action_digest, name="Soul assessment action digest")
    utc_time(value.cutoff, name="Soul assessment cutoff")
    _digest(value.digest, name="Soul assessment digest")
    for outcome in value.outcomes:
        _require_outcome_structure(outcome)
    for constraint in value.constraints:
        _require_constraint_structure(constraint)
    for framework_id in value.undetermined_frameworks:
        _identifier(framework_id, name="undetermined Soul framework ID")
    for declaration in value._declarations:
        _require_response_structure(declaration)


def _require_response_structure(value: object) -> None:
    if (
        type(value) is not SoulResponseDeclaration
        or type(value.framework_id) is not str
        or type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.action_id) is not str
        or type(value.action_digest) is not str
        or type(value.state) is not str
        or type(value.provenance_id) is not str
        or (
            value.constraint_type is not None
            and type(value.constraint_type) is not SoulConstraintType
        )
        or (value.constraint_id is not None and type(value.constraint_id) is not str)
        or (value.authority is not None and type(value.authority) is not str)
        or (
            value.undetermined_reason is not None
            and type(value.undetermined_reason) is not SoulUndeterminedReason
        )
    ):
        raise ValidationError("represented Soul response structure is invalid")
    utc_time(value.query_cutoff, name="represented Soul query cutoff")
    utc_time(value.observed_at, name="represented Soul observed-at")


def _require_outcome_structure(value: object) -> None:
    if (
        type(value) is not SoulFrameworkOutcome
        or type(value.framework_id) is not str
        or type(value.state) is not SoulAssessmentState
        or (value.observed_at is not None and type(value.observed_at) is not datetime)
        or (value.provenance_id is not None and type(value.provenance_id) is not str)
        or (
            value.constraint is not None
            and type(value.constraint) is not SoulConstraint
        )
        or (
            value.undetermined_reason is not None
            and type(value.undetermined_reason) is not SoulUndeterminedReason
        )
    ):
        raise ValidationError("Soul framework outcome structure is invalid")
    _identifier(value.framework_id, name="Soul outcome framework ID")
    if value.observed_at is not None:
        utc_time(value.observed_at, name="Soul outcome observed-at")
    if value.provenance_id is not None:
        _identifier(value.provenance_id, name="Soul outcome provenance ID")
    if value.constraint is not None:
        _require_constraint_structure(value.constraint)
    if value.state is SoulAssessmentState.CLEAR:
        if value.constraint is not None or value.undetermined_reason is not None:
            raise ValidationError("clear Soul outcome structure is invalid")
    elif value.state is SoulAssessmentState.VETO:
        if value.constraint is None or value.undetermined_reason is not None:
            raise ValidationError("veto Soul outcome structure is invalid")
    elif value.constraint is not None or value.undetermined_reason is None:
        raise ValidationError("undetermined Soul outcome structure is invalid")


def _require_constraint_structure(value: object) -> None:
    if (
        type(value) is not SoulConstraint
        or type(value.framework_id) is not str
        or type(value.constraint_type) is not SoulConstraintType
        or type(value.constraint_id) is not str
        or type(value.authority) is not str
        or type(value.provenance_id) is not str
    ):
        raise ValidationError("Soul constraint structure is invalid")
    _identifier(value.framework_id, name="Soul constraint framework ID")
    _constraint_id(value.constraint_id)
    _authority_uri(value.authority)
    _identifier(value.provenance_id, name="Soul constraint provenance ID")


def _assessment_projection(
    value: SoulAssessment, *, include_digest: bool = True
) -> Mapping[str, object]:
    projection: dict[str, object] = {
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "action_id": value.action_id,
        "action_digest": value.action_digest,
        "cutoff": value.cutoff,
        "state": value.state,
        "vetoed": value.vetoed,
        "reason_code": value.reason_code,
        "outcomes": value.outcomes,
        "constraints": value.constraints,
        "undetermined_frameworks": value.undetermined_frameworks,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _profile_ref(value: object) -> ProfileRef:
    if type(value) is not ProfileRef:
        raise ValidationError("Soul profile reference is invalid")
    try:
        profile_id = value.profile_id
        version = value.version
    except AttributeError as exc:
        raise ValidationError("Soul profile reference structure is invalid") from exc
    profile_id = _identifier(profile_id, name="Soul profile ID")
    if type(version) is not int or version <= 0:
        raise ValidationError("Soul profile version must be a positive integer")
    return ProfileRef(profile_id, version)


def _identifier(value: object, *, name: str) -> str:
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    return validate_identifier(value, name=name)


def _digest(value: object, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _constraint_id(value: object) -> str:
    if type(value) is not str:
        raise ValidationError("Soul veto requires a constraint ID")
    _unicode_text(value, name="Soul constraint ID", maximum=_MAX_CONSTRAINT_ID_LENGTH)
    if any(
        character.isspace() or category(character).startswith("C")
        for character in value
    ):
        raise ValidationError("Soul constraint ID contains forbidden characters")
    return value


def _authority_uri(value: object) -> str:
    return validate_absolute_uri(value, name="Soul authority URI")


def _unicode_text(value: str, *, name: str, maximum: int) -> None:
    if not value or len(value) > maximum:
        raise ValidationError(f"{name} must contain 1 through {maximum} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
    if normalize("NFC", value) != value:
        raise ValidationError(f"{name} must use NFC Unicode")


__all__ = ["assess_soul", "require_validated_soul_assessment"]
