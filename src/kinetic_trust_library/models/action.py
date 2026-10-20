"""Action, capability, and external moment-criticality declarations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library._owned_mapping import (
    _OwnedMapping,
    _require_owned_mapping_items,
)
from kinetic_trust_library.errors import ValidationError

from ._uri import validate_absolute_uri
from ._common import validate_constraint_magnitude, validate_identifier

if TYPE_CHECKING:
    from .profile import (
        ActionPolicy,
        DeploymentProfile,
        MomentCriticalityFactorProfile,
        ProfileRef,
    )


@dataclass(frozen=True, slots=True)
class MomentCriticalityDeclaration:
    value: DecimalLike
    supplier: str
    unit: str
    observed_at: datetime
    provenance_id: str


@dataclass(frozen=True, slots=True)
class MomentCriticality:
    value: Decimal
    supplier: str
    unit: str
    observed_at: datetime
    provenance_id: str


class NormativeGateDecision(StrEnum):
    CLEAR = "clear"
    VETO = "veto"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class NormativeGateToken:
    gate_id: str
    schema_uri: str
    decision: NormativeGateDecision
    authority: str
    observed_at: datetime
    provenance_id: str


@dataclass(frozen=True, slots=True)
class ActionDemandDeclaration:
    action_id: str
    subject: str
    action_class: str
    demand: DecimalLike
    demand_unit: str
    demand_source: str
    granted_constraints: Mapping[str, DecimalLike]
    requested_constraints: Mapping[str, DecimalLike]
    moment_criticality: MomentCriticalityDeclaration
    normative_gate_tokens: tuple[NormativeGateToken, ...] = ()


@dataclass(frozen=True, slots=True)
class CapabilityDeclaration:
    subject: str
    action_classes: tuple[str, ...]
    constraint_ceiling: Mapping[str, DecimalLike]
    not_before: datetime
    not_after: datetime
    provenance_id: str


@dataclass(frozen=True, slots=True, init=False)
class ValidatedCapability:
    profile_ref: ProfileRef
    profile_digest: str
    action_policies: Mapping[str, ActionPolicy]
    subject: str
    action_classes: tuple[str, ...]
    constraint_ceiling: Mapping[str, Decimal]
    not_before: datetime
    not_after: datetime
    provenance_id: str
    validation_cutoff: datetime
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("ValidatedCapability values are created by validate()")

    @classmethod
    def validate(
        cls,
        declaration: CapabilityDeclaration,
        *,
        profile: DeploymentProfile,
        cutoff: datetime,
    ) -> ValidatedCapability:
        from .profile import _validated_profile_context

        return _validate_capability_with_context(
            cls,
            declaration=declaration,
            context=_validated_profile_context(profile),
            cutoff=cutoff,
        )


@dataclass(frozen=True, slots=True)
class _ValidatedActionMembers:
    profile_ref: ProfileRef
    profile_digest: str
    profile_action_demand_unit: str
    action_policy: ActionPolicy
    moment_criticality_factor: MomentCriticalityFactorProfile
    misattestation_adjudicator: str
    action_id: str
    subject: str
    action_class: str
    demand: Decimal
    demand_unit: str
    demand_source: str
    capability: ValidatedCapability
    validation_cutoff: datetime
    granted_constraints: Mapping[str, Decimal]
    requested_constraints: Mapping[str, Decimal]
    moment_criticality: MomentCriticality
    normative_gate_tokens: tuple[NormativeGateToken, ...]


@dataclass(frozen=True, slots=True, init=False)
class ValidatedActionDemand:
    profile_ref: ProfileRef
    profile_digest: str
    profile_action_demand_unit: str
    action_policy: ActionPolicy
    moment_criticality_factor: MomentCriticalityFactorProfile
    misattestation_adjudicator: str
    action_id: str
    subject: str
    action_class: str
    demand: Decimal
    demand_unit: str
    demand_source: str
    capability: ValidatedCapability
    validation_cutoff: datetime
    granted_constraints: Mapping[str, Decimal]
    requested_constraints: Mapping[str, Decimal]
    moment_criticality: MomentCriticality
    normative_gate_tokens: tuple[NormativeGateToken, ...]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("ValidatedActionDemand values are created by validate()")

    @classmethod
    def validate(
        cls,
        declaration: ActionDemandDeclaration,
        *,
        profile: DeploymentProfile,
        capability: CapabilityDeclaration,
        cutoff: datetime,
    ) -> ValidatedActionDemand:
        from .profile import _validated_profile_context

        return _validate_action_with_context(
            cls,
            declaration=declaration,
            context=_validated_profile_context(profile),
            capability=capability,
            cutoff=cutoff,
        )


def _validate_action_with_context(
    cls: type[ValidatedActionDemand],
    *,
    declaration: ActionDemandDeclaration,
    context: object,
    capability: CapabilityDeclaration,
    cutoff: datetime,
) -> ValidatedActionDemand:
    from .profile import _profile_from_context

    effective_profile = _profile_from_context(context)
    if type(declaration) is not ActionDemandDeclaration:
        raise ValidationError("action demand must use the explicit declaration")
    action_class = validate_identifier(declaration.action_class, name="action class")
    try:
        policy = effective_profile.actions[action_class]
    except KeyError as exc:
        raise ValidationError(f"undeclared action class: {action_class}") from exc
    if type(capability) is CapabilityDeclaration and any(
        capability.constraint_ceiling is mapping
        for mapping in (
            declaration.granted_constraints,
            declaration.requested_constraints,
        )
    ):
        raise ValidationError("mutable aliases are not permitted")
    validated_capability = _validate_capability_with_context(
        ValidatedCapability,
        declaration=capability,
        context=context,
        cutoff=cutoff,
    )
    members = _validate_action_snapshot(
        profile_ref=effective_profile.ref,
        profile_digest=effective_profile.digest,
        profile_action_demand_unit=effective_profile.action_demand_unit,
        action_policy=policy,
        moment_criticality_factor=effective_profile.risk_factors.moment_criticality,
        misattestation_adjudicator=effective_profile.misattestation_adjudicator,
        declaration=declaration,
        capability=validated_capability,
        cutoff=cutoff,
    )
    return _build_validated_action(cls, members)


def require_validated_action(
    value: object, *, profile: DeploymentProfile | None = None
) -> ValidatedActionDemand:
    """Return a structurally valid action with exact snapshot bindings."""
    if profile is None:
        return _require_validated_action_structure(value)
    from .profile import _validated_profile_context

    return _require_validated_action_with_context(
        value, _validated_profile_context(profile)
    )


def _require_validated_action_with_context(
    value: object, context: object
) -> ValidatedActionDemand:
    """Private action validation against one already validated profile."""
    validated = _require_validated_action_structure(value)
    from .profile import _profile_from_context

    effective_profile = _profile_from_context(context)
    try:
        profile_policy = effective_profile.actions[validated.action_class]
    except KeyError as exc:
        raise ValidationError(
            "validated action demand belongs to another profile"
        ) from exc
    if (
        validated.profile_ref != effective_profile.ref
        or validated.profile_digest != effective_profile.digest
        or validated.profile_action_demand_unit != effective_profile.action_demand_unit
        or validated.demand_unit != effective_profile.action_demand_unit
        or validated.action_policy != profile_policy
        or validated.moment_criticality_factor
        != effective_profile.risk_factors.moment_criticality
        or validated.misattestation_adjudicator
        != effective_profile.misattestation_adjudicator
    ):
        raise ValidationError("validated action demand belongs to another profile")
    return validated


def _require_validated_action_structure(value: object) -> ValidatedActionDemand:
    if type(value) is not ValidatedActionDemand:
        raise ValidationError("value is not a validated action demand")
    try:
        declaration, capability = _action_inputs_from_value(value)
        members = _validate_action_snapshot(
            profile_ref=value.profile_ref,
            profile_digest=value.profile_digest,
            profile_action_demand_unit=value.profile_action_demand_unit,
            action_policy=value.action_policy,
            moment_criticality_factor=value.moment_criticality_factor,
            misattestation_adjudicator=value.misattestation_adjudicator,
            declaration=declaration,
            capability=capability,
            cutoff=value.validation_cutoff,
        )
        expected_digest = _action_digest(members)
    except (AttributeError, KeyError, TypeError, ValidationError) as exc:
        raise ValidationError("validated action demand integrity is invalid") from exc
    if value.digest != expected_digest:
        raise ValidationError("validated action demand integrity is invalid")
    return value


def _validate_action_snapshot(
    *,
    profile_ref: ProfileRef,
    profile_digest: str,
    profile_action_demand_unit: str,
    action_policy: ActionPolicy,
    moment_criticality_factor: MomentCriticalityFactorProfile,
    misattestation_adjudicator: str,
    declaration: ActionDemandDeclaration,
    capability: ValidatedCapability,
    cutoff: datetime,
) -> _ValidatedActionMembers:
    from .profile import (
        ActionPolicy,
        FactorName,
        ProfileRef,
        _validate_action_policy,
        MomentCriticalityFactorProfile,
    )

    if type(declaration) is not ActionDemandDeclaration:
        raise ValidationError("action demand must use the explicit declaration")
    require_validated_capability(capability)
    if (
        type(profile_ref) is not ProfileRef
        or type(profile_ref.profile_id) is not str
        or type(profile_ref.version) is not int
    ):
        raise ValidationError("action profile reference is invalid")
    normalized_ref = ProfileRef(profile_ref.profile_id, profile_ref.version)
    normalized_profile_digest = _validate_digest(
        profile_digest, name="action profile digest"
    )
    normalized_profile_unit = validate_identifier(
        profile_action_demand_unit, name="profile action demand unit"
    )
    validated_cutoff = _require_owned_utc_datetime(cutoff, name="action cutoff")

    action_id = validate_identifier(declaration.action_id, name="action ID")
    subject = _validate_subject(declaration.subject, name="action subject")
    action_class = validate_identifier(declaration.action_class, name="action class")
    demand_source = validate_identifier(declaration.demand_source, name="demand source")
    demand_unit = validate_identifier(
        declaration.demand_unit, name="action demand unit"
    )
    if demand_unit != normalized_profile_unit:
        raise ValidationError("action demand unit must exactly match the profile")

    seen_mappings: set[int] = set()
    if type(action_policy) is not ActionPolicy:
        raise ValidationError("action policy must use the explicit declaration")
    policy_units = _copy_mapping_entries(
        action_policy.constraint_units,
        name="action policy constraint units",
        seen_mappings=seen_mappings,
    )
    policy = _validate_action_policy(
        action_class,
        ActionPolicy(
            action_class=action_policy.action_class,
            demand_min=action_policy.demand_min,
            demand_max=action_policy.demand_max,
            constraint_units=dict(policy_units),
            normative_gates=action_policy.normative_gates,
        ),
        seen_mutable=set(),
    )
    if (
        type(moment_criticality_factor) is not MomentCriticalityFactorProfile
        or moment_criticality_factor.name is not FactorName.MOMENT_CRITICALITY
        or type(moment_criticality_factor.weight) is not Decimal
        or type(moment_criticality_factor.supplier) is not str
        or type(moment_criticality_factor.unit) is not str
    ):
        raise ValidationError("moment criticality factor is invalid")
    moment_weight = as_decimal(
        moment_criticality_factor.weight,
        name="moment criticality factor weight",
        minimum=0,
        maximum=1,
    )
    if moment_weight == 0:
        raise ValidationError("moment criticality factor weight must be positive")
    moment_factor = MomentCriticalityFactorProfile(
        name=moment_criticality_factor.name,
        weight=moment_weight,
        supplier=validate_identifier(
            moment_criticality_factor.supplier, name="moment supplier"
        ),
        unit=validate_identifier(moment_criticality_factor.unit, name="moment unit"),
    )
    adjudicator = validate_identifier(
        misattestation_adjudicator, name="misattestation adjudicator"
    )
    if subject == adjudicator:
        raise ValidationError(
            "misattestation adjudicator must be distinct from subject"
        )

    demand = as_decimal(
        declaration.demand,
        name="action demand",
        minimum=policy.demand_min,
        maximum=policy.demand_max,
    )
    if (
        capability.profile_ref != normalized_ref
        or capability.profile_digest != normalized_profile_digest
    ):
        raise ValidationError("capability belongs to another action profile")
    validated_capability = _validate_capability_for_action(
        capability,
        policy=policy,
        adjudicator=adjudicator,
        subject=subject,
        action_class=action_class,
        cutoff=validated_cutoff,
        seen_mappings=seen_mappings,
    )
    granted = _validate_constraints(
        declaration.granted_constraints,
        name="granted constraints",
        expected=frozenset(policy.constraint_units),
        seen_mappings=seen_mappings,
    )
    requested = _validate_constraints(
        declaration.requested_constraints,
        name="requested constraints",
        expected=frozenset(policy.constraint_units),
        seen_mappings=seen_mappings,
    )
    for constraint in policy.constraint_units:
        if granted[constraint] > validated_capability.constraint_ceiling[constraint]:
            raise ValidationError(
                "granted constraints must not exceed capability ceilings"
            )
        if requested[constraint] > granted[constraint]:
            raise ValidationError("requested constraints must only tighten the grant")

    moment = _validate_moment(
        declaration.moment_criticality,
        factor=moment_factor,
        cutoff=validated_cutoff,
    )
    tokens = _validate_gate_tokens(
        declaration.normative_gate_tokens,
        policies=policy.normative_gates,
        cutoff=validated_cutoff,
    )
    return _ValidatedActionMembers(
        profile_ref=normalized_ref,
        profile_digest=normalized_profile_digest,
        profile_action_demand_unit=normalized_profile_unit,
        action_policy=policy,
        moment_criticality_factor=moment_factor,
        misattestation_adjudicator=adjudicator,
        action_id=action_id,
        subject=subject,
        action_class=action_class,
        demand=demand,
        demand_unit=demand_unit,
        demand_source=demand_source,
        capability=validated_capability,
        validation_cutoff=validated_cutoff,
        granted_constraints=granted,
        requested_constraints=requested,
        moment_criticality=moment,
        normative_gate_tokens=tokens,
    )


def _build_validated_action(
    cls: type[ValidatedActionDemand], members: _ValidatedActionMembers
) -> ValidatedActionDemand:
    value = object.__new__(cls)
    for name in (
        "profile_ref",
        "profile_digest",
        "profile_action_demand_unit",
        "action_policy",
        "moment_criticality_factor",
        "misattestation_adjudicator",
        "action_id",
        "subject",
        "action_class",
        "demand",
        "demand_unit",
        "demand_source",
        "capability",
        "validation_cutoff",
        "granted_constraints",
        "requested_constraints",
        "moment_criticality",
        "normative_gate_tokens",
    ):
        object.__setattr__(value, name, getattr(members, name))
    object.__setattr__(value, "digest", _action_digest(members))
    return value


def _action_inputs_from_value(
    value: ValidatedActionDemand,
) -> tuple[ActionDemandDeclaration, ValidatedCapability]:
    from .profile import (
        ActionPolicy,
        FactorName,
        MomentCriticalityFactorProfile,
        ProfileRef,
    )

    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.profile_action_demand_unit) is not str
        or type(value.action_policy) is not ActionPolicy
        or type(value.action_policy.action_class) is not str
        or type(value.moment_criticality_factor) is not MomentCriticalityFactorProfile
        or type(value.moment_criticality_factor.name) is not FactorName
        or type(value.moment_criticality_factor.weight) is not Decimal
        or type(value.moment_criticality_factor.supplier) is not str
        or type(value.moment_criticality_factor.unit) is not str
        or type(value.action_policy.demand_min) is not Decimal
        or type(value.action_policy.demand_max) is not Decimal
        or type(value.misattestation_adjudicator) is not str
        or type(value.action_id) is not str
        or type(value.subject) is not str
        or type(value.action_class) is not str
        or type(value.demand) is not Decimal
        or type(value.demand_unit) is not str
        or type(value.demand_source) is not str
        or type(value.digest) is not str
        or type(value.action_policy.constraint_units) is not _OwnedMapping
        or type(value.action_policy.normative_gates) is not tuple
        or not isinstance(value.granted_constraints, MappingProxyType)
        or not isinstance(value.requested_constraints, MappingProxyType)
    ):
        raise ValidationError("validated action structure is invalid")
    if type(value.capability) is not ValidatedCapability:
        raise ValidationError("validated capability structure is invalid")
    _require_owned_utc_datetime(value.validation_cutoff, name="action cutoff")
    for name in ("not_before", "not_after", "validation_cutoff"):
        _require_owned_utc_datetime(
            getattr(value.capability, name),
            name=f"capability {name.replace('_', '-')}",
        )
    if (
        type(value.moment_criticality) is not MomentCriticality
        or type(value.normative_gate_tokens) is not tuple
        or any(
            type(token) is not NormativeGateToken
            for token in value.normative_gate_tokens
        )
    ):
        raise ValidationError("validated action snapshot structure is invalid")
    _require_validated_moment_criticality(
        value.moment_criticality,
        factor=value.moment_criticality_factor,
        cutoff=value.validation_cutoff,
    )
    for token in value.normative_gate_tokens:
        _require_owned_utc_datetime(
            token.observed_at, name="normative gate observed-at"
        )
    if any(
        type(constraint) is not str or type(unit) is not str
        for constraint, unit in _require_owned_mapping_items(
            value.action_policy.constraint_units,
            name="validated action policy constraint units",
        )
    ):
        raise ValidationError("validated action policy structure is invalid")
    if any(
        type(policy.gate_id) is not str
        or type(policy.schema_uri) is not str
        or type(policy.required) is not bool
        for policy in value.action_policy.normative_gates
    ):
        raise ValidationError("validated normative gate policy structure is invalid")
    for mapping in (
        value.granted_constraints,
        value.requested_constraints,
        value.capability.constraint_ceiling,
    ):
        if not isinstance(mapping, MappingProxyType) or any(
            type(key) is not str or type(number) is not Decimal
            for key, number in mapping.items()
        ):
            raise ValidationError("validated constraint structure is invalid")
    if type(value.capability.action_classes) is not tuple or any(
        type(token.gate_id) is not str
        or type(token.schema_uri) is not str
        or type(token.decision) is not NormativeGateDecision
        or type(token.authority) is not str
        or type(token.provenance_id) is not str
        for token in value.normative_gate_tokens
    ):
        raise ValidationError("validated action snapshot structure is invalid")

    declaration = ActionDemandDeclaration(
        action_id=value.action_id,
        subject=value.subject,
        action_class=value.action_class,
        demand=value.demand,
        demand_unit=value.demand_unit,
        demand_source=value.demand_source,
        granted_constraints=value.granted_constraints,
        requested_constraints=value.requested_constraints,
        moment_criticality=MomentCriticalityDeclaration(
            value=value.moment_criticality.value,
            supplier=value.moment_criticality.supplier,
            unit=value.moment_criticality.unit,
            observed_at=value.moment_criticality.observed_at,
            provenance_id=value.moment_criticality.provenance_id,
        ),
        normative_gate_tokens=value.normative_gate_tokens,
    )
    return declaration, value.capability


def _action_digest(value: _ValidatedActionMembers | ValidatedActionDemand) -> str:
    from kinetic_trust_library._canonical import canonical_sha256

    return canonical_sha256(_action_digest_input(value))


def _action_digest_input(
    value: _ValidatedActionMembers | ValidatedActionDemand,
) -> Mapping[str, object]:
    return {
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "profile_action_demand_unit": value.profile_action_demand_unit,
        "action_policy": value.action_policy,
        "moment_criticality_factor": value.moment_criticality_factor,
        "misattestation_adjudicator": value.misattestation_adjudicator,
        "action_id": value.action_id,
        "subject": value.subject,
        "action_class": value.action_class,
        "demand": value.demand,
        "demand_unit": value.demand_unit,
        "demand_source": value.demand_source,
        "capability": value.capability,
        "validation_cutoff": value.validation_cutoff,
        "granted_constraints": value.granted_constraints,
        "requested_constraints": value.requested_constraints,
        "moment_criticality": value.moment_criticality,
        "normative_gate_tokens": value.normative_gate_tokens,
    }


def _build_validated_capability(
    cls: type[ValidatedCapability],
    *,
    declaration: CapabilityDeclaration,
    profile: DeploymentProfile,
    cutoff: datetime,
) -> ValidatedCapability:
    from .profile import _validate_action_policy

    if type(declaration) is not CapabilityDeclaration:
        raise ValidationError("capability must use the explicit declaration")
    validated_cutoff = _require_owned_utc_datetime(cutoff, name="capability cutoff")
    not_before = _require_owned_utc_datetime(
        declaration.not_before, name="capability not-before"
    )
    not_after = _require_owned_utc_datetime(
        declaration.not_after, name="capability not-after"
    )
    capability_subject = _validate_subject(
        declaration.subject, name="capability subject"
    )
    if capability_subject == profile.misattestation_adjudicator:
        raise ValidationError(
            "misattestation adjudicator must be distinct from capability subject"
        )
    action_classes = _validate_identifier_tuple(
        declaration.action_classes, name="capability action classes"
    )
    policies: dict[str, ActionPolicy] = {}
    for action_class in action_classes:
        try:
            policy = profile.actions[action_class]
        except KeyError as exc:
            raise ValidationError(
                f"capability declares undeclared action class: {action_class}"
            ) from exc
        policies[action_class] = _validate_action_policy(
            action_class, policy, seen_mutable=set()
        )
    if not_before >= not_after:
        raise ValidationError("capability validity interval must be positive")
    if validated_cutoff < not_before or validated_cutoff > not_after:
        raise ValidationError("capability is not current at the action cutoff")
    provenance_id = validate_identifier(
        declaration.provenance_id, name="capability provenance ID"
    )
    constraint_names = _shared_constraint_names(
        policies,
        message="capability action classes must share one constraint envelope",
    )
    ceilings = _validate_constraints(
        declaration.constraint_ceiling,
        name="capability constraint ceiling",
        expected=constraint_names,
        seen_mappings=set(),
    )
    value = object.__new__(cls)
    for name, member in (
        ("profile_ref", profile.ref),
        ("profile_digest", profile.digest),
        ("action_policies", MappingProxyType(policies)),
        ("subject", capability_subject),
        ("action_classes", action_classes),
        ("constraint_ceiling", ceilings),
        ("not_before", not_before),
        ("not_after", not_after),
        ("provenance_id", provenance_id),
        ("validation_cutoff", validated_cutoff),
    ):
        object.__setattr__(value, name, member)
    object.__setattr__(value, "digest", _capability_digest(value))
    return value


def _validate_capability_with_context(
    cls: type[ValidatedCapability],
    *,
    declaration: CapabilityDeclaration,
    context: object,
    cutoff: datetime,
) -> ValidatedCapability:
    from .profile import _profile_from_context

    return _build_validated_capability(
        cls,
        declaration=declaration,
        profile=_profile_from_context(context),
        cutoff=cutoff,
    )


def require_validated_capability(
    value: object, *, profile: DeploymentProfile | None = None
) -> ValidatedCapability:
    """Return a structurally valid, immutable capability snapshot."""
    if profile is None:
        return _require_validated_capability_structure(value)[0]
    from .profile import _validated_profile_context

    return _require_validated_capability_with_context(
        value, _validated_profile_context(profile)
    )


def _require_validated_capability_with_context(
    value: object, context: object
) -> ValidatedCapability:
    """Private capability validation against one already validated profile."""
    validated, action_classes = _require_validated_capability_structure(value)
    from .profile import _profile_from_context

    effective_profile = _profile_from_context(context)
    if (
        validated.profile_ref != effective_profile.ref
        or validated.profile_digest != effective_profile.digest
    ):
        raise ValidationError("validated capability belongs to another profile")
    for action_class in action_classes:
        try:
            profile_policy = effective_profile.actions[action_class]
        except KeyError as exc:
            raise ValidationError(
                "validated capability belongs to another profile"
            ) from exc
        if validated.action_policies[action_class] != profile_policy:
            raise ValidationError("validated capability belongs to another profile")
    if validated.subject == effective_profile.misattestation_adjudicator:
        raise ValidationError(
            "misattestation adjudicator must be distinct from capability subject"
        )
    return validated


def _require_validated_capability_structure(
    value: object,
) -> tuple[ValidatedCapability, tuple[str, ...]]:
    from .profile import ProfileRef, _validate_action_policy

    if type(value) is not ValidatedCapability:
        raise ValidationError("value is not a validated capability")
    try:
        if (
            type(value.profile_ref) is not ProfileRef
            or type(value.profile_ref.profile_id) is not str
            or type(value.profile_ref.version) is not int
            or type(value.profile_digest) is not str
            or not isinstance(value.action_policies, MappingProxyType)
            or type(value.action_classes) is not tuple
            or not isinstance(value.constraint_ceiling, MappingProxyType)
            or type(value.subject) is not str
            or type(value.provenance_id) is not str
            or type(value.digest) is not str
        ):
            raise ValidationError("validated capability structure is invalid")
        not_before = _require_owned_utc_datetime(
            value.not_before, name="capability not-before"
        )
        not_after = _require_owned_utc_datetime(
            value.not_after, name="capability not-after"
        )
        cutoff = _require_owned_utc_datetime(
            value.validation_cutoff, name="capability cutoff"
        )
        ProfileRef(value.profile_ref.profile_id, value.profile_ref.version)
        _validate_digest(value.profile_digest, name="capability profile digest")
        action_classes = _validate_identifier_tuple(
            value.action_classes, name="capability action classes"
        )
        policy_entries = _copy_mapping_entries(
            value.action_policies,
            name="capability action policies",
            seen_mappings=set(),
        )
        if tuple(action_class for action_class, _ in policy_entries) != action_classes:
            raise ValidationError("capability action policies are incomplete")
        policies: dict[str, ActionPolicy] = {}
        for action_class, policy in policy_entries:
            policies[action_class] = _validate_action_policy(
                action_class, policy, seen_mutable=set()
            )
        constraint_names = _shared_constraint_names(
            policies, message="capability constraint envelopes are incoherent"
        )
        ceilings = _validate_constraints(
            value.constraint_ceiling,
            name="capability constraint ceiling",
            expected=constraint_names,
            seen_mappings=set(),
        )
        _validate_subject(value.subject, name="capability subject")
        if not_before >= not_after or cutoff < not_before or cutoff > not_after:
            raise ValidationError("capability validity is invalid")
        validate_identifier(value.provenance_id, name="capability provenance ID")
        if (
            ceilings != value.constraint_ceiling
            or _capability_digest(value) != value.digest
        ):
            raise ValidationError("capability integrity is invalid")
    except (AttributeError, KeyError, RuntimeError, TypeError, ValidationError) as exc:
        raise ValidationError("validated capability integrity is invalid") from exc

    return value, action_classes


def _capability_digest(value: ValidatedCapability) -> str:
    from kinetic_trust_library._canonical import canonical_sha256

    return canonical_sha256(
        {
            "profile_ref": value.profile_ref,
            "profile_digest": value.profile_digest,
            "action_policies": value.action_policies,
            "subject": value.subject,
            "action_classes": value.action_classes,
            "constraint_ceiling": value.constraint_ceiling,
            "not_before": value.not_before,
            "not_after": value.not_after,
            "provenance_id": value.provenance_id,
            "validation_cutoff": value.validation_cutoff,
        }
    )


def _shared_constraint_names(
    policies: Mapping[str, ActionPolicy], *, message: str
) -> frozenset[str]:
    """Validate one complete name-to-unit envelope and return its names."""
    envelopes = {
        frozenset(policy.constraint_units.items()) for policy in policies.values()
    }
    if len(envelopes) != 1:
        raise ValidationError(message)
    return frozenset(name for name, _ in next(iter(envelopes)))


def _validate_capability_for_action(
    value: ValidatedCapability,
    *,
    policy: ActionPolicy,
    adjudicator: str,
    subject: str,
    action_class: str,
    cutoff: datetime,
    seen_mappings: set[int],
) -> ValidatedCapability:
    require_validated_capability(value)
    if value.subject != subject:
        raise ValidationError("capability subject must exactly match action subject")
    if subject == adjudicator:
        raise ValidationError(
            "misattestation adjudicator must be distinct from subject"
        )
    if action_class not in value.action_classes:
        raise ValidationError("action class is not declared by capability")
    if value.validation_cutoff != cutoff:
        raise ValidationError("capability cutoff must exactly match action cutoff")
    if value.action_policies[action_class] != policy:
        raise ValidationError(
            "capability action policy must exactly match action policy"
        )
    copied = _validate_constraints(
        value.constraint_ceiling,
        name="capability constraint ceiling",
        expected=frozenset(policy.constraint_units),
        seen_mappings=seen_mappings,
    )
    if copied != value.constraint_ceiling:
        raise ValidationError("capability constraint ceiling is invalid")
    return value


def _validate_constraints(
    value: Mapping[str, DecimalLike],
    *,
    name: str,
    expected: frozenset[str],
    seen_mappings: set[int],
) -> Mapping[str, Decimal]:
    entries = _copy_mapping_entries(value, name=name, seen_mappings=seen_mappings)
    constraints: dict[str, Decimal] = {}
    for key, raw_value in entries:
        constraint = validate_constraint_magnitude(key, name="constraint name")
        if constraint in constraints:
            raise ValidationError(f"duplicate constraint: {constraint}")
        constraints[constraint] = as_decimal(
            raw_value, name=f"{name} {constraint}", minimum=0
        )
    if frozenset(constraints) != expected:
        raise ValidationError(f"{name} must exactly match declared constraints")
    return MappingProxyType(constraints)


def _validate_moment(
    value: MomentCriticalityDeclaration,
    *,
    factor: MomentCriticalityFactorProfile,
    cutoff: datetime,
) -> MomentCriticality:
    if type(value) is not MomentCriticalityDeclaration:
        raise ValidationError("moment criticality must use the explicit declaration")
    observed_at = _require_owned_utc_datetime(
        value.observed_at, name="moment observed-at"
    )
    supplier = validate_identifier(value.supplier, name="moment supplier")
    unit = validate_identifier(value.unit, name="moment unit")
    if supplier != factor.supplier:
        raise ValidationError("moment supplier must exactly match the profile")
    if unit != factor.unit:
        raise ValidationError("moment unit must exactly match the profile")
    if observed_at > cutoff:
        raise ValidationError("moment criticality must not be observed after cutoff")
    return MomentCriticality(
        value=as_decimal(value.value, name="moment criticality", minimum=0, maximum=1),
        supplier=supplier,
        unit=unit,
        observed_at=observed_at,
        provenance_id=validate_identifier(
            value.provenance_id, name="moment provenance ID"
        ),
    )


def _require_validated_moment_criticality(
    value: object,
    *,
    factor: MomentCriticalityFactorProfile,
    cutoff: datetime,
) -> MomentCriticality:
    """Validate one represented moment before any caller-controlled hook can run."""
    from .profile import FactorName, MomentCriticalityFactorProfile

    if type(value) is not MomentCriticality:
        raise ValidationError("represented moment criticality is invalid")
    if (
        type(value.value) is not Decimal
        or type(value.supplier) is not str
        or type(value.unit) is not str
        or type(value.provenance_id) is not str
        or type(factor) is not MomentCriticalityFactorProfile
        or factor.name is not FactorName.MOMENT_CRITICALITY
        or type(factor.weight) is not Decimal
        or type(factor.supplier) is not str
        or type(factor.unit) is not str
    ):
        raise ValidationError("represented moment criticality is invalid")
    _require_owned_utc_datetime(value.observed_at, name="moment observed-at")
    _require_owned_utc_datetime(cutoff, name="action cutoff")

    normalized = _validate_moment(
        MomentCriticalityDeclaration(
            value=value.value,
            supplier=value.supplier,
            unit=value.unit,
            observed_at=value.observed_at,
            provenance_id=value.provenance_id,
        ),
        factor=MomentCriticalityFactorProfile(
            name=FactorName.MOMENT_CRITICALITY,
            weight=as_decimal(
                factor.weight,
                name="moment criticality factor weight",
                minimum=0,
                maximum=1,
            ),
            supplier=validate_identifier(factor.supplier, name="moment supplier"),
            unit=validate_identifier(factor.unit, name="moment unit"),
        ),
        cutoff=cutoff,
    )
    if value != normalized:
        raise ValidationError("represented moment criticality is not canonical")
    return value


def _validate_gate_tokens(
    value: tuple[NormativeGateToken, ...],
    *,
    policies: tuple[object, ...],
    cutoff: datetime,
) -> tuple[NormativeGateToken, ...]:
    from .profile import NormativeGatePolicy

    if type(value) is not tuple:
        raise ValidationError("normative gate tokens must be a tuple")
    if len(value) > len(policies):
        raise ValidationError("normative gate token inventory exceeds policy inventory")
    declared: dict[str, NormativeGatePolicy] = {}
    for policy in policies:
        if type(policy) is not NormativeGatePolicy:
            raise ValidationError("normative gate policy structure is invalid")
        declared[policy.gate_id] = policy
    supplied: dict[str, NormativeGateToken] = {}
    gate_ids: set[str] = set()
    for token in value:
        if type(token) is not NormativeGateToken:
            raise ValidationError(
                "normative gate token must use the explicit declaration"
            )
        observed_at = _require_owned_utc_datetime(
            token.observed_at, name="normative gate observed-at"
        )
        gate_id = validate_identifier(token.gate_id, name="normative gate ID")
        if gate_id in gate_ids:
            raise ValidationError(f"duplicate normative gate ID: {gate_id}")
        gate_ids.add(gate_id)
        try:
            policy = declared[gate_id]
        except KeyError as exc:
            raise ValidationError(f"undeclared normative gate ID: {gate_id}") from exc
        schema_uri = validate_absolute_uri(
            token.schema_uri, name="normative gate schema URI"
        )
        if schema_uri != policy.schema_uri:
            raise ValidationError("normative gate schema URI must exactly match policy")
        if type(token.decision) is not NormativeGateDecision:
            raise ValidationError(
                "normative gate decision must use NormativeGateDecision"
            )
        if observed_at != cutoff:
            raise ValidationError("normative gate token must be current at cutoff")
        supplied[gate_id] = NormativeGateToken(
            gate_id=gate_id,
            schema_uri=schema_uri,
            decision=token.decision,
            authority=validate_absolute_uri(
                token.authority, name="normative gate authority URI"
            ),
            observed_at=observed_at,
            provenance_id=validate_identifier(
                token.provenance_id, name="normative gate provenance ID"
            ),
        )
    return tuple(
        supplied[policy.gate_id] for policy in policies if policy.gate_id in supplied
    )


def _require_owned_utc_datetime(value: object, *, name: str) -> datetime:
    """Require one exact, library-owned UTC datetime without invoking tzinfo."""
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise ValidationError(f"{name} must be an exact UTC datetime")
    return value


def _validate_identifier_tuple(value: tuple[str, ...], *, name: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise ValidationError(f"{name} must be a non-empty tuple")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        validated = validate_identifier(item, name="capability action class")
        if validated in seen:
            raise ValidationError(f"{name} must be unique")
        seen.add(validated)
        result.append(validated)
    return tuple(result)


def _copy_mapping_entries(
    value: Mapping[object, object],
    *,
    name: str,
    seen_mappings: set[int],
) -> tuple[tuple[object, object], ...]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{name} must be a mapping")
    identity = id(value)
    if identity in seen_mappings:
        raise ValidationError("mutable aliases are not permitted")
    seen_mappings.add(identity)
    entries: list[tuple[object, object]] = []
    keys: set[str] = set()
    try:
        iterator = iter(value)
    except Exception as exc:
        raise ValidationError(f"{name} changed during validation") from exc
    while True:
        try:
            raw_key = next(iterator)
        except StopIteration:
            break
        except Exception as exc:
            raise ValidationError(f"{name} changed during validation") from exc
        if type(raw_key) is not str:
            raise ValidationError(f"{name} keys must use exact str")
        if raw_key in keys:
            raise ValidationError(f"{name} contains duplicate keys")
        keys.add(raw_key)
        try:
            raw_value = value[raw_key]
        except Exception as exc:
            raise ValidationError(f"{name} changed during validation") from exc
        entries.append((raw_key, raw_value))
    return tuple(entries)


def _validate_subject(value: object, *, name: str) -> str:
    return validate_absolute_uri(validate_identifier(value, name=name), name=name)


def _validate_digest(value: str, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "ActionDemandDeclaration",
    "CapabilityDeclaration",
    "MomentCriticality",
    "MomentCriticalityDeclaration",
    "NormativeGateDecision",
    "NormativeGateToken",
    "ValidatedActionDemand",
    "ValidatedCapability",
    "require_validated_action",
    "require_validated_capability",
]
