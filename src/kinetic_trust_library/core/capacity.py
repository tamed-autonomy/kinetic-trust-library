"""Exact private KTP-Core capacity derivation and focused revalidation."""

from __future__ import annotations

import re
from decimal import Decimal

from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import utc_time, validate_identifier
from kinetic_trust_library.models.action import (
    ValidatedActionDemand,
    _require_validated_action_with_context,
)
from kinetic_trust_library.models.capacity import CapacityRelation, CoreCapacityResult
from kinetic_trust_library.models.profile import ProfileRef, _profile_from_context
from kinetic_trust_library.models.trust import TrustSnapshot

from .trust import _require_validated_trust_snapshot_with_context


def _capacity_relation(demand: Decimal, effective_trust: Decimal) -> CapacityRelation:
    if type(demand) is not Decimal or type(effective_trust) is not Decimal:
        raise ValidationError("capacity terms must be exact Decimals")
    if not demand.is_finite() or not effective_trust.is_finite():
        raise ValidationError("capacity terms must be finite")
    if not Decimal(0) <= demand <= Decimal(100):
        raise ValidationError("autonomy demand must be in [0, 100]")
    if not Decimal(0) <= effective_trust <= Decimal(100):
        raise ValidationError("effective trust must be in [0, 100]")
    if demand < effective_trust:
        return CapacityRelation.BELOW_CAPACITY
    if demand == effective_trust:
        return CapacityRelation.AT_CAPACITY
    return CapacityRelation.ABOVE_CAPACITY


def _core_capacity_digest(value: CoreCapacityResult) -> str:
    return canonical_sha256(
        {
            "operation_id": value.operation_id,
            "profile_ref": value.profile_ref,
            "profile_digest": value.profile_digest,
            "action_id": value.action_id,
            "action_digest": value.action_digest,
            "trust_digest": value.trust_digest,
            "cutoff": value.cutoff,
            "autonomy_demand": value.autonomy_demand,
            "effective_trust": value.effective_trust,
            "relation": value.relation,
        }
    )


def _derive_core_capacity_with_context(
    context: object,
    action: ValidatedActionDemand,
    trust: TrustSnapshot,
    *,
    operation_id: str,
) -> CoreCapacityResult:
    effective_profile = _profile_from_context(context)
    effective_operation = validate_identifier(operation_id, name="operation ID")
    effective_action = _require_validated_action_with_context(action, context)
    effective_trust = _require_validated_trust_snapshot_with_context(trust, context)
    if (
        effective_trust.action_id != effective_action.action_id
        or effective_trust.action_digest != effective_action.digest
        or effective_trust.observed_at != effective_action.validation_cutoff
        or effective_trust._risk_result.evidence_operation_id != effective_operation
    ):
        raise ValidationError("trust snapshot belongs to another capacity evaluation")

    relation = _capacity_relation(
        effective_action.demand, effective_trust.effective_trust
    )
    result = object.__new__(CoreCapacityResult)
    for name, member in (
        ("operation_id", effective_operation),
        ("profile_ref", effective_profile.ref),
        ("profile_digest", effective_profile.digest),
        ("action_id", effective_action.action_id),
        ("action_digest", effective_action.digest),
        ("trust_digest", effective_trust.digest),
        ("cutoff", effective_action.validation_cutoff),
        ("autonomy_demand", effective_action.demand),
        ("effective_trust", effective_trust.effective_trust),
        ("relation", relation),
    ):
        object.__setattr__(result, name, member)
    object.__setattr__(result, "digest", _core_capacity_digest(result))
    return result


def require_validated_core_capacity_result(value: object) -> CoreCapacityResult:
    """Recompute the exact relation and digest after structural preflight."""
    try:
        if type(value) is not CoreCapacityResult:
            raise ValidationError("value is not a Core capacity result")
        relation = _capacity_relation(value.autonomy_demand, value.effective_trust)
        if (
            type(value.profile_ref) is not ProfileRef
            or type(value.profile_ref.version) is not int
            or value.profile_ref.version < 1
            or type(value.relation) is not CapacityRelation
            or value.relation is not relation
        ):
            raise ValidationError("Core capacity structure or relation is invalid")
        validate_identifier(value.operation_id, name="capacity operation ID")
        validate_identifier(value.profile_ref.profile_id, name="capacity profile ID")
        validate_identifier(value.action_id, name="capacity action ID")
        utc_time(value.cutoff, name="capacity cutoff")
        for digest in (
            value.profile_digest,
            value.action_digest,
            value.trust_digest,
            value.digest,
        ):
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValidationError("Core capacity digest is invalid")
        if value.digest != _core_capacity_digest(value):
            raise ValidationError(
                "Core capacity digest does not match represented fields"
            )
    except Exception as exc:
        raise ValidationError("Core capacity integrity is invalid") from exc
    return value


def _require_validated_core_capacity_result_with_context(
    value: object,
    context: object,
    *,
    action: ValidatedActionDemand,
    trust: TrustSnapshot,
    operation_id: str,
) -> CoreCapacityResult:
    """Bind a structurally valid result to one validated evaluation context."""
    try:
        result = require_validated_core_capacity_result(value)
        effective_profile = _profile_from_context(context)
        effective_operation = validate_identifier(operation_id, name="operation ID")
        effective_action = _require_validated_action_with_context(action, context)
        effective_trust = _require_validated_trust_snapshot_with_context(trust, context)
        if (
            effective_trust.action_id != effective_action.action_id
            or effective_trust.action_digest != effective_action.digest
            or effective_trust.observed_at != effective_action.validation_cutoff
            or effective_trust._risk_result.evidence_operation_id != effective_operation
        ):
            raise ValidationError("trust snapshot belongs to another capacity evaluation")
        if (
            result.profile_ref != effective_profile.ref
            or result.profile_digest != effective_profile.digest
            or result.operation_id != effective_operation
            or result.action_id != effective_action.action_id
            or result.action_digest != effective_action.digest
            or result.trust_digest != effective_trust.digest
            or result.cutoff != effective_action.validation_cutoff
            or result.autonomy_demand != effective_action.demand
            or result.effective_trust != effective_trust.effective_trust
            or result.relation is not _capacity_relation(
                effective_action.demand, effective_trust.effective_trust
            )
        ):
            raise ValidationError("Core capacity belongs to another evaluation")
    except Exception as exc:
        raise ValidationError("Core capacity integrity is invalid") from exc
    return result


__all__ = ["require_validated_core_capacity_result"]
