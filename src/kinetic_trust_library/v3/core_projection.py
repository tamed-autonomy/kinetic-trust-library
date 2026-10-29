"""Ordered native v3 Core calculation, deliberately without permission.

Authentication of standing, demand and environmental evidence happens at the
installed provider boundary. The final authorizing result also requires proof
acceptance, readiness, grants and envelope.
"""

from __future__ import annotations

from dataclasses import dataclass

from kinetic_trust_library._decimal import DecimalLike
from kinetic_trust_library.errors import ValidationError

from .base_trust import NativeBaseTrust
from .core import preflight_core
from .core_capacity import NativeCapacityProjection, project_native_capacity
from .core_risk import NativeRiskAssessment
from .evidence_state import (
    FactorEvidenceState, UndefinedInputState, canonical_undefined_inputs,
)
from .soul import SoulGate, SoulGateState
from .demand_classification import NativeClassifiedDemand
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import digest_demand_operation
from .installed_standing import NativeStandingAssessment
from .installed_soul import NativeSoulAssessment
from .installed_environment import NativeEnvironmentAssessment
from .enclosure import EnclosureInputs, NativeEnclosureAssessment, _profile as _enclosure_profile
from .boundary import BoundaryAssessment


@dataclass(frozen=True, slots=True)
class NativeCoreContext:
    deployment_profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    algorithm: str
    enclosure_profile_bytes: bytes | None = None

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.operation_bytes) is not bytes
                or type(self.evaluated_at) is not int or not 0 <= self.evaluated_at <= 2**53 - 1
                or self.algorithm not in ("sha256", "sha384")):
            raise ValidationError("native Core context is invalid")
        _parse_jcs_object(self.deployment_profile_bytes)
        digest_demand_operation(_parse_jcs_object(self.operation_bytes), algorithm=self.algorithm)
        if self.enclosure_profile_bytes is not None:
            if type(self.enclosure_profile_bytes) is not bytes:
                raise ValidationError("enclosure profile must be immutable installed bytes")
            _enclosure_profile(self.enclosure_profile_bytes)


@dataclass(frozen=True, slots=True, init=False)
class NativeCoreProjection:
    soul: SoulGate
    standing: NativeBaseTrust | None
    risk: NativeRiskAssessment | None
    capacity: NativeCapacityProjection | None
    classified_demand: NativeClassifiedDemand | None
    standing_assessment: NativeStandingAssessment | None
    soul_assessment: NativeSoulAssessment | None
    environment_assessment: NativeEnvironmentAssessment | None
    enclosure_assessment: NativeEnclosureAssessment | None
    boundary_assessment: BoundaryAssessment | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("NativeCoreProjection values are derived by project_native_core()")

    @property
    def undefined_inputs(self) -> tuple[UndefinedInputState, ...]:
        risk_inputs = () if self.risk is None else self.risk.undefined_inputs
        return canonical_undefined_inputs(self.soul.undefined_inputs + risk_inputs)


def project_native_core(
    soul: SoulGate,
    *,
    standing: NativeBaseTrust,
    factors: tuple[FactorEvidenceState, ...],
    weights: dict[str, DecimalLike],
    demand: DecimalLike,
    enclosure: EnclosureInputs | None = None,
) -> NativeCoreProjection:
    """Stop at Soul, validate standing, then calculate risk and capacity.

    A relation at or below capacity is not permission to execute. This function
    only records the arithmetic reached by the ordered Core stages.
    """
    if type(soul) is not SoulGate:
        raise ValidationError("native Soul gate is required")
    if soul.state is not SoulGateState.CLEAR:
        return _projection(soul, None, None, None)
    if type(standing) is not NativeBaseTrust:
        raise ValidationError("native standing is required before risk")
    preflight = preflight_core(soul, factors=factors, weights=weights, enclosure=enclosure)
    capacity = project_native_capacity(preflight, standing=standing, demand=demand)
    return _projection(soul, standing, preflight.risk, capacity)


def _projection(
    soul: SoulGate,
    standing: NativeBaseTrust | None,
    risk: NativeRiskAssessment | None,
    capacity: NativeCapacityProjection | None,
    classified_demand: NativeClassifiedDemand | None = None,
    standing_assessment: NativeStandingAssessment | None = None,
    soul_assessment: NativeSoulAssessment | None = None,
    environment_assessment: NativeEnvironmentAssessment | None = None,
    enclosure_assessment: NativeEnclosureAssessment | None = None,
    boundary_assessment: BoundaryAssessment | None = None,
) -> NativeCoreProjection:
    result = object.__new__(NativeCoreProjection)
    for name, value in (
        ("soul", soul), ("standing", standing),
        ("risk", risk), ("capacity", capacity),
        ("classified_demand", classified_demand),
        ("standing_assessment", standing_assessment),
        ("soul_assessment", soul_assessment),
        ("environment_assessment", environment_assessment),
        ("enclosure_assessment", enclosure_assessment),
        ("boundary_assessment", boundary_assessment),
    ):
        object.__setattr__(result, name, value)
    return result


def project_classified_native_core(
    soul: NativeSoulAssessment, *, standing: NativeStandingAssessment,
    environment: NativeEnvironmentAssessment, context: NativeCoreContext,
    demand: NativeClassifiedDemand,
    enclosure: NativeEnclosureAssessment | None = None,
    boundary: BoundaryAssessment | None = None,
) -> NativeCoreProjection:
    """Compose installed, invocation-bound demand with native Core arithmetic.

    This remains a projection until proof acceptance and all remaining
    authorization prerequisites are composed.
    """
    if type(context) is not NativeCoreContext:
        raise ValidationError("installed native Core context is required")
    profile = _parse_jcs_object(context.deployment_profile_bytes)
    deployment_digest = _digest(profile, context.algorithm)
    operation_digest = digest_demand_operation(_parse_jcs_object(context.operation_bytes), algorithm=context.algorithm)
    if "boundary" in profile:
        if (type(boundary) is not BoundaryAssessment or boundary.deployment_digest!=deployment_digest
                or boundary.operation_digest!=operation_digest or boundary.evaluated_at!=context.evaluated_at
                or boundary.expires_at<=context.evaluated_at):
            raise ValidationError("declared boundary requires current bound assessment")
        if not boundary.allowed:raise ValidationError("native Core boundary denied: "+boundary.reason)
        if context.enclosure_profile_bytes is not None and _parse_jcs_object(context.enclosure_profile_bytes)["depth"]>0:
            if boundary.enclosing_deployment_profile_bytes is None:
                raise ValidationError("nested boundary requires enclosing resources")
    elif boundary is not None:raise ValidationError("boundary evidence requires a declared boundary")
    if type(soul) is not NativeSoulAssessment:
        raise ValidationError("installed Soul assessment is required")
    if (soul.deployment_digest != deployment_digest or soul.operation_digest != operation_digest
            or soul.evaluated_at != context.evaluated_at
            or soul.required_frameworks != tuple(profile.get("soul_veto", {}).get("frameworks", ()))):
        raise ValidationError("Soul assessment belongs to another Core context")
    if soul.gate.state is not SoulGateState.CLEAR:
        return _projection(soul.gate, None, None, None, soul_assessment=soul,boundary_assessment=boundary)
    if type(demand) is not NativeClassifiedDemand:
        raise ValidationError("installed classified demand is required")
    if type(standing) is not NativeStandingAssessment:
        raise ValidationError("installed standing assessment is required")
    if (demand.deployment_digest != _digest(profile, context.algorithm)
            or demand.operation_digest != digest_demand_operation(_parse_jcs_object(context.operation_bytes), algorithm=context.algorithm)
            or demand.evaluated_at != context.evaluated_at):
        raise ValidationError("classified demand belongs to another Core context")
    if (standing.deployment_digest != demand.deployment_digest
            or standing.operation_digest != demand.operation_digest
            or standing.evaluated_at != context.evaluated_at):
        raise ValidationError("standing belongs to another Core context")
    if type(environment) is not NativeEnvironmentAssessment:
        raise ValidationError("installed environment assessment is required")
    if (environment.deployment_digest != demand.deployment_digest
            or environment.operation_digest != demand.operation_digest
            or environment.evaluated_at != context.evaluated_at):
        raise ValidationError("environment belongs to another Core context")
    if context.enclosure_profile_bytes is not None:
        if (type(enclosure) is not NativeEnclosureAssessment or enclosure.profile_bytes != context.enclosure_profile_bytes
                or enclosure.deployment_digest != deployment_digest or enclosure.operation_digest != operation_digest
                or enclosure.evaluated_at != context.evaluated_at or enclosure.expires_at <= context.evaluated_at):
            raise ValidationError("selected enclosure profile requires current bound source evidence")
    elif enclosure is not None:
        raise ValidationError("enclosure evidence requires an installed Core profile")
    if boundary is not None and enclosure is not None:
        body=_parse_jcs_object(enclosure.authenticated_body_bytes)
        if (boundary.zone_id!=body["zone_id"] or boundary.enclosure_zone!=body["enclosure_zone"]
                or boundary.topology_epoch!=body["topology_epoch"]):
            raise ValidationError("boundary differs from current enclosure topology")
    try:
        weights = {name: factor["weight"] for name, factor in profile["risk_factors"].items()}
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValidationError("Core profile factor weights are unavailable") from exc
    projected = project_native_core(
        soul.gate, standing=standing.base, factors=environment.factors, weights=weights, demand=demand.demand,
        enclosure=None if enclosure is None else enclosure.inputs,
    )
    return _projection(soul.gate, projected.standing, projected.risk, projected.capacity, demand, standing, soul, environment, enclosure,boundary)


__all__ = ["NativeCoreContext", "NativeCoreProjection", "project_native_core", "project_classified_native_core"]
