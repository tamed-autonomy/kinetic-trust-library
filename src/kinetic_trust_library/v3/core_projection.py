"""Ordered native v3 Core calculation, deliberately without permission.

Authentication of standing, demand and environmental evidence happens at the
installed provider boundary. The final authorizing result also requires the
resolved R/E precision rule, proof acceptance, readiness, grants and envelope.
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


@dataclass(frozen=True, slots=True)
class NativeCoreContext:
    deployment_profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.operation_bytes) is not bytes
                or type(self.evaluated_at) is not int or not 0 <= self.evaluated_at <= 2**53 - 1
                or self.algorithm not in ("sha256", "sha384")):
            raise ValidationError("native Core context is invalid")
        _parse_jcs_object(self.deployment_profile_bytes)
        digest_demand_operation(_parse_jcs_object(self.operation_bytes), algorithm=self.algorithm)


@dataclass(frozen=True, slots=True, init=False)
class NativeCoreProjection:
    soul: SoulGate
    standing: NativeBaseTrust | None
    risk: NativeRiskAssessment | None
    capacity: NativeCapacityProjection | None
    classified_demand: NativeClassifiedDemand | None

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
    preflight = preflight_core(soul, factors=factors, weights=weights)
    capacity = project_native_capacity(preflight, standing=standing, demand=demand)
    return _projection(soul, standing, preflight.risk, capacity)


def _projection(
    soul: SoulGate,
    standing: NativeBaseTrust | None,
    risk: NativeRiskAssessment | None,
    capacity: NativeCapacityProjection | None,
    classified_demand: NativeClassifiedDemand | None = None,
) -> NativeCoreProjection:
    result = object.__new__(NativeCoreProjection)
    for name, value in (
        ("soul", soul), ("standing", standing),
        ("risk", risk), ("capacity", capacity),
        ("classified_demand", classified_demand),
    ):
        object.__setattr__(result, name, value)
    return result


def project_classified_native_core(
    soul: SoulGate, *, standing: NativeBaseTrust,
    factors: tuple[FactorEvidenceState, ...], context: NativeCoreContext,
    demand: NativeClassifiedDemand,
) -> NativeCoreProjection:
    """Compose installed, invocation-bound demand with native Core arithmetic.

    This remains a projection until standing authentication, final precision,
    proof acceptance and all remaining authorization prerequisites are composed.
    """
    if type(soul) is not SoulGate:
        raise ValidationError("native Soul gate is required")
    if soul.state is not SoulGateState.CLEAR:
        return _projection(soul, None, None, None)
    if type(demand) is not NativeClassifiedDemand:
        raise ValidationError("installed classified demand is required")
    if type(context) is not NativeCoreContext:
        raise ValidationError("installed native Core context is required")
    profile = _parse_jcs_object(context.deployment_profile_bytes)
    if (demand.deployment_digest != _digest(profile, context.algorithm)
            or demand.operation_digest != digest_demand_operation(_parse_jcs_object(context.operation_bytes), algorithm=context.algorithm)
            or demand.evaluated_at != context.evaluated_at):
        raise ValidationError("classified demand belongs to another Core context")
    try:
        weights = {name: factor["weight"] for name, factor in profile["risk_factors"].items()}
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValidationError("Core profile factor weights are unavailable") from exc
    projected = project_native_core(
        soul, standing=standing, factors=factors, weights=weights, demand=demand.demand,
    )
    return _projection(soul, projected.standing, projected.risk, projected.capacity, demand)


__all__ = ["NativeCoreContext", "NativeCoreProjection", "project_native_core", "project_classified_native_core"]
