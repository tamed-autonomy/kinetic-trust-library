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


@dataclass(frozen=True, slots=True, init=False)
class NativeCoreProjection:
    soul: SoulGate
    standing: NativeBaseTrust | None
    risk: NativeRiskAssessment | None
    capacity: NativeCapacityProjection | None

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
) -> NativeCoreProjection:
    result = object.__new__(NativeCoreProjection)
    for name, value in (
        ("soul", soul), ("standing", standing),
        ("risk", risk), ("capacity", capacity),
    ):
        object.__setattr__(result, name, value)
    return result


__all__ = ["NativeCoreProjection", "project_native_core"]
