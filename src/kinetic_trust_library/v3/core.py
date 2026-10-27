"""Native v3 Core preflight stage order under provisional RFC proposals.

This stops at Soul and risk. It never returns authorization, capacity or an
effective trust score while those contracts remain under RFC review.
"""

from __future__ import annotations

from dataclasses import dataclass

from kinetic_trust_library._decimal import DecimalLike
from kinetic_trust_library.errors import ValidationError

from .core_risk import NativeRiskAssessment, assess_five_factor_risk
from .evidence_state import FactorEvidenceState
from .soul import SoulGate, SoulGateState


@dataclass(frozen=True, slots=True, init=False)
class NativeCorePreflight:
    soul: SoulGate
    risk: NativeRiskAssessment | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("NativeCorePreflight values are derived by preflight_core()")


def preflight_core(
    soul: SoulGate,
    *,
    factors: tuple[FactorEvidenceState, ...],
    weights: dict[str, DecimalLike],
) -> NativeCorePreflight:
    """Evaluate Soul first; never compute later risk after veto or unknownness."""
    if type(soul) is not SoulGate:
        raise ValidationError("native v3 Soul gate is required")
    risk = (
        assess_five_factor_risk(factors, weights=weights)
        if soul.state is SoulGateState.CLEAR else None
    )
    result = object.__new__(NativeCorePreflight)
    object.__setattr__(result, "soul", soul)
    object.__setattr__(result, "risk", risk)
    return result


__all__ = ["NativeCorePreflight", "preflight_core"]
