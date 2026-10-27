"""Native v3 five-factor risk assessment with explicit missing evidence.

This composes provisional RFC PR #164 and #203 primitives. It does not
authorize an action or resolve the proposed R/E rounding discrepancy.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from kinetic_trust_library._decimal import DecimalLike
from kinetic_trust_library.errors import ValidationError

from .evidence_state import (
    FactorEvidenceState,
    UndefinedInputState,
    canonical_undefined_inputs,
)
from .risk import _FACTORS, calculate_five_factor_risk


@dataclass(frozen=True, slots=True, init=False)
class NativeRiskAssessment:
    factors: tuple[FactorEvidenceState, ...]
    measured_risk: Decimal | None
    decision_risk: Decimal
    undefined_inputs: tuple[UndefinedInputState, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("NativeRiskAssessment values are derived by assess_five_factor_risk()")

    @property
    def has_complete_measurement(self) -> bool:
        return self.measured_risk is not None


def assess_five_factor_risk(
    factors: tuple[FactorEvidenceState, ...],
    *,
    weights: dict[str, DecimalLike],
) -> NativeRiskAssessment:
    """Keep measured R separate from restrictive decision R when inputs fail."""
    if type(factors) is not tuple or len(factors) != len(_FACTORS):
        raise ValidationError("exactly five factor states are required")
    if any(type(factor) is not FactorEvidenceState for factor in factors):
        raise ValidationError("risk factor state is invalid")
    by_name = {factor.factor: factor for factor in factors}
    if len(by_name) != len(_FACTORS) or set(by_name) != set(_FACTORS):
        raise ValidationError("five distinct named Risk Factors are required")
    ordered = tuple(by_name[name] for name in _FACTORS)
    restrictive_inputs: dict[str, Decimal] = {}
    all_observable = True
    for state in ordered:
        if state.state == "observable":
            if state.value is None or state.decision_stress != state.value:
                raise ValidationError("observable factor has inconsistent stress")
            restrictive_inputs[state.factor] = state.value
        elif state.state == "unobservable":
            if state.value is not None or state.decision_stress != Decimal(1):
                raise ValidationError("unobservable factor has an invented measurement")
            restrictive_inputs[state.factor] = state.decision_stress
            all_observable = False
        else:
            raise ValidationError("risk factor state is invalid")
    restrictive_risk = calculate_five_factor_risk(restrictive_inputs, weights)
    undefined = canonical_undefined_inputs(tuple(
        entry for state in ordered for entry in state.undefined_inputs
    ))
    result = object.__new__(NativeRiskAssessment)
    for name, value in (
        ("factors", ordered),
        ("measured_risk", restrictive_risk if all_observable else None),
        ("decision_risk", restrictive_risk),
        ("undefined_inputs", undefined),
    ):
        object.__setattr__(result, name, value)
    return result


__all__ = ["NativeRiskAssessment", "assess_five_factor_risk"]
