"""Exact, non-authorizing capacity projection for the native v3 Core path.

The inputs must eventually come from authenticated standing and classified
demand. This module deliberately makes no permission decision while the RFC's
R/E intermediate precision and surrounding proof contract are unresolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from ._exact import finite_decimal

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError

from .core import NativeCorePreflight
from .base_trust import NativeBaseTrust




@dataclass(frozen=True, slots=True, init=False)
class NativeCapacityProjection:
    base_trust: Decimal
    demand: Decimal
    measured_effective_trust: Decimal | None
    decision_effective_trust: Decimal
    relation: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("NativeCapacityProjection values are derived by project_native_capacity()")

    @property
    def capacity_known(self) -> bool:
        return self.measured_effective_trust is not None


def project_native_capacity(
    preflight: NativeCorePreflight,
    *,
    standing: NativeBaseTrust,
    demand: DecimalLike,
) -> NativeCapacityProjection | None:
    """Project exact E and A/E relation after clear Soul; never authorize.

    A missing factor retains unknown measured E. Its separate restrictive risk
    reading yields a conservative decision E without inventing a measurement.
    The exact arithmetic is an implementation diagnostic pending the RFC's
    intermediate R/E precision decision.
    """
    if type(preflight) is not NativeCorePreflight:
        raise ValidationError("native Core preflight is required")
    if preflight.risk is None:
        return None
    if type(standing) is not NativeBaseTrust:
        raise ValidationError("native derived base trust is required")
    base = standing.base_trust
    action_demand = as_decimal(demand, name="autonomy demand", minimum=0, maximum=100)
    risk = preflight.risk
    decision_e = finite_decimal(Fraction(base) * (1 - Fraction(risk.decision_risk)))
    measured_e = (None if risk.measured_risk is None else
                  finite_decimal(Fraction(base) * (1 - Fraction(risk.measured_risk))))
    relation = (
        "below" if action_demand < decision_e
        else "at" if action_demand == decision_e
        else "above"
    )
    result = object.__new__(NativeCapacityProjection)
    for name, value in (
        ("base_trust", base),
        ("demand", action_demand),
        ("measured_effective_trust", measured_e),
        ("decision_effective_trust", decision_e),
        ("relation", relation),
    ):
        object.__setattr__(result, name, value)
    return result


__all__ = ["NativeCapacityProjection", "project_native_capacity"]
