"""Native envelope calculation under the installed threshold declaration.

Supervision is a floor for later authorization; stable never establishes grants,
proof acceptance, readiness, replay protection or permission to execute.
"""
from dataclasses import dataclass
from decimal import Context, Decimal, localcontext
from fractions import Fraction
from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError
from .core_capacity import NativeCapacityProjection


@dataclass(frozen=True, slots=True)
class NativeEnvelopeThresholds:
    veto: Decimal
    assisted_floor: Decimal
    metacognitive_floor: Decimal
    allow: Decimal

    def __init__(self, veto: DecimalLike, assisted_floor: DecimalLike,
                 metacognitive_floor: DecimalLike, allow: DecimalLike):
        values = tuple(as_decimal(v, name="envelope threshold", minimum=0)
                       for v in (veto, assisted_floor, metacognitive_floor, allow))
        if not values[0] < values[1] < values[2] < values[3]:
            raise ValidationError("envelope thresholds must be strictly ordered")
        for name, value in zip(("veto", "assisted_floor", "metacognitive_floor", "allow"), values):
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True, init=False)
class NativeEnvelopeProjection:
    margin: Decimal | None
    supervision: str
    capacity_known: bool

    def __init__(self, *args, **kwargs):
        raise TypeError("NativeEnvelopeProjection is derived by project_native_envelope()")


def project_native_envelope(capacity: NativeCapacityProjection, *,
                            thresholds: NativeEnvelopeThresholds | None = None) -> NativeEnvelopeProjection:
    if type(capacity) is not NativeCapacityProjection:
        raise ValidationError("native capacity projection is required")
    if thresholds is not None and type(thresholds) is not NativeEnvelopeThresholds:
        raise ValidationError("native envelope threshold declaration is invalid")
    margin = None
    if capacity.decision_effective_trust == 0 or capacity.relation == "above":
        supervision = "silent_veto"
    else:
        # Compare ratios by cross multiplication so rounded display margins
        # cannot move an outcome across a declared threshold.
        exact_margin = 1 - Fraction(capacity.demand) / Fraction(capacity.decision_effective_trust)
        vetoed = exact_margin <= Fraction(0 if thresholds is None else thresholds.veto)
        stable = thresholds is None or exact_margin >= Fraction(thresholds.allow)
        metacognitive = thresholds is not None and exact_margin >= Fraction(thresholds.metacognitive_floor)
        assisted = thresholds is not None and exact_margin >= Fraction(thresholds.assisted_floor)
        with localcontext(Context(prec=34)):
            margin = Decimal(1) - capacity.demand / capacity.decision_effective_trust
        if vetoed:
            supervision = "silent_veto"
        elif stable:
            supervision = "stable"
        elif metacognitive:
            supervision = "metacognitive"
        elif assisted:
            supervision = "assisted"
        else:
            supervision = "regulated"
    if not capacity.capacity_known and supervision in ("stable", "metacognitive"):
        supervision = "assisted"
    result = object.__new__(NativeEnvelopeProjection)
    for name, value in (("margin", margin), ("supervision", supervision),
                        ("capacity_known", capacity.capacity_known)):
        object.__setattr__(result, name, value)
    return result


__all__ = ["NativeEnvelopeThresholds", "NativeEnvelopeProjection", "project_native_envelope"]
