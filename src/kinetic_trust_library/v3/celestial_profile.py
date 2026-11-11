"""Provisional pure calculations from KTP-CELESTIAL and RFC PR #222.

These projections neither issue Extended Trust Proofs nor grant transit
authority. The RFC has not reconciled extended validity with Core's ten-second
Trust Proof lifetime (proposed L22 in RFC PR #209).
"""

from __future__ import annotations

from decimal import Decimal, localcontext

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError


_VALIDITY_CAPS = {0: 60, 1: 1800, 2: 86400, 3: 604800, 4: 2592000}


def projected_validity_seconds(
    *,
    latency_class: int,
    light_time_seconds: DecimalLike,
    departure_tier_value: DecimalLike,
    mission_duration_seconds: DecimalLike | None = None,
) -> Decimal:
    """Apply the RFC's illustrative formula and class cap, without issuing a proof.

    The caller supplies the class explicitly: the RFC's class ranges leave
    gaps and boundary questions, so this function does not infer a class.
    ``departure_tier_value`` is the RFC's numeric example input, not a tier
    ordinal. Behavioral variance and mission criticality have no specified
    factors in this formula and are not inferred here.
    """
    if type(latency_class) is not int or latency_class not in range(6):
        raise ValidationError("celestial latency class must be 0 through 5")
    light_time = as_decimal(light_time_seconds, name="one-way light time", minimum=0)
    if light_time == 0:
        raise ValidationError("one-way light time must be positive")
    tier = as_decimal(departure_tier_value, name="departure tier value", minimum=0, maximum=1)
    if latency_class == 5:
        if mission_duration_seconds is None:
            raise ValidationError("class 5 needs a declared mission duration cap")
        cap = as_decimal(mission_duration_seconds, name="mission duration", minimum=0)
        if cap == 0:
            raise ValidationError("mission duration must be positive")
    else:
        if mission_duration_seconds is not None:
            raise ValidationError("mission duration cap belongs only to class 5")
        cap = Decimal(_VALIDITY_CAPS[latency_class])
    with localcontext() as context:
        context.prec = 50
        computed = Decimal(10) * (2 * light_time) * (1 + tier * Decimal("0.5"))
        return min(computed, cap)


def latest_verifiable_event_time(now: DecimalLike, light_time_seconds: DecimalLike) -> Decimal:
    """Return the latest remote event time a local Oracle could have observed."""
    current = as_decimal(now, name="observation time")
    light_time = as_decimal(light_time_seconds, name="one-way light time", minimum=0)
    return current - light_time


def degraded_trust(
    initial_trust: DecimalLike,
    *,
    elapsed_seconds: DecimalLike,
    validity_seconds: DecimalLike,
    curve: str,
    half_life_seconds: DecimalLike | None = None,
) -> Decimal:
    """Project linear or corrected exponential E_trust within validity."""
    initial = as_decimal(initial_trust, name="initial trust", minimum=0, maximum=100)
    elapsed = as_decimal(elapsed_seconds, name="elapsed time", minimum=0)
    validity = as_decimal(validity_seconds, name="validity", minimum=0)
    if validity == 0 or elapsed > validity:
        raise ValidationError("celestial degradation requires an unexpired positive validity")
    if curve == "linear":
        if half_life_seconds is not None:
            raise ValidationError("linear degradation has no half-life")
        return initial * (1 - elapsed / validity)
    if curve != "exponential":
        raise ValidationError("unknown celestial degradation curve")
    if half_life_seconds is None:
        raise ValidationError("exponential degradation requires a half-life")
    half_life = as_decimal(half_life_seconds, name="half-life", minimum=0)
    if half_life == 0:
        raise ValidationError("half-life must be positive")
    with localcontext() as context:
        context.prec = 50
        return initial * (-(Decimal(2).ln() / half_life) * elapsed).exp()


def step_tier_ceiling(*, elapsed_seconds: DecimalLike, validity_seconds: DecimalLike) -> str | None:
    """Return the RFC's transit tier ceiling; None means no step has occurred."""
    elapsed = as_decimal(elapsed_seconds, name="elapsed time", minimum=0)
    validity = as_decimal(validity_seconds, name="validity", minimum=0)
    if validity == 0 or elapsed > validity:
        raise ValidationError("celestial step degradation requires an unexpired positive validity")
    fraction = elapsed / validity
    if fraction >= Decimal("0.9"):
        return "hibernation"
    if fraction >= Decimal("0.75"):
        return "observer"
    if fraction >= Decimal("0.5"):
        return "analyst"
    return None


__all__ = ["projected_validity_seconds", "latest_verifiable_event_time", "degraded_trust", "step_tier_ceiling"]
