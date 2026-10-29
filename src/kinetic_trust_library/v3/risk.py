"""Provisional five-factor Core risk calculation from RFC PR #164."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from ._exact import finite_decimal

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError


_FACTORS = (
    "evidence_density",
    "trust_trend",
    "adversarial_pressure",
    "update_resistance",
    "attestation_coverage",
)


def calculate_five_factor_risk(
    normalized_inputs: dict[str, DecimalLike],
    weights: dict[str, DecimalLike],
) -> Decimal:
    """Return exact five-factor R; demand input and Soul never enter this sum."""
    if (
        type(normalized_inputs) is not dict
        or type(weights) is not dict
        or any(type(name) is not str for name in normalized_inputs)
        or any(type(name) is not str for name in weights)
        or set(normalized_inputs) != set(_FACTORS)
        or set(weights) != set(_FACTORS)
    ):
        raise ValidationError("five named Risk Factor inputs and weights are required")
    values = {
        name: as_decimal(normalized_inputs[name], name=name, minimum=0, maximum=1)
        for name in _FACTORS
    }
    validated_weights = {
        name: as_decimal(weights[name], name=f"{name} weight", minimum=0, maximum=1)
        for name in _FACTORS
    }
    if any(weight == 0 for weight in validated_weights.values()):
        raise ValidationError("Risk Factor weights must be positive")
    if sum((Fraction(w) for w in validated_weights.values()), Fraction(0)) != 1:
        raise ValidationError("Risk Factor weights must sum to one")
    return finite_decimal(sum(
        (Fraction(validated_weights[name]) * Fraction(values[name]) for name in _FACTORS),
        Fraction(0),
    ))


__all__ = ["calculate_five_factor_risk"]
