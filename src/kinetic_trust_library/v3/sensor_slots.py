"""Exact fixed-slot feed aggregation for the provisional v3 sensor profile.

The caller authenticates and normalizes current readings and establishes
source independence. An absent required slot remains undefined.
"""

from __future__ import annotations

from fractions import Fraction

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError

from .sensor_config import validate_sensor_factor_config


def aggregate_weighted_slots(
    configuration: dict[str, object],
    current_values: dict[str, DecimalLike],
    *,
    admissible_sources: frozenset[str],
) -> Fraction | None:
    """Select one admissible alternative per slot and keep its fixed weight.

    ``admissible_sources`` must come from independent source and population
    checks; a feed's declaration alone cannot establish admissibility.
    Returns ``None`` if a required slot has no current admissible source.
    """
    if not validate_sensor_factor_config(configuration):
        raise ValidationError("invalid v3 sensor configuration")
    if configuration.get("aggregation") != "weighted_average":
        raise ValidationError("fixed slots require weighted_average")
    slots = configuration.get("aggregation_slots")
    feeds = configuration["feeds"]
    if type(slots) is not list or type(current_values) is not dict or type(admissible_sources) is not frozenset:
        raise ValidationError("fixed slots, current values and admissible sources are required")
    feed_ids = [feed["id"] for feed in feeds]
    slot_ids = [slot["id"] for slot in slots]
    if (len(set(feed_ids)) != len(feed_ids) or len(set(slot_ids)) != len(slot_ids)
            or set(current_values) - set(feed_ids) or not admissible_sources <= set(feed_ids)
            or any(len(set(slot["alternatives"])) != len(slot["alternatives"])
                   or set(slot["alternatives"]) - set(feed_ids) for slot in slots)):
        raise ValidationError("fixed-slot declarations or current source IDs are invalid")
    readings = {
        name: Fraction(as_decimal(value, name=f"feed {name}", minimum=0, maximum=1))
        for name, value in current_values.items()
    }
    numerator = Fraction(0)
    denominator = Fraction(0)
    for slot in slots:
        weight = Fraction(as_decimal(slot["weight"], name="slot weight", minimum=0))
        if weight <= 0:
            raise ValidationError("slot weight must be positive")
        denominator += weight
        chosen = next((name for name in slot["alternatives"]
                       if name in readings and name in admissible_sources), None)
        if chosen is None:
            return None
        numerator += weight * readings[chosen]
    return numerator / denominator


__all__ = ["aggregate_weighted_slots"]
