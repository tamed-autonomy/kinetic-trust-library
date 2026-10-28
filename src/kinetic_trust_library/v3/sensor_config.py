"""Validate proposed v3 sensor-factor configuration at the schema boundary.

The five weighted factors and Soul are sensor dimensions. Demand-side
moment_criticality is supplied under a separate contract, never here.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import json

from kinetic_trust_library.errors import ValidationError


@lru_cache(maxsize=1)
def _validator():
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise ValidationError("v3 sensor configuration support is unavailable") from exc
    schema = json.loads(
        files("kinetic_trust_library.v3")
        .joinpath("schemas/sensor-config-v3.json")
        .read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema)


def validate_sensor_factor_config(configuration: dict[str, object]) -> bool:
    """Report whether a candidate matches the proposal's closed configuration schema.

    This checks shape only. Source authenticity, independence, and signal
    population require the installed deployment context.
    """
    if type(configuration) is not dict:
        return False
    return _validator().is_valid(configuration)


__all__ = ["validate_sensor_factor_config"]
