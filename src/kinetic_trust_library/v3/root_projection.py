"""Closed External Root wire shape from provisional RFC PR #201.

Schema success establishes neither instrument authentication nor current
lifecycle, exposure, chain truth or credit eligibility.
"""
from functools import lru_cache
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError


@lru_cache(maxsize=1)
def _validator():
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise ValidationError("v3 root schema support is unavailable") from exc
    schema = json.loads(files("kinetic_trust_library.v3").joinpath(
        "schemas/root-instrument-v3.json").read_text("utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_root_projection(value: dict[str, object]) -> bool:
    """Check the closed none/bond/attestation union without awarding credit."""
    return type(value) is dict and _validator().is_valid(value)


__all__ = ["validate_root_projection"]
