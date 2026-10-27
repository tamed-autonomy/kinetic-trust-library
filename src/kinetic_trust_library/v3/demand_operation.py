"""Provisional RFC PR #202 preclassification operation digest.

The caller must reconstruct this descriptor from the authenticated actual
invocation. A matching digest does not authenticate a demand supplier.
"""

from __future__ import annotations

from functools import lru_cache
import hashlib
from importlib.resources import files
import json

from kinetic_trust_library.errors import ValidationError


_PREFIX = b"KTP/demand-operation-v1\x00"


@lru_cache(maxsize=1)
def _operation_validator():
    from jsonschema import Draft202012Validator, FormatChecker

    schema = json.loads(files("kinetic_trust_library.v3").joinpath(
        "schemas/demand-operation-v1.json"
    ).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def canonical_demand_operation_bytes(operation: dict[str, object]) -> bytes:
    """Validate and JCS-encode the complete actual operation descriptor."""
    if type(operation) is not dict:
        raise ValidationError("demand operation must be an object")
    try:
        import rfc8785
        from kinetic_trust_library.v3.trust_proof_json import _check_tree

        _check_tree(operation, 1)
        if not _operation_validator().is_valid(operation):
            raise ValidationError("demand operation fails proposed schema")
        return rfc8785.dumps(operation)
    except ImportError as exc:
        raise ValidationError("v3 demand canonicalization support is unavailable") from exc
    except (ValueError, TypeError, RecursionError, rfc8785.CanonicalizationError) as exc:
        raise ValidationError("demand operation cannot be canonicalized") from exc


def digest_demand_operation(operation: dict[str, object], *, algorithm: str) -> str:
    """Hash preclassification operation bytes under the proposed domain."""
    if algorithm not in ("sha256", "sha384"):
        raise ValidationError("demand operation digest algorithm is invalid")
    canonical = canonical_demand_operation_bytes(operation)
    return f"{algorithm}:{hashlib.new(algorithm, _PREFIX + canonical).hexdigest()}"


__all__ = ["canonical_demand_operation_bytes", "digest_demand_operation"]
