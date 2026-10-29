"""Provisional RFC PR #197 canonical Decision Geometry body digest.

This primitive only validates shape and canonical bytes. It does not establish
truthful inputs, a valid evaluation, an authorized signer, or execution.
"""

from __future__ import annotations

from functools import lru_cache
import hashlib
from importlib.resources import files
import json

from kinetic_trust_library.errors import ValidationError


_PREFIX = b"KTP/decision-geometry-v1\x00"


@lru_cache(maxsize=1)
def _geometry_validator():
    from .schema_formats import installed_format_checker
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    base = files("kinetic_trust_library.v3").joinpath("schemas")
    schemas = [
        json.loads(base.joinpath(name).read_text(encoding="utf-8"))
        for name in (
            "decision-geometry-v1.json", "request-binding-v1.json",
            "request-proof-association-v1.json",
        )
    ]
    registry = Registry(retrieve=_no_network).with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )
    return Draft202012Validator(
        schemas[0], registry=registry, format_checker=installed_format_checker()
    )


def _no_network(uri: str):
    raise LookupError(f"unbundled geometry schema reference: {uri}")


def canonical_geometry_bytes(body: dict[str, object]) -> bytes:
    """Validate and JCS-encode one complete proposed geometry body."""
    if type(body) is not dict:
        raise ValidationError("Decision Geometry body must be an object")
    try:
        import rfc8785
        from kinetic_trust_library.v3.trust_proof_json import _check_tree

        _check_tree(body, 1)
        if not _geometry_validator().is_valid(body):
            raise ValidationError("Decision Geometry body fails proposed schema")
        canonical = rfc8785.dumps(body)
        if len(canonical) > 262_144:
            raise ValidationError("Decision Geometry body exceeds its byte limit")
        return canonical
    except ImportError as exc:
        raise ValidationError("v3 geometry canonicalization support is unavailable") from exc
    except (ValueError, TypeError, RecursionError, rfc8785.CanonicalizationError) as exc:
        raise ValidationError("Decision Geometry body cannot be canonicalized") from exc


def digest_geometry_body(body: dict[str, object], *, algorithm: str) -> str:
    """Hash the complete body under the proposed geometry domain prefix."""
    if algorithm not in ("sha256", "sha384"):
        raise ValidationError("Decision Geometry digest algorithm is invalid")
    canonical = canonical_geometry_bytes(body)
    return f"{algorithm}:{hashlib.new(algorithm, _PREFIX + canonical).hexdigest()}"


__all__ = ["canonical_geometry_bytes", "digest_geometry_body"]
