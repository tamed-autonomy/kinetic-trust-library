"""Provisional RFC PR #195 closed payload schema validation (stage 6).

Bundled proposal schema and native v3 Risk Factors are loaded locally. No schema
reference is fetched from a proof or the network. Shape alone is not authority.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import json
from typing import Any


def _no_network(uri: str) -> Any:
    raise LookupError(f"unbundled schema reference: {uri}")


@lru_cache(maxsize=1)
def _validator() -> Any:
    from .schema_formats import installed_format_checker
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    base = files("kinetic_trust_library.v3").joinpath("schemas")
    schemas = [
        json.loads(base.joinpath(name).read_text(encoding="utf-8"))
        for name in (
            "trust-proof-v3.json", "risk-factors-native-v3.json", "soul-constraint-v2.json"
        )
    ]
    registry = Registry(retrieve=_no_network).with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )
    return Draft202012Validator(
        schemas[0], registry=registry, format_checker=installed_format_checker()
    )


def trust_proof_schema_valid(payload: dict[str, object]) -> bool:
    """Validate closed proposed schema, failing closed if support is absent."""
    if type(payload) is not dict:
        return False
    try:
        return _validator().is_valid(payload)
    except (ImportError, LookupError, ValueError, TypeError):
        return False


__all__ = ["trust_proof_schema_valid"]
