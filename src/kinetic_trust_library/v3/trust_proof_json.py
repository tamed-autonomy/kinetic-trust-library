"""Provisional strict JSON/JCS portion of RFC PR #195 Trust Proof stage 1."""

from __future__ import annotations

import json
import math

from kinetic_trust_library.errors import ProofFormatError
from kinetic_trust_library.v3.trust_proof_framing import CompactFraming


_MAX_SAFE_INTEGER = 2**53 - 1


def _reject_constant(value: str) -> object:
    raise ValueError(f"JSON constant {value} is not finite")


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object has duplicate members")
        result[key] = value
    return result


def _check_tree(value: object, depth: int) -> None:
    if type(value) is dict:
        if depth > 32:
            raise ValueError("JSON exceeds container nesting limit")
        for member in value.values():
            _check_tree(member, depth + 1)
    elif type(value) is list:
        if depth > 32:
            raise ValueError("JSON exceeds container nesting limit")
        for member in value:
            _check_tree(member, depth + 1)
    elif type(value) is int:
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError("JSON integer exceeds safe range")
    elif type(value) is float:
        if not math.isfinite(value) or (
            value.is_integer() and abs(value) > _MAX_SAFE_INTEGER
        ):
            raise ValueError("JSON number exceeds finite safe range")


def _parse_jcs_object(raw: bytes) -> dict[str, object]:
    try:
        import rfc8785

        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
        )
        if type(value) is not dict:
            raise ValueError("proof JSON root must be an object")
        _check_tree(value, 1)
        if rfc8785.dumps(value) != raw:
            raise ValueError("proof JSON is not JCS")
    except ImportError as exc:
        raise ProofFormatError("RFC 8785 support is unavailable") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError,
            RecursionError, rfc8785.CanonicalizationError) as exc:
        raise ProofFormatError("proof JSON must be strict JCS") from exc
    return value


def parse_proof_json_objects(
    framing: CompactFraming,
) -> tuple[dict[str, object], dict[str, object]]:
    """Parse already bounded raw segments without changing signed bytes."""
    if type(framing) is not CompactFraming:
        raise ProofFormatError("proof framing is required")
    return _parse_jcs_object(framing.header_bytes), _parse_jcs_object(
        framing.payload_bytes
    )


__all__ = ["parse_proof_json_objects"]
