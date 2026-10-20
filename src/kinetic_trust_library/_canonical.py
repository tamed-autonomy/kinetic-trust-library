"""Deterministic JSON serialization for Kinetic Trust values."""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
import hashlib
import json
from math import isfinite
from types import MappingProxyType

from ._decimal import MAX_DECIMAL_TEXT_LENGTH, as_decimal, require_derived_margin
from ._owned_mapping import _OwnedMapping, _require_owned_mapping_items
from .errors import ValidationError


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic UTF-8 JSON for the supported KTP value boundary."""
    return _encode(value, active=set(), seen_mutable=set()).encode("utf-8")


def canonical_sha256(value: object) -> str:
    """Return the SHA-256 digest of canonical JSON bytes as lowercase hex."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class _CanonicalDerivedMargin:
    value: Decimal


def _canonical_derived_margin(value: Decimal) -> object:
    """Mark only a validated internal margin for the closed output domain."""

    return _CanonicalDerivedMargin(require_derived_margin(value))


def _encode(value: object, *, active: set[int], seen_mutable: set[int]) -> str:
    if value is None:
        return "null"
    if type(value) is _CanonicalDerivedMargin:
        return _encode_decimal(require_derived_margin(value.value))
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Enum):
        return _encode(value.value, active=active, seen_mutable=seen_mutable)
    if isinstance(value, int):
        return _encode_decimal(as_decimal(value, name="canonical JSON number"))
    if isinstance(value, Decimal):
        return _encode_decimal(as_decimal(value, name="canonical JSON number"))
    if isinstance(value, float):
        if not isfinite(value):
            raise ValidationError("canonical JSON numbers must be finite")
        return _encode_decimal(as_decimal(value, name="canonical JSON number"))
    if isinstance(value, str):
        _validate_unicode(value, name="string value")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, datetime):
        return _encode_datetime(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _encode_dataclass(value, active=active, seen_mutable=seen_mutable)
    if isinstance(value, Mapping):
        return _encode_mapping(value, active=active, seen_mutable=seen_mutable)
    if isinstance(value, (list, tuple)):
        return _encode_sequence(value, active=active, seen_mutable=seen_mutable)
    raise ValidationError(f"unsupported canonical JSON value: {type(value).__name__}")


def _encode_dataclass(
    value: object, *, active: set[int], seen_mutable: set[int]
) -> str:
    _enter_container(
        value,
        active=active,
        seen_mutable=seen_mutable,
        mutable=not _is_frozen_dataclass(value),
    )
    try:
        return _encode_members(
            ((field.name, getattr(value, field.name)) for field in fields(value)),
            active=active,
            seen_mutable=seen_mutable,
        )
    finally:
        active.remove(id(value))


def _encode_mapping(
    value: Mapping[object, object], *, active: set[int], seen_mutable: set[int]
) -> str:
    owned = type(value) is _OwnedMapping
    _enter_container(
        value,
        active=active,
        seen_mutable=seen_mutable,
        mutable=not (owned or isinstance(value, MappingProxyType)),
    )
    try:
        entries = (
            _require_owned_mapping_items(value, name="canonical mapping")
            if owned
            else ((key, value[key]) for key in value)
        )
        return _encode_members(
            entries,
            active=active,
            seen_mutable=seen_mutable,
        )
    finally:
        active.remove(id(value))


def _encode_members(
    entries: object, *, active: set[int], seen_mutable: set[int]
) -> str:
    members: dict[str, object] = {}
    for key, member in entries:
        if not isinstance(key, str):
            raise ValidationError("canonical JSON object keys must be strings")
        _validate_unicode(key, name="object key")
        if key in members:
            raise ValidationError("canonical JSON object contains duplicate keys")
        members[key] = member
    return (
        "{"
        + ",".join(
            json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            + ":"
            + _encode(members[key], active=active, seen_mutable=seen_mutable)
            for key in sorted(members)
        )
        + "}"
    )


def _encode_sequence(
    value: list[object] | tuple[object, ...],
    *,
    active: set[int],
    seen_mutable: set[int],
) -> str:
    _enter_container(
        value,
        active=active,
        seen_mutable=seen_mutable,
        mutable=isinstance(value, list),
    )
    try:
        return (
            "["
            + ",".join(
                _encode(item, active=active, seen_mutable=seen_mutable)
                for item in value
            )
            + "]"
        )
    finally:
        active.remove(id(value))


def _encode_datetime(value: datetime) -> str:
    normalized = _canonical_utc_time(value)
    text = normalized.isoformat(timespec="microseconds")
    timestamp = text[:-6]
    if "." in timestamp:
        timestamp = timestamp.rstrip("0").rstrip(".")
    return json.dumps(timestamp + "Z", ensure_ascii=False, separators=(",", ":"))


def _canonical_utc_time(value: datetime) -> datetime:
    """Canonicalize only after an owning boundary has preflighted authority."""
    if type(value) is not datetime:
        raise ValidationError("canonical datetime must be a datetime")
    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise ValidationError("canonical datetime must be UTC") from exc
    if offset is None or offset != timedelta(0):
        raise ValidationError("canonical datetime must be UTC")
    return value.replace(tzinfo=timezone.utc)


def _encode_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise ValidationError("canonical JSON numbers must be finite")
    if value.is_zero():
        return "0"
    sign, digits, exponent = value.as_tuple()
    coefficient = "".join(str(digit) for digit in digits)
    if (
        _plain_decimal_length(coefficient, exponent, sign=bool(sign))
        > MAX_DECIMAL_TEXT_LENGTH
    ):
        significant = coefficient.rstrip("0")
        mantissa = significant[0]
        if len(significant) > 1:
            mantissa += "." + significant[1:]
        adjusted = exponent + len(coefficient) - 1
        return ("-" if sign else "") + mantissa + "e" + str(adjusted)
    if exponent >= 0:
        integer, fractional = coefficient + ("0" * exponent), ""
    elif len(coefficient) > -exponent:
        split = len(coefficient) + exponent
        integer, fractional = coefficient[:split], coefficient[split:]
    else:
        integer = "0"
        fractional = ("0" * (-exponent - len(coefficient))) + coefficient
    fractional = fractional.rstrip("0")
    result = integer if not fractional else f"{integer}.{fractional}"
    return f"-{result}" if sign else result


def _plain_decimal_length(coefficient: str, exponent: int, *, sign: bool) -> int:
    prefix = 1 if sign else 0
    if exponent >= 0:
        return prefix + len(coefficient) + exponent
    if len(coefficient) > -exponent:
        return prefix + len(coefficient) + 1
    return prefix + 2 - exponent


def _enter_container(
    value: object,
    *,
    active: set[int],
    seen_mutable: set[int],
    mutable: bool,
) -> None:
    identity = id(value)
    if identity in active:
        raise ValidationError("canonical JSON values must not contain cycles")
    if mutable and identity in seen_mutable:
        raise ValidationError("mutable aliases are not permitted")
    active.add(identity)
    if mutable:
        seen_mutable.add(identity)


def _is_frozen_dataclass(value: object) -> bool:
    parameters = getattr(type(value), "__dataclass_params__", None)
    return bool(parameters and parameters.frozen)


def _validate_unicode(value: str, *, name: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
