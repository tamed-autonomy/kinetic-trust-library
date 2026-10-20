"""Validation and ownership helpers for common model values."""

import re
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from math import isfinite
from types import MappingProxyType
from typing import TypeAlias

from kinetic_trust_library.errors import ValidationError


FrozenValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | Decimal
    | datetime
    | Enum
    | tuple["FrozenValue", ...]
    | Mapping[str, "FrozenValue"]
)

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CONSTRAINT_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*$")
_ENGINEERING_UNIT = re.compile(
    r"^(?:[A-Za-z]+(?:-[A-Za-z]+)*(?:[²³])?)"
    r"(?:·[A-Za-z]+(?:-[A-Za-z]+)*(?:[²³])?)*"
    r"(?:/(?:[A-Za-z]+(?:-[A-Za-z]+)*(?:[²³])?)"
    r"(?:·[A-Za-z]+(?:-[A-Za-z]+)*(?:[²³])?)*)?$"
)
_MAX_CONSTRAINT_MAGNITUDE_LENGTH = 256
_MAX_CONSTRAINT_NAMESPACE_SEGMENTS = 8
_MAX_ENGINEERING_UNIT_LENGTH = 64


def validate_identifier(value: str, *, name: str) -> str:
    """Validate a bounded, NFC KTP identifier without changing its value."""
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    _validate_unicode(value, name=name)
    if unicodedata.normalize("NFC", value) != value or not _IDENTIFIER.fullmatch(value):
        raise ValidationError(f"{name} is not a valid identifier")
    return value


def validate_constraint_magnitude(value: str, *, name: str) -> str:
    """Validate one case-sensitive magnitude without weakening KTP identifiers."""

    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    _validate_unicode(value, name=name)
    if (
        not value
        or len(value) > _MAX_CONSTRAINT_MAGNITUDE_LENGTH
        or unicodedata.normalize("NFC", value) != value
        or not value.isascii()
    ):
        raise ValidationError(f"{name} is not a valid constraint magnitude")
    segments = value.split(":")
    if len(segments) > _MAX_CONSTRAINT_NAMESPACE_SEGMENTS or any(
        _CONSTRAINT_SEGMENT.fullmatch(segment) is None for segment in segments
    ):
        raise ValidationError(f"{name} is not a valid constraint magnitude")
    return value


def validate_engineering_unit(value: str, *, name: str) -> str:
    """Validate and preserve one bounded, case-sensitive engineering unit."""

    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    _validate_unicode(value, name=name)
    if (
        not value
        or len(value) > _MAX_ENGINEERING_UNIT_LENGTH
        or unicodedata.normalize("NFC", value) != value
        or _ENGINEERING_UNIT.fullmatch(value) is None
    ):
        raise ValidationError(f"{name} is not a valid engineering unit")
    return value


def utc_time(value: datetime, *, name: str) -> datetime:
    """Require one exact, library-owned UTC datetime without invoking tzinfo."""
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise ValidationError(f"{name} must be an exact UTC datetime")
    return value


def freeze_mapping(value: Mapping[str, object]) -> Mapping[str, FrozenValue]:
    """Copy a JSON-shaped mapping into immutable, independently owned values."""
    if not isinstance(value, Mapping):
        raise ValidationError("value must be a mapping")
    return _freeze_mapping(value, seen_mutable=set())


def _freeze_mapping(
    value: Mapping[str, object], *, seen_mutable: set[int]
) -> Mapping[str, FrozenValue]:
    _claim_mutable(value, seen_mutable)
    result: dict[str, FrozenValue] = {}
    for key in value:
        if not isinstance(key, str):
            raise ValidationError("mapping keys must be strings")
        _validate_unicode(key, name="mapping key")
        if key in result:
            raise ValidationError("mapping contains duplicate keys")
        result[key] = _freeze_value(value[key], seen_mutable=seen_mutable)
    return MappingProxyType(result)


def _freeze_value(value: object, *, seen_mutable: set[int]) -> FrozenValue:
    if isinstance(value, Enum):
        _validate_owned_enum_value(value.value)
        return value
    if value is None or isinstance(value, (bool, int, str, Decimal, datetime)):
        if isinstance(value, str):
            _validate_unicode(value, name="string value")
        if isinstance(value, Decimal) and not value.is_finite():
            raise ValidationError("decimal value must be finite")
        if isinstance(value, datetime):
            return utc_time(value, name="datetime value")
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValidationError("float value must be finite")
        return value
    if isinstance(value, Mapping):
        return _freeze_mapping(value, seen_mutable=seen_mutable)
    if isinstance(value, (list, tuple)):
        _claim_mutable(value, seen_mutable) if isinstance(value, list) else None
        return tuple(_freeze_value(item, seen_mutable=seen_mutable) for item in value)
    raise ValidationError(f"unsupported mapping value: {type(value).__name__}")


def _validate_owned_enum_value(value: object) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        _validate_unicode(value, name="enum value")
        return
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValidationError("enum decimal value must be finite")
        return
    if isinstance(value, datetime):
        utc_time(value, name="enum datetime value")
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise ValidationError("enum float value must be finite")
        return
    if isinstance(value, tuple):
        for item in value:
            _validate_owned_enum_value(item)
        return
    raise ValidationError("enum value is not an immutable supported value")


def _claim_mutable(value: object, seen_mutable: set[int]) -> None:
    identity = id(value)
    if identity in seen_mutable:
        raise ValidationError("mutable aliases are not permitted")
    seen_mutable.add(identity)


def _validate_unicode(value: str, *, name: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
