"""Portable immutable mappings for retained library-owned model graphs."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from reprlib import recursive_repr
from typing import TypeVar

from kinetic_trust_library.errors import ValidationError


_Key = TypeVar("_Key")
_Value = TypeVar("_Value")


class _OwnedMapping(Mapping[_Key, _Value]):
    """A read-only mapping with directly inspectable owned representation."""

    __slots__ = ("_entries", "_index")

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("owned mappings are created from validated dictionaries")

    def __getitem__(self, key: _Key) -> _Value:
        return self._index[key]

    def __iter__(self) -> Iterator[_Key]:
        return (entry[0] for entry in self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    @recursive_repr("{...}")
    def __repr__(self) -> str:
        entries = _require_owned_mapping_items(self, name="read-only mapping")
        return "{" + ", ".join(f"{key!r}: {value!r}" for key, value in entries) + "}"

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("owned mappings are immutable")


def _owned_mapping_from_dict(value: dict[_Key, _Value]) -> _OwnedMapping[_Key, _Value]:
    """Own one exact built-in dictionary without retaining its mutable shell."""

    if type(value) is not dict:
        raise TypeError("owned mapping source must be an exact dictionary")
    owned = object.__new__(_OwnedMapping)
    object.__setattr__(owned, "_entries", tuple(dict.items(value)))
    object.__setattr__(owned, "_index", dict.copy(value))
    return owned


def _require_owned_mapping_items(
    value: object,
    *,
    name: str,
) -> tuple[tuple[object, object], ...]:
    """Return exact entries only after a non-hooking representation preflight."""

    if type(value) is not _OwnedMapping:
        raise ValidationError(f"{name} must be an owned immutable mapping")
    try:
        entries = object.__getattribute__(value, "_entries")
        index = object.__getattribute__(value, "_index")
    except AttributeError as exc:
        raise ValidationError(f"{name} ownership is invalid") from exc
    if type(entries) is not tuple or type(index) is not dict:
        raise ValidationError(f"{name} ownership is invalid")
    index_items = tuple(dict.items(index))
    if len(entries) != len(index_items):
        raise ValidationError(f"{name} ownership is invalid")
    for entry, index_entry in zip(entries, index_items, strict=True):
        if (
            type(entry) is not tuple
            or len(entry) != 2
            or entry[0] is not index_entry[0]
            or entry[1] is not index_entry[1]
        ):
            raise ValidationError(f"{name} ownership is invalid")
    return entries
