from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal
from types import MappingProxyType
from typing import Iterator, Mapping

from ..errors import ValidationError
from ._models import TrajectoryAgentState


def _number(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValidationError(f"{name} must be a number")
    number = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    if not number.is_finite():
        raise ValidationError(f"{name} must be finite")
    return number


@contextmanager
def _object(
    value: object, name: str, active: set[int],
) -> Iterator[dict[str, object]]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{name} must be an object")
    identity = id(value)
    if identity in active:
        raise ValidationError(f"{name} contains a cycle")
    active.add(identity)
    try:
        snapshot = dict(value)
        if any(not isinstance(key, str) for key in snapshot):
            raise ValidationError(f"{name} keys must be strings")
        yield snapshot
    finally:
        active.remove(identity)


def _freeze_json(value: object, name: str, active: set[int]) -> object:
    if isinstance(value, Mapping):
        with _object(value, name, active) as snapshot:
            return MappingProxyType({
                key: _freeze_json(item, f"{name}.{key}", active)
                for key, item in snapshot.items()
            })
    if isinstance(value, list):
        identity = id(value)
        if identity in active:
            raise ValidationError(f"{name} contains a cycle")
        active.add(identity)
        try:
            return tuple(_freeze_json(item, name, active) for item in value)
        finally:
            active.remove(identity)
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, (int, float, Decimal)):
        return _number(value, name)
    raise ValidationError(f"{name} must contain only JSON values")


def _json_equal(left: object, right: object) -> bool:
    """Compare already-normalized JSON values without conflating scalar kinds."""
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, (int, float, Decimal)) and isinstance(right, (int, float, Decimal)):
        left_number = Decimal(repr(left)) if isinstance(left, float) else Decimal(left)
        right_number = Decimal(repr(right)) if isinstance(right, float) else Decimal(right)
        return left_number == right_number
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return left.keys() == right.keys() and all(
            _json_equal(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, tuple) and isinstance(right, tuple):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    return False


def _state_equal(left: TrajectoryAgentState, right: TrajectoryAgentState) -> bool:
    return all(_json_equal(a, b) for a, b in (
        (left.e_base, right.e_base),
        (left.e_trust, right.e_trust),
        (left.location, right.location),
        (left.tier, right.tier),
        (left.lineage, right.lineage),
        (left.generation, right.generation),
        (left.extensions, right.extensions),
    ))
