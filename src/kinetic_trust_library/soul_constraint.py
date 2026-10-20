"""Semantic parsing for the official KTP v2.1 Soul Constraint document.

Parsing validates document shape only. It does not authenticate the source,
establish that an authority is trusted, evaluate a constraint for an action,
or enforce an outcome.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from .errors import ValidationError
from .models.soul import SoulConstraintType


__all__ = [
    "SoulConstraintDocument",
    "SoulConstraintType",
    "parse_soul_constraint",
]


_MEMBERS = frozenset(
    {
        "soul",
        "constraint_type",
        "constraint_id",
        "constraint_name",
        "authority",
        "community",
        "remediation",
    }
)


@dataclass(frozen=True, slots=True)
class SoulConstraintDocument:
    """A detached value matching the released Soul Constraint schema."""

    soul: Literal[0, 1]
    constraint_type: SoulConstraintType | None
    constraint_id: str | None
    constraint_name: str | None
    authority: str | None
    community: str | None
    remediation: str | None


def _snapshot(document: object) -> dict[str, object]:
    if not isinstance(document, Mapping):
        raise ValidationError("Soul constraint document must be an object")
    try:
        snapshot = dict(document)
    except Exception as exc:
        raise ValidationError(
            "Soul constraint document could not be read"
        ) from exc
    if any(type(key) is not str for key in snapshot):
        raise ValidationError("Soul constraint document keys must be strings")
    unknown = snapshot.keys() - _MEMBERS
    if unknown:
        raise ValidationError(
            "Soul constraint document contains unknown members: "
            + ", ".join(sorted(unknown))
        )
    return snapshot


def _optional_string(data: dict[str, object], name: str) -> str | None:
    value = data.get(name)
    if value is None:
        return None
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string or null")
    return value


def parse_soul_constraint(
    document: Mapping[str, object], /
) -> SoulConstraintDocument:
    """Validate one decoded v2.1 Soul Constraint object without authentication."""

    data = _snapshot(document)
    if "soul" not in data:
        raise ValidationError("Soul constraint document is missing soul")
    soul = data["soul"]
    if type(soul) is not int or soul not in (0, 1):
        raise ValidationError("soul must be the exact integer 0 or 1")

    constraint_type_value = _optional_string(data, "constraint_type")
    try:
        constraint_type = (
            None
            if constraint_type_value is None
            else SoulConstraintType(constraint_type_value)
        )
    except ValueError as exc:
        raise ValidationError("constraint_type is not a supported value") from exc

    authority = _optional_string(data, "authority")
    if soul == 1 and constraint_type is None:
        raise ValidationError("soul=1 requires non-null constraint_type")
    if soul == 1 and authority is None:
        raise ValidationError("soul=1 requires non-null authority")

    return SoulConstraintDocument(
        soul=cast(Literal[0, 1], soul),
        constraint_type=constraint_type,
        constraint_id=_optional_string(data, "constraint_id"),
        constraint_name=_optional_string(data, "constraint_name"),
        authority=authority,
        community=_optional_string(data, "community"),
        remediation=_optional_string(data, "remediation"),
    )
