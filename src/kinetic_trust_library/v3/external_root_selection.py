"""Provisional RFC PR #201 strongest-single eligible root selector.

Callers must independently authenticate complete signed instruments, current
status, exposure, chain and strength. This function never makes one eligible.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import re

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError


_DIGEST = re.compile(r"(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})\Z")


@dataclass(frozen=True, slots=True)
class EligibleRoot:
    instrument_id: str
    complete_digest: str
    strength: Decimal

    def __init__(
        self, instrument_id: str, complete_digest: str, strength: DecimalLike
    ) -> None:
        if type(instrument_id) is not str or not instrument_id:
            raise ValidationError("eligible root identifier is invalid")
        if type(complete_digest) is not str or _DIGEST.fullmatch(complete_digest) is None:
            raise ValidationError("eligible root complete digest is invalid")
        value = as_decimal(strength, name="eligible root strength", minimum=0, maximum=100)
        if value == 0:
            raise ValidationError("zero-strength root is ineligible")
        object.__setattr__(self, "instrument_id", instrument_id)
        object.__setattr__(self, "complete_digest", complete_digest)
        object.__setattr__(self, "strength", value)


def select_strongest_root(
    candidates: tuple[EligibleRoot, ...], *, algorithm: str
) -> EligibleRoot | None:
    """Select one prevalidated root; break strength ties by exact digest."""
    if algorithm not in ("sha256", "sha384") or type(candidates) is not tuple:
        raise ValidationError("root selection profile or candidates are invalid")
    if any(type(candidate) is not EligibleRoot for candidate in candidates):
        raise ValidationError("root candidate is not an eligible value")
    if any(not candidate.complete_digest.startswith(algorithm + ":") for candidate in candidates):
        raise ValidationError("root candidate digest algorithm differs from policy")
    if len({candidate.instrument_id for candidate in candidates}) != len(candidates):
        raise ValidationError("root candidates contain a duplicate instrument")
    return min(candidates, key=lambda item: (-item.strength, item.complete_digest)) if candidates else None


__all__ = ["EligibleRoot", "select_strongest_root"]
