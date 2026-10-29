"""Native v3 software-agent E_base composition from authenticated components.

This calculation neither authenticates PoR, root instruments, peer evidence
nor the provenance of each applicable ceiling. It is not a standing verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from ._exact import finite_decimal

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError


_REQUIRED_CEILINGS = frozenset({"generation", "ial", "trajectory", "adversity"})
_BUILT_IN_VALUES = {
    "generation": frozenset({25, 35, 45, 55, 65, 75, 85, 100}),
    "ial": frozenset({40, 80, 95}),
    "trajectory": frozenset({50, 70, 100}),
    "adversity": frozenset({60, 80, 90, 100}),
}


@dataclass(frozen=True, slots=True, init=False)
class NativeBaseTrust:
    por_share: Decimal
    root_share: Decimal
    peer_share: Decimal
    raw_base: Decimal
    base_trust: Decimal
    ceilings: tuple[tuple[str, Decimal], ...]
    binding_ceilings: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("NativeBaseTrust values are derived by calculate_native_base_trust()")


def calculate_native_base_trust(
    *,
    por_contribution: DecimalLike,
    root_score: DecimalLike,
    peer_share: DecimalLike,
    peer_score: DecimalLike,
    ceilings: dict[str, DecimalLike],
) -> NativeBaseTrust:
    """Apply the 70/30 allocation, peer reallocation and minimum ceiling.

    Every contribution and ceiling must already be derived from authenticated
    source evidence. The no-root cap applies even if a caller omits it.
    """
    por = as_decimal(por_contribution, name="PoR contribution", minimum=0, maximum=70)
    root = as_decimal(root_score, name="External Root score", minimum=0, maximum=100)
    peer_weight = as_decimal(peer_share, name="peer share", minimum=0, maximum=20)
    peer = as_decimal(peer_score, name="peer score", minimum=0, maximum=100)
    if peer_weight != 0 and peer_weight < 10:
        raise ValidationError("peer share must be zero or within 10 to 20")
    if peer_weight == 0 and peer != 0:
        raise ValidationError("peer score cannot contribute without a declared share")
    if (
        type(ceilings) is not dict
        or any(type(name) is not str or not name for name in ceilings)
        or not _REQUIRED_CEILINGS.issubset(ceilings)
    ):
        raise ValidationError("all applicable base trust ceilings must be declared")
    bounded = {
        name: as_decimal(value, name=f"{name} ceiling", minimum=0, maximum=100)
        for name, value in ceilings.items()
    }
    if any(bounded[name] not in allowed for name, allowed in _BUILT_IN_VALUES.items()):
        raise ValidationError("built-in base trust ceiling is not an RFC value")
    if root == 0:
        bounded["external_root_missing"] = min(
            bounded.get("external_root_missing", Decimal(70)), Decimal(70)
        )
    remainder = (100 - Fraction(peer_weight)) / 100
    por_share = finite_decimal(70 * remainder)
    root_share = finite_decimal(30 * remainder)
    raw = finite_decimal(Fraction(por) * remainder + Fraction(root) * 30 * remainder / 100
                         + Fraction(peer) * Fraction(peer_weight) / 100)
    base = min(raw, *bounded.values())
    binding = tuple(sorted(name for name, value in bounded.items() if value == base))
    result = object.__new__(NativeBaseTrust)
    for name, value in (
        ("por_share", por_share),
        ("root_share", root_share),
        ("peer_share", peer_weight),
        ("raw_base", raw),
        ("base_trust", base),
        ("ceilings", tuple(sorted(bounded.items()))),
        ("binding_ceilings", binding),
    ):
        object.__setattr__(result, name, value)
    return result


__all__ = ["NativeBaseTrust", "calculate_native_base_trust"]
