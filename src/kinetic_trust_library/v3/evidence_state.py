"""Provisional pure factor and undefined-state projection from RFC PR #203.

Callers establish feed authenticity, signal population, and the installed
aggregation. This module never treats an unavailable input as an observation.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError


_LAYERS = {"feed": 0, "signal": 1, "term": 2, "query": 3}
_STATES = {"absent", "unanswered", "stale", "undefined"}


@dataclass(frozen=True, slots=True)
class UndefinedInputState:
    input: str
    layer: str
    state: str

    def __post_init__(self) -> None:
        if type(self.input) is not str or not self.input:
            raise ValidationError("undefined input must have an identifier")
        if type(self.layer) is not str or self.layer not in _LAYERS:
            raise ValidationError("undefined input layer is invalid")
        if type(self.state) is not str or self.state not in _STATES:
            raise ValidationError("undefined input state is invalid")

    def record(self) -> dict[str, str]:
        return {"input": self.input, "layer": self.layer, "state": self.state}


@dataclass(frozen=True, slots=True, init=False)
class FactorEvidenceState:
    factor: str
    state: str
    value: Decimal | None
    decision_stress: Decimal
    undefined_inputs: tuple[UndefinedInputState, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("FactorEvidenceState values are derived by assess_required_factor()")

    def record(self) -> dict[str, str | Decimal]:
        if self.state == "observable":
            if self.value is None:
                raise ValidationError("observable factor has no value")
            return {
                "input": self.factor,
                "layer": "term",
                "state": "observable",
                "value": self.value,
            }
        return {
            "input": self.factor,
            "layer": "term",
            "state": "unobservable",
            "reason": "undefined",
            "decision_stress": self.decision_stress,
        }


def _factor_state(
    factor: str,
    state: str,
    value: Decimal | None,
    decision_stress: Decimal,
    undefined_inputs: tuple[UndefinedInputState, ...],
) -> FactorEvidenceState:
    result = object.__new__(FactorEvidenceState)
    for name, member in (
        ("factor", factor),
        ("state", state),
        ("value", value),
        ("decision_stress", decision_stress),
        ("undefined_inputs", undefined_inputs),
    ):
        object.__setattr__(result, name, member)
    return result


def canonical_undefined_inputs(
    entries: tuple[UndefinedInputState, ...],
) -> tuple[UndefinedInputState, ...]:
    """Deduplicate evaluated inputs and order them by RFC layer and name."""
    if type(entries) is not tuple:
        raise ValidationError("undefined inputs must be an owned tuple")
    distinct: dict[tuple[str, str], UndefinedInputState] = {}
    for entry in entries:
        if type(entry) is not UndefinedInputState:
            raise ValidationError("undefined input entry is invalid")
        key = (entry.layer, entry.input)
        prior = distinct.get(key)
        if prior is not None and prior.state != entry.state:
            raise ValidationError("undefined input has conflicting states")
        distinct[key] = entry
    return tuple(
        sorted(distinct.values(), key=lambda item: (_LAYERS[item.layer], item.input))
    )


def assess_required_factor(
    *,
    factor: str,
    required_signals: tuple[str, ...],
    populated_signals: dict[str, DecimalLike | None],
    measured_stress: DecimalLike | None,
    feed_undefined: tuple[UndefinedInputState, ...] = (),
) -> FactorEvidenceState:
    """Project an installed factor's required subset and supplied aggregate."""
    if type(factor) is not str or not factor:
        raise ValidationError("factor identifier is invalid")
    if (
        type(required_signals) is not tuple
        or any(type(name) is not str or not name for name in required_signals)
        or len(set(required_signals)) != len(required_signals)
        or type(populated_signals) is not dict
        or any(type(name) is not str for name in populated_signals)
    ):
        raise ValidationError("required signal subset is invalid")
    failures = list(canonical_undefined_inputs(feed_undefined))
    unknown: list[str] = []
    for name in required_signals:
        candidate = populated_signals.get(name)
        if candidate is None:
            unknown.append(name)
        else:
            as_decimal(candidate, name=f"signal {name}", minimum=0, maximum=1)
    if not required_signals or unknown:
        failures.extend(
            UndefinedInputState(name, "signal", "undefined") for name in unknown
        )
        failures.append(UndefinedInputState(factor, "term", "undefined"))
        return _factor_state(
            factor, "unobservable", None, Decimal(1),
            canonical_undefined_inputs(tuple(failures)),
        )
    if measured_stress is None:
        raise ValidationError("observable factor needs an installed aggregate")
    stress = as_decimal(
        measured_stress, name=f"factor {factor}", minimum=0, maximum=1
    )
    return _factor_state(
        factor, "observable", stress, stress,
        canonical_undefined_inputs(tuple(failures)),
    )


__all__ = [
    "FactorEvidenceState",
    "UndefinedInputState",
    "assess_required_factor",
    "canonical_undefined_inputs",
]
