"""Provisional native v3 Soul query-state projection from RFC PR #203.

Callers establish framework applicability and response authenticity. A state
label supplied by an untrusted requester has no authority here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from kinetic_trust_library.errors import ValidationError

from .evidence_state import UndefinedInputState, canonical_undefined_inputs


class SoulGateState(StrEnum):
    CLEAR = "clear"
    VETO = "veto"
    UNDETERMINED = "undetermined"


_QUERY_STATES = {"clear", "veto", "absent", "unanswered", "stale", "undefined"}


@dataclass(frozen=True, slots=True)
class SoulQueryState:
    framework: str
    state: str

    def __post_init__(self) -> None:
        if type(self.framework) is not str or not self.framework:
            raise ValidationError("Soul framework identifier is invalid")
        if type(self.state) is not str or self.state not in _QUERY_STATES:
            raise ValidationError("Soul query state is invalid")


@dataclass(frozen=True, slots=True, init=False)
class SoulGate:
    state: SoulGateState
    queries: tuple[SoulQueryState, ...]
    undefined_inputs: tuple[UndefinedInputState, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("SoulGate values are derived by assess_soul_queries()")


def assess_soul_queries(
    *,
    required_frameworks: tuple[str, ...],
    responses: tuple[SoulQueryState, ...],
) -> SoulGate:
    """Preserve a known veto and every missing applicable query."""
    if (
        type(required_frameworks) is not tuple
        or not required_frameworks
        or any(type(name) is not str or not name for name in required_frameworks)
        or len(set(required_frameworks)) != len(required_frameworks)
        or type(responses) is not tuple
        or any(type(response) is not SoulQueryState for response in responses)
    ):
        raise ValidationError("applicable Soul framework queries are invalid")
    by_name = {response.framework: response for response in responses}
    if len(by_name) != len(responses) or not set(by_name) <= set(required_frameworks):
        raise ValidationError("Soul responses duplicate or exceed declared frameworks")
    ordered = tuple(by_name.get(name, SoulQueryState(name, "absent"))
                    for name in required_frameworks)
    undefined = canonical_undefined_inputs(tuple(
        UndefinedInputState(response.framework, "query", response.state)
        for response in ordered if response.state not in {"clear", "veto"}
    ))
    state = (
        SoulGateState.VETO if any(response.state == "veto" for response in ordered)
        else SoulGateState.UNDETERMINED if undefined
        else SoulGateState.CLEAR
    )
    result = object.__new__(SoulGate)
    for name, value in (
        ("state", state), ("queries", ordered), ("undefined_inputs", undefined)
    ):
        object.__setattr__(result, name, value)
    return result


__all__ = ["SoulGate", "SoulGateState", "SoulQueryState", "assess_soul_queries"]
