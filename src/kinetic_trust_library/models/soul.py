"""Immutable declarations and derived values for the independent Soul veto."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from .profile import ProfileRef

if TYPE_CHECKING:
    from .action import ValidatedActionDemand
    from .profile import DeploymentProfile


class SoulConstraintType(StrEnum):
    TK_LABEL = "tk_label"
    OCAP = "ocap"
    CARE = "care"
    SACRED_LAND = "sacred_land"
    TREATY = "treaty"
    LINEAGE = "lineage"
    CULTURAL_HERITAGE = "cultural_heritage"


class SoulUndeterminedReason(StrEnum):
    """Disclosure-safe query-failure classes; all have identical veto force."""

    MISSING = "missing"
    UNREACHABLE = "unreachable"
    ERROR = "error"
    TIMEOUT = "timeout"
    EMPTY = "empty"


class SoulAssessmentState(StrEnum):
    CLEAR = "clear"
    VETO = "veto"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class SoulResponseDeclaration:
    framework_id: str
    profile_ref: ProfileRef
    profile_digest: str
    action_id: str
    action_digest: str
    query_cutoff: datetime
    state: Literal["clear", "veto", "undetermined"]
    observed_at: datetime
    provenance_id: str
    constraint_type: SoulConstraintType | None = None
    constraint_id: str | None = None
    authority: str | None = None
    undetermined_reason: SoulUndeterminedReason | None = None


@dataclass(frozen=True, slots=True, init=False)
class SoulConstraint:
    framework_id: str
    constraint_type: SoulConstraintType
    constraint_id: str
    authority: str
    provenance_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("SoulConstraint values are created by assess_soul()")


@dataclass(frozen=True, slots=True, init=False)
class SoulFrameworkOutcome:
    framework_id: str
    state: SoulAssessmentState
    observed_at: datetime | None
    provenance_id: str | None
    constraint: SoulConstraint | None
    undetermined_reason: SoulUndeterminedReason | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("SoulFrameworkOutcome values are created by assess_soul()")


@dataclass(frozen=True, slots=True, init=False)
class SoulAssessment:
    profile_ref: ProfileRef
    profile_digest: str
    action_id: str
    action_digest: str
    cutoff: datetime
    state: SoulAssessmentState
    vetoed: bool
    reason_code: str | None
    outcomes: tuple[SoulFrameworkOutcome, ...]
    constraints: tuple[SoulConstraint, ...]
    undetermined_frameworks: tuple[str, ...]
    digest: str
    _profile: DeploymentProfile = field(repr=False, compare=False)
    _action: ValidatedActionDemand = field(repr=False, compare=False)
    _declarations: tuple[SoulResponseDeclaration, ...] = field(
        repr=False, compare=False
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("SoulAssessment values are created by assess_soul()")


__all__ = [
    "SoulAssessment",
    "SoulAssessmentState",
    "SoulConstraint",
    "SoulConstraintType",
    "SoulFrameworkOutcome",
    "SoulResponseDeclaration",
    "SoulUndeterminedReason",
]
