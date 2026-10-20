"""Immutable represented values for effective trust and its velocity."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING

from .profile import ProfileRef

if TYPE_CHECKING:
    from .action import ValidatedActionDemand
    from .profile import DeploymentProfile
    from .risk import RiskResult
    from .soul import SoulAssessment
    from .standing import StandingSnapshot


class TrustTier(StrEnum):
    HIBERNATION = "hibernation"
    OBSERVER = "observer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


@dataclass(frozen=True, slots=True, init=False)
class TrustSnapshot:
    profile_ref: ProfileRef
    profile_digest: str
    subject: str
    action_id: str
    action_digest: str
    action_class: str
    standing_digest: str
    risk_digest: str
    soul_digest: str
    observed_at: datetime
    base_trust: Decimal
    risk: Decimal
    effective_trust: Decimal
    tier: TrustTier
    digest: str
    _profile: DeploymentProfile = field(repr=False, compare=False)
    _standing: StandingSnapshot = field(repr=False, compare=False)
    _risk_result: RiskResult = field(repr=False, compare=False)
    _soul: SoulAssessment = field(repr=False, compare=False)
    _action: ValidatedActionDemand = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "TrustSnapshot values are created by calculate_effective_trust()"
        )


@dataclass(frozen=True, slots=True, init=False)
class TrustVelocity:
    subject: str
    profile_ref: ProfileRef
    profile_digest: str
    action_class: str
    value: Decimal
    previous_digest: str
    current_digest: str
    previous_at: datetime
    current_at: datetime
    elapsed_seconds: Decimal
    digest: str
    _previous: TrustSnapshot = field(repr=False, compare=False)
    _current: TrustSnapshot = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("TrustVelocity values are created by calculate_velocity()")


__all__ = ["TrustSnapshot", "TrustTier", "TrustVelocity"]
