"""Immutable Kinetic Envelope results and pure evaluation request values."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING

from .profile import ProfileRef
from .trust import TrustTier

if TYPE_CHECKING:
    from .action import NormativeGateToken, ValidatedActionDemand
    from .capacity import CoreCapacityResult
    from .evidence import EvidenceSnapshot, ObservationDeclaration
    from .profile import DeploymentProfile
    from .risk import RiskResult
    from .soul import SoulAssessment, SoulResponseDeclaration
    from .standing import StandingDeclaration, StandingSnapshot
    from .trust import TrustSnapshot, TrustVelocity


class Supervision(StrEnum):
    STABLE = "stable"
    METACOGNITIVE = "metacognitive"
    ASSISTED = "assisted"
    REGULATED = "regulated"
    SILENT_VETO = "silent_veto"


class EvaluationStage(StrEnum):
    CAPABILITY = "capability"
    SOUL = "soul"
    STANDING = "standing"
    EVIDENCE = "evidence"
    RISK = "risk"
    TRUST = "trust"
    TIER = "tier"
    CORE_CAPACITY = "core_capacity"
    ENVELOPE = "envelope"


class UndefinedInputLayer(StrEnum):
    FEED = "feed"
    SIGNAL = "signal"
    TERM = "term"
    QUERY = "query"
    GATE = "gate"


class NormativeGateState(StrEnum):
    CLEAR = "clear"
    VETO = "veto"
    UNDETERMINED = "undetermined"
    MISSING = "missing"


class RejectionReason(StrEnum):
    """Library validation outcome, not product recovery or transport policy."""

    INVALID_DECLARATION = "invalid_declaration"


@dataclass(frozen=True, slots=True, init=False)
class ConstraintCeiling:
    magnitude: str
    unit: str
    maximum: Decimal

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("ConstraintCeiling values are derived by compute_envelope()")


@dataclass(frozen=True, slots=True, init=False)
class TightenedConstraints:
    profile_ref: ProfileRef
    profile_digest: str
    action_class: str
    ceilings: tuple[ConstraintCeiling, ...]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("TightenedConstraints values are derived by compute_envelope()")


@dataclass(frozen=True, slots=True, init=False)
class UndefinedInput:
    input_id: str
    layer: UndefinedInputLayer
    reason: str
    provenance_ids: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("UndefinedInput values are derived by compute_envelope()")


@dataclass(frozen=True, slots=True, init=False)
class NormativeGateOutcome:
    gate_id: str
    schema_uri: str
    required: bool
    state: NormativeGateState
    token: NormativeGateToken | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("NormativeGateOutcome values are derived by compute_envelope()")


@dataclass(frozen=True, slots=True, init=False)
class KineticEnvelopeResult:
    operation_id: str
    profile_ref: ProfileRef
    profile_digest: str
    action_id: str
    action_digest: str
    core_capacity_digest: str | None
    cutoff: datetime
    autonomy_demand: Decimal
    environmental_capacity: Decimal | None
    margin: Decimal | None
    capacity_known: bool
    tightened_constraints: TightenedConstraints
    supervision: Supervision
    policy_code: str | None
    rationale: tuple[str, ...]
    tier: TrustTier | None
    normative_gate_outcomes: tuple[NormativeGateOutcome, ...] | None
    undefined_inputs: tuple[UndefinedInput, ...]
    trace: tuple[EvaluationStage, ...]
    digest: str
    _profile: DeploymentProfile = field(repr=False, compare=False)
    _action: ValidatedActionDemand = field(repr=False, compare=False)
    _soul: SoulAssessment = field(repr=False, compare=False)
    _trust: TrustSnapshot | None = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "KineticEnvelopeResult values are derived by compute_envelope()"
        )


@dataclass(frozen=True, slots=True)
class EvaluationRequest:
    """One pure evaluation request with capability already owned by its action."""

    operation_id: str
    profile: DeploymentProfile
    action: ValidatedActionDemand
    standing: StandingDeclaration
    observations: tuple[ObservationDeclaration, ...]
    soul_responses: tuple[SoulResponseDeclaration, ...]
    cutoff: datetime
    previous_trust: TrustSnapshot | None = None


@dataclass(frozen=True, slots=True, init=False)
class RejectedRequest:
    reason_code: RejectionReason
    failed_stage: EvaluationStage
    trace: tuple[EvaluationStage, ...]
    rationale: tuple[str, ...]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("RejectedRequest values are created by evaluate()")


@dataclass(frozen=True, slots=True, init=False)
class EvaluationBundle:
    profile_ref: ProfileRef
    profile_digest: str
    operation_id: str
    cutoff: datetime
    action: ValidatedActionDemand
    soul: SoulAssessment
    standing: StandingSnapshot | None
    evidence: EvidenceSnapshot | None
    risk: RiskResult | None
    trust: TrustSnapshot | None
    velocity: TrustVelocity | None
    core_capacity: CoreCapacityResult | None
    envelope: KineticEnvelopeResult
    digest: str
    _request: EvaluationRequest | None = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("EvaluationBundle values are created by evaluate()")


__all__ = [
    "ConstraintCeiling",
    "EvaluationBundle",
    "EvaluationRequest",
    "EvaluationStage",
    "KineticEnvelopeResult",
    "NormativeGateOutcome",
    "NormativeGateState",
    "RejectedRequest",
    "RejectionReason",
    "Supervision",
    "TightenedConstraints",
    "UndefinedInput",
    "UndefinedInputLayer",
]
