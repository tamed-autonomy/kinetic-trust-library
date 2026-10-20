from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Literal

from .capacity import CapacityRelation
from .envelope import (
    EvaluationStage,
    NormativeGateOutcome,
    Supervision,
    TightenedConstraints,
    UndefinedInput,
)
from .profile import ProfileRef
from .risk import (
    DomainRiskResult,
    MomentCriticalityResult,
    RiskContext,
    SignalFactorResult,
)
from .soul import SoulAssessmentState, SoulConstraint, SoulFrameworkOutcome
from .trust import TrustTier


@dataclass(frozen=True, slots=True, init=False)
class DecisionRecord:
    record_profile: Literal["ktp-python-decision-record-v1"]
    record_id: str
    evaluated_at: datetime
    profile_ref: ProfileRef
    profile_digest: str
    subject: str
    action_id: str
    action_digest: str
    autonomy_demand: Decimal
    evaluation_digest: str
    soul_digest: str
    standing_digest: str | None
    evidence_digest: str | None
    risk_digest: str | None
    trust_digest: str | None
    velocity_digest: str | None
    core_capacity_digest: str | None
    capacity_relation: CapacityRelation | None
    envelope_digest: str
    soul_state: SoulAssessmentState
    soul_outcomes: tuple[SoulFrameworkOutcome, ...]
    soul_constraints: tuple[SoulConstraint, ...]
    undetermined_frameworks: tuple[str, ...]
    risk_context: RiskContext | None
    risk_factors: tuple[SignalFactorResult | MomentCriticalityResult, ...] | None
    domain_risks: tuple[DomainRiskResult, ...] | None
    base_trust: Decimal | None
    risk: Decimal | None
    effective_trust: Decimal | None
    tier: TrustTier | None
    velocity: Decimal | None
    environmental_capacity: Decimal | None
    capacity_known: bool
    margin: Decimal | None
    supervision: Supervision
    tightened_constraints: TightenedConstraints
    policy_code: str | None
    normative_gate_outcomes: tuple[NormativeGateOutcome, ...] | None
    rationale: tuple[str, ...]
    undefined_inputs: tuple[UndefinedInput, ...]
    trace: tuple[EvaluationStage, ...]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("DecisionRecord values are created by Library record operations")


__all__ = ["DecisionRecord"]
