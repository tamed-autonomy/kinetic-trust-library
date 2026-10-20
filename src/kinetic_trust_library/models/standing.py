"""Immutable declarations and derived values for PoR and agent standing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, TypeAlias

from kinetic_trust_library._decimal import DecimalLike

if TYPE_CHECKING:
    from .profile import DeploymentProfile


class FrictionCategory(StrEnum):
    ELEVATED = "elevated"
    HIGH = "high"
    SEVERE = "severe"
    CRISIS = "crisis"


@dataclass(frozen=True, slots=True)
class PoRAttestationDeclaration:
    attestation_id: str
    agent_id: str
    transaction_ref: str
    friction: DecimalLike
    friction_category: FrictionCategory
    action_risk: DecimalLike
    outcome: Literal["success", "graceful_degrade"]
    timestamp: datetime
    oracle_id: str
    verification_ref: str


@dataclass(frozen=True, slots=True, init=False)
class PoRResult:
    eligible_attestation_ids: tuple[str, ...]
    resilience_score: Decimal
    contribution: Decimal
    digest: str
    _agent_id: str
    _cutoff: datetime
    _attestations: tuple[PoRAttestationDeclaration, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("PoRResult values are created by calculate_por()")


class LineagePhase(StrEnum):
    SPONSORED = "sponsored"
    INDEPENDENT = "independent"
    GUARANTOR = "guarantor"


class RootInstrumentStatus(StrEnum):
    CURRENT = "current"
    NON_RENEWABLE = "non_renewable"
    EXPIRED = "expired"
    FOR_CAUSE_PENDING = "for_cause_pending"
    FOR_CAUSE_SUSTAINED = "for_cause_sustained"
    FOR_CAUSE_REJECTED = "for_cause_rejected"
    FOR_CAUSE_UNRESOLVED = "for_cause_unresolved"
    MISATTESTATION = "misattestation"
    NONE = "none"


class ExternalTerminatorKind(StrEnum):
    LEGAL_ENTITY = "legal_entity"
    NAMED_HUMAN = "named_human"
    PHYSICAL_PRESENCE = "physical_presence"


class WithdrawalCause(StrEnum):
    WITHOUT_CAUSE = "without_cause"
    FOR_CAUSE = "for_cause"


class AdjudicationFindingOutcome(StrEnum):
    FOR_CAUSE_SUSTAINED = "for_cause_sustained"
    FOR_CAUSE_REJECTED = "for_cause_rejected"
    MISATTESTATION = "misattestation"


@dataclass(frozen=True, slots=True)
class RootIssuanceDeclaration:
    issued_at: datetime
    end_time: datetime
    verification_ref: str


@dataclass(frozen=True, slots=True)
class RootWithdrawalClaim:
    claim_id: str
    declared_by: str
    cause: WithdrawalCause
    claimed_at: datetime
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class RootAdjudicationFinding:
    finding_id: str
    adjudicator_id: str
    outcome: AdjudicationFindingOutcome
    found_at: datetime
    claim_id: str | None
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class ExternalTerminatorDeclaration:
    kind: ExternalTerminatorKind
    identifier: str
    verification_ref: str


@dataclass(frozen=True, slots=True)
class RootInstrumentDeclaration:
    instrument_id: str
    attestor: str
    issuance: RootIssuanceDeclaration
    sponsor_standing: StandingSnapshot | None
    stake_percentage: DecimalLike | None
    exposure_class: str | None
    declared_exposure: DecimalLike | None
    anchored_capacity: DecimalLike | None
    chain: tuple[str, ...]
    terminator: ExternalTerminatorDeclaration
    withdrawal_claim: RootWithdrawalClaim | None
    adjudication_finding: RootAdjudicationFinding | None


@dataclass(frozen=True, slots=True)
class NoRootInstrumentDeclaration:
    instrument_id: str


RootDeclaration: TypeAlias = RootInstrumentDeclaration | NoRootInstrumentDeclaration


@dataclass(frozen=True, slots=True)
class PeerScoreDeclaration:
    score: DecimalLike
    source_id: str
    evidence_ids: tuple[str, ...]
    provenance_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CeilingDeclaration:
    name: str
    value: DecimalLike
    provenance_id: str


@dataclass(frozen=True, slots=True)
class StandingDeclaration:
    agent_id: str
    generation: int
    identity_assurance_level: int
    trajectory_length: int
    por_attestations: tuple[PoRAttestationDeclaration, ...]
    root_instruments: tuple[RootDeclaration, ...]
    peer: PeerScoreDeclaration | None
    additional_ceilings: tuple[CeilingDeclaration, ...]
    advancement_floor: DecimalLike


@dataclass(frozen=True, slots=True)
class ShareAllocation:
    por: Decimal
    root: Decimal
    peer: Decimal


@dataclass(frozen=True, slots=True, init=False)
class StandingSnapshot:
    agent_id: str
    generation: int
    lineage: LineagePhase
    por: PoRResult
    root_score: Decimal
    root_instrument: RootDeclaration
    root_status: RootInstrumentStatus
    peer: PeerScoreDeclaration | None
    shares: ShareAllocation
    applicable_ceilings: tuple[CeilingDeclaration, ...]
    advancement_floor: Decimal
    base_trust: Decimal
    digest: str
    _profile: DeploymentProfile = field(repr=False, compare=False)
    _declaration: StandingDeclaration = field(repr=False, compare=False)
    _cutoff: datetime = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("StandingSnapshot values are created by prepare_standing()")


__all__ = [
    "AdjudicationFindingOutcome",
    "CeilingDeclaration",
    "ExternalTerminatorDeclaration",
    "ExternalTerminatorKind",
    "FrictionCategory",
    "LineagePhase",
    "NoRootInstrumentDeclaration",
    "PeerScoreDeclaration",
    "PoRAttestationDeclaration",
    "PoRResult",
    "RootAdjudicationFinding",
    "RootDeclaration",
    "RootInstrumentDeclaration",
    "RootInstrumentStatus",
    "RootIssuanceDeclaration",
    "RootWithdrawalClaim",
    "ShareAllocation",
    "StandingDeclaration",
    "StandingSnapshot",
    "WithdrawalCause",
]
