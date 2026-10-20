from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Mapping


class TrajectoryLinkFinding(StrEnum):
    CHAIN_ID_MISMATCH = "CHAIN_ID_MISMATCH"
    SEQUENCE_DISCONTINUITY = "SEQUENCE_DISCONTINUITY"
    MISSING_PREVIOUS_HASH = "MISSING_PREVIOUS_HASH"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    TIMESTAMP_ORDER_UNDEFINED = "TIMESTAMP_ORDER_UNDEFINED"
    NON_INCREASING_TIMESTAMP = "NON_INCREASING_TIMESTAMP"
    MISSING_PREVIOUS_STATE = "MISSING_PREVIOUS_STATE"
    PREVIOUS_STATE_MISMATCH = "PREVIOUS_STATE_MISMATCH"


@dataclass(frozen=True, slots=True)
class TrajectoryAgentState:
    e_base: Decimal
    e_trust: Decimal
    location: str
    tier: str
    lineage: str
    generation: int
    extensions: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class TrajectoryAction:
    action_type: str
    action_risk: Decimal
    target: str | None
    result: str
    details: Mapping[str, object] | None
    extensions: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class TrajectoryOracleAttestation:
    oracle_id: str
    attestation_time: str
    risk_factors: Mapping[str, Decimal]
    oracle_signature: str
    extensions: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class TrajectoryTransaction:
    record_id: str
    chain_id: str
    sequence: int
    timestamp: str
    previous_hash: str | None
    previous_state: TrajectoryAgentState | None
    current_state: TrajectoryAgentState
    action: TrajectoryAction
    friction: Decimal
    velocity: Decimal
    agent_signature: str
    oracle_attestation: TrajectoryOracleAttestation
    record_hash: str
    extensions: Mapping[str, object]
