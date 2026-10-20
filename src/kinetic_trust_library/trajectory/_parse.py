from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal
from types import MappingProxyType
from typing import Iterator, Mapping

from ..errors import ValidationError
from ._json import _freeze_json, _number, _object
from ._models import (
    TrajectoryAction,
    TrajectoryAgentState,
    TrajectoryOracleAttestation,
    TrajectoryTransaction,
)
from ._time import _validate_rfc3339


def _ranged(value: object, name: str, maximum: int | None = None) -> Decimal:
    number = _number(value, name)
    if number < 0 or (maximum is not None and number > maximum):
        raise ValidationError(f"{name} is outside its range")
    return number


def _integer(value: object, name: str) -> int:
    number = _ranged(value, name)
    if number != number.to_integral_value():
        raise ValidationError(f"{name} must be mathematically integral")
    return int(number)


_STATE = frozenset(("e_base", "e_trust", "location", "tier", "lineage", "generation"))
_ACTION = frozenset(("action_type", "action_risk", "result"))
_ORACLE = frozenset(("oracle_id", "attestation_time", "risk_factors", "oracle_signature"))
_TRANSACTION = frozenset((
    "record_id", "chain_id", "sequence", "timestamp", "current_state", "action",
    "friction", "velocity", "agent_signature", "oracle_attestation", "record_hash",
))
_RISK = frozenset((
    "adversarial_pressure", "attestation_coverage", "evidence_density",
    "moment_criticality", "trust_trend", "update_resistance",
))


@contextmanager
def _schema_object(
    value: object, name: str, required: frozenset[str], active: set[int],
) -> Iterator[dict[str, object]]:
    with _object(value, name, active) as snapshot:
        missing = required - snapshot.keys()
        if missing:
            raise ValidationError(f"{name} is missing {', '.join(sorted(missing))}")
        yield snapshot


def _string(value: object, name: str, choices: tuple[str, ...] = ()) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    if choices and value not in choices:
        raise ValidationError(f"{name} is not a supported value")
    return value


def _optional_string(value: object, name: str) -> str | None:
    return None if value is None else _string(value, name)


def _extensions(
    data: dict[str, object], known: frozenset[str], name: str, active: set[int],
) -> Mapping[str, object]:
    return MappingProxyType({
        key: _freeze_json(value, f"{name}.{key}", active)
        for key, value in data.items() if key not in known
    })


def _state(value: object, name: str, active: set[int]) -> TrajectoryAgentState:
    with _schema_object(value, name, _STATE, active) as data:
        return TrajectoryAgentState(
            e_base=_ranged(data["e_base"], f"{name}.e_base", 100),
            e_trust=_ranged(data["e_trust"], f"{name}.e_trust", 100),
            location=_string(data["location"], f"{name}.location"),
            tier=_string(data["tier"], f"{name}.tier", (
                "hibernation", "observer", "analyst", "operator", "admin",
            )),
            lineage=_string(data["lineage"], f"{name}.lineage", (
                "sponsored", "independent", "guarantor",
            )),
            generation=_integer(data["generation"], f"{name}.generation"),
            extensions=_extensions(data, _STATE, name, active),
        )


def _action(value: object, active: set[int]) -> TrajectoryAction:
    with _schema_object(value, "action", _ACTION, active) as data:
        details = None
        if "details" in data:
            if not isinstance(data["details"], Mapping):
                raise ValidationError("action.details must be an object")
            details = _freeze_json(data["details"], "action.details", active)
        return TrajectoryAction(
            action_type=_string(data["action_type"], "action.action_type"),
            action_risk=_ranged(data["action_risk"], "action.action_risk", 100),
            target=_optional_string(data.get("target"), "action.target"),
            result=_string(data["result"], "action.result", ("success", "denied")),
            details=details,
            extensions=_extensions(data, _ACTION | {"target", "details"}, "action", active),
        )


def _oracle(value: object, active: set[int]) -> TrajectoryOracleAttestation:
    with _schema_object(value, "oracle_attestation", _ORACLE, active) as data:
        with _schema_object(data["risk_factors"], "risk_factors", _RISK, active) as risk:
            if risk.keys() - _RISK:
                raise ValidationError("risk_factors contains unknown members")
            factors = MappingProxyType({
                key: _ranged(item, f"risk_factors.{key}", 1)
                for key, item in risk.items()
            })
        return TrajectoryOracleAttestation(
            oracle_id=_string(data["oracle_id"], "oracle_attestation.oracle_id"),
            attestation_time=_validate_rfc3339(
                data["attestation_time"], "oracle_attestation.attestation_time",
            ),
            risk_factors=factors,
            oracle_signature=_string(data["oracle_signature"], "oracle_attestation.oracle_signature"),
            extensions=_extensions(data, _ORACLE, "oracle_attestation", active),
        )


def parse_trajectory_transaction(data: Mapping[str, object], /) -> TrajectoryTransaction:
    """Validate the v2.1 schema and Library time rules, without authentication."""
    active: set[int] = set()
    with _schema_object(data, "transaction", _TRANSACTION, active) as snapshot:
        previous = snapshot.get("previous_state")
        return TrajectoryTransaction(
            record_id=_string(snapshot["record_id"], "record_id"),
            chain_id=_string(snapshot["chain_id"], "chain_id"),
            sequence=_integer(snapshot["sequence"], "sequence"),
            timestamp=_validate_rfc3339(snapshot["timestamp"], "timestamp"),
            previous_hash=_optional_string(snapshot.get("previous_hash"), "previous_hash"),
            previous_state=None if previous is None else _state(previous, "previous_state", active),
            current_state=_state(snapshot["current_state"], "current_state", active),
            action=_action(snapshot["action"], active),
            friction=_ranged(snapshot["friction"], "friction", 1),
            velocity=_ranged(snapshot["velocity"], "velocity"),
            agent_signature=_string(snapshot["agent_signature"], "agent_signature"),
            oracle_attestation=_oracle(snapshot["oracle_attestation"], active),
            record_hash=_string(snapshot["record_hash"], "record_hash"),
            extensions=_extensions(
                snapshot, _TRANSACTION | {"previous_hash", "previous_state"}, "transaction", active,
            ),
        )
