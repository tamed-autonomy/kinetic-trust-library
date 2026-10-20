from __future__ import annotations

from datetime import datetime, timedelta

from kinetic_trust_library import EvaluationBundle
from kinetic_trust_library.core import evaluate
from kinetic_trust_library.models.evidence import (
    AdjudicatedMeasurementEnvelope,
    EnumeratedMeasurementEnvelope,
    ObservationClass,
    ObservationDeclaration,
    ObservationWindow,
    PopulationState,
    PublishedMeasurementEnvelope,
    PublishedObservationPeriod,
)
from kinetic_trust_library.models.profile import RiskDomain

from _support import CUTOFF, SIGNALS, build_observations, build_request


def require_string(payload: dict[str, object], key: str) -> str:
    value = payload[key]
    if type(value) is not str:
        raise TypeError(f"{key} must be an exact string")
    return value


def require_int(payload: dict[str, object], key: str) -> int:
    value = payload[key]
    if type(value) is not int:
        raise TypeError(f"{key} must be an exact integer")
    return value


def require_datetime(payload: dict[str, object], key: str) -> datetime:
    value = payload[key]
    if type(value) is not datetime:
        raise TypeError(f"{key} must be a datetime")
    return value


COMPUTE_API_RESPONSES = (
    {
        "id": "api:compute:old",
        "sequence": 10,
        "utilization": "0.35",
        "observed_at": CUTOFF - timedelta(seconds=4),
        "ingested_at": CUTOFF - timedelta(seconds=3),
    },
    {
        "id": "api:compute:new",
        "sequence": 11,
        "utilization": "0.25",
        "observed_at": CUTOFF - timedelta(seconds=2),
        "ingested_at": CUTOFF - timedelta(seconds=1),
    },
)
ALARM_API_RESPONSE = {
    "id": "api:alarms:unavailable",
    "sequence": 20,
    "observed_at": CUTOFF - timedelta(seconds=2),
    "ingested_at": CUTOFF - timedelta(seconds=1),
    "available": False,
}
INDEX_API_RESPONSE = {
    "id": "api:index:2026-07",
    "sequence": 30,
    "value": "220",
    "period_start": CUTOFF - timedelta(days=30, seconds=2),
    "period_end": CUTOFF - timedelta(seconds=2),
    "published_at": CUTOFF - timedelta(seconds=1),
    "ingested_at": CUTOFF,
    "vintage": "2026-07",
}


def map_compute_reading(payload: dict[str, object]) -> ObservationDeclaration:
    observed_at = require_datetime(payload, "observed_at")
    ingested_at = require_datetime(payload, "ingested_at")
    return ObservationDeclaration(
        observation_id=require_string(payload, "id"),
        source_id="feed:node:1",
        sequence=require_int(payload, "sequence"),
        signal_id=SIGNALS[1],
        domain=RiskDomain.NODE,
        observation_class=ObservationClass.ENUMERATED,
        measurement_envelope=EnumeratedMeasurementEnvelope(
            subject_boundary="urn:ktp:host:example",
            population="scheduler:tasks",
            membership_rule="task:admitted",
            reset_semantics="window:rolling",
            membership_mode="enumerated",
        ),
        raw_value=require_string(payload, "utilization"),
        unit="ratio",
        observed_at=observed_at,
        ingested_at=ingested_at,
        population_state=PopulationState.OBSERVED,
        window=ObservationWindow(observed_at - timedelta(seconds=1), observed_at),
    )


def map_unavailable_alarm_feed(payload: dict[str, object]) -> ObservationDeclaration:
    observed_at = require_datetime(payload, "observed_at")
    ingested_at = require_datetime(payload, "ingested_at")
    if payload["available"] is not False:
        raise ValueError("this mapping represents an unavailable alarm source")
    return ObservationDeclaration(
        observation_id=require_string(payload, "id"),
        source_id="feed:neighborhood:2",
        sequence=require_int(payload, "sequence"),
        signal_id=SIGNALS[2],
        domain=RiskDomain.NEIGHBORHOOD,
        observation_class=ObservationClass.ADJUDICATED,
        measurement_envelope=AdjudicatedMeasurementEnvelope(
            issuing_authority="authority:security-operations",
            authority_scope="platform:example",
            measurement_party="sensor:alarm-api",
            record_set="alarms:active",
            adjudication_criteria="criteria:active-alarm",
            criteria_version="version:1",
        ),
        raw_value=None,
        unit="count",
        observed_at=observed_at,
        ingested_at=ingested_at,
        population_state=PopulationState.UNAVAILABLE,
        window=ObservationWindow(observed_at - timedelta(seconds=1), observed_at),
    )


def map_published_index(payload: dict[str, object]) -> ObservationDeclaration:
    period_start = require_datetime(payload, "period_start")
    period_end = require_datetime(payload, "period_end")
    published_at = require_datetime(payload, "published_at")
    ingested_at = require_datetime(payload, "ingested_at")
    return ObservationDeclaration(
        observation_id=require_string(payload, "id"),
        source_id="feed:global:3",
        sequence=require_int(payload, "sequence"),
        signal_id=SIGNALS[3],
        domain=RiskDomain.GLOBAL,
        observation_class=ObservationClass.PUBLISHED,
        measurement_envelope=PublishedMeasurementEnvelope(
            publisher_universe_reference="universe:economic-index",
            population_reference="population:economic-index",
            publisher="publisher:example-statistics",
            series_id="series:example-index",
        ),
        raw_value=require_string(payload, "value"),
        unit="index",
        observed_at=published_at,
        ingested_at=ingested_at,
        population_state=PopulationState.OBSERVED,
        published_period=PublishedObservationPeriod(
            start=period_start,
            end=period_end,
            published_at=published_at,
            publication_lag_ms=1_000,
            vintage=require_string(payload, "vintage"),
        ),
    )


def main() -> None:
    replaced_routes = {
        (RiskDomain.NODE, SIGNALS[1]),
        (RiskDomain.NEIGHBORHOOD, SIGNALS[2]),
        (RiskDomain.GLOBAL, SIGNALS[3]),
    }
    observations = tuple(
        observation
        for observation in build_observations()
        if (observation.domain, observation.signal_id) not in replaced_routes
    ) + (
        *(map_compute_reading(payload) for payload in COMPUTE_API_RESPONSES),
        map_unavailable_alarm_feed(ALARM_API_RESPONSE),
        map_published_index(INDEX_API_RESPONSE),
    )
    outcome = evaluate(build_request(observations=observations))
    if (
        type(outcome) is not EvaluationBundle
        or outcome.evidence is None
        or outcome.core_capacity is None
    ):
        raise RuntimeError("mapped observations did not produce evidence")

    compute_entry = outcome.evidence.selected(SIGNALS[1], domain=RiskDomain.NODE)
    alarm_reason = outcome.evidence.undefined(
        SIGNALS[2], domain=RiskDomain.NEIGHBORHOOD
    )
    index_entry = outcome.evidence.selected(SIGNALS[3], domain=RiskDomain.GLOBAL)
    if not compute_entry.selected_observations:
        raise RuntimeError("compute API observations were not selected")
    if alarm_reason is None:
        raise RuntimeError("unavailable alarm source was not preserved")
    if not index_entry.selected_observations:
        raise RuntimeError("published index observation was not selected")

    print("result_type=EvaluationBundle")
    print(
        "selected_compute_observation="
        + compute_entry.selected_observations[0].observation_id
    )
    print(f"unavailable_alarm_reason={alarm_reason.value}")
    print(
        "published_index_observation="
        + index_entry.selected_observations[0].observation_id
    )
    print(f"capacity_relation={outcome.core_capacity.relation.value}")
    print(f"within_capacity={outcome.core_capacity.within_capacity}")
    print(f"envelope_margin={outcome.envelope.margin}")
    print(f"envelope_supervision={outcome.envelope.supervision.value}")
    print("network_calls=0")
    print("action_executed=false")


if __name__ == "__main__":
    main()
