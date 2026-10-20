"""Immutable observation declarations and prepared evidence snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, TypeAlias

from kinetic_trust_library.errors import ValidationError

from .profile import ProfileRef, RiskDomain

if TYPE_CHECKING:
    from .profile import DeploymentProfile


class ObservationClass(StrEnum):
    DIRECT = "D"
    ENUMERATED = "N"
    ADJUDICATED = "A"
    PUBLISHED = "P"
    DERIVED_STATE = "S"


class PopulationState(StrEnum):
    OBSERVED = "observed"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class DirectMeasurementEnvelope:
    subject: str
    modality: str
    instrument_make_model: str
    calibration_at: datetime
    calibration_reference: str


@dataclass(frozen=True, slots=True)
class EnumeratedMeasurementEnvelope:
    subject_boundary: str
    population: str
    membership_rule: str
    reset_semantics: str
    membership_mode: Literal["enumerated", "inferred"]
    instrument_identity: str | None = None
    instrument_version: str | None = None


@dataclass(frozen=True, slots=True)
class AdjudicatedMeasurementEnvelope:
    issuing_authority: str
    authority_scope: str
    measurement_party: str
    record_set: str
    adjudication_criteria: str
    criteria_version: str


@dataclass(frozen=True, slots=True)
class PublishedMeasurementEnvelope:
    publisher_universe_reference: str
    population_reference: str
    publisher: str
    series_id: str


@dataclass(frozen=True, slots=True)
class DerivedStateMeasurementEnvelope:
    scope: str
    authoritative_source: str
    source_version: str


MeasurementEnvelope: TypeAlias = (
    DirectMeasurementEnvelope
    | EnumeratedMeasurementEnvelope
    | AdjudicatedMeasurementEnvelope
    | PublishedMeasurementEnvelope
    | DerivedStateMeasurementEnvelope
)

ObservationValue: TypeAlias = bool | int | Decimal | str | datetime


@dataclass(frozen=True, slots=True)
class ObservationWindow:
    start: datetime
    end: datetime


@dataclass(frozen=True, slots=True)
class PublishedObservationPeriod:
    start: datetime
    end: datetime
    published_at: datetime
    publication_lag_ms: int
    vintage: str


@dataclass(frozen=True, slots=True)
class OnDemandQueryBinding:
    operation_id: str
    requested_at: datetime


@dataclass(frozen=True, slots=True)
class ObservationDeclaration:
    observation_id: str
    source_id: str
    sequence: int
    signal_id: str
    domain: RiskDomain
    observation_class: ObservationClass
    measurement_envelope: MeasurementEnvelope
    raw_value: ObservationValue | None
    unit: str
    observed_at: datetime
    ingested_at: datetime
    valid_until: datetime | None = None
    population_state: PopulationState | None = None
    window: ObservationWindow | None = None
    published_period: PublishedObservationPeriod | None = None
    on_demand_binding: OnDemandQueryBinding | None = None


@dataclass(frozen=True, slots=True)
class EvaluatedObservation:
    """Owned declaration facts evaluated for one profile-bound feed route."""

    observation_id: str
    sequence: int
    observation_class: ObservationClass
    measurement_envelope: MeasurementEnvelope
    raw_value: ObservationValue | None
    observed_at: datetime
    ingested_at: datetime
    valid_until: datetime | None
    population_state: PopulationState | None
    window: ObservationWindow | None
    published_period: PublishedObservationPeriod | None
    on_demand_binding: OnDemandQueryBinding | None


@dataclass(frozen=True, slots=True)
class SelectedObservation:
    observation_id: str
    source_id: str
    sequence: int
    signal_id: str
    domain: RiskDomain
    observation_class: ObservationClass
    measurement_envelope: MeasurementEnvelope
    raw_value: ObservationValue
    unit: str
    population_state: PopulationState | None
    window: ObservationWindow | None
    published_period: PublishedObservationPeriod | None
    on_demand_binding: OnDemandQueryBinding | None
    normalized: Decimal
    observed_at: datetime
    ingested_at: datetime
    valid_until: datetime | None
    provenance_digest: str


class UndefinedReason(StrEnum):
    NO_ELIGIBLE_OBSERVATION = "no_eligible_observation"
    EXPIRED = "expired"
    STALE = "stale"
    SOURCE_UNAVAILABLE = "source_unavailable"
    EMPTY_WINDOW = "empty_window"


class FeedOutcomeState(StrEnum):
    SELECTED = "selected"
    NO_ELIGIBLE_OBSERVATION = "no_eligible_observation"
    EXPIRED = "expired"
    STALE = "stale"
    SOURCE_UNAVAILABLE = "source_unavailable"
    EMPTY_WINDOW = "empty_window"


@dataclass(frozen=True, slots=True)
class SelectedFeedOutcome:
    state: FeedOutcomeState
    observation: SelectedObservation
    evaluated_observations: tuple[EvaluatedObservation, ...]
    provenance_digest: str

    @property
    def source_id(self) -> str:
        return self.observation.source_id


@dataclass(frozen=True, slots=True)
class UndefinedFeedOutcome:
    source_id: str
    state: FeedOutcomeState
    evaluated_observations: tuple[EvaluatedObservation, ...]
    provenance_digest: str


FeedEvidenceOutcome: TypeAlias = SelectedFeedOutcome | UndefinedFeedOutcome


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    signal_id: str
    domain: RiskDomain
    feed_outcomes: tuple[FeedEvidenceOutcome, ...]
    normalized: Decimal | None
    undefined_reason: UndefinedReason | None

    @property
    def selected_observations(self) -> tuple[SelectedObservation, ...]:
        return tuple(
            outcome.observation
            for outcome in self.feed_outcomes
            if type(outcome) is SelectedFeedOutcome
        )


@dataclass(frozen=True, slots=True, init=False)
class EvidenceSnapshot:
    _profile: DeploymentProfile = field(repr=False, compare=False)
    profile_ref: ProfileRef
    profile_digest: str
    operation_id: str
    cutoff: datetime
    entries: tuple[EvidenceEntry, ...]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("EvidenceSnapshot values are created by prepare_evidence()")

    def selected(
        self,
        signal_id: str,
        *,
        domain: RiskDomain,
        profile: DeploymentProfile | None = None,
    ) -> EvidenceEntry:
        """Return the unique prepared entry for an exact domain and signal."""
        from kinetic_trust_library._catalog import validate_signal_id
        from kinetic_trust_library.core.evidence import require_validated_evidence_snapshot

        require_validated_evidence_snapshot(self, profile=profile)

        if type(domain) is not RiskDomain:
            raise ValidationError("evidence domain must be a RiskDomain")
        try:
            if type(signal_id) is not str:
                raise TypeError
            signal = validate_signal_id(signal_id)
        except (TypeError, ValueError) as exc:
            raise ValidationError(str(exc)) from exc
        for entry in self.entries:
            if entry.domain is domain and entry.signal_id == signal:
                return entry
        raise ValidationError(
            f"evidence snapshot has no entry for {domain.value}/{signal}"
        )

    def undefined(
        self,
        signal_id: str,
        *,
        domain: RiskDomain,
        profile: DeploymentProfile | None = None,
    ) -> UndefinedReason | None:
        """Return the undefined reason for an exact prepared entry, if any."""
        return self.selected(signal_id, domain=domain, profile=profile).undefined_reason


__all__ = [
    "AdjudicatedMeasurementEnvelope",
    "DerivedStateMeasurementEnvelope",
    "DirectMeasurementEnvelope",
    "EnumeratedMeasurementEnvelope",
    "EvaluatedObservation",
    "EvidenceEntry",
    "EvidenceSnapshot",
    "FeedEvidenceOutcome",
    "FeedOutcomeState",
    "MeasurementEnvelope",
    "ObservationClass",
    "ObservationDeclaration",
    "ObservationValue",
    "ObservationWindow",
    "OnDemandQueryBinding",
    "PopulationState",
    "PublishedMeasurementEnvelope",
    "PublishedObservationPeriod",
    "SelectedFeedOutcome",
    "SelectedObservation",
    "UndefinedFeedOutcome",
    "UndefinedReason",
]
