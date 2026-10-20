"""Validate raw observation declarations into one immutable evidence snapshot."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, localcontext
from types import MappingProxyType
from unicodedata import normalize

from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library._catalog import CATALOG, validate_signal_id
from kinetic_trust_library._decimal import KTP_CONTEXT, as_decimal
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import utc_time, validate_identifier
from kinetic_trust_library.models.evidence import (
    AdjudicatedMeasurementEnvelope,
    DerivedStateMeasurementEnvelope,
    DirectMeasurementEnvelope,
    EnumeratedMeasurementEnvelope,
    EvidenceEntry,
    EvidenceSnapshot,
    EvaluatedObservation,
    FeedOutcomeState,
    MeasurementEnvelope,
    ObservationClass,
    ObservationDeclaration,
    ObservationWindow,
    OnDemandQueryBinding,
    PopulationState,
    PublishedMeasurementEnvelope,
    PublishedObservationPeriod,
    SelectedFeedOutcome,
    SelectedObservation,
    UndefinedFeedOutcome,
    UndefinedReason,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    FeedDeclaration,
    IdentityNormalization,
    LabelSetDeclaration,
    MinMaxNormalization,
    RiskDomain,
    SignalRouteDeclaration,
    _ValidatedProfileContext,
    _bind_profile_to_context,
    _profile_from_context,
    _validated_profile_context,
    require_validated_profile as require_validated_profile,
)


@dataclass(frozen=True, slots=True)
class _ValidatedObservation:
    observation_id: str
    source_id: str
    sequence: int
    signal_id: str
    domain: RiskDomain
    observation_class: ObservationClass
    measurement_envelope: MeasurementEnvelope
    raw_value: bool | int | Decimal | str | datetime | None
    unit: str
    observed_at: datetime
    ingested_at: datetime
    valid_until: datetime | None
    population_state: PopulationState | None
    window: ObservationWindow | None
    published_period: PublishedObservationPeriod | None
    on_demand_binding: OnDemandQueryBinding | None


@dataclass(frozen=True, slots=True)
class _IndexedRoute:
    feed: FeedDeclaration
    route: SignalRouteDeclaration
    normalization: IdentityNormalization | MinMaxNormalization | LabelSetDeclaration


@dataclass(frozen=True, slots=True)
class _ProfileEvidenceIndex:
    pairs: tuple[tuple[RiskDomain, str], ...]
    routes: Mapping[tuple[RiskDomain, str, str], _IndexedRoute]
    routes_by_pair: Mapping[tuple[RiskDomain, str], tuple[_IndexedRoute, ...]]


_UNDEFINED_PRECEDENCE = (
    UndefinedReason.STALE,
    UndefinedReason.EXPIRED,
    UndefinedReason.SOURCE_UNAVAILABLE,
    UndefinedReason.EMPTY_WINDOW,
    UndefinedReason.NO_ELIGIBLE_OBSERVATION,
)
_MAX_OBSERVATION_SEQUENCE = (1 << 63) - 1
# Implementation-safety limits, not KTP or product policy. One observation for
# every signal in the pinned 1,644-signal catalogue fits within the total bound
# with 24% headroom; one route retains at most a 64-reading operation history.
MAX_EVIDENCE_DECLARATIONS = 2048
MAX_EVIDENCE_CANDIDATES_PER_ROUTE = 64


def _profile_evidence_index(profile: DeploymentProfile) -> _ProfileEvidenceIndex:
    """Index one already-validated profile without invoking public accessors."""
    aggregations = (
        profile.risk_factors.evidence_density.aggregation,
        profile.risk_factors.trust_trend.aggregation,
        profile.risk_factors.adversarial_pressure.aggregation,
        profile.risk_factors.update_resistance.aggregation,
        profile.risk_factors.attestation_coverage.aggregation,
    )
    signals = tuple(
        sorted(
            {
                signal
                for aggregation in aggregations
                for signal in aggregation.signals
            }
        )
    )
    pairs = tuple(
        (domain, signal) for domain in RiskDomain for signal in signals
    )

    mutable_by_pair: dict[tuple[RiskDomain, str], list[_IndexedRoute]] = {
        pair: [] for pair in pairs
    }
    routes: dict[tuple[RiskDomain, str, str], _IndexedRoute] = {}
    for source_id in sorted(profile.feeds):
        feed = profile.feeds[source_id]
        for route in feed.routes:
            pair = (route.domain, route.signal_id)
            if pair not in mutable_by_pair:
                raise ValidationError(
                    "profile feed route is outside the evidence inventory"
                )
            normalization = profile.normalizations.get(route.signal_id)
            if normalization is None:
                try:
                    normalization = profile.label_sets[route.signal_id]
                except KeyError as exc:
                    raise ValidationError(
                        "profile feed route has no normalization"
                    ) from exc
            indexed = _IndexedRoute(feed, route, normalization)
            key = (route.domain, route.signal_id, source_id)
            if key in routes:
                raise ValidationError("profile evidence routes must be unique")
            routes[key] = indexed
            mutable_by_pair[pair].append(indexed)

    if any(not values for values in mutable_by_pair.values()):
        raise ValidationError("profile evidence route inventory is incomplete")
    return _ProfileEvidenceIndex(
        pairs=tuple(pairs),
        routes=MappingProxyType(routes),
        routes_by_pair=MappingProxyType(
            {pair: tuple(values) for pair, values in mutable_by_pair.items()}
        ),
    )


def _validated_declarations(
    declarations: Iterable[ObservationDeclaration],
    *,
    profile_index: _ProfileEvidenceIndex,
    cutoff: datetime,
    operation_id: str,
) -> tuple[_ValidatedObservation, ...]:
    try:
        iterator = iter(declarations)
    except Exception as exc:
        raise ValidationError("observation declarations must be iterable") from exc

    validated: list[_ValidatedObservation] = []
    observation_ids: set[str] = set()
    sequences: set[tuple[str, int]] = set()
    route_counts: dict[tuple[RiskDomain, str, str], int] = {}
    pulled = 0
    while True:
        try:
            declaration = next(iterator)
        except StopIteration:
            return tuple(validated)
        except Exception as exc:
            raise ValidationError("observation declarations must be iterable") from exc
        pulled += 1
        if pulled > MAX_EVIDENCE_DECLARATIONS:
            raise ValidationError(
                f"total declaration safety limit exceeded ({MAX_EVIDENCE_DECLARATIONS})"
            )
        if type(declaration) is not ObservationDeclaration:
            raise ValidationError("observation must use the explicit declaration")
        value = _validate_observation(
            declaration,
            profile_index=profile_index,
            cutoff=cutoff,
            operation_id=operation_id,
        )
        route_key = (value.domain, value.signal_id, value.source_id)
        indexed_route = profile_index.routes[route_key]
        # Intrinsic validation always precedes this eligibility filter. Valid
        # future cached material is absent from retained and conflict sets.
        if indexed_route.feed.refresh_interval_ms != 0 and value.ingested_at > cutoff:
            continue
        route_count = route_counts.get(route_key, 0) + 1
        if route_count > MAX_EVIDENCE_CANDIDATES_PER_ROUTE:
            raise ValidationError(
                "per-route candidate safety limit exceeded "
                f"({MAX_EVIDENCE_CANDIDATES_PER_ROUTE})"
            )
        route_counts[route_key] = route_count
        if value.observation_id in observation_ids:
            raise ValidationError(f"duplicate observation ID: {value.observation_id}")
        observation_ids.add(value.observation_id)
        sequence_key = (value.source_id, value.sequence)
        if sequence_key in sequences:
            raise ValidationError("conflicting same-source observation sequence")
        sequences.add(sequence_key)
        validated.append(value)


def prepare_evidence(
    profile: DeploymentProfile,
    declarations: Iterable[ObservationDeclaration],
    cutoff: datetime,
    *,
    operation_id: str,
) -> EvidenceSnapshot:
    """Derive a snapshot from the complete bounded iterable supplied now.

    This validates and owns every declaration in this call. It does not prove
    that a provider supplied all real-world evidence or authenticate its source.
    """
    return _prepare_evidence_with_context(
        _validated_profile_context(profile),
        declarations,
        cutoff,
        operation_id=operation_id,
    )


def _prepare_evidence_with_context(
    context: object,
    declarations: Iterable[ObservationDeclaration],
    cutoff: datetime,
    *,
    operation_id: str,
) -> EvidenceSnapshot:
    profile = _profile_from_context(context)
    profile_index = _profile_evidence_index(profile)
    effective_cutoff = utc_time(cutoff, name="evidence cutoff")
    current_operation = _identifier(operation_id, name="evidence operation ID")
    validated = _validated_declarations(
        declarations,
        profile_index=profile_index,
        cutoff=effective_cutoff,
        operation_id=current_operation,
    )

    grouped: dict[tuple[RiskDomain, str, str], list[_ValidatedObservation]] = {}
    for value in validated:
        grouped.setdefault((value.domain, value.signal_id, value.source_id), []).append(
            value
        )

    entries: list[EvidenceEntry] = []
    for domain, signal in profile_index.pairs:
        outcomes: list[SelectedFeedOutcome | UndefinedFeedOutcome] = []
        selections: list[SelectedObservation] = []
        reasons: list[UndefinedReason] = []
        for indexed_route in profile_index.routes_by_pair[(domain, signal)]:
            feed = indexed_route.feed
            selected, reason, evaluated = _select_source_observation(
                grouped.get((domain, signal, feed.source_id), ()),
                feed=feed,
                normalization=indexed_route.normalization,
                profile=profile,
                cutoff=effective_cutoff,
            )
            evaluated_observations = tuple(
                _evaluated_observation(value) for value in evaluated
            )
            if selected is not None:
                selections.append(selected)
                state = FeedOutcomeState.SELECTED
                provenance_digest = _feed_outcome_digest(
                    profile=profile,
                    source_id=feed.source_id,
                    domain=domain,
                    signal_id=signal,
                    state=state,
                    evaluated_observations=evaluated_observations,
                    selected=selected,
                )
                outcomes.append(
                    SelectedFeedOutcome(
                        state,
                        selected,
                        evaluated_observations,
                        provenance_digest,
                    )
                )
            elif reason is not None:
                reasons.append(reason)
                state = FeedOutcomeState(reason.value)
                provenance_digest = _feed_outcome_digest(
                    profile=profile,
                    source_id=feed.source_id,
                    domain=domain,
                    signal_id=signal,
                    state=state,
                    evaluated_observations=evaluated_observations,
                    selected=None,
                )
                outcomes.append(
                    UndefinedFeedOutcome(
                        source_id=feed.source_id,
                        state=state,
                        evaluated_observations=evaluated_observations,
                        provenance_digest=provenance_digest,
                    )
                )
        if selections:
            normalized = _combine_active_sources(profile_index, selections=selections)
            reason = None
        else:
            normalized = None
            reason = _choose_undefined_reason(reasons)
        entries.append(
            EvidenceEntry(
                signal_id=signal,
                domain=domain,
                feed_outcomes=tuple(outcomes),
                normalized=normalized,
                undefined_reason=reason,
            )
        )

    snapshot = object.__new__(EvidenceSnapshot)
    for name, member in (
        ("_profile", profile),
        ("profile_ref", profile.ref),
        ("profile_digest", profile.digest),
        ("operation_id", current_operation),
        ("cutoff", effective_cutoff),
        ("entries", tuple(entries)),
    ):
        object.__setattr__(snapshot, name, member)
    object.__setattr__(snapshot, "digest", canonical_sha256(_snapshot_input(snapshot)))
    _require_snapshot_structure(snapshot, profile=profile, profile_index=profile_index)
    return snapshot


def require_validated_evidence_snapshot(
    value: object, *, profile: DeploymentProfile | None = None
) -> EvidenceSnapshot:
    """Verify internal coherence of the represented snapshot and inventory.

    This detects inconsistent mutation/forgery and rechecks derivation, bounds,
    arithmetic, and digests. It does not authenticate evidence sources or prove
    that the provider supplied every real-world declaration.
    """
    if type(value) is not EvidenceSnapshot:
        raise ValidationError("value is not a validated evidence snapshot")
    try:
        stored_profile = value._profile
        context = _validated_profile_context(
            stored_profile if profile is None else profile
        )
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ValidationError("evidence snapshot integrity is invalid") from exc
    return _require_validated_evidence_snapshot_with_context(value, context)


def _require_validated_evidence_snapshot_with_context(
    value: object,
    context: object,
) -> EvidenceSnapshot:
    """Private evidence verification against one already validated profile."""
    if type(value) is not EvidenceSnapshot:
        raise ValidationError("value is not a validated evidence snapshot")
    try:
        effective_profile = _require_profile_binding(value._profile, context)
        profile_index = _profile_evidence_index(effective_profile)
        _require_snapshot_structure(
            value, profile=effective_profile, profile_index=profile_index
        )
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ValidationError("evidence snapshot integrity is invalid") from exc
    return value


def _require_snapshot_structure(
    value: EvidenceSnapshot,
    *,
    profile: DeploymentProfile,
    profile_index: _ProfileEvidenceIndex,
) -> None:
    from kinetic_trust_library.models.profile import ProfileRef

    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or value.profile_ref != profile.ref
        or _digest(value.profile_digest, name="evidence profile digest")
        != profile.digest
    ):
        raise ValidationError("evidence snapshot belongs to another profile")
    cutoff = utc_time(value.cutoff, name="evidence cutoff")
    operation_id = _identifier(value.operation_id, name="evidence operation ID")
    if type(value.entries) is not tuple:
        raise ValidationError("evidence snapshot entries must be an owned tuple")

    expected_pairs = profile_index.pairs
    if len(value.entries) != len(expected_pairs):
        raise ValidationError("evidence snapshot inventory is incomplete")
    _require_candidate_inventory_bounds(
        value.entries, expected_pairs=expected_pairs, profile_index=profile_index
    )
    observation_ids: set[str] = set()
    sequences: set[tuple[str, int]] = set()
    for entry, expected_pair in zip(value.entries, expected_pairs, strict=True):
        _require_entry_structure(
            entry,
            expected_pair=expected_pair,
            profile=profile,
            profile_index=profile_index,
            cutoff=cutoff,
            operation_id=operation_id,
            observation_ids=observation_ids,
            sequences=sequences,
        )
    digest = _digest(value.digest, name="evidence snapshot digest")
    if digest != canonical_sha256(_snapshot_input(value)):
        raise ValidationError("evidence snapshot digest does not match its contents")


def _require_profile_binding(
    stored: object,
    context: _ValidatedProfileContext,
) -> DeploymentProfile:
    try:
        return _bind_profile_to_context(context, stored)
    except (AttributeError, ValidationError) as exc:
        raise ValidationError("evidence snapshot belongs to another profile") from exc


def _require_candidate_inventory_bounds(
    entries: tuple[EvidenceEntry, ...],
    *,
    expected_pairs: tuple[tuple[RiskDomain, str], ...],
    profile_index: _ProfileEvidenceIndex,
) -> None:
    total = 0
    for entry, (domain, signal_id) in zip(entries, expected_pairs, strict=True):
        if type(entry) is not EvidenceEntry or type(entry.feed_outcomes) is not tuple:
            raise ValidationError("evidence entry inventory is invalid")
        routes = profile_index.routes_by_pair[(domain, signal_id)]
        if len(entry.feed_outcomes) != len(routes):
            raise ValidationError("evidence entry feed inventory is incomplete")
        for outcome in entry.feed_outcomes:
            if type(outcome) not in (SelectedFeedOutcome, UndefinedFeedOutcome):
                raise ValidationError("feed outcome has the wrong type")
            candidates = outcome.evaluated_observations
            if type(candidates) is not tuple:
                raise ValidationError(
                    "feed outcome candidate inventory must be a tuple"
                )
            count = len(candidates)
            if count > MAX_EVIDENCE_CANDIDATES_PER_ROUTE:
                raise ValidationError(
                    "per-route candidate safety limit exceeded "
                    f"({MAX_EVIDENCE_CANDIDATES_PER_ROUTE})"
                )
            total += count
            if total > MAX_EVIDENCE_DECLARATIONS:
                raise ValidationError(
                    "total candidate safety limit exceeded "
                    f"({MAX_EVIDENCE_DECLARATIONS})"
                )


def _require_entry_structure(
    value: EvidenceEntry,
    *,
    expected_pair: tuple[RiskDomain, str],
    profile: DeploymentProfile,
    profile_index: _ProfileEvidenceIndex,
    cutoff: datetime,
    operation_id: str,
    observation_ids: set[str],
    sequences: set[tuple[str, int]],
) -> None:
    if type(value) is not EvidenceEntry:
        raise ValidationError("evidence entry has the wrong type")
    expected_domain, expected_signal = expected_pair
    if (
        type(value.domain) is not RiskDomain
        or value.domain is not expected_domain
        or type(value.signal_id) is not str
        or value.signal_id != expected_signal
        or type(value.feed_outcomes) is not tuple
    ):
        raise ValidationError("evidence entry inventory is invalid")
    routes = profile_index.routes_by_pair[(expected_domain, expected_signal)]
    if len(value.feed_outcomes) != len(routes):
        raise ValidationError("evidence entry feed inventory is incomplete")

    selections: list[SelectedObservation] = []
    reasons: list[UndefinedReason] = []
    for outcome, indexed_route in zip(value.feed_outcomes, routes, strict=True):
        feed = indexed_route.feed
        if type(outcome) not in (SelectedFeedOutcome, UndefinedFeedOutcome):
            raise ValidationError("feed outcome has the wrong type")
        if type(outcome.state) is not FeedOutcomeState:
            raise ValidationError("feed outcome state is invalid")
        if type(outcome.evaluated_observations) is not tuple:
            raise ValidationError("feed outcome candidate inventory must be a tuple")
        candidates = _require_evaluated_inventory(
            outcome.evaluated_observations,
            feed=feed,
            indexed_route=indexed_route,
            domain=expected_domain,
            signal_id=expected_signal,
            profile_index=profile_index,
            cutoff=cutoff,
            operation_id=operation_id,
        )
        for candidate in candidates:
            if candidate.observation_id in observation_ids:
                raise ValidationError("evidence observation IDs must be unique")
            observation_ids.add(candidate.observation_id)
            sequence_key = (candidate.source_id, candidate.sequence)
            if sequence_key in sequences:
                raise ValidationError("evidence source sequences must be unique")
            sequences.add(sequence_key)

        selected, reason, evaluated = _select_source_observation(
            candidates,
            feed=feed,
            normalization=indexed_route.normalization,
            profile=profile,
            cutoff=cutoff,
        )
        expected_evaluated = tuple(
            _evaluated_observation(candidate) for candidate in evaluated
        )
        if outcome.evaluated_observations != expected_evaluated:
            raise ValidationError("feed outcome candidate inventory is not canonical")

        if type(outcome) is SelectedFeedOutcome:
            _require_selected_observation_structure(
                outcome.observation,
                profile_index=profile_index,
                cutoff=cutoff,
                operation_id=operation_id,
            )
            if (
                outcome.state is not FeedOutcomeState.SELECTED
                or type(outcome.observation) is not SelectedObservation
                or selected is None
                or reason is not None
                or outcome.observation != selected
            ):
                raise ValidationError("selected feed outcome is invalid")
            source_id = selected.source_id
            selections.append(selected)
        else:
            if (
                type(outcome.source_id) is not str
                or outcome.source_id != feed.source_id
                or outcome.state is FeedOutcomeState.SELECTED
                or selected is not None
                or reason is None
                or outcome.state is not FeedOutcomeState(reason.value)
            ):
                raise ValidationError("undefined feed outcome is invalid")
            source_id = outcome.source_id
            reasons.append(reason)

        if source_id != feed.source_id:
            raise ValidationError("feed outcome source is invalid")
        provenance_digest = _digest(
            outcome.provenance_digest, name="feed outcome provenance digest"
        )
        if provenance_digest != _feed_outcome_digest(
            profile=profile,
            source_id=feed.source_id,
            domain=expected_domain,
            signal_id=expected_signal,
            state=outcome.state,
            evaluated_observations=expected_evaluated,
            selected=selected,
        ):
            raise ValidationError("feed outcome provenance is invalid")

    if selections:
        if type(value.normalized) is not Decimal:
            raise ValidationError("selected evidence must carry Decimal stress")
        expected_normalized = _combine_active_sources(
            profile_index, selections=selections
        )
        if (
            value.normalized != expected_normalized
            or value.undefined_reason is not None
        ):
            raise ValidationError("selected evidence result is invalid")
    else:
        if value.normalized is not None:
            raise ValidationError("undefined evidence must not carry stress")
        if type(value.undefined_reason) is not UndefinedReason:
            raise ValidationError("undefined evidence reason is invalid")
        if value.undefined_reason is not _choose_undefined_reason(reasons):
            raise ValidationError("undefined evidence summary is invalid")


def _require_evaluated_inventory(
    values: tuple[EvaluatedObservation, ...],
    *,
    feed: FeedDeclaration,
    indexed_route: _IndexedRoute,
    domain: RiskDomain,
    signal_id: str,
    profile_index: _ProfileEvidenceIndex,
    cutoff: datetime,
    operation_id: str,
) -> tuple[_ValidatedObservation, ...]:
    route = indexed_route.route
    result: list[_ValidatedObservation] = []
    for value in values:
        if type(value) is not EvaluatedObservation:
            raise ValidationError("evaluated observation has the wrong type")
        declaration = ObservationDeclaration(
            observation_id=value.observation_id,
            source_id=feed.source_id,
            sequence=value.sequence,
            signal_id=signal_id,
            domain=domain,
            observation_class=value.observation_class,
            measurement_envelope=value.measurement_envelope,
            raw_value=value.raw_value,
            unit=route.unit,
            observed_at=value.observed_at,
            ingested_at=value.ingested_at,
            valid_until=value.valid_until,
            population_state=value.population_state,
            window=value.window,
            published_period=value.published_period,
            on_demand_binding=value.on_demand_binding,
        )
        candidate = _validate_observation(
            declaration,
            profile_index=profile_index,
            cutoff=cutoff,
            operation_id=operation_id,
        )
        if feed.refresh_interval_ms != 0 and candidate.ingested_at > cutoff:
            raise ValidationError(
                "future cached evidence is not an evaluated candidate"
            )
        if value != _evaluated_observation(candidate):
            raise ValidationError("evaluated observation integrity is invalid")
        result.append(candidate)
    return tuple(result)


def _evaluated_observation(value: _ValidatedObservation) -> EvaluatedObservation:
    return EvaluatedObservation(
        observation_id=value.observation_id,
        sequence=value.sequence,
        observation_class=value.observation_class,
        measurement_envelope=value.measurement_envelope,
        raw_value=value.raw_value,
        observed_at=value.observed_at,
        ingested_at=value.ingested_at,
        valid_until=value.valid_until,
        population_state=value.population_state,
        window=value.window,
        published_period=value.published_period,
        on_demand_binding=value.on_demand_binding,
    )


def _feed_outcome_digest(
    *,
    profile: DeploymentProfile,
    source_id: str,
    domain: RiskDomain,
    signal_id: str,
    state: FeedOutcomeState,
    evaluated_observations: tuple[EvaluatedObservation, ...],
    selected: SelectedObservation | None,
) -> str:
    return canonical_sha256(
        {
            "profile_ref": profile.ref,
            "profile_digest": profile.digest,
            "source_id": source_id,
            "domain": domain,
            "signal_id": signal_id,
            "state": state,
            "evaluated_observations": evaluated_observations,
            "selected": selected,
        }
    )


def _validate_observation(
    declaration: ObservationDeclaration,
    *,
    profile_index: _ProfileEvidenceIndex,
    cutoff: datetime,
    operation_id: str,
) -> _ValidatedObservation:
    try:
        declaration = ObservationDeclaration(
            observation_id=declaration.observation_id,
            source_id=declaration.source_id,
            sequence=declaration.sequence,
            signal_id=declaration.signal_id,
            domain=declaration.domain,
            observation_class=declaration.observation_class,
            measurement_envelope=declaration.measurement_envelope,
            raw_value=declaration.raw_value,
            unit=declaration.unit,
            observed_at=declaration.observed_at,
            ingested_at=declaration.ingested_at,
            valid_until=declaration.valid_until,
            population_state=declaration.population_state,
            window=declaration.window,
            published_period=declaration.published_period,
            on_demand_binding=declaration.on_demand_binding,
        )
    except AttributeError as exc:
        raise ValidationError("observation declaration structure is invalid") from exc
    observation_id = _identifier(declaration.observation_id, name="observation ID")
    source_id = _identifier(declaration.source_id, name="observation source ID")
    sequence = _nonnegative_int(
        declaration.sequence,
        name="observation sequence",
        maximum=_MAX_OBSERVATION_SEQUENCE,
    )
    if type(declaration.domain) is not RiskDomain:
        raise ValidationError("observation domain must be a RiskDomain")
    domain = declaration.domain
    try:
        if type(declaration.signal_id) is not str:
            raise TypeError
        signal_id = validate_signal_id(declaration.signal_id)
    except (TypeError, ValueError) as exc:
        raise ValidationError("observation signal ID is invalid") from exc
    try:
        indexed_route = profile_index.routes[(domain, signal_id, source_id)]
    except KeyError as exc:
        raise ValidationError(
            f"source {source_id} does not populate {domain.value}/{signal_id}"
        ) from exc
    route = indexed_route.route
    if type(declaration.unit) is not str or declaration.unit != route.unit:
        raise ValidationError("observation unit must exactly match the profile route")
    if type(declaration.observation_class) is not ObservationClass:
        raise ValidationError("observation class must be an ObservationClass")
    observation_class = declaration.observation_class
    if CATALOG[signal_id].observation_class != observation_class.value:
        raise ValidationError("observation class must exactly match the catalogue")

    observed_at = utc_time(declaration.observed_at, name="observation observed-at")
    ingested_at = utc_time(declaration.ingested_at, name="observation ingested-at")
    if observed_at > cutoff:
        raise ValidationError("observation must not be observed after cutoff")
    if observed_at > ingested_at:
        raise ValidationError("observation observed-at must not exceed ingested-at")
    population_required = observation_class in {
        ObservationClass.ENUMERATED,
        ObservationClass.ADJUDICATED,
        ObservationClass.PUBLISHED,
    }
    if population_required:
        if type(declaration.population_state) is not PopulationState:
            raise ValidationError("observation class requires a population state")
    elif declaration.population_state is not None:
        raise ValidationError("observation class forbids a population state")
    population_state = declaration.population_state
    if population_state in (None, PopulationState.OBSERVED):
        if declaration.raw_value is None:
            raise ValidationError("an observed value must not be empty")
    elif declaration.raw_value is not None:
        raise ValidationError("empty and unavailable populations must not carry values")

    envelope, window, period, valid_until = _validate_class_contract(
        declaration,
        observation_class=observation_class,
        observed_at=observed_at,
    )
    binding = _validate_binding(
        declaration.on_demand_binding,
        feed=indexed_route.feed,
        operation_id=operation_id,
        cutoff=cutoff,
        ingested_at=ingested_at,
    )
    raw_value: bool | int | Decimal | str | datetime | None
    if declaration.raw_value is None:
        raw_value = None
    else:
        raw_value = _catalogue_value(
            declaration.raw_value,
            signal_id=signal_id,
        )
    if raw_value is not None:
        # Every declaration crosses the complete normalization boundary, even
        # if it is later excluded or another declaration wins selection.
        _normalize(
            indexed_route.normalization,
            signal_id=signal_id,
            raw=raw_value,
        )
    return _ValidatedObservation(
        observation_id=observation_id,
        source_id=source_id,
        sequence=sequence,
        signal_id=signal_id,
        domain=domain,
        observation_class=observation_class,
        measurement_envelope=envelope,
        raw_value=raw_value,
        unit=route.unit,
        observed_at=observed_at,
        ingested_at=ingested_at,
        valid_until=valid_until,
        population_state=population_state,
        window=window,
        published_period=period,
        on_demand_binding=binding,
    )


def _require_selected_observation_structure(
    value: object,
    *,
    profile_index: _ProfileEvidenceIndex,
    cutoff: datetime,
    operation_id: str,
) -> None:
    if type(value) is not SelectedObservation:
        raise ValidationError("selected observation structure is invalid")
    declaration = ObservationDeclaration(
        observation_id=value.observation_id,
        source_id=value.source_id,
        sequence=value.sequence,
        signal_id=value.signal_id,
        domain=value.domain,
        observation_class=value.observation_class,
        measurement_envelope=value.measurement_envelope,
        raw_value=value.raw_value,
        unit=value.unit,
        observed_at=value.observed_at,
        ingested_at=value.ingested_at,
        valid_until=value.valid_until,
        population_state=value.population_state,
        window=value.window,
        published_period=value.published_period,
        on_demand_binding=value.on_demand_binding,
    )
    _validate_observation(
        declaration,
        profile_index=profile_index,
        cutoff=cutoff,
        operation_id=operation_id,
    )
    if type(value.normalized) is not Decimal or not value.normalized.is_finite():
        raise ValidationError("selected observation stress structure is invalid")
    _digest(value.provenance_digest, name="selected observation provenance digest")


def _validate_class_contract(
    declaration: ObservationDeclaration,
    *,
    observation_class: ObservationClass,
    observed_at: datetime,
) -> tuple[
    MeasurementEnvelope,
    ObservationWindow | None,
    PublishedObservationPeriod | None,
    datetime | None,
]:
    valid_until = (
        None
        if declaration.valid_until is None
        else utc_time(declaration.valid_until, name="observation valid-until")
    )
    if observation_class is ObservationClass.DIRECT:
        envelope = _direct_envelope(declaration.measurement_envelope, observed_at)
        window = _required_window(declaration.window, observed_at=observed_at)
        _forbid(declaration.published_period, "Direct published period")
        _forbid(valid_until, "Direct validity horizon")
        return envelope, window, None, None
    if observation_class is ObservationClass.ENUMERATED:
        envelope = _enumerated_envelope(declaration.measurement_envelope)
        window = _required_window(declaration.window, observed_at=observed_at)
        _forbid(declaration.published_period, "Enumerated published period")
        _forbid(valid_until, "Enumerated validity horizon")
        return envelope, window, None, None
    if observation_class is ObservationClass.ADJUDICATED:
        envelope = _adjudicated_envelope(declaration.measurement_envelope)
        window = _required_window(declaration.window, observed_at=observed_at)
        _forbid(declaration.published_period, "Adjudicated published period")
        _forbid(valid_until, "Adjudicated validity horizon")
        return envelope, window, None, None
    if observation_class is ObservationClass.PUBLISHED:
        envelope = _published_envelope(declaration.measurement_envelope)
        _forbid(declaration.window, "Published observation window")
        _forbid(valid_until, "Published validity horizon")
        period = _published_period(
            declaration.published_period, observed_at=observed_at
        )
        return envelope, None, period, None
    envelope = _derived_envelope(declaration.measurement_envelope)
    _forbid(declaration.window, "Derived State observation window")
    _forbid(declaration.published_period, "Derived State published period")
    if valid_until is None:
        raise ValidationError("Derived State requires a validity horizon")
    if valid_until < observed_at:
        raise ValidationError("Derived State validity must not precede its as-of time")
    return envelope, None, None, valid_until


def _direct_envelope(value: object, observed_at: datetime) -> DirectMeasurementEnvelope:
    if type(value) is not DirectMeasurementEnvelope:
        raise ValidationError("Direct observation requires its exact envelope")
    try:
        subject = value.subject
        modality = value.modality
        instrument_make_model = value.instrument_make_model
        calibration_at = value.calibration_at
        calibration_reference = value.calibration_reference
    except AttributeError as exc:
        raise ValidationError("Direct envelope structure is invalid") from exc
    calibration_at = utc_time(calibration_at, name="Direct calibration-at")
    if calibration_at > observed_at:
        raise ValidationError("Direct calibration must not follow the observation")
    return DirectMeasurementEnvelope(
        subject=_text(subject, name="Direct subject"),
        modality=_text(modality, name="Direct modality"),
        instrument_make_model=_text(
            instrument_make_model, name="Direct instrument make/model"
        ),
        calibration_at=calibration_at,
        calibration_reference=_text(
            calibration_reference, name="Direct calibration reference"
        ),
    )


def _enumerated_envelope(value: object) -> EnumeratedMeasurementEnvelope:
    if type(value) is not EnumeratedMeasurementEnvelope:
        raise ValidationError("Enumerated observation requires its exact envelope")
    try:
        subject_boundary = value.subject_boundary
        population = value.population
        membership_rule = value.membership_rule
        reset_semantics = value.reset_semantics
        membership_mode = value.membership_mode
        instrument_identity = value.instrument_identity
        instrument_version = value.instrument_version
    except AttributeError as exc:
        raise ValidationError("Enumerated envelope structure is invalid") from exc
    if type(membership_mode) is not str or membership_mode not in (
        "enumerated",
        "inferred",
    ):
        raise ValidationError("Enumerated membership mode is invalid")
    identity = (
        None
        if instrument_identity is None
        else _text(instrument_identity, name="Enumerated instrument identity")
    )
    version = (
        None
        if instrument_version is None
        else _text(instrument_version, name="Enumerated instrument version")
    )
    if (identity is None) != (version is None):
        raise ValidationError("Enumerated instrument identity and version are paired")
    if membership_mode == "inferred" and identity is None:
        raise ValidationError("inferred Enumerated membership requires an instrument")
    return EnumeratedMeasurementEnvelope(
        subject_boundary=_text(
            subject_boundary, name="Enumerated subject boundary"
        ),
        population=_text(population, name="Enumerated population"),
        membership_rule=_text(membership_rule, name="Enumerated membership rule"),
        reset_semantics=_text(reset_semantics, name="Enumerated reset semantics"),
        membership_mode=membership_mode,
        instrument_identity=identity,
        instrument_version=version,
    )


def _adjudicated_envelope(value: object) -> AdjudicatedMeasurementEnvelope:
    if type(value) is not AdjudicatedMeasurementEnvelope:
        raise ValidationError("Adjudicated observation requires its exact envelope")
    try:
        issuing_authority = value.issuing_authority
        authority_scope = value.authority_scope
        measurement_party = value.measurement_party
        record_set = value.record_set
        adjudication_criteria = value.adjudication_criteria
        criteria_version = value.criteria_version
    except AttributeError as exc:
        raise ValidationError("Adjudicated envelope structure is invalid") from exc
    issuer = _text(issuing_authority, name="Adjudicated issuing authority")
    measurement_party = _text(
        measurement_party, name="Adjudicated measurement party"
    )
    if issuer == measurement_party:
        raise ValidationError("Adjudicated issuer must be outside the measurement")
    return AdjudicatedMeasurementEnvelope(
        issuing_authority=issuer,
        authority_scope=_text(
            authority_scope, name="Adjudicated authority scope"
        ),
        measurement_party=measurement_party,
        record_set=_text(record_set, name="Adjudicated record set"),
        adjudication_criteria=_text(
            adjudication_criteria, name="Adjudicated criteria"
        ),
        criteria_version=_text(
            criteria_version, name="Adjudicated criteria version"
        ),
    )


def _published_envelope(value: object) -> PublishedMeasurementEnvelope:
    if type(value) is not PublishedMeasurementEnvelope:
        raise ValidationError("Published observation requires its exact envelope")
    try:
        publisher_universe_reference = value.publisher_universe_reference
        population_reference = value.population_reference
        publisher = value.publisher
        series_id = value.series_id
    except AttributeError as exc:
        raise ValidationError("Published envelope structure is invalid") from exc
    return PublishedMeasurementEnvelope(
        publisher_universe_reference=_text(
            publisher_universe_reference,
            name="Published universe reference",
        ),
        population_reference=_text(
            population_reference, name="Published population reference"
        ),
        publisher=_text(publisher, name="Published publisher"),
        series_id=_text(series_id, name="Published series ID"),
    )


def _derived_envelope(value: object) -> DerivedStateMeasurementEnvelope:
    if type(value) is not DerivedStateMeasurementEnvelope:
        raise ValidationError("Derived State observation requires its exact envelope")
    try:
        scope = value.scope
        authoritative_source = value.authoritative_source
        source_version = value.source_version
    except AttributeError as exc:
        raise ValidationError("Derived State envelope structure is invalid") from exc
    return DerivedStateMeasurementEnvelope(
        scope=_text(scope, name="Derived State scope"),
        authoritative_source=_text(
            authoritative_source, name="Derived State authoritative source"
        ),
        source_version=_text(source_version, name="Derived State source version"),
    )


def _required_window(
    value: ObservationWindow | None, *, observed_at: datetime
) -> ObservationWindow:
    if type(value) is not ObservationWindow:
        raise ValidationError("observation class requires an observation window")
    try:
        start = value.start
        end = value.end
    except AttributeError as exc:
        raise ValidationError("observation window structure is invalid") from exc
    start = utc_time(start, name="observation window start")
    end = utc_time(end, name="observation window end")
    if start >= end:
        raise ValidationError("observation window must have positive duration")
    if end > observed_at:
        raise ValidationError("observation window must end by observed-at")
    return ObservationWindow(start, end)


def _published_period(
    value: PublishedObservationPeriod | None, *, observed_at: datetime
) -> PublishedObservationPeriod:
    if type(value) is not PublishedObservationPeriod:
        raise ValidationError("Published observation requires a reference period")
    try:
        start = value.start
        end = value.end
        published_at = value.published_at
        publication_lag_ms = value.publication_lag_ms
        vintage = value.vintage
    except AttributeError as exc:
        raise ValidationError("Published reference-period structure is invalid") from exc
    start = utc_time(start, name="Published reference-period start")
    end = utc_time(end, name="Published reference-period end")
    published_at = utc_time(published_at, name="Published publication time")
    if start >= end:
        raise ValidationError("Published reference period must have positive duration")
    if end > published_at:
        raise ValidationError("Published reference period must end before publication")
    if published_at > observed_at:
        raise ValidationError("publication time must not follow observation time")
    lag = _nonnegative_int(publication_lag_ms, name="publication lag")
    lag_microseconds = _timedelta_microseconds(published_at - end)
    if lag_microseconds % 1000 != 0 or lag != lag_microseconds // 1000:
        raise ValidationError("publication lag must exactly match the reference period")
    return PublishedObservationPeriod(
        start=start,
        end=end,
        published_at=published_at,
        publication_lag_ms=lag,
        vintage=_text(vintage, name="Published vintage"),
    )


def _validate_binding(
    value: OnDemandQueryBinding | None,
    *,
    feed: FeedDeclaration,
    operation_id: str,
    cutoff: datetime,
    ingested_at: datetime,
) -> OnDemandQueryBinding | None:
    on_demand = feed.refresh_interval_ms == 0 and feed.stale_threshold_ms == 0
    if not on_demand:
        if value is not None:
            raise ValidationError("cached evidence must not carry an on-demand binding")
        return None
    if type(value) is not OnDemandQueryBinding:
        raise ValidationError("on-demand evidence requires a current query binding")
    try:
        bound_operation = value.operation_id
        requested_at = value.requested_at
    except AttributeError as exc:
        raise ValidationError("on-demand query binding structure is invalid") from exc
    bound_operation = _identifier(bound_operation, name="on-demand operation ID")
    requested_at = utc_time(requested_at, name="on-demand requested-at")
    if bound_operation != operation_id or requested_at != cutoff:
        raise ValidationError("on-demand evidence binding does not match preparation")
    if ingested_at < requested_at:
        raise ValidationError("on-demand response cannot precede its request")
    return OnDemandQueryBinding(bound_operation, requested_at)


def _select_source_observation(
    observations: Iterable[_ValidatedObservation],
    *,
    feed: FeedDeclaration,
    normalization: IdentityNormalization | MinMaxNormalization | LabelSetDeclaration,
    profile: DeploymentProfile,
    cutoff: datetime,
) -> tuple[
    SelectedObservation | None,
    UndefinedReason | None,
    tuple[_ValidatedObservation, ...],
]:
    owned = tuple(
        sorted(
            observations,
            key=lambda item: (item.observed_at, item.sequence, item.observation_id),
        )
    )
    unexpired = tuple(
        value
        for value in owned
        if value.valid_until is None or value.valid_until >= cutoff
    )
    if not unexpired:
        reason = (
            UndefinedReason.EXPIRED
            if owned
            else UndefinedReason.NO_ELIGIBLE_OBSERVATION
        )
        return None, reason, owned
    if feed.stale_threshold_ms == 0:
        current = unexpired
    else:
        threshold = timedelta(milliseconds=feed.stale_threshold_ms)
        current = tuple(
            value
            for value in unexpired
            if cutoff - _freshness_origin(value) <= threshold
        )
    if not current:
        return None, UndefinedReason.STALE, owned
    value = max(
        current,
        key=lambda item: (item.observed_at, item.sequence, item.observation_id),
    )
    if value.population_state is PopulationState.EMPTY:
        return None, UndefinedReason.EMPTY_WINDOW, owned
    if value.population_state is PopulationState.UNAVAILABLE:
        return None, UndefinedReason.SOURCE_UNAVAILABLE, owned
    if value.raw_value is None:
        raise ValidationError("selected observation has no measured value")
    normalized = _normalize(
        normalization, signal_id=value.signal_id, raw=value.raw_value
    )
    provenance = {
        "profile_ref": profile.ref,
        "profile_digest": profile.digest,
        "observation": value,
        "normalized": normalized,
    }
    selected = SelectedObservation(
        observation_id=value.observation_id,
        source_id=value.source_id,
        sequence=value.sequence,
        signal_id=value.signal_id,
        domain=value.domain,
        observation_class=value.observation_class,
        measurement_envelope=value.measurement_envelope,
        raw_value=value.raw_value,
        unit=value.unit,
        population_state=value.population_state,
        window=value.window,
        published_period=value.published_period,
        on_demand_binding=value.on_demand_binding,
        normalized=normalized,
        observed_at=value.observed_at,
        ingested_at=value.ingested_at,
        valid_until=value.valid_until,
        provenance_digest=canonical_sha256(provenance),
    )
    return selected, None, owned


def _freshness_origin(value: _ValidatedObservation) -> datetime:
    if value.observation_class is ObservationClass.PUBLISHED:
        if value.published_period is None:
            raise ValidationError("Published observation has no reference period")
        return value.published_period.end
    return value.observed_at


def _normalize(
    declaration: IdentityNormalization | MinMaxNormalization | LabelSetDeclaration,
    *,
    signal_id: str,
    raw: bool | int | Decimal | str | datetime,
) -> Decimal:
    if type(declaration) is LabelSetDeclaration:
        label = _categorical_label(raw, signal_id=signal_id)
        if label not in declaration.stress_by_label:
            raise ValidationError("categorical observation uses an undeclared label")
        return declaration.stress_by_label[label]
    if type(raw) not in (int, Decimal):
        raise ValidationError("numeric observation requires a Decimal value")
    numeric = as_decimal(raw, name=f"{signal_id} numeric observation")
    if type(declaration) is IdentityNormalization:
        value = as_decimal(
            numeric,
            name=f"{signal_id} identity-normalized value",
            minimum=0,
            maximum=1,
        )
    elif type(declaration) is MinMaxNormalization:
        if (
            not declaration.clamp
            and not declaration.minimum <= numeric <= declaration.maximum
        ):
            raise ValidationError("unclamped min/max observation is outside its range")
        bounded = numeric
        if declaration.clamp:
            bounded = min(declaration.maximum, max(declaration.minimum, numeric))
        with localcontext(KTP_CONTEXT):
            value = (bounded - declaration.minimum) / (
                declaration.maximum - declaration.minimum
            )
        value = as_decimal(
            value, name=f"{signal_id} normalized value", minimum=0, maximum=1
        )
    else:
        raise ValidationError("unsupported profile normalization")
    if declaration.invert:
        with localcontext(KTP_CONTEXT):
            value = Decimal(1) - value
    return as_decimal(value, name=f"{signal_id} stress", minimum=0, maximum=1)


def _catalogue_value(
    value: object, *, signal_id: str
) -> bool | int | Decimal | str | datetime:
    value_type = CATALOG[signal_id].value_type
    if value_type == "int":
        if type(value) is not int:
            raise ValidationError("integer observations require an exact integer")
        as_decimal(value, name=f"{signal_id} integer observation")
        return value
    if value_type in {"float", "duration"}:
        if type(value) not in (int, str, Decimal):
            raise ValidationError(
                f"{value_type} observations require exact decimal input"
            )
        return as_decimal(value, name=f"{signal_id} raw observation")
    if value_type == "bool":
        if type(value) is not bool:
            raise ValidationError("boolean observations require an exact boolean")
        return value
    if value_type in {"enum", "string"}:
        if type(value) is not str:
            raise ValidationError(f"{value_type} observations require an exact string")
        return _label(value)
    raise ValidationError(
        f"catalogue scalar type {value_type} has no KTP-Core normalization"
    )


def _categorical_label(
    value: bool | int | Decimal | str | datetime, *, signal_id: str
) -> str:
    value_type = CATALOG[signal_id].value_type
    if value_type == "bool" and type(value) is bool:
        return "true" if value else "false"
    if value_type in {"enum", "string"} and type(value) is str:
        return value
    raise ValidationError("categorical observation has the wrong catalogue scalar type")


def _combine_active_sources(
    profile_index: _ProfileEvidenceIndex, *, selections: list[SelectedObservation]
) -> Decimal:
    with localcontext(KTP_CONTEXT):
        numerator = sum(
            (
                profile_index.routes[
                    (selection.domain, selection.signal_id, selection.source_id)
                ].feed.weight
                * selection.normalized
                for selection in selections
            ),
            start=Decimal(0),
        )
        denominator = sum(
            (
                profile_index.routes[
                    (selection.domain, selection.signal_id, selection.source_id)
                ].feed.weight
                for selection in selections
            ),
            start=Decimal(0),
        )
        if denominator <= 0:
            raise ValidationError("active evidence weight denominator is empty")
        result = numerator / denominator
    return as_decimal(result, name="combined evidence stress", minimum=0, maximum=1)


def _choose_undefined_reason(reasons: list[UndefinedReason]) -> UndefinedReason:
    for reason in _UNDEFINED_PRECEDENCE:
        if reason in reasons:
            return reason
    return UndefinedReason.NO_ELIGIBLE_OBSERVATION


def _snapshot_input(value: EvidenceSnapshot) -> MappingProxyType[str, object]:
    return MappingProxyType(
        {
            "profile_ref": value.profile_ref,
            "profile_digest": value.profile_digest,
            "operation_id": value.operation_id,
            "cutoff": value.cutoff,
            "entries": value.entries,
        }
    )


def _text(value: str, *, name: str) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise ValidationError(f"{name} must be a non-empty bounded string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
    if normalize("NFC", value) != value or any(
        ord(character) < 32 for character in value
    ):
        raise ValidationError(f"{name} contains invalid characters")
    return value


def _label(value: str) -> str:
    return _text(value, name="categorical observation label")


def _nonnegative_int(value: int, *, name: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0:
        raise ValidationError(f"{name} must be a nonnegative integer")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{name} exceeds the implementation safety maximum")
    return value


def _identifier(value: str, *, name: str) -> str:
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    return validate_identifier(value, name=name)


def _digest(value: str, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _forbid(value: object, name: str) -> None:
    if value is not None:
        raise ValidationError(f"{name} is forbidden")


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


__all__ = [
    "MAX_EVIDENCE_CANDIDATES_PER_ROUTE",
    "MAX_EVIDENCE_DECLARATIONS",
    "prepare_evidence",
    "require_validated_evidence_snapshot",
]
