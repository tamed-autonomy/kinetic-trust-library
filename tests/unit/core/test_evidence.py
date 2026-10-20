import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, getcontext, setcontext
from pathlib import Path

from kinetic_trust_library.core.evidence import prepare_evidence
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.evidence import (
    AdjudicatedMeasurementEnvelope,
    DerivedStateMeasurementEnvelope,
    DirectMeasurementEnvelope,
    EnumeratedMeasurementEnvelope,
    EvidenceSnapshot,
    ObservationClass,
    ObservationDeclaration,
    ObservationWindow,
    OnDemandQueryBinding,
    PopulationState,
    PublishedMeasurementEnvelope,
    PublishedObservationPeriod,
    UndefinedReason,
)
from kinetic_trust_library.models.profile import (
    ActionPolicy,
    DeploymentProfile,
    DeploymentProfileDeclaration,
    EnvelopeThresholds,
    FactorAggregationDeclaration,
    FactorName,
    FeedDeclaration,
    IdentityNormalization,
    LabelSetDeclaration,
    MinMaxNormalization,
    MomentCriticalityFactorDeclaration,
    RiskDomain,
    RiskFactorsDeclaration,
    SignalRouteDeclaration,
    SignalRiskFactorDeclaration,
)


UTC = timezone.utc
CUTOFF = datetime(2026, 8, 20, 12, tzinfo=UTC)
SIGNALS = (
    "world.optical.illuminance",  # D
    "body.compute.compute_utilization",  # N
    "body.hardware.active_alarms",  # A
    "world.economic.consumer_price_index",  # P
    "body.clock.sync_state",  # S
)
FACTORS = (
    FactorName.EVIDENCE_DENSITY,
    FactorName.TRUST_TREND,
    FactorName.ADVERSARIAL_PRESSURE,
    FactorName.UPDATE_RESISTANCE,
    FactorName.ATTESTATION_COVERAGE,
)
UNITS = {
    SIGNALS[0]: "lx",
    SIGNALS[1]: "ratio",
    SIGNALS[2]: "count",
    SIGNALS[3]: "index",
    SIGNALS[4]: "state",
}
_AUTO_STATE = object()


def _risk_factors():
    aggregations = {
        factor: FactorAggregationDeclaration((signal,), "maximum")
        for factor, signal in zip(FACTORS, SIGNALS, strict=True)
    }
    return RiskFactorsDeclaration(
        evidence_density=SignalRiskFactorDeclaration(
            "0.20", aggregations[FactorName.EVIDENCE_DENSITY]
        ),
        trust_trend=SignalRiskFactorDeclaration(
            "0.20", aggregations[FactorName.TRUST_TREND]
        ),
        adversarial_pressure=SignalRiskFactorDeclaration(
            "0.15", aggregations[FactorName.ADVERSARIAL_PRESSURE]
        ),
        update_resistance=SignalRiskFactorDeclaration(
            "0.15", aggregations[FactorName.UPDATE_RESISTANCE]
        ),
        attestation_coverage=SignalRiskFactorDeclaration(
            "0.15", aggregations[FactorName.ATTESTATION_COVERAGE]
        ),
        moment_criticality=MomentCriticalityFactorDeclaration(
            "0.15", "action-api", "stress-0-1"
        ),
    )


def profile_declaration(*, on_demand_source=None, extra_feeds=()):
    feeds = {}
    for domain in RiskDomain:
        for index, signal in enumerate(SIGNALS):
            source = f"feed:{domain.value}:{index}"
            on_demand = source == on_demand_source
            feeds[source] = FeedDeclaration(
                source_id=source,
                routes=(SignalRouteDeclaration(signal, domain, UNITS[signal]),),
                refresh_interval_ms=0 if on_demand else 1000,
                stale_threshold_ms=0 if on_demand else 30_000,
                stale_threshold_reason=(None if on_demand else "source:test-window"),
            )
    for feed in extra_feeds:
        feeds[feed.source_id] = feed
    return DeploymentProfileDeclaration(
        profile_id="profile.evidence",
        version=1,
        action_demand_unit="trust-points",
        risk_factors=_risk_factors(),
        risk_domain_weights={
            RiskDomain.NODE: "0.30",
            RiskDomain.NEIGHBORHOOD: "0.40",
            RiskDomain.GLOBAL: "0.30",
        },
        soul_frameworks=("soul.framework",),
        peer_share="0",
        external_root_hop_bound=6,
        misattestation_adjudicator="adjudicator:one",
        standing_decay_rate="16",
        envelope_thresholds=EnvelopeThresholds(
            Decimal("0"), Decimal("0.4"), Decimal("0.2"), Decimal("0.1")
        ),
        actions={
            "deploy": ActionPolicy(
                "deploy", Decimal("0"), Decimal("100"), {"rate": "ops"}, ()
            )
        },
        feeds=feeds,
        alias_selections={},
        normalizations={
            SIGNALS[0]: MinMaxNormalization("0", "200", clamp=True),
            SIGNALS[1]: IdentityNormalization(),
            SIGNALS[2]: MinMaxNormalization("0", "10", clamp=True),
            SIGNALS[3]: MinMaxNormalization("100", "300", invert=True, clamp=True),
        },
        label_sets={
            SIGNALS[4]: LabelSetDeclaration(
                ("synchronized", "unsynchronized"),
                {"synchronized": "0", "unsynchronized": "1"},
                source_id="clock:taxonomy",
            )
        },
    )


def profile(**changes):
    return DeploymentProfile.validate(profile_declaration(**changes))


def direct_envelope(**changes):
    values = {
        "subject": "room:one",
        "modality": "photometric",
        "instrument_make_model": "meter:model-one",
        "calibration_at": CUTOFF - timedelta(days=1),
        "calibration_reference": "calibration:one",
    }
    values.update(changes)
    return DirectMeasurementEnvelope(**values)


def enumerated_envelope(**changes):
    values = {
        "subject_boundary": "host:one",
        "population": "scheduler:tasks",
        "membership_rule": "task:admitted",
        "reset_semantics": "window:reset",
        "membership_mode": "enumerated",
    }
    values.update(changes)
    return EnumeratedMeasurementEnvelope(**values)


def adjudicated_envelope(**changes):
    values = {
        "issuing_authority": "authority:one",
        "authority_scope": "platform:one",
        "measurement_party": "sensor:one",
        "record_set": "alarms:active",
        "adjudication_criteria": "criteria:alarm",
        "criteria_version": "version:one",
    }
    values.update(changes)
    return AdjudicatedMeasurementEnvelope(**values)


def published_envelope(**changes):
    values = {
        "publisher_universe_reference": "universe:cpi",
        "population_reference": "population:cpi",
        "publisher": "publisher:one",
        "series_id": "series:cpi",
    }
    values.update(changes)
    return PublishedMeasurementEnvelope(**values)


def derived_envelope(**changes):
    values = {
        "scope": "host:one",
        "authoritative_source": "clock:service",
        "source_version": "version:one",
    }
    values.update(changes)
    return DerivedStateMeasurementEnvelope(**values)


def observation(
    *,
    signal=SIGNALS[0],
    domain=RiskDomain.NODE,
    source="feed:node:0",
    observation_id="observation:one",
    sequence=1,
    raw="150",
    observed_at=CUTOFF - timedelta(seconds=2),
    ingested_at=CUTOFF - timedelta(seconds=1),
    population_state=_AUTO_STATE,
    window=None,
    valid_until=None,
    published_period=None,
    on_demand_binding=None,
    observation_class=ObservationClass.DIRECT,
    measurement_envelope=None,
    unit=None,
):
    if window is None and observation_class in {
        ObservationClass.DIRECT,
        ObservationClass.ENUMERATED,
        ObservationClass.ADJUDICATED,
    }:
        window = ObservationWindow(observed_at - timedelta(seconds=1), observed_at)
    if measurement_envelope is None:
        measurement_envelope = {
            ObservationClass.DIRECT: direct_envelope(),
            ObservationClass.ENUMERATED: enumerated_envelope(),
            ObservationClass.ADJUDICATED: adjudicated_envelope(),
            ObservationClass.PUBLISHED: published_envelope(),
            ObservationClass.DERIVED_STATE: derived_envelope(),
        }[observation_class]
    if population_state is _AUTO_STATE:
        population_state = (
            None
            if observation_class
            in {ObservationClass.DIRECT, ObservationClass.DERIVED_STATE}
            else PopulationState.OBSERVED
        )
    return ObservationDeclaration(
        observation_id=observation_id,
        source_id=source,
        sequence=sequence,
        signal_id=signal,
        domain=domain,
        observation_class=observation_class,
        measurement_envelope=measurement_envelope,
        raw_value=raw,
        unit=UNITS[signal] if unit is None else unit,
        observed_at=observed_at,
        ingested_at=ingested_at,
        valid_until=valid_until,
        population_state=population_state,
        window=window,
        published_period=published_period,
        on_demand_binding=on_demand_binding,
    )


class EvidencePreparationTests(unittest.TestCase):
    def test_selects_latest_fresh_observation_before_cutoff(self):
        older = observation(observation_id="observation:older", raw="50", sequence=1)
        newer = observation(observation_id="observation:newer", raw="150", sequence=2)
        snapshot = prepare_evidence(
            profile(), [older, newer], CUTOFF, operation_id="operation:one"
        )
        selected = snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE)
        self.assertEqual(selected.normalized, Decimal("0.75"))
        self.assertEqual(
            selected.selected_observations[0].observation_id, "observation:newer"
        )

    def test_empty_snapshot_is_unknown_not_zero(self):
        snapshot = prepare_evidence(profile(), [], CUTOFF, operation_id="operation:one")
        self.assertEqual(
            snapshot.undefined(SIGNALS[0], domain=RiskDomain.NODE),
            UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )
        self.assertIsNone(
            snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE).normalized
        )

    def test_combines_latest_active_source_values_by_positive_feed_weight(self):
        extra = FeedDeclaration(
            "feed:node:extra",
            (SignalRouteDeclaration(SIGNALS[0], RiskDomain.NODE, UNITS[SIGNALS[0]]),),
            1000,
            weight="3",
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        declarations = [
            observation(raw="0", source="feed:node:0", observation_id="observation:a"),
            observation(
                raw="200",
                source="feed:node:extra",
                observation_id="observation:b",
            ),
        ]
        snapshot = prepare_evidence(
            profile(extra_feeds=(extra,)),
            declarations,
            CUTOFF,
            operation_id="operation:one",
        )
        entry = snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE)
        self.assertEqual(entry.normalized, Decimal("0.75"))
        self.assertEqual(
            tuple(item.source_id for item in entry.selected_observations),
            ("feed:node:0", "feed:node:extra"),
        )

    def test_unavailable_source_does_not_enter_active_weight_denominator(self):
        extra = FeedDeclaration(
            "feed:node:extra",
            (SignalRouteDeclaration(SIGNALS[1], RiskDomain.NODE, UNITS[SIGNALS[1]]),),
            1000,
            weight="99",
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        declarations = [
            observation(
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="0.5",
                observation_class=ObservationClass.ENUMERATED,
                observation_id="observation:active",
            ),
            observation(
                source="feed:node:extra",
                signal=SIGNALS[1],
                observation_class=ObservationClass.ENUMERATED,
                observation_id="observation:unavailable",
                raw=None,
                population_state=PopulationState.UNAVAILABLE,
            ),
        ]
        entry = prepare_evidence(
            profile(extra_feeds=(extra,)),
            declarations,
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[1], domain=RiskDomain.NODE)
        self.assertEqual(entry.normalized, Decimal("0.5"))
        self.assertEqual(len(entry.selected_observations), 1)

    def test_snapshot_owns_inputs_and_is_deeply_immutable(self):
        declarations = [observation()]
        snapshot = prepare_evidence(
            profile(), declarations, CUTOFF, operation_id="operation:one"
        )
        digest = snapshot.digest
        declarations.clear()
        self.assertEqual(snapshot.digest, digest)
        self.assertEqual(len(snapshot.entries), 15)
        with self.assertRaises(FrozenInstanceError):
            snapshot.operation_id = "operation:changed"
        with self.assertRaises(TypeError):
            snapshot.entries[0] = snapshot.entries[0]

    def test_result_is_deterministic_under_another_ambient_decimal_context(self):
        original = getcontext().copy()
        try:
            first = prepare_evidence(
                profile(),
                [observation(raw="100")],
                CUTOFF,
                operation_id="operation:one",
            )
            getcontext().prec = 6
            second = prepare_evidence(
                profile(),
                [observation(raw="100")],
                CUTOFF,
                operation_id="operation:one",
            )
        finally:
            setcontext(original)
        self.assertEqual(first, second)
        self.assertEqual(first.digest, second.digest)


class DeclarationValidationTests(unittest.TestCase):
    def assertInvalid(self, declaration, match=None):
        context = (
            self.assertRaisesRegex(ValidationError, match)
            if match
            else self.assertRaises(ValidationError)
        )
        with context:
            prepare_evidence(
                profile(), [declaration], CUTOFF, operation_id="operation:one"
            )

    def test_missing_measurement_envelope_slots_are_validation_errors(self):
        cases = (
            (ObservationClass.DIRECT, SIGNALS[0], "150", "subject", {}),
            (ObservationClass.ENUMERATED, SIGNALS[1], "0.5", "population", {}),
            (ObservationClass.ADJUDICATED, SIGNALS[2], "2", "record_set", {}),
            (
                ObservationClass.PUBLISHED,
                SIGNALS[3],
                "200",
                "publisher",
                {
                    "published_period": PublishedObservationPeriod(
                        CUTOFF - timedelta(seconds=4),
                        CUTOFF - timedelta(seconds=3),
                        CUTOFF - timedelta(seconds=2),
                        1000,
                        "vintage:one",
                    ),
                },
            ),
            (
                ObservationClass.DERIVED_STATE,
                SIGNALS[4],
                "synchronized",
                "scope",
                {"valid_until": CUTOFF},
            ),
        )
        for index, (observation_class, signal, raw, member, changes) in enumerate(cases):
            declaration = observation(
                observation_class=observation_class,
                signal=signal,
                source=f"feed:node:{index}",
                raw=raw,
                **changes,
            )
            object.__delattr__(declaration.measurement_envelope, member)
            with self.subTest(observation_class=observation_class, member=member):
                self.assertInvalid(declaration)

    def test_missing_window_period_and_binding_slots_are_validation_errors(self):
        cases = (
            (observation(), "window", "start", profile()),
            (
                observation(
                    observation_class=ObservationClass.PUBLISHED,
                    signal=SIGNALS[3],
                    source="feed:node:3",
                    raw="200",
                    published_period=PublishedObservationPeriod(
                        CUTOFF - timedelta(seconds=4),
                        CUTOFF - timedelta(seconds=3),
                        CUTOFF - timedelta(seconds=2),
                        1000,
                        "vintage:one",
                    ),
                ),
                "published_period",
                "published_at",
                profile(),
            ),
            (
                observation(
                    observed_at=CUTOFF,
                    ingested_at=CUTOFF,
                    on_demand_binding=OnDemandQueryBinding("operation:one", CUTOFF),
                ),
                "on_demand_binding",
                "operation_id",
                profile(on_demand_source="feed:node:0"),
            ),
        )
        for declaration, location, member, selected_profile in cases:
            object.__delattr__(getattr(declaration, location), member)
            with self.subTest(location=location, member=member):
                with self.assertRaises(ValidationError):
                    prepare_evidence(
                        selected_profile,
                        [declaration],
                        CUTOFF,
                        operation_id="operation:one",
                    )

    def test_duplicate_observation_ids_are_rejected(self):
        with self.assertRaisesRegex(ValidationError, "duplicate observation ID"):
            prepare_evidence(
                profile(),
                [observation(sequence=1), observation(sequence=2)],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_same_source_route_sequence_conflict_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "sequence"):
            prepare_evidence(
                profile(),
                [
                    observation(observation_id="observation:a", sequence=7),
                    observation(observation_id="observation:b", sequence=7),
                ],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_same_source_sequence_cannot_name_two_different_signals(self):
        declaration = profile_declaration()
        feed = declaration.feeds["feed:node:0"]
        two_route_profile = DeploymentProfile.validate(
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:node:0": replace(
                        feed,
                        routes=(
                            feed.routes[0],
                            SignalRouteDeclaration(
                                SIGNALS[1], RiskDomain.NODE, UNITS[SIGNALS[1]]
                            ),
                        ),
                    ),
                    "feed:node:1": replace(
                        declaration.feeds["feed:node:1"],
                        routes=(feed.routes[0],),
                    ),
                },
            )
        )
        with self.assertRaisesRegex(ValidationError, "sequence"):
            prepare_evidence(
                two_route_profile,
                [
                    observation(observation_id="observation:a", sequence=8),
                    observation(
                        observation_id="observation:b",
                        sequence=8,
                        signal=SIGNALS[1],
                        source="feed:node:0",
                        raw="0.5",
                        observation_class=ObservationClass.ENUMERATED,
                    ),
                ],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_cached_future_ingestion_is_filtered_before_duplicate_checks(self):
        current = observation()
        future = replace(current, ingested_at=CUTOFF + timedelta(microseconds=1))
        snapshot = prepare_evidence(
            profile(), [current, future], CUTOFF, operation_id="operation:one"
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE).normalized,
            Decimal("0.75"),
        )

    def test_cached_future_ingestion_is_filtered_before_sequence_conflicts(self):
        current = observation(observation_id="observation:current", sequence=9)
        future = observation(
            observation_id="observation:future",
            sequence=9,
            ingested_at=CUTOFF + timedelta(microseconds=1),
        )
        snapshot = prepare_evidence(
            profile(), [current, future], CUTOFF, operation_id="operation:one"
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE)
            .selected_observations[0]
            .observation_id,
            "observation:current",
        )

    def test_unknown_route_signal_unit_class_and_domain_are_invalid(self):
        cases = (
            replace(observation(), signal_id="world.missing.signal"),
            replace(observation(), source_id="feed:missing"),
            replace(observation(), unit="percent"),
            replace(observation(), observation_class=ObservationClass.ENUMERATED),
            replace(observation(), domain=RiskDomain.GLOBAL),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_observed_after_ingested_is_invalid(self):
        self.assertInvalid(
            observation(
                observed_at=CUTOFF - timedelta(seconds=1),
                ingested_at=CUTOFF - timedelta(seconds=2),
            ),
            "observed-at",
        )

    def test_exact_primitive_and_utc_boundaries_are_enforced(self):
        cases = (
            replace(observation(), sequence=True),
            replace(observation(), domain="node"),
            replace(observation(), observed_at=CUTOFF.replace(tzinfo=None)),
            replace(observation(), observation_id="observation:\ud800"),
            replace(observation(), population_state="observed"),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_duplicate_aliases_fail_while_collision_signals_coexist(self):
        declaration = profile_declaration()
        duplicate_aggregation = FactorAggregationDeclaration(
            ("body.clock.frequency_error", "time.sync.drift_rate"),
            "maximum",
        )
        with self.assertRaisesRegex(ValidationError, "alias set"):
            DeploymentProfile.validate(
                replace(
                    declaration,
                    risk_factors=replace(
                        declaration.risk_factors,
                        evidence_density=replace(
                            declaration.risk_factors.evidence_density,
                            aggregation=duplicate_aggregation,
                        ),
                    ),
                )
            )

        collisions = (
            "relational.communication.delivery_latency",
            "information.integrity.delivery_latency",
        )
        collision_aggregation = FactorAggregationDeclaration(
            collisions,
            "weighted_average",
            {collisions[0]: "1", collisions[1]: "1"},
        )
        feeds = dict(declaration.feeds)
        for domain in RiskDomain:
            source = f"feed:{domain.value}:0"
            feeds[source] = replace(
                feeds[source],
                routes=tuple(
                    SignalRouteDeclaration(signal, domain, "seconds")
                    for signal in collisions
                ),
            )
        normalizations = dict(declaration.normalizations)
        normalizations.pop(SIGNALS[0])
        normalizations.update(
            {
                collisions[0]: MinMaxNormalization("0", "10"),
                collisions[1]: MinMaxNormalization("0", "10"),
            }
        )
        collision_profile = DeploymentProfile.validate(
            replace(
                declaration,
                risk_factors=replace(
                    declaration.risk_factors,
                    evidence_density=replace(
                        declaration.risk_factors.evidence_density,
                        aggregation=collision_aggregation,
                    ),
                ),
                feeds=feeds,
                normalizations=normalizations,
            )
        )
        declarations = tuple(
            observation(
                observation_id=f"observation:collision:{index}",
                sequence=index,
                signal=signal,
                source="feed:node:0",
                raw=str(index * 2),
                observation_class=ObservationClass.ENUMERATED,
                measurement_envelope=enumerated_envelope(),
                unit="seconds",
            )
            for index, signal in enumerate(collisions, start=1)
        )
        snapshot = prepare_evidence(
            collision_profile,
            declarations,
            CUTOFF,
            operation_id="operation:one",
        )
        self.assertEqual(
            tuple(
                snapshot.selected(signal, domain=RiskDomain.NODE).normalized
                for signal in collisions
            ),
            (Decimal("0.2"), Decimal("0.4")),
        )

    def test_observed_state_requires_value_and_empty_states_forbid_it(self):
        for case in (
            observation(raw=None),
            observation(
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="0",
                observation_class=ObservationClass.ENUMERATED,
                population_state=PopulationState.EMPTY,
            ),
            observation(
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="0",
                observation_class=ObservationClass.ENUMERATED,
                population_state=PopulationState.UNAVAILABLE,
            ),
        ):
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_stale_expired_empty_and_unavailable_reasons_are_distinct(self):
        stale = observation(
            observed_at=CUTOFF - timedelta(seconds=31),
            ingested_at=CUTOFF - timedelta(seconds=30),
        )
        empty = observation(
            signal=SIGNALS[1],
            source="feed:node:1",
            raw=None,
            observation_class=ObservationClass.ENUMERATED,
            population_state=PopulationState.EMPTY,
        )
        unavailable = observation(
            signal=SIGNALS[1],
            source="feed:node:1",
            raw=None,
            observation_class=ObservationClass.ENUMERATED,
            population_state=PopulationState.UNAVAILABLE,
        )
        derived = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            valid_until=CUTOFF - timedelta(microseconds=1),
            window=None,
        )
        cases = (
            (stale, SIGNALS[0], UndefinedReason.STALE),
            (empty, SIGNALS[1], UndefinedReason.EMPTY_WINDOW),
            (unavailable, SIGNALS[1], UndefinedReason.SOURCE_UNAVAILABLE),
            (derived, SIGNALS[4], UndefinedReason.EXPIRED),
        )
        for declaration, signal, expected in cases:
            with self.subTest(expected=expected):
                snapshot = prepare_evidence(
                    profile(), [declaration], CUTOFF, operation_id="operation:one"
                )
                self.assertEqual(
                    snapshot.undefined(signal, domain=RiskDomain.NODE), expected
                )

    def test_exact_staleness_and_validity_horizons_remain_current(self):
        stale_edge = observation(
            observed_at=CUTOFF - timedelta(seconds=30),
            ingested_at=CUTOFF - timedelta(seconds=29),
        )
        derived_edge = observation(
            observation_id="observation:derived",
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            valid_until=CUTOFF,
            window=None,
        )
        snapshot = prepare_evidence(
            profile(), [stale_edge, derived_edge], CUTOFF, operation_id="operation:one"
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE).normalized,
            Decimal("0.75"),
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[4], domain=RiskDomain.NODE).normalized,
            Decimal("0"),
        )


class MeasurementEnvelopeTests(unittest.TestCase):
    def test_all_five_observation_classes_are_accepted(self):
        period_end = CUTOFF
        published_at = CUTOFF
        cases = (
            observation(),
            observation(
                observation_id="observation:enumerated",
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="0.4",
                observation_class=ObservationClass.ENUMERATED,
            ),
            observation(
                observation_id="observation:adjudicated",
                signal=SIGNALS[2],
                source="feed:node:2",
                raw=4,
                observation_class=ObservationClass.ADJUDICATED,
            ),
            observation(
                observation_id="observation:published",
                signal=SIGNALS[3],
                source="feed:node:3",
                raw="200",
                observation_class=ObservationClass.PUBLISHED,
                observed_at=published_at,
                ingested_at=published_at,
                window=None,
                published_period=PublishedObservationPeriod(
                    period_end - timedelta(days=30),
                    period_end,
                    published_at,
                    0,
                    "vintage:one",
                ),
            ),
            observation(
                observation_id="observation:derived",
                signal=SIGNALS[4],
                source="feed:node:4",
                raw="unsynchronized",
                observation_class=ObservationClass.DERIVED_STATE,
                window=None,
                valid_until=CUTOFF + timedelta(minutes=1),
            ),
        )
        snapshot = prepare_evidence(
            profile(), cases, CUTOFF, operation_id="operation:one"
        )
        self.assertEqual(
            tuple(
                snapshot.selected(signal, domain=RiskDomain.NODE).normalized
                for signal in SIGNALS
            ),
            (
                Decimal("0.75"),
                Decimal("0.4"),
                Decimal("0.4"),
                Decimal("0.5"),
                Decimal("1"),
            ),
        )

    def test_direct_requires_window_and_calibration_and_has_no_population_slot(self):
        with self.assertRaises(TypeError):
            DirectMeasurementEnvelope(
                subject="room:one",
                modality="light",
                instrument_make_model="meter:one",
                calibration_at=CUTOFF,
                calibration_reference="calibration:one",
                population="people",
            )
        for case in (
            replace(observation(), window=None),
            replace(observation(), population_state=PopulationState.OBSERVED),
            observation(
                measurement_envelope=direct_envelope(
                    calibration_at=CUTOFF + timedelta(seconds=1)
                )
            ),
        ):
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_enumerated_adjudicated_and_published_require_population_state(self):
        cases = (
            observation(
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="0.5",
                observation_class=ObservationClass.ENUMERATED,
                population_state=None,
            ),
            observation(
                signal=SIGNALS[2],
                source="feed:node:2",
                raw=4,
                observation_class=ObservationClass.ADJUDICATED,
                population_state=None,
            ),
            observation(
                signal=SIGNALS[3],
                source="feed:node:3",
                raw="200",
                observation_class=ObservationClass.PUBLISHED,
                population_state=None,
                observed_at=CUTOFF,
                ingested_at=CUTOFF,
                window=None,
                published_period=PublishedObservationPeriod(
                    CUTOFF - timedelta(days=1),
                    CUTOFF,
                    CUTOFF,
                    0,
                    "vintage:one",
                ),
            ),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_enumerated_requires_boundary_population_rules_and_inferred_instrument(
        self,
    ):
        base = observation(
            signal=SIGNALS[1],
            source="feed:node:1",
            raw="0.4",
            observation_class=ObservationClass.ENUMERATED,
        )
        for envelope in (
            enumerated_envelope(population=""),
            enumerated_envelope(membership_rule=""),
            enumerated_envelope(membership_mode="inferred"),
            enumerated_envelope(
                membership_mode="enumerated", instrument_identity="instrument:one"
            ),
        ):
            with self.subTest(envelope=envelope), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(),
                    [replace(base, measurement_envelope=envelope)],
                    CUTOFF,
                    operation_id="operation:one",
                )
        valid = replace(
            base,
            measurement_envelope=enumerated_envelope(
                membership_mode="inferred",
                instrument_identity="classifier:one",
                instrument_version="version:one",
            ),
        )
        self.assertEqual(
            prepare_evidence(profile(), [valid], CUTOFF, operation_id="operation:one")
            .selected(SIGNALS[1], domain=RiskDomain.NODE)
            .normalized,
            Decimal("0.4"),
        )

    def test_adjudicated_requires_outside_issuer_criteria_and_horizon(self):
        base = observation(
            signal=SIGNALS[2],
            source="feed:node:2",
            raw=4,
            observation_class=ObservationClass.ADJUDICATED,
        )
        for case in (
            replace(base, window=None),
            replace(
                base,
                measurement_envelope=adjudicated_envelope(
                    issuing_authority="sensor:one"
                ),
            ),
            replace(
                base,
                measurement_envelope=adjudicated_envelope(criteria_version=""),
            ),
        ):
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_published_requires_only_reference_period_vintage_and_exact_lag(self):
        end = CUTOFF
        published = CUTOFF
        base = observation(
            signal=SIGNALS[3],
            source="feed:node:3",
            raw="200",
            observation_class=ObservationClass.PUBLISHED,
            observed_at=published,
            ingested_at=published,
            window=None,
            published_period=PublishedObservationPeriod(
                end - timedelta(days=30), end, published, 0, "vintage:one"
            ),
        )
        self.assertEqual(
            prepare_evidence(profile(), [base], CUTOFF, operation_id="operation:one")
            .selected(SIGNALS[3], domain=RiskDomain.NODE)
            .normalized,
            Decimal("0.5"),
        )
        for case in (
            replace(base, published_period=None),
            replace(base, window=ObservationWindow(end, published)),
            replace(
                base,
                published_period=replace(base.published_period, vintage=""),
            ),
            replace(
                base,
                published_period=replace(base.published_period, publication_lag_ms=1),
            ),
        ):
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_derived_state_requires_validity_and_forbids_population_window_period(self):
        base = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            window=None,
            valid_until=CUTOFF + timedelta(minutes=1),
        )
        for case in (
            replace(base, valid_until=None),
            replace(base, population_state=PopulationState.OBSERVED),
            replace(
                base,
                window=ObservationWindow(
                    CUTOFF - timedelta(seconds=2), CUTOFF - timedelta(seconds=1)
                ),
            ),
            replace(
                base,
                published_period=PublishedObservationPeriod(
                    CUTOFF - timedelta(days=2),
                    CUTOFF - timedelta(days=1),
                    CUTOFF,
                    86_400_000,
                    "vintage:one",
                ),
            ),
        ):
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )

    def test_class_specific_forbidden_slots_are_rejected(self):
        for case in (
            replace(observation(), valid_until=CUTOFF + timedelta(seconds=1)),
            replace(
                observation(
                    signal=SIGNALS[1],
                    source="feed:node:1",
                    raw="0.4",
                    observation_class=ObservationClass.ENUMERATED,
                ),
                published_period=PublishedObservationPeriod(
                    CUTOFF - timedelta(days=2),
                    CUTOFF - timedelta(days=1),
                    CUTOFF,
                    86_400_000,
                    "vintage:one",
                ),
            ),
        ):
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    profile(), [case], CUTOFF, operation_id="operation:one"
                )


class FreshnessAndNormalizationTests(unittest.TestCase):
    def _published(self, age):
        end = CUTOFF - age
        published = CUTOFF
        return observation(
            signal=SIGNALS[3],
            source="feed:node:3",
            raw="200",
            observation_class=ObservationClass.PUBLISHED,
            observed_at=published,
            ingested_at=published,
            window=None,
            published_period=PublishedObservationPeriod(
                end - timedelta(days=30),
                end,
                published,
                int(age.total_seconds() * 1000),
                "vintage:one",
            ),
        )

    def test_published_freshness_ages_from_reference_period_end(self):
        declaration = profile_declaration()
        feed = declaration.feeds["feed:node:3"]
        configured = DeploymentProfile.validate(
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:node:3": replace(
                        feed,
                        refresh_interval_ms=86_400_000,
                        stale_threshold_ms=30 * 86_400_000,
                        stale_threshold_reason="source:publication-period",
                    ),
                },
            )
        )
        cases = (
            (timedelta(days=30) - timedelta(milliseconds=1), False),
            (timedelta(days=30), False),
            (timedelta(days=30) + timedelta(milliseconds=1), True),
            (timedelta(days=90), True),
        )
        for age, stale in cases:
            with self.subTest(age=age):
                snapshot = prepare_evidence(
                    configured,
                    [self._published(age)],
                    CUTOFF,
                    operation_id="operation:one",
                )
                reason = snapshot.undefined(SIGNALS[3], domain=RiskDomain.NODE)
                self.assertEqual(reason is UndefinedReason.STALE, stale)

    def test_on_demand_requires_exact_current_binding_and_forbids_cached_binding(self):
        source = "feed:node:0"
        on_demand_profile = profile(on_demand_source=source)
        valid = observation(
            observed_at=CUTOFF,
            ingested_at=CUTOFF + timedelta(milliseconds=1),
            on_demand_binding=OnDemandQueryBinding("operation:one", CUTOFF),
        )
        self.assertEqual(
            prepare_evidence(
                on_demand_profile,
                [valid],
                CUTOFF,
                operation_id="operation:one",
            )
            .selected(SIGNALS[0], domain=RiskDomain.NODE)
            .normalized,
            Decimal("0.75"),
        )
        invalid = (
            replace(valid, on_demand_binding=None),
            replace(
                valid,
                on_demand_binding=OnDemandQueryBinding("operation:other", CUTOFF),
            ),
            replace(
                valid,
                on_demand_binding=OnDemandQueryBinding(
                    "operation:one", CUTOFF - timedelta(microseconds=1)
                ),
            ),
        )
        for case in invalid:
            with self.subTest(case=case), self.assertRaises(ValidationError):
                prepare_evidence(
                    on_demand_profile,
                    [case],
                    CUTOFF,
                    operation_id="operation:one",
                )
        with self.assertRaises(ValidationError):
            prepare_evidence(
                profile(),
                [
                    replace(
                        valid,
                        observed_at=CUTOFF - timedelta(milliseconds=2),
                        ingested_at=CUTOFF - timedelta(milliseconds=1),
                    )
                ],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_two_on_demand_declarations_with_same_binding_only_prove_coherence(self):
        bound = OnDemandQueryBinding("operation:one", CUTOFF)
        declarations = (
            observation(
                observation_id="observation:first",
                sequence=1,
                raw="50",
                observed_at=CUTOFF,
                ingested_at=CUTOFF,
                on_demand_binding=bound,
            ),
            observation(
                observation_id="observation:second",
                sequence=2,
                raw="150",
                observed_at=CUTOFF,
                ingested_at=CUTOFF,
                on_demand_binding=bound,
            ),
        )
        entry = prepare_evidence(
            profile(on_demand_source="feed:node:0"),
            declarations,
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[0], domain=RiskDomain.NODE)
        self.assertEqual(entry.normalized, Decimal("0.75"))
        self.assertEqual(
            entry.selected_observations[0].observation_id, "observation:second"
        )

    def test_min_max_clamps_then_inverts_and_identity_rejects_out_of_range(self):
        declarations = (
            observation(raw="-1", observation_id="observation:low"),
            observation(
                signal=SIGNALS[3],
                source="feed:node:3",
                raw="400",
                observation_id="observation:published",
                observation_class=ObservationClass.PUBLISHED,
                observed_at=CUTOFF,
                ingested_at=CUTOFF,
                window=None,
                published_period=PublishedObservationPeriod(
                    CUTOFF - timedelta(days=2),
                    CUTOFF,
                    CUTOFF,
                    0,
                    "vintage:one",
                ),
            ),
        )
        snapshot = prepare_evidence(
            profile(), declarations, CUTOFF, operation_id="operation:one"
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE).normalized,
            Decimal("0"),
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[3], domain=RiskDomain.NODE).normalized,
            Decimal("0"),
        )
        with self.assertRaises(ValidationError):
            prepare_evidence(
                profile(),
                [
                    observation(
                        signal=SIGNALS[1],
                        source="feed:node:1",
                        raw="1.1",
                        observation_class=ObservationClass.ENUMERATED,
                    )
                ],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_categorical_label_must_be_declared(self):
        valid = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="unsynchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            window=None,
            valid_until=CUTOFF,
        )
        self.assertEqual(
            prepare_evidence(profile(), [valid], CUTOFF, operation_id="operation:one")
            .selected(SIGNALS[4], domain=RiskDomain.NODE)
            .normalized,
            Decimal("1"),
        )
        with self.assertRaises(ValidationError):
            prepare_evidence(
                profile(),
                [replace(valid, raw_value="unknown")],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_unselected_malformed_values_do_not_enter_a_validated_snapshot(self):
        derived_values = (
            observation(
                observation_id="observation:bad-label",
                sequence=1,
                signal=SIGNALS[4],
                source="feed:node:4",
                raw="unknown",
                observation_class=ObservationClass.DERIVED_STATE,
                window=None,
                valid_until=CUTOFF,
            ),
            observation(
                observation_id="observation:good-label",
                sequence=2,
                signal=SIGNALS[4],
                source="feed:node:4",
                raw="synchronized",
                observation_class=ObservationClass.DERIVED_STATE,
                window=None,
                valid_until=CUTOFF,
            ),
        )
        numeric_values = (
            observation(
                observation_id="observation:bad-ratio",
                sequence=1,
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="1.1",
                observation_class=ObservationClass.ENUMERATED,
            ),
            observation(
                observation_id="observation:good-ratio",
                sequence=2,
                signal=SIGNALS[1],
                source="feed:node:1",
                raw="0.5",
                observation_class=ObservationClass.ENUMERATED,
            ),
        )
        for declarations in (derived_values, numeric_values):
            with (
                self.subTest(declarations=declarations),
                self.assertRaises(ValidationError),
            ):
                prepare_evidence(
                    profile(),
                    declarations,
                    CUTOFF,
                    operation_id="operation:one",
                )


class EmptyWindowVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[3]
        path = root / "spec/v2.1.0/conformance/aggregation-empty-window-v1.json"
        data = path.read_bytes()
        cls.vectors = json.loads(data)["vectors"]
        cls.digest = hashlib.sha256(data).hexdigest()

    def test_pinned_vector_bytes_and_complete_case_inventory(self):
        self.assertEqual(
            self.digest,
            "8b3403ed7889f6b3d708d2e75f7cb8b9b700e75aaa00959ef46bf6d2d35aaa73",
        )
        self.assertEqual(
            tuple(vector["id"] for vector in self.vectors),
            (
                "A1-empty-window-emit",
                "A2-single-reading-variance-undefined",
                "A3-empty-host-is-not-dropped",
                "C1-consumer-must-not-observe",
                "C2-legacy-flagged-entry-still-fails-closed",
                "C3-missing-sample-count-is-not-an-observation",
            ),
        )

    def test_a1_empty_window_emits_unknown_entry(self):
        snapshot = prepare_evidence(
            profile(),
            [
                observation(
                    signal=SIGNALS[1],
                    source="feed:node:1",
                    raw=None,
                    observation_class=ObservationClass.ENUMERATED,
                    population_state=PopulationState.EMPTY,
                )
            ],
            CUTOFF,
            operation_id="operation:one",
        )
        self.assertEqual(len(snapshot.entries), 15)
        self.assertEqual(
            snapshot.undefined(SIGNALS[1], domain=RiskDomain.NODE),
            UndefinedReason.EMPTY_WINDOW,
        )

    def test_a2_single_reading_retains_only_the_defined_value(self):
        snapshot = prepare_evidence(
            profile(), [observation(raw="82")], CUTOFF, operation_id="operation:one"
        )
        self.assertEqual(
            snapshot.selected(SIGNALS[0], domain=RiskDomain.NODE).normalized,
            Decimal("0.41"),
        )

    def test_a3_empty_source_is_not_dropped(self):
        snapshot = prepare_evidence(
            profile(),
            [
                observation(
                    signal=SIGNALS[1],
                    source="feed:node:1",
                    raw=None,
                    observation_class=ObservationClass.ENUMERATED,
                    population_state=PopulationState.EMPTY,
                )
            ],
            CUTOFF,
            operation_id="operation:one",
        )
        self.assertIsNotNone(snapshot.selected(SIGNALS[1], domain=RiskDomain.NODE))

    def test_c1_consumer_uses_observed_source_and_not_empty_source(self):
        extra = FeedDeclaration(
            "feed:node:empty",
            (SignalRouteDeclaration(SIGNALS[1], RiskDomain.NODE, "ratio"),),
            1000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        snapshot = prepare_evidence(
            profile(extra_feeds=(extra,)),
            [
                observation(
                    signal=SIGNALS[1],
                    source="feed:node:1",
                    raw="0.43",
                    observation_class=ObservationClass.ENUMERATED,
                    observation_id="observation:host-001",
                ),
                observation(
                    source="feed:node:empty",
                    signal=SIGNALS[1],
                    observation_class=ObservationClass.ENUMERATED,
                    observation_id="observation:host-002",
                    raw=None,
                    population_state=PopulationState.EMPTY,
                ),
            ],
            CUTOFF,
            operation_id="operation:one",
        )
        entry = snapshot.selected(SIGNALS[1], domain=RiskDomain.NODE)
        self.assertEqual(entry.normalized, Decimal("0.43"))
        self.assertEqual(len(entry.selected_observations), 1)

    def test_c2_flagged_zero_cannot_be_read_as_an_observation(self):
        with self.assertRaises(ValidationError):
            prepare_evidence(
                profile(),
                [
                    observation(
                        signal=SIGNALS[1],
                        source="feed:node:1",
                        raw="0",
                        observation_class=ObservationClass.ENUMERATED,
                        population_state=PopulationState.EMPTY,
                    )
                ],
                CUTOFF,
                operation_id="operation:one",
            )

    def test_c3_missing_count_adapter_emits_no_declaration_and_is_unknown(self):
        snapshot = prepare_evidence(profile(), [], CUTOFF, operation_id="operation:one")
        self.assertEqual(
            snapshot.undefined(SIGNALS[0], domain=RiskDomain.NODE),
            UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )


class SnapshotSurfaceTests(unittest.TestCase):
    def test_snapshot_cannot_be_constructed_by_callers(self):
        with self.assertRaises(TypeError):
            EvidenceSnapshot(
                profile_ref=profile().ref,
                operation_id="operation:one",
                cutoff=CUTOFF,
                entries=(),
                digest="0" * 64,
            )

    def test_selected_and_undefined_require_exact_domain_and_known_entry(self):
        snapshot = prepare_evidence(profile(), [], CUTOFF, operation_id="operation:one")
        with self.assertRaises(ValidationError):
            snapshot.selected(SIGNALS[0], domain="node")
        with self.assertRaises(ValidationError):
            snapshot.selected("world.missing.signal", domain=RiskDomain.NODE)


if __name__ == "__main__":
    unittest.main()
