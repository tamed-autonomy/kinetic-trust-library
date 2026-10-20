"""Adversarial regressions for the independent Core Task 1 review."""

import copy
import sys
import unittest
from collections.abc import Mapping
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from types import MappingProxyType

import kinetic_trust_library.core.evidence as evidence_module
from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library._catalog import CATALOG
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.evidence import (
    EvidenceSnapshot,
    FeedOutcomeState,
    ObservationClass,
    ObservationWindow,
    OnDemandQueryBinding,
    PopulationState,
    PublishedObservationPeriod,
    SelectedFeedOutcome,
    UndefinedFeedOutcome,
    UndefinedReason,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    FactorAggregationDeclaration,
    FeedDeclaration,
    LabelSetDeclaration,
    MinMaxNormalization,
    RiskDomain,
    SignalRouteDeclaration,
)
from tests.unit.core.test_evidence import (
    CUTOFF,
    SIGNALS,
    UNITS,
    observation,
    profile,
    profile_declaration,
)


class StringSubclass(str):
    pass


class IntSubclass(int):
    pass


class DecimalSubclass(Decimal):
    pass


class ArmedEqualityString(str):
    calls = 0

    def __eq__(self, other):
        type(self).calls += 1
        raise RuntimeError("armed equality")

    __hash__ = str.__hash__


class ObservableZeroOffsetTimezone(tzinfo):
    def __init__(self):
        self.calls = 0

    def utcoffset(self, value):
        self.calls += 1
        return timedelta(0)

    def dst(self, value):
        self.calls += 1
        return timedelta(0)


class OneRoutePerFeedMapping(Mapping):
    def __init__(self, route_count):
        route_templates = tuple(
            SignalRouteDeclaration(signal, domain, UNITS[signal])
            for domain in RiskDomain
            for signal in SIGNALS
        )
        self._keys = tuple(f"feed:fanout:{index}" for index in range(route_count))
        self._feeds = tuple(
            FeedDeclaration(
                key,
                (route_templates[index % len(route_templates)],),
                1000,
                stale_threshold_ms=30_000,
                stale_threshold_reason="source:test-window",
            )
            for index, key in enumerate(self._keys)
        )
        self.iterations = 0
        self.lookups = 0

    def __iter__(self):
        for key in self._keys:
            self.iterations += 1
            yield key

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, key):
        self.lookups += 1
        try:
            index = int(key.rsplit(":", 1)[1])
            return self._feeds[index]
        except (IndexError, ValueError) as exc:
            raise KeyError(key) from exc


class HostileDatetime(datetime):
    def replace(self, *args, **kwargs):
        return "not-a-datetime"


def hostile_time():
    return HostileDatetime(2026, 8, 20, 12, tzinfo=timezone.utc)


def profile_with_first_signal(
    signal_id,
    *,
    unit,
    normalization=None,
    label_set=None,
):
    declaration = profile_declaration()
    feeds = dict(declaration.feeds)
    risk_factors = replace(
        declaration.risk_factors,
        evidence_density=replace(
            declaration.risk_factors.evidence_density,
            aggregation=FactorAggregationDeclaration((signal_id,), "maximum"),
        ),
    )
    for domain in RiskDomain:
        source_id = f"feed:{domain.value}:0"
        feeds[source_id] = replace(
            feeds[source_id],
            routes=(SignalRouteDeclaration(signal_id, domain, unit),),
        )
    normalizations = dict(declaration.normalizations)
    del normalizations[SIGNALS[0]]
    if normalization is not None:
        normalizations[signal_id] = normalization
    label_sets = dict(declaration.label_sets)
    if label_set is not None:
        label_sets[signal_id] = label_set
    return DeploymentProfile.validate(
        replace(
            declaration,
            risk_factors=risk_factors,
            feeds=feeds,
            normalizations=normalizations,
            label_sets=label_sets,
        )
    )


def declaration_for_scalar(signal_id, *, raw_value, unit):
    observation_class = ObservationClass(CATALOG[signal_id].observation_class)
    kwargs = {
        "signal": signal_id,
        "source": "feed:node:0",
        "raw": raw_value,
        "unit": unit,
        "observation_class": observation_class,
    }
    if observation_class is ObservationClass.DERIVED_STATE:
        kwargs.update(window=None, valid_until=CUTOFF)
    return observation(**kwargs)


def forged_snapshot(original, **changes):
    value = object.__new__(EvidenceSnapshot)
    for field in fields(EvidenceSnapshot):
        object.__setattr__(
            value, field.name, changes.get(field.name, getattr(original, field.name))
        )
    return value


def snapshot_with_selected_changes(snapshot, **changes):
    entries = list(snapshot.entries)
    entry_index = next(
        index
        for index, entry in enumerate(entries)
        if entry.domain is RiskDomain.NODE and entry.signal_id == SIGNALS[0]
    )
    entry = entries[entry_index]
    outcomes = list(entry.feed_outcomes)
    outcome_index = next(
        index
        for index, outcome in enumerate(outcomes)
        if type(outcome) is SelectedFeedOutcome
    )
    outcome = outcomes[outcome_index]
    outcomes[outcome_index] = replace(
        outcome,
        observation=replace(outcome.observation, **changes),
    )
    entries[entry_index] = replace(entry, feed_outcomes=tuple(outcomes))
    return forged_snapshot(snapshot, entries=tuple(entries))


def profile_with_route_count(route_count):
    """Build a valid profile with exactly ``route_count`` feed routes."""
    declaration = profile_declaration()
    route_templates = tuple(
        SignalRouteDeclaration(signal, domain, UNITS[signal])
        for domain in RiskDomain
        for signal in SIGNALS
    )
    if route_count < len(route_templates):
        raise ValueError("route count must preserve complete profile coverage")
    feeds = {}
    remaining = route_count
    source_index = 0
    while remaining:
        routes = route_templates[: min(remaining, len(route_templates))]
        source_id = f"feed:fanout:{source_index}"
        feeds[source_id] = FeedDeclaration(
            source_id,
            routes,
            1000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        remaining -= len(routes)
        source_index += 1
    return DeploymentProfile.validate(replace(declaration, feeds=feeds))


def profile_with_counted_one_route_feeds(route_count):
    declaration = profile_declaration()
    feeds = OneRoutePerFeedMapping(route_count)
    configured = DeploymentProfile.validate(replace(declaration, feeds=feeds))
    return configured, feeds


class CatalogueScalarTypeTests(unittest.TestCase):
    def test_catalogue_types_without_core_normalization_fail_closed_in_profile(self):
        with self.assertRaisesRegex(ValidationError, "without a deterministic KTP-Core"):
            profile_with_first_signal(
                "relational.obligation.next_due",
                unit="timestamp",
            )

    def test_integer_signal_requires_and_preserves_an_exact_builtin_integer(self):
        configured = profile()
        valid = observation(
            signal=SIGNALS[2],
            source="feed:node:2",
            raw=4,
            observation_class=ObservationClass.ADJUDICATED,
        )
        snapshot = evidence_module.prepare_evidence(
            configured, [valid], CUTOFF, operation_id="operation:one"
        )
        selected = snapshot.selected(
            SIGNALS[2], domain=RiskDomain.NODE, profile=configured
        ).selected_observations[0]
        self.assertIs(type(selected.raw_value), int)
        self.assertEqual(selected.normalized, Decimal("0.4"))

        invalid_values = (
            "4",
            Decimal("4"),
            Decimal("4.5"),
            True,
            IntSubclass(4),
        )
        for raw_value in invalid_values:
            with self.subTest(raw_value=raw_value), self.assertRaises(ValidationError):
                evidence_module.prepare_evidence(
                    configured,
                    [replace(valid, raw_value=raw_value)],
                    CUTOFF,
                    operation_id="operation:one",
                )

    def test_float_and_duration_use_exact_decimal_semantics(self):
        configured = profile()
        float_declaration = observation(raw=Decimal("150"))
        selected = evidence_module.prepare_evidence(
            configured,
            [float_declaration],
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[0], domain=RiskDomain.NODE, profile=configured)
        self.assertIs(type(selected.selected_observations[0].raw_value), Decimal)

        duration_signal = "body.compute.queue_wait_time"
        duration_profile = profile_with_first_signal(
            duration_signal,
            unit="seconds",
            normalization=MinMaxNormalization("0", "100"),
        )
        duration = declaration_for_scalar(
            duration_signal, raw_value=Decimal("25.5"), unit="seconds"
        )
        duration_selected = evidence_module.prepare_evidence(
            duration_profile,
            [duration],
            CUTOFF,
            operation_id="operation:one",
        ).selected(duration_signal, domain=RiskDomain.NODE, profile=duration_profile)
        self.assertIs(
            type(duration_selected.selected_observations[0].raw_value), Decimal
        )
        self.assertEqual(duration_selected.normalized, Decimal("0.255"))

        for configured_profile, declaration in (
            (configured, replace(float_declaration, raw_value=150.0)),
            (configured, replace(float_declaration, raw_value=True)),
            (
                configured,
                replace(float_declaration, raw_value=DecimalSubclass("150")),
            ),
            (duration_profile, replace(duration, raw_value=25.5)),
        ):
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                evidence_module.prepare_evidence(
                    configured_profile,
                    [declaration],
                    CUTOFF,
                    operation_id="operation:one",
                )

    def test_bool_enum_and_string_preserve_their_catalogue_scalar_families(self):
        bool_signal = "body.compute.cpu_throttle"
        bool_profile = profile_with_first_signal(
            bool_signal,
            unit="boolean",
            label_set=LabelSetDeclaration(
                ("false", "true"), {"false": "0", "true": "1"}
            ),
        )
        bool_declaration = declaration_for_scalar(
            bool_signal, raw_value=True, unit="boolean"
        )
        bool_selected = evidence_module.prepare_evidence(
            bool_profile,
            [bool_declaration],
            CUTOFF,
            operation_id="operation:one",
        ).selected(bool_signal, domain=RiskDomain.NODE, profile=bool_profile)
        self.assertIs(type(bool_selected.selected_observations[0].raw_value), bool)
        self.assertEqual(bool_selected.normalized, Decimal("1"))

        enum_profile = profile()
        enum_declaration = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            window=None,
            valid_until=CUTOFF,
        )
        enum_selected = evidence_module.prepare_evidence(
            enum_profile,
            [enum_declaration],
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[4], domain=RiskDomain.NODE, profile=enum_profile)
        self.assertIs(type(enum_selected.selected_observations[0].raw_value), str)

        string_signal = "world.regulatory.primary_jurisdiction"
        string_profile = profile_with_first_signal(
            string_signal,
            unit="jurisdiction-code",
            label_set=LabelSetDeclaration(("us", "eu"), {"us": "0", "eu": "1"}),
        )
        string_declaration = declaration_for_scalar(
            string_signal, raw_value="us", unit="jurisdiction-code"
        )
        string_selected = evidence_module.prepare_evidence(
            string_profile,
            [string_declaration],
            CUTOFF,
            operation_id="operation:one",
        ).selected(string_signal, domain=RiskDomain.NODE, profile=string_profile)
        self.assertEqual(string_selected.normalized, Decimal("0"))

        invalid = (
            (bool_profile, replace(bool_declaration, raw_value=1)),
            (bool_profile, replace(bool_declaration, raw_value="true")),
            (
                enum_profile,
                replace(enum_declaration, raw_value=StringSubclass("synchronized")),
            ),
            (
                string_profile,
                replace(string_declaration, raw_value=StringSubclass("us")),
            ),
        )
        for configured_profile, declaration in invalid:
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                evidence_module.prepare_evidence(
                    configured_profile,
                    [declaration],
                    CUTOFF,
                    operation_id="operation:one",
                )

        with self.assertRaises(ValidationError):
            profile_with_first_signal(
                bool_signal,
                unit="boolean",
                label_set=LabelSetDeclaration(("off", "on"), {"off": "0", "on": "1"}),
            )


class MissingnessProvenanceTests(unittest.TestCase):
    def test_each_configured_feed_retains_its_exact_outcome(self):
        extra = FeedDeclaration(
            "feed:node:extra",
            (SignalRouteDeclaration(SIGNALS[1], RiskDomain.NODE, UNITS[SIGNALS[1]]),),
            1000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        configured = profile(extra_feeds=(extra,))
        stale = observation(
            signal=SIGNALS[1],
            source="feed:node:1",
            observation_id="observation:stale",
            raw=Decimal("0.5"),
            observation_class=ObservationClass.ENUMERATED,
            observed_at=CUTOFF - timedelta(seconds=31),
        )
        empty = observation(
            signal=SIGNALS[1],
            source="feed:node:extra",
            observation_id="observation:empty",
            raw=None,
            observation_class=ObservationClass.ENUMERATED,
            population_state=PopulationState.EMPTY,
        )
        entry = evidence_module.prepare_evidence(
            configured, [empty, stale], CUTOFF, operation_id="operation:one"
        ).selected(SIGNALS[1], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(
            tuple(
                (outcome.source_id, outcome.state.value)
                for outcome in entry.feed_outcomes
            ),
            (
                ("feed:node:1", "stale"),
                ("feed:node:extra", "empty_window"),
            ),
        )
        self.assertEqual(entry.selected_observations, ())
        self.assertIs(entry.undefined_reason, UndefinedReason.STALE)

    def test_selected_and_missing_feeds_are_both_preserved_once(self):
        extra = FeedDeclaration(
            "feed:node:extra",
            (SignalRouteDeclaration(SIGNALS[1], RiskDomain.NODE, UNITS[SIGNALS[1]]),),
            1000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        configured = profile(extra_feeds=(extra,))
        active = observation(
            signal=SIGNALS[1],
            source="feed:node:1",
            observation_id="observation:active",
            raw=Decimal("0.25"),
            observation_class=ObservationClass.ENUMERATED,
        )
        unavailable = observation(
            signal=SIGNALS[1],
            source="feed:node:extra",
            observation_id="observation:unavailable",
            raw=None,
            observation_class=ObservationClass.ENUMERATED,
            population_state=PopulationState.UNAVAILABLE,
        )
        entry = evidence_module.prepare_evidence(
            configured, [active, unavailable], CUTOFF, operation_id="operation:one"
        ).selected(SIGNALS[1], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(
            tuple(
                (outcome.source_id, outcome.state.value)
                for outcome in entry.feed_outcomes
            ),
            (
                ("feed:node:1", "selected"),
                ("feed:node:extra", "source_unavailable"),
            ),
        )
        self.assertEqual(len(entry.selected_observations), 1)
        self.assertIsNone(entry.undefined_reason)

    def test_no_eligible_and_expired_are_distinct_source_outcomes(self):
        configured = profile()
        empty_entry = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        ).selected(SIGNALS[4], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(
            empty_entry.feed_outcomes[0].state.value, "no_eligible_observation"
        )

        expired = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            observed_at=CUTOFF - timedelta(seconds=2),
            ingested_at=CUTOFF - timedelta(seconds=1),
            window=None,
            valid_until=CUTOFF - timedelta(seconds=1),
        )
        expired_entry = evidence_module.prepare_evidence(
            configured, [expired], CUTOFF, operation_id="operation:one"
        ).selected(SIGNALS[4], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(expired_entry.feed_outcomes[0].state.value, "expired")
        self.assertIs(expired_entry.undefined_reason, UndefinedReason.EXPIRED)

    def test_missing_source_identity_occurs_once_in_its_canonical_feed_outcome(self):
        configured = profile()
        entry = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        ).selected(SIGNALS[0], domain=RiskDomain.NODE, profile=configured)
        encoded = canonical_json_bytes(entry.feed_outcomes[0])
        self.assertEqual(encoded.count(b'"source_id":"feed:node:0"'), 1)

    def test_invalid_declaration_rejects_the_snapshot_instead_of_becoming_absent(self):
        extra = FeedDeclaration(
            "feed:node:extra",
            (SignalRouteDeclaration(SIGNALS[2], RiskDomain.NODE, UNITS[SIGNALS[2]]),),
            1000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:test-window",
        )
        configured = profile(extra_feeds=(extra,))
        valid = observation(
            signal=SIGNALS[2],
            source="feed:node:2",
            observation_id="observation:valid",
            raw=4,
            observation_class=ObservationClass.ADJUDICATED,
        )
        invalid = replace(
            valid,
            source_id="feed:node:extra",
            observation_id="observation:invalid",
            raw_value=Decimal("4.5"),
        )
        with self.assertRaises(ValidationError):
            evidence_module.prepare_evidence(
                configured, [valid, invalid], CUTOFF, operation_id="operation:one"
            )

    def test_malformed_future_cached_declarations_fail_before_eligibility_filtering(
        self,
    ):
        configured = profile()
        current = observation(
            observation_id="observation:current",
            sequence=2,
            raw=Decimal("100"),
        )
        future = replace(
            current,
            observation_id="observation:future",
            sequence=3,
            ingested_at=CUTOFF + timedelta(microseconds=1),
        )
        malformed = (
            replace(future, observation_id=""),
            replace(future, sequence=1 << 63),
            replace(future, signal_id=SIGNALS[1]),
            replace(future, unit="wrong-unit"),
            replace(future, observation_class=ObservationClass.ENUMERATED),
            replace(future, measurement_envelope=object()),
            replace(future, observed_at=CUTOFF + timedelta(microseconds=1)),
            replace(future, raw_value=object()),
        )
        for declaration in malformed:
            for companions in ((), (current,)):
                with (
                    self.subTest(declaration=declaration, companions=companions),
                    self.assertRaises(ValidationError),
                ):
                    evidence_module.prepare_evidence(
                        configured,
                        [*companions, declaration],
                        CUTOFF,
                        operation_id="operation:one",
                    )

    def test_undefined_outcome_retains_complete_typed_candidate_inventory(self):
        configured = profile()
        stale = observation(
            observation_id="observation:stale-a",
            sequence=1,
            raw=Decimal("50"),
            observed_at=CUTOFF - timedelta(seconds=31),
            ingested_at=CUTOFF - timedelta(seconds=30),
        )
        later_stale = replace(
            stale,
            observation_id="observation:stale-b",
            sequence=2,
            observed_at=CUTOFF - timedelta(seconds=30, microseconds=1),
            ingested_at=CUTOFF - timedelta(seconds=29),
        )
        outcome = (
            evidence_module.prepare_evidence(
                configured,
                [later_stale, stale],
                CUTOFF,
                operation_id="operation:one",
            )
            .selected(SIGNALS[0], domain=RiskDomain.NODE, profile=configured)
            .feed_outcomes[0]
        )
        self.assertEqual(outcome.state, FeedOutcomeState.STALE)
        self.assertEqual(
            tuple(item.observation_id for item in outcome.evaluated_observations),
            ("observation:stale-a", "observation:stale-b"),
        )
        self.assertEqual(len(outcome.provenance_digest), 64)

    def test_inconsistent_undefined_reason_and_candidate_facts_fail_coherence(self):
        configured = profile()
        declarations = (
            observation(
                observation_id="observation:stale",
                raw=Decimal("50"),
                observed_at=CUTOFF - timedelta(seconds=31),
                ingested_at=CUTOFF - timedelta(seconds=30),
            ),
            observation(
                signal=SIGNALS[4],
                source="feed:node:4",
                observation_id="observation:expired",
                raw="synchronized",
                observation_class=ObservationClass.DERIVED_STATE,
                observed_at=CUTOFF - timedelta(seconds=2),
                ingested_at=CUTOFF - timedelta(seconds=1),
                window=None,
                valid_until=CUTOFF - timedelta(seconds=1),
            ),
            observation(
                signal=SIGNALS[1],
                source="feed:node:1",
                observation_id="observation:empty",
                raw=None,
                observation_class=ObservationClass.ENUMERATED,
                population_state=PopulationState.EMPTY,
            ),
            observation(
                signal=SIGNALS[2],
                source="feed:node:2",
                observation_id="observation:unavailable",
                raw=None,
                observation_class=ObservationClass.ADJUDICATED,
                population_state=PopulationState.UNAVAILABLE,
            ),
        )
        prepared = evidence_module.prepare_evidence(
            configured, declarations, CUTOFF, operation_id="operation:one"
        )
        target_states = (
            FeedOutcomeState.STALE,
            FeedOutcomeState.EXPIRED,
            FeedOutcomeState.EMPTY_WINDOW,
            FeedOutcomeState.SOURCE_UNAVAILABLE,
        )
        for target_state in target_states:
            index = next(
                index
                for index, entry in enumerate(prepared.entries)
                if entry.domain is RiskDomain.NODE
                and entry.feed_outcomes[0].state is target_state
            )
            entry = prepared.entries[index]
            outcome = entry.feed_outcomes[0]
            forged_outcome = replace(
                outcome, state=FeedOutcomeState.NO_ELIGIBLE_OBSERVATION
            )
            forged_entry = replace(
                entry,
                feed_outcomes=(forged_outcome,),
                undefined_reason=UndefinedReason.NO_ELIGIBLE_OBSERVATION,
            )
            entries = list(prepared.entries)
            entries[index] = forged_entry
            forged = forged_snapshot(prepared, entries=tuple(entries), digest="0" * 64)
            object.__setattr__(
                forged,
                "digest",
                canonical_sha256(evidence_module._snapshot_input(forged)),
            )
            with (
                self.subTest(target_state=target_state),
                self.assertRaises(ValidationError),
            ):
                evidence_module.require_validated_evidence_snapshot(
                    forged, profile=configured
                )

        stale_index = next(
            index
            for index, entry in enumerate(prepared.entries)
            if entry.domain is RiskDomain.NODE
            and entry.feed_outcomes[0].state is FeedOutcomeState.STALE
        )
        stale_entry = prepared.entries[stale_index]
        stale_outcome = stale_entry.feed_outcomes[0]
        changed_candidate = replace(
            stale_outcome.evaluated_observations[0], observed_at=CUTOFF
        )
        changed_outcome = replace(
            stale_outcome, evaluated_observations=(changed_candidate,)
        )
        changed_entry = replace(stale_entry, feed_outcomes=(changed_outcome,))
        entries = list(prepared.entries)
        entries[stale_index] = changed_entry
        forged = forged_snapshot(prepared, entries=tuple(entries), digest="0" * 64)
        object.__setattr__(
            forged, "digest", canonical_sha256(evidence_module._snapshot_input(forged))
        )
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )

    def test_represented_current_candidate_cannot_be_omitted_from_source_result(self):
        configured = profile()
        stale = observation(
            observation_id="observation:stale",
            sequence=1,
            raw=Decimal("50"),
            observed_at=CUTOFF - timedelta(seconds=31),
            ingested_at=CUTOFF - timedelta(seconds=30),
        )
        current = observation(
            observation_id="observation:current",
            sequence=2,
            raw=Decimal("100"),
        )
        prepared = evidence_module.prepare_evidence(
            configured, [current, stale], CUTOFF, operation_id="operation:one"
        )
        index = next(
            index
            for index, entry in enumerate(prepared.entries)
            if entry.domain is RiskDomain.NODE and entry.signal_id == SIGNALS[0]
        )
        entry = prepared.entries[index]
        selected_outcome = entry.feed_outcomes[0]
        forged_outcome = UndefinedFeedOutcome(
            source_id="feed:node:0",
            state=FeedOutcomeState.STALE,
            evaluated_observations=selected_outcome.evaluated_observations,
            provenance_digest=selected_outcome.provenance_digest,
        )
        forged_entry = replace(
            entry,
            feed_outcomes=(forged_outcome,),
            normalized=None,
            undefined_reason=UndefinedReason.STALE,
        )
        entries = list(prepared.entries)
        entries[index] = forged_entry
        forged = forged_snapshot(prepared, entries=tuple(entries), digest="0" * 64)
        object.__setattr__(
            forged, "digest", canonical_sha256(evidence_module._snapshot_input(forged))
        )
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )

    def test_coherent_omission_is_not_external_completeness_or_authenticity(self):
        configured = profile()
        stale = observation(
            observation_id="observation:stale",
            raw=Decimal("50"),
            observed_at=CUTOFF - timedelta(seconds=31),
            ingested_at=CUTOFF - timedelta(seconds=30),
        )
        prepared = evidence_module.prepare_evidence(
            configured, [stale], CUTOFF, operation_id="operation:one"
        )
        index = next(
            index
            for index, entry in enumerate(prepared.entries)
            if entry.domain is RiskDomain.NODE and entry.signal_id == SIGNALS[0]
        )
        entry = prepared.entries[index]
        outcome = entry.feed_outcomes[0]
        state = FeedOutcomeState.NO_ELIGIBLE_OBSERVATION
        coherent_outcome = replace(
            outcome,
            state=state,
            evaluated_observations=(),
            provenance_digest=evidence_module._feed_outcome_digest(
                profile=configured,
                source_id=outcome.source_id,
                domain=entry.domain,
                signal_id=entry.signal_id,
                state=state,
                evaluated_observations=(),
                selected=None,
            ),
        )
        coherent_entry = replace(
            entry,
            feed_outcomes=(coherent_outcome,),
            undefined_reason=UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )
        entries = list(prepared.entries)
        entries[index] = coherent_entry
        reconstructed = forged_snapshot(
            prepared, entries=tuple(entries), digest="0" * 64
        )
        object.__setattr__(
            reconstructed,
            "digest",
            canonical_sha256(evidence_module._snapshot_input(reconstructed)),
        )

        self.assertIs(
            evidence_module.require_validated_evidence_snapshot(
                reconstructed, profile=configured
            ),
            reconstructed,
        )
        self.assertIs(
            reconstructed.undefined(
                SIGNALS[0], domain=RiskDomain.NODE, profile=configured
            ),
            UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )


class EvidenceResourceBoundTests(unittest.TestCase):
    def future_cached_observation(self):
        return replace(
            observation(raw=Decimal("100")),
            ingested_at=CUTOFF + timedelta(microseconds=1),
        )

    def current_observations(self, count):
        for index in range(count):
            yield observation(
                observation_id=f"observation:bounded:{index}",
                sequence=index,
                raw=Decimal("100"),
            )

    def test_documented_absolute_limits_support_the_full_catalogue(self):
        self.assertEqual(evidence_module.MAX_EVIDENCE_DECLARATIONS, 2048)
        self.assertEqual(evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE, 64)
        self.assertGreater(evidence_module.MAX_EVIDENCE_DECLARATIONS, len(CATALOG))

    def test_empty_high_fanout_preparation_validates_profile_once(self):
        route_count = 2_100
        configured, source_mapping = profile_with_counted_one_route_feeds(route_count)
        self.assertEqual(source_mapping.iterations, route_count)
        self.assertEqual(source_mapping.lookups, route_count)
        self.assertTrue(all(type(source_id) is str for source_id in configured.feeds))
        validation_code = evidence_module.require_validated_profile.__code__
        public_accessor_codes = {
            DeploymentProfile.feed.__code__,
            DeploymentProfile.signal_route.__code__,
            DeploymentProfile.normalization.__code__,
        }
        selection_code = evidence_module._select_source_observation.__code__
        validation_calls = 0
        public_accessor_calls = 0
        selection_calls = 0

        def count_calls(frame, event, _argument):
            nonlocal validation_calls, public_accessor_calls, selection_calls
            if event == "call" and frame.f_code is validation_code:
                validation_calls += 1
            if event == "call" and frame.f_code in public_accessor_codes:
                public_accessor_calls += 1
            if event == "call" and frame.f_code is selection_code:
                selection_calls += 1

        sys.setprofile(count_calls)
        try:
            prepared = evidence_module.prepare_evidence(
                configured, (), CUTOFF, operation_id="operation:one"
            )
        finally:
            sys.setprofile(None)

        self.assertEqual(
            sum(len(entry.feed_outcomes) for entry in prepared.entries), route_count
        )
        self.assertEqual(validation_calls, 1)
        self.assertEqual(public_accessor_calls, 0)
        # Preparation and independent snapshot revalidation each visit every
        # configured route exactly once, without rescanning the profile.
        self.assertEqual(selection_calls, route_count * 2)

    def test_public_snapshot_validation_validates_bound_profile_once(self):
        configured = profile()
        equivalent_profile = profile()
        self.assertIsNot(configured, equivalent_profile)
        prepared = evidence_module.prepare_evidence(
            configured, (), CUTOFF, operation_id="operation:one"
        )
        validation_code = evidence_module.require_validated_profile.__code__
        validation_calls = 0

        def count_calls(frame, event, _argument):
            nonlocal validation_calls
            if event == "call" and frame.f_code is validation_code:
                validation_calls += 1

        sys.setprofile(count_calls)
        try:
            evidence_module.require_validated_evidence_snapshot(
                prepared, profile=equivalent_profile
            )
        finally:
            sys.setprofile(None)

        self.assertEqual(validation_calls, 1)

    def test_total_declaration_limit_accepts_exact_maximum_and_rejects_next(self):
        maximum = evidence_module.MAX_EVIDENCE_DECLARATIONS
        configured = profile()
        future = self.future_cached_observation()
        accepted = evidence_module.prepare_evidence(
            configured,
            (future for _ in range(maximum)),
            CUTOFF,
            operation_id="operation:one",
        )
        self.assertIs(
            accepted.undefined(SIGNALS[0], domain=RiskDomain.NODE, profile=configured),
            UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )
        with self.assertRaisesRegex(ValidationError, "total declaration safety"):
            evidence_module.prepare_evidence(
                configured,
                (future for _ in range(maximum + 1)),
                CUTOFF,
                operation_id="operation:one",
            )

    def test_guarded_infinite_iterable_terminates_at_maximum_plus_one(self):
        maximum = evidence_module.MAX_EVIDENCE_DECLARATIONS
        future = self.future_cached_observation()

        class GuardedInfinite:
            def __init__(self):
                self.seen = 0

            def __iter__(self):
                while self.seen <= maximum:
                    self.seen += 1
                    yield future
                raise AssertionError("preparation failed to stop at the safety limit")

        declarations = GuardedInfinite()
        with self.assertRaisesRegex(ValidationError, "total declaration safety"):
            evidence_module.prepare_evidence(
                profile(), declarations, CUTOFF, operation_id="operation:one"
            )
        self.assertEqual(declarations.seen, maximum + 1)

    def test_per_route_limit_accepts_exact_maximum_and_rejects_next(self):
        maximum = evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE
        configured = profile()
        accepted = evidence_module.prepare_evidence(
            configured,
            self.current_observations(maximum),
            CUTOFF,
            operation_id="operation:one",
        )
        outcome = accepted.selected(
            SIGNALS[0], domain=RiskDomain.NODE, profile=configured
        ).feed_outcomes[0]
        self.assertEqual(len(outcome.evaluated_observations), maximum)
        with self.assertRaisesRegex(ValidationError, "per-route candidate safety"):
            evidence_module.prepare_evidence(
                configured,
                self.current_observations(maximum + 1),
                CUTOFF,
                operation_id="operation:one",
            )

    def test_two_thousand_same_route_candidates_fail_at_the_route_limit(self):
        seen = 0

        def counted_observations():
            nonlocal seen
            for value in self.current_observations(2000):
                seen += 1
                yield value

        with self.assertRaisesRegex(ValidationError, "per-route candidate safety"):
            evidence_module.prepare_evidence(
                profile(),
                counted_observations(),
                CUTOFF,
                operation_id="operation:one",
            )
        self.assertEqual(seen, evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE + 1)

    def test_future_cache_exclusions_do_not_consume_route_candidate_budget(self):
        seen = 0
        maximum = evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE

        def mixed_observations():
            nonlocal seen
            for value in self.current_observations(maximum):
                seen += 1
                yield value
            future = self.future_cached_observation()
            for _ in range(100):
                seen += 1
                yield future
            seen += 1
            yield observation(
                observation_id="observation:bounded:overflow",
                sequence=maximum,
                raw=Decimal("100"),
            )

        with self.assertRaisesRegex(ValidationError, "per-route candidate safety"):
            evidence_module.prepare_evidence(
                profile(), mixed_observations(), CUTOFF, operation_id="operation:one"
            )
        self.assertEqual(seen, maximum + 101)

    def test_structural_boundary_rejects_forged_oversized_route_inventory(self):
        configured = profile()
        prepared = evidence_module.prepare_evidence(
            configured,
            self.current_observations(1),
            CUTOFF,
            operation_id="operation:one",
        )
        entry_index = next(
            index
            for index, entry in enumerate(prepared.entries)
            if entry.domain is RiskDomain.NODE and entry.signal_id == SIGNALS[0]
        )
        entry = prepared.entries[entry_index]
        outcome = entry.feed_outcomes[0]
        oversized = outcome.evaluated_observations * (
            evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE + 1
        )
        forged_outcome = replace(outcome, evaluated_observations=oversized)
        forged_entry = replace(entry, feed_outcomes=(forged_outcome,))
        entries = list(prepared.entries)
        entries[entry_index] = forged_entry
        forged = forged_snapshot(prepared, entries=tuple(entries), digest="0" * 64)
        object.__setattr__(
            forged, "digest", canonical_sha256(evidence_module._snapshot_input(forged))
        )
        with self.assertRaisesRegex(
            ValidationError, "evidence snapshot integrity"
        ) as raised:
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )
        self.assertRegex(str(raised.exception.__cause__), "per-route candidate safety")

    def test_structural_boundary_rejects_forged_oversized_total_inventory(self):
        route_count = (
            evidence_module.MAX_EVIDENCE_DECLARATIONS
            // evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE
            + 1
        )
        extra_feeds = tuple(
            FeedDeclaration(
                f"feed:node:bounded:{index}",
                (
                    SignalRouteDeclaration(
                        SIGNALS[0], RiskDomain.NODE, UNITS[SIGNALS[0]]
                    ),
                ),
                1000,
                stale_threshold_ms=30_000,
                stale_threshold_reason="source:test-window",
            )
            for index in range(route_count - 1)
        )
        configured = profile(extra_feeds=extra_feeds)
        prepared = evidence_module.prepare_evidence(
            configured,
            self.current_observations(1),
            CUTOFF,
            operation_id="operation:one",
        )
        entry = next(
            entry
            for entry in prepared.entries
            if entry.domain is RiskDomain.NODE and entry.signal_id == SIGNALS[0]
        )
        outcome = entry.feed_outcomes[0]
        route_inventory = outcome.evaluated_observations * (
            evidence_module.MAX_EVIDENCE_CANDIDATES_PER_ROUTE
        )
        bounded_outcomes = tuple(
            replace(value, evaluated_observations=route_inventory)
            for value in entry.feed_outcomes
        )
        self.assertEqual(len(bounded_outcomes), route_count)
        forged_entry = replace(entry, feed_outcomes=bounded_outcomes)
        entries = tuple(
            forged_entry if value is entry else value for value in prepared.entries
        )
        forged = forged_snapshot(prepared, entries=entries, digest="0" * 64)
        object.__setattr__(
            forged, "digest", canonical_sha256(evidence_module._snapshot_input(forged))
        )
        with self.assertRaisesRegex(
            ValidationError, "evidence snapshot integrity"
        ) as raised:
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )
        self.assertRegex(str(raised.exception.__cause__), "total candidate safety")


class CurrentSelectionOrderingTests(unittest.TestCase):
    def published_observation(
        self,
        *,
        observation_id,
        sequence,
        observed_offset_ms,
        reference_age_ms,
    ):
        observed_at = CUTOFF - timedelta(milliseconds=observed_offset_ms)
        reference_end = CUTOFF - timedelta(milliseconds=reference_age_ms)
        published_at = observed_at - timedelta(milliseconds=1)
        return observation(
            signal=SIGNALS[3],
            source="feed:node:3",
            observation_id=observation_id,
            sequence=sequence,
            raw=Decimal("200"),
            observation_class=ObservationClass.PUBLISHED,
            observed_at=observed_at,
            ingested_at=observed_at,
            window=None,
            published_period=PublishedObservationPeriod(
                reference_end - timedelta(days=1),
                reference_end,
                published_at,
                reference_age_ms - observed_offset_ms - 1,
                f"vintage:{sequence}",
            ),
        )

    def test_newer_acquired_stale_published_does_not_suppress_current(self):
        configured = profile()
        current = self.published_observation(
            observation_id="observation:current",
            sequence=1,
            observed_offset_ms=2_000,
            reference_age_ms=10_000,
        )
        stale = self.published_observation(
            observation_id="observation:stale",
            sequence=2,
            observed_offset_ms=1_000,
            reference_age_ms=31_000,
        )
        for declarations in ((current, stale), (stale, current)):
            entry = evidence_module.prepare_evidence(
                configured, declarations, CUTOFF, operation_id="operation:one"
            ).selected(SIGNALS[3], domain=RiskDomain.NODE, profile=configured)
            self.assertEqual(
                entry.selected_observations[0].observation_id,
                "observation:current",
            )

    def test_published_freshness_is_inclusive_at_exact_threshold_before_selection(self):
        configured = profile()
        just_inside = self.published_observation(
            observation_id="observation:inside",
            sequence=1,
            observed_offset_ms=3_000,
            reference_age_ms=29_999,
        )
        equal = self.published_observation(
            observation_id="observation:equal",
            sequence=2,
            observed_offset_ms=2_000,
            reference_age_ms=30_000,
        )
        outside = self.published_observation(
            observation_id="observation:outside",
            sequence=3,
            observed_offset_ms=1_000,
            reference_age_ms=30_001,
        )
        entry = evidence_module.prepare_evidence(
            configured,
            [outside, just_inside, equal],
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[3], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(
            entry.selected_observations[0].observation_id, "observation:equal"
        )

    def test_newer_expired_derived_state_does_not_suppress_current(self):
        configured = profile()
        current = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            observation_id="observation:current",
            sequence=1,
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            observed_at=CUTOFF - timedelta(seconds=10),
            ingested_at=CUTOFF - timedelta(seconds=9),
            window=None,
            valid_until=CUTOFF + timedelta(seconds=1),
        )
        expired = replace(
            current,
            observation_id="observation:expired",
            sequence=2,
            observed_at=CUTOFF - timedelta(seconds=2),
            ingested_at=CUTOFF - timedelta(seconds=1),
            valid_until=CUTOFF - timedelta(microseconds=1),
        )
        entry = evidence_module.prepare_evidence(
            configured,
            [current, expired],
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[4], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(
            entry.selected_observations[0].observation_id, "observation:current"
        )


class EvidenceStructuralCoherenceTests(unittest.TestCase):
    def test_structural_boundary_revalidates_prepared_snapshot_and_exact_copy(self):
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured,
            [observation(raw=Decimal("150"))],
            CUTOFF,
            operation_id="operation:one",
        )
        self.assertIs(
            evidence_module.require_validated_evidence_snapshot(
                snapshot, profile=configured
            ),
            snapshot,
        )
        exact_copy = forged_snapshot(snapshot)
        self.assertIs(
            evidence_module.require_validated_evidence_snapshot(
                exact_copy, profile=configured
            ),
            exact_copy,
        )
        self.assertEqual(
            snapshot.selected(
                SIGNALS[0], domain=RiskDomain.NODE, profile=configured
            ).normalized,
            Decimal("0.75"),
        )

    def test_constructor_name_and_digest_do_not_bypass_coherence_checks(self):
        configured = profile()
        prepared = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        )
        forged = forged_snapshot(prepared, entries=(), digest="0" * 64)
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )

        object.__setattr__(prepared, "digest", "0" * 64)
        with self.assertRaises(ValidationError):
            prepared.selected(SIGNALS[0], domain=RiskDomain.NODE, profile=configured)

    def test_nested_mutation_wrong_profile_and_non_owned_structure_are_rejected(self):
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured,
            [observation(raw=Decimal("150"))],
            CUTOFF,
            operation_id="operation:one",
        )
        entry = next(
            entry
            for entry in snapshot.entries
            if entry.domain is RiskDomain.NODE and entry.signal_id == SIGNALS[0]
        )
        selected_outcome = next(
            outcome
            for outcome in entry.feed_outcomes
            if outcome.state.value == "selected"
        )
        object.__setattr__(selected_outcome.observation, "normalized", Decimal("0.1"))
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                snapshot, profile=configured
            )

        prepared = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        )
        wrong_profile = DeploymentProfile.validate(
            replace(profile_declaration(), version=2)
        )
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                prepared, profile=wrong_profile
            )
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged_snapshot(prepared, entries=list(prepared.entries)),
                profile=configured,
            )

    def test_retained_selected_tree_rejects_passive_and_armed_primitives_first(self):
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured,
            [observation(raw=Decimal("150"))],
            CUTOFF,
            operation_id="operation:one",
        )
        selected = snapshot.selected(
            SIGNALS[0], domain=RiskDomain.NODE, profile=configured
        ).selected_observations[0]
        passive_cases = (
            {"observation_id": StringSubclass(selected.observation_id)},
            {"normalized": DecimalSubclass(str(selected.normalized))},
            {"provenance_digest": StringSubclass(selected.provenance_digest)},
            {
                "measurement_envelope": replace(
                    selected.measurement_envelope,
                    subject=StringSubclass(selected.measurement_envelope.subject),
                )
            },
        )
        for changes in passive_cases:
            with self.subTest(field=next(iter(changes))):
                forged = snapshot_with_selected_changes(snapshot, **changes)
                with self.assertRaises(ValidationError):
                    evidence_module.require_validated_evidence_snapshot(
                        forged, profile=configured
                    )

        ArmedEqualityString.calls = 0
        armed = snapshot_with_selected_changes(
            snapshot,
            observation_id=ArmedEqualityString(selected.observation_id),
        )
        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                armed, profile=configured
            )
        self.assertEqual(ArmedEqualityString.calls, 0)

    def test_retained_evidence_utc_rejects_custom_timezone_without_hooks(self):
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured,
            [observation(raw=Decimal("150"))],
            CUTOFF,
            operation_id="operation:one",
        )
        selected = snapshot.selected(
            SIGNALS[0], domain=RiskDomain.NODE, profile=configured
        ).selected_observations[0]
        custom_timezone = ObservableZeroOffsetTimezone()
        hostile_time = datetime(
            selected.observed_at.year,
            selected.observed_at.month,
            selected.observed_at.day,
            selected.observed_at.hour,
            selected.observed_at.minute,
            selected.observed_at.second,
            selected.observed_at.microsecond,
            tzinfo=custom_timezone,
        )
        forged = snapshot_with_selected_changes(snapshot, observed_at=hostile_time)

        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )
        self.assertEqual(custom_timezone.calls, 0)

    def test_stored_profile_binding_is_gated_before_equality(self):
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        )
        hostile_profile = copy.copy(configured)
        hostile_ref = copy.copy(configured.ref)
        ArmedEqualityString.calls = 0
        object.__setattr__(
            hostile_ref,
            "profile_id",
            ArmedEqualityString(configured.profile_id),
        )
        object.__setattr__(hostile_profile, "ref", hostile_ref)
        forged = forged_snapshot(snapshot, _profile=hostile_profile)

        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )
        self.assertEqual(ArmedEqualityString.calls, 0)

    def test_stored_profile_tree_rejects_armed_nested_field_before_hooks(self):
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        )
        hostile_profile = copy.copy(configured)
        ArmedEqualityString.calls = 0
        object.__setattr__(
            hostile_profile,
            "misattestation_adjudicator",
            ArmedEqualityString(configured.misattestation_adjudicator),
        )
        forged = forged_snapshot(snapshot, _profile=hostile_profile)

        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )
        self.assertEqual(ArmedEqualityString.calls, 0)
        self.assertEqual(forged, snapshot)
        self.assertEqual(ArmedEqualityString.calls, 0)

    def test_stored_profile_tree_rejects_custom_proxy_mapping_without_hooks(self):
        class ArmedMapping(Mapping):
            calls = 0

            def _explode(self):
                type(self).calls += 1
                raise RuntimeError("armed retained profile mapping")

            def __iter__(self):
                return self._explode()

            def __len__(self):
                return self._explode()

            def __getitem__(self, _key):
                return self._explode()

        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured, [], CUTOFF, operation_id="operation:one"
        )
        hostile_profile = copy.copy(configured)
        hostile_mapping = ArmedMapping()
        object.__setattr__(
            hostile_profile,
            "actions",
            MappingProxyType(hostile_mapping),
        )
        forged = forged_snapshot(snapshot, _profile=hostile_profile)

        with self.assertRaises(ValidationError):
            evidence_module.require_validated_evidence_snapshot(
                forged, profile=configured
            )
        self.assertEqual(ArmedMapping.calls, 0)


class HostileBoundaryTests(unittest.TestCase):
    def test_every_evidence_datetime_slot_rejects_subclasses_as_validation_errors(self):
        hostile = hostile_time()
        base = observation(raw=Decimal("150"))
        cases = (
            (replace(base, observed_at=hostile), CUTOFF),
            (replace(base, ingested_at=hostile), CUTOFF),
            (
                replace(
                    base,
                    window=ObservationWindow(hostile, base.window.end),
                ),
                CUTOFF,
            ),
            (
                replace(
                    base,
                    window=ObservationWindow(base.window.start, hostile),
                ),
                CUTOFF,
            ),
            (
                replace(
                    base,
                    measurement_envelope=replace(
                        base.measurement_envelope, calibration_at=hostile
                    ),
                ),
                CUTOFF,
            ),
            (base, hostile),
        )
        for declaration, cutoff in cases:
            with (
                self.subTest(declaration=declaration, cutoff=cutoff),
                self.assertRaises(ValidationError),
            ):
                evidence_module.prepare_evidence(
                    profile(), [declaration], cutoff, operation_id="operation:one"
                )

        derived = observation(
            signal=SIGNALS[4],
            source="feed:node:4",
            raw="synchronized",
            observation_class=ObservationClass.DERIVED_STATE,
            window=None,
            valid_until=hostile,
        )
        published = observation(
            signal=SIGNALS[3],
            source="feed:node:3",
            raw=Decimal("200"),
            observation_class=ObservationClass.PUBLISHED,
            observed_at=CUTOFF,
            ingested_at=CUTOFF,
            window=None,
            published_period=PublishedObservationPeriod(
                CUTOFF - timedelta(days=1), CUTOFF, CUTOFF, 0, "vintage:one"
            ),
        )
        on_demand = replace(
            base,
            observed_at=CUTOFF,
            ingested_at=CUTOFF,
            on_demand_binding=OnDemandQueryBinding("operation:one", hostile),
        )
        published_cases = tuple(
            replace(published, published_period=period)
            for period in (
                replace(published.published_period, start=hostile),
                replace(published.published_period, end=hostile),
                replace(published.published_period, published_at=hostile),
                replace(
                    published.published_period,
                    publication_lag_ms=IntSubclass(0),
                ),
            )
        )
        for configured, declaration in (
            (profile(), derived),
            *((profile(), declaration) for declaration in published_cases),
            (profile(on_demand_source="feed:node:0"), on_demand),
        ):
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                evidence_module.prepare_evidence(
                    configured,
                    [declaration],
                    CUTOFF,
                    operation_id="operation:one",
                )

    def test_sequence_is_exact_and_bounded(self):
        configured = profile()
        maximum = (1 << 63) - 1
        accepted = evidence_module.prepare_evidence(
            configured,
            [observation(sequence=maximum, raw=Decimal("150"))],
            CUTOFF,
            operation_id="operation:one",
        ).selected(SIGNALS[0], domain=RiskDomain.NODE, profile=configured)
        self.assertEqual(accepted.selected_observations[0].sequence, maximum)
        for sequence in (maximum + 1, IntSubclass(1), True):
            with self.subTest(sequence=sequence), self.assertRaises(ValidationError):
                evidence_module.prepare_evidence(
                    configured,
                    [observation(sequence=sequence, raw=Decimal("150"))],
                    CUTOFF,
                    operation_id="operation:one",
                )

    def test_hostile_iterable_failures_are_normalized_without_catching_control_flow(
        self,
    ):
        class ThrowingIterable:
            def __iter__(self):
                yield observation(raw=Decimal("150"))
                raise ValueError("changed while iterating")

        with self.assertRaises(ValidationError):
            evidence_module.prepare_evidence(
                profile(), ThrowingIterable(), CUTOFF, operation_id="operation:one"
            )

        class InterruptingIterable:
            def __iter__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            evidence_module.prepare_evidence(
                profile(), InterruptingIterable(), CUTOFF, operation_id="operation:one"
            )

    def test_neighboring_evidence_primitives_reject_subclasses(self):
        base = observation(raw=Decimal("150"))
        for declaration in (
            replace(base, observation_id=StringSubclass("observation:one")),
            replace(base, source_id=StringSubclass("feed:node:0")),
            replace(base, signal_id=StringSubclass(SIGNALS[0])),
            replace(base, unit=StringSubclass(UNITS[SIGNALS[0]])),
        ):
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                evidence_module.prepare_evidence(
                    profile(), [declaration], CUTOFF, operation_id="operation:one"
                )
        configured = profile()
        snapshot = evidence_module.prepare_evidence(
            configured, [base], CUTOFF, operation_id="operation:one"
        )
        with self.assertRaises(ValidationError):
            snapshot.selected(
                StringSubclass(SIGNALS[0]),
                domain=RiskDomain.NODE,
                profile=configured,
            )


if __name__ == "__main__":
    unittest.main()
