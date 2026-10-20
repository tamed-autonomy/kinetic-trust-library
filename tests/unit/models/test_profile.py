import sys
import unittest
from collections.abc import Mapping
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import MappingProxyType

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import validate_identifier
from kinetic_trust_library.models.action import (
    ActionDemandDeclaration,
    CapabilityDeclaration,
    MomentCriticalityDeclaration,
    NormativeGateDecision,
    NormativeGateToken,
    ValidatedActionDemand,
    ValidatedCapability,
)
from kinetic_trust_library.models.profile import (
    ActionPolicy,
    DeploymentProfile,
    DeploymentProfileDeclaration,
    EnvelopeThresholds,
    FeedDeclaration,
    FactorAggregationDeclaration,
    FactorName,
    IdentityNormalization,
    LabelSetDeclaration,
    MinMaxNormalization,
    MomentCriticalityFactorDeclaration,
    NormativeGatePolicy,
    RiskDomain,
    RiskFactorsDeclaration,
    SignalRiskFactorDeclaration,
    SignalRouteDeclaration,
    require_validated_profile,
)
import kinetic_trust_library.models.profile as profile_module


UTC_NOW = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
SIGNALS = (
    "world.optical.illuminance",
    "world.weather.air_temperature",
    "body.compute.compute_utilization",
    "information.attention.region_entropy",
    "relational.communication.delivery_success",
)
SIGNAL_FACTORS = (
    FactorName.EVIDENCE_DENSITY,
    FactorName.TRUST_TREND,
    FactorName.ADVERSARIAL_PRESSURE,
    FactorName.UPDATE_RESISTANCE,
    FactorName.ATTESTATION_COVERAGE,
)
ALL_FACTORS = SIGNAL_FACTORS + (FactorName.MOMENT_CRITICALITY,)
FACTOR_MEMBERS = {
    FactorName.EVIDENCE_DENSITY: "evidence_density",
    FactorName.TRUST_TREND: "trust_trend",
    FactorName.ADVERSARIAL_PRESSURE: "adversarial_pressure",
    FactorName.UPDATE_RESISTANCE: "update_resistance",
    FactorName.ATTESTATION_COVERAGE: "attestation_coverage",
    FactorName.MOMENT_CRITICALITY: "moment_criticality",
}


def complete_risk_factors() -> RiskFactorsDeclaration:
    aggregations = {
        factor: FactorAggregationDeclaration(
            signals=(signal,),
            method="maximum",
            signal_weights=None,
        )
        for factor, signal in zip(SIGNAL_FACTORS, SIGNALS, strict=True)
    }
    return RiskFactorsDeclaration(
        evidence_density=SignalRiskFactorDeclaration(
            weight="0.20",
            aggregation=aggregations[FactorName.EVIDENCE_DENSITY],
        ),
        trust_trend=SignalRiskFactorDeclaration(
            weight="0.20",
            aggregation=aggregations[FactorName.TRUST_TREND],
        ),
        adversarial_pressure=SignalRiskFactorDeclaration(
            weight="0.15",
            aggregation=aggregations[FactorName.ADVERSARIAL_PRESSURE],
        ),
        update_resistance=SignalRiskFactorDeclaration(
            weight="0.15",
            aggregation=aggregations[FactorName.UPDATE_RESISTANCE],
        ),
        attestation_coverage=SignalRiskFactorDeclaration(
            weight="0.15",
            aggregation=aggregations[FactorName.ATTESTATION_COVERAGE],
        ),
        moment_criticality=MomentCriticalityFactorDeclaration(
            weight="0.15",
            supplier="action-api",
            unit="stress-0-1",
        ),
    )


def complete_profile_declaration(
    *,
    risk_factors=None,
    risk_domain_weights=None,
    soul_frameworks=("soul.framework.primary",),
    peer_share="10",
    external_root_hop_bound=6,
    misattestation_adjudicator="adjudicator:one",
    standing_decay_rate="16",
    envelope_thresholds=None,
    actions=None,
    action_demand_unit="trust-points",
    feeds=None,
    alias_selections=None,
    normalizations=None,
    label_sets=None,
):
    if risk_domain_weights is None:
        risk_domain_weights = {
            RiskDomain.NODE: "0.30",
            RiskDomain.NEIGHBORHOOD: "0.40",
            RiskDomain.GLOBAL: "0.30",
        }
    if risk_factors is None:
        risk_factors = complete_risk_factors()
    if envelope_thresholds is None:
        envelope_thresholds = EnvelopeThresholds(
            veto=Decimal("0"),
            allow=Decimal("0.40"),
            metacognitive_floor=Decimal("0.20"),
            assisted_floor=Decimal("0.10"),
        )
    if actions is None:
        actions = {
            "deploy": ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units={"rate": "ops-per-minute"},
                normative_gates=(),
            )
        }
    if feeds is None:
        feeds = {
            f"feed:{index}": FeedDeclaration(
                source_id=f"feed:{index}",
                routes=(
                    SignalRouteDeclaration(
                        signal_id=signal,
                        domain=domain,
                        unit={
                            "world.optical.illuminance": "lx",
                            "world.weather.air_temperature": "celsius",
                            "body.compute.compute_utilization": "ratio",
                            "information.attention.region_entropy": "bits",
                            "relational.communication.delivery_success": "ratio",
                        }[signal],
                    ),
                ),
                refresh_interval_ms=1000,
                stale_threshold_ms=None,
                stale_threshold_reason=None,
            )
            for index, (domain, signal) in enumerate(
                ((domain, signal) for domain in RiskDomain for signal in SIGNALS),
                start=1,
            )
        }
    if alias_selections is None:
        alias_selections = {}
    if normalizations is None:
        normalizations = {
            "world.optical.illuminance": MinMaxNormalization(
                minimum="0", maximum="200000", invert=False, clamp=True
            ),
            "world.weather.air_temperature": MinMaxNormalization(
                minimum="-100", maximum="70", invert=False, clamp=True
            ),
            "body.compute.compute_utilization": IdentityNormalization(),
            "information.attention.region_entropy": MinMaxNormalization(
                minimum="0", maximum="16", invert=False, clamp=True
            ),
            "relational.communication.delivery_success": IdentityNormalization(
                invert=True
            ),
        }
    if label_sets is None:
        label_sets = {}
    return DeploymentProfileDeclaration(
        profile_id="profile.full-core",
        version=4,
        action_demand_unit=action_demand_unit,
        risk_factors=risk_factors,
        risk_domain_weights=risk_domain_weights,
        soul_frameworks=soul_frameworks,
        peer_share=peer_share,
        external_root_hop_bound=external_root_hop_bound,
        misattestation_adjudicator=misattestation_adjudicator,
        standing_decay_rate=standing_decay_rate,
        envelope_thresholds=envelope_thresholds,
        actions=actions,
        feeds=feeds,
        alias_selections=alias_selections,
        normalizations=normalizations,
        label_sets=label_sets,
    )


def factor_declaration(declaration, factor):
    return getattr(declaration.risk_factors, FACTOR_MEMBERS[factor])


def with_factor_aggregation(declaration, factor, aggregation):
    member = FACTOR_MEMBERS[factor]
    return replace(
        declaration,
        risk_factors=replace(
            declaration.risk_factors,
            **{
                member: replace(
                    getattr(declaration.risk_factors, member),
                    aggregation=aggregation,
                )
            },
        ),
    )


def feeds_replacing_signal(declaration, old_signal, new_signal, unit):
    return {
        source_id: replace(
            feed,
            routes=tuple(
                SignalRouteDeclaration(new_signal, route.domain, unit)
                if route.signal_id == old_signal
                else route
                for route in feed.routes
            ),
        )
        for source_id, feed in declaration.feeds.items()
    }


def complete_capability(**changes):
    values = {
        "subject": "agent:one",
        "action_classes": ("deploy",),
        "constraint_ceiling": {"rate": "25"},
        "not_before": UTC_NOW - timedelta(minutes=1),
        "not_after": UTC_NOW + timedelta(minutes=1),
        "provenance_id": "capability:one",
    }
    values.update(changes)
    return CapabilityDeclaration(**values)


def complete_action(**changes):
    values = {
        "action_id": "action:one",
        "subject": "agent:one",
        "action_class": "deploy",
        "demand": "40",
        "demand_unit": "trust-points",
        "demand_source": "demand-api",
        "granted_constraints": {"rate": "20"},
        "requested_constraints": {"rate": "10"},
        "moment_criticality": MomentCriticalityDeclaration(
            value="0.75",
            supplier="action-api",
            unit="stress-0-1",
            observed_at=UTC_NOW,
            provenance_id="moment:one",
        ),
        "normative_gate_tokens": (),
    }
    values.update(changes)
    return ActionDemandDeclaration(**values)


class _DisappearingMapping(Mapping):
    def __iter__(self):
        yield "deploy"

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise KeyError(key)


class _RuntimeMutationMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("mapping mutated")
        yield

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise AssertionError("iteration must fail first")


class _ExternalFailureMapping(Mapping):
    def __init__(self, *, iteration_error=None, lookup_error=None):
        self._iteration_error = iteration_error
        self._lookup_error = lookup_error

    def __iter__(self):
        if self._iteration_error is not None:
            raise self._iteration_error
        return iter(("deploy",))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        if self._lookup_error is not None:
            raise self._lookup_error
        raise AssertionError("a failure must be configured")


class _KeySequenceMapping(Mapping):
    def __init__(self, keys, value):
        self._keys = tuple(keys)
        self._value = value

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, key):
        return self._value


class _StringSubclass(str):
    pass


class _RaisingStringSubclass(str):
    calls = 0

    def __str__(self):
        type(self).calls += 1
        raise ValueError("hostile __str__")


class _DeceptiveStringSubclass(str):
    calls = 0

    def __str__(self):
        type(self).calls += 1
        return "different"


class _UnhashableString(str):
    __hash__ = None


class _ToggleHashString(str):
    armed = False
    calls = 0

    def __hash__(self):
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError("toggled string hash ran")
        return str.__hash__(self)


class _RaisingEqualityString(str):
    calls = 0
    __hash__ = str.__hash__

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("hostile string equality ran")


class _IntSubclass(int):
    pass


class _ToggleInt(int):
    armed = False
    calls = 0

    @classmethod
    def reset(cls, *, armed: bool) -> None:
        cls.armed = armed
        cls.calls = 0

    def _observe(self) -> None:
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError("hostile integer hook ran")

    def __eq__(self, other):
        self._observe()
        return int.__eq__(self, other)

    def __ne__(self, other):
        self._observe()
        return int.__ne__(self, other)

    def __lt__(self, other):
        self._observe()
        return int.__lt__(self, other)

    def __le__(self, other):
        self._observe()
        return int.__le__(self, other)

    def __gt__(self, other):
        self._observe()
        return int.__gt__(self, other)

    def __ge__(self, other):
        self._observe()
        return int.__ge__(self, other)

    def __hash__(self):
        self._observe()
        return int.__hash__(self)

    def __index__(self):
        self._observe()
        return int.__index__(self)

    def __int__(self):
        self._observe()
        return int.__int__(self)


class _ArmedMomentShell:
    armed = False
    calls = 0

    @classmethod
    def reset(cls, *, armed: bool) -> None:
        cls.armed = armed
        cls.calls = 0

    def __getattr__(self, _name):
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError("hostile moment attribute hook ran")
        raise AttributeError


class ProfileTests(unittest.TestCase):
    def test_profile_owns_one_shared_six_factor_model(self):
        profile = DeploymentProfile.validate(complete_profile_declaration())
        self.assertEqual(
            profile.factor(FactorName.EVIDENCE_DENSITY).weight,
            Decimal("0.20"),
        )
        self.assertEqual(
            profile.domain_weight(RiskDomain.NEIGHBORHOOD),
            Decimal("0.40"),
        )
        self.assertFalse(hasattr(profile, "domains"))
        self.assertFalse(hasattr(profile, "moment_criticality"))

    def test_factor_and_domain_weights_are_positive_complete_and_exact_sum(self):
        declaration = complete_profile_declaration()
        zero_factor = replace(
            declaration.risk_factors,
            trust_trend=replace(
                declaration.risk_factors.trust_trend,
                weight="0",
            ),
        )
        with self.assertRaisesRegex(ValidationError, "factor weights must be positive"):
            DeploymentProfile.validate(replace(declaration, risk_factors=zero_factor))

        zero_domain = dict(declaration.risk_domain_weights)
        zero_domain[RiskDomain.NODE] = "0"
        with self.assertRaisesRegex(ValidationError, "domain weights must be positive"):
            DeploymentProfile.validate(
                replace(declaration, risk_domain_weights=zero_domain)
            )

    def test_profile_owns_complete_evidence_contract(self):
        profile = DeploymentProfile.validate(complete_profile_declaration())
        route = profile.feed("feed:1").routes[0]
        self.assertEqual(route.unit, "lx")
        self.assertEqual(
            profile.signal_route(
                "feed:1",
                signal_id="world.optical.illuminance",
                domain=RiskDomain.NODE,
            ),
            route,
        )
        self.assertEqual(profile.feed("feed:1").stale_threshold_ms, 5000)
        self.assertEqual(profile.feed("feed:1").weight, Decimal("1"))
        self.assertIsInstance(profile.normalizations, Mapping)
        self.assertIsInstance(
            profile.normalization("world.optical.illuminance"),
            MinMaxNormalization,
        )

    def test_evidence_contract_rejects_missing_routes_units_and_normalization(self):
        declaration = complete_profile_declaration()
        cases = (
            replace(declaration, feeds={}),
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:1": replace(
                        declaration.feeds["feed:1"],
                        routes=(
                            replace(declaration.feeds["feed:1"].routes[0], unit=""),
                        ),
                    ),
                },
            ),
            replace(
                declaration,
                normalizations={
                    key: value
                    for key, value in declaration.normalizations.items()
                    if key != "world.optical.illuminance"
                },
            ),
            replace(
                declaration,
                normalizations={
                    **declaration.normalizations,
                    "body.compute.compute_utilization": IdentityNormalization(invert=1),
                },
            ),
        )
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                DeploymentProfile.validate(invalid)

    def test_shared_factor_routes_require_every_domain_signal_pair(self):
        declaration = complete_profile_declaration()
        feeds = dict(declaration.feeds)
        feeds.pop("feed:15")
        with self.assertRaisesRegex(ValidationError, "cover exactly"):
            DeploymentProfile.validate(replace(declaration, feeds=feeds))

    def test_identity_normalization_accepts_determined_zero_one_only(self):
        """Catches rejecting a formula-determined 0-1 signal or widening to any range."""
        signal = "information.amplification.amplifier_hhi"
        declaration = complete_profile_declaration()
        aggregation = replace(
            factor_declaration(
                declaration, FactorName.EVIDENCE_DENSITY
            ).aggregation,
            signals=(signal,),
        )
        determined = replace(
            declaration,
            risk_factors=with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            ).risk_factors,
            feeds=feeds_replacing_signal(
                declaration, SIGNALS[0], signal, "ratio"
            ),
            normalizations={
                **{
                    key: value
                    for key, value in declaration.normalizations.items()
                    if key != SIGNALS[0]
                },
                signal: IdentityNormalization(),
            },
        )

        profile = DeploymentProfile.validate(determined)
        self.assertEqual(profile.normalization(signal), IdentityNormalization())

        with self.assertRaisesRegex(ValidationError, "declared 0-1 signal"):
            DeploymentProfile.validate(
                replace(
                    declaration,
                    normalizations={
                        **declaration.normalizations,
                        "world.optical.illuminance": IdentityNormalization(),
                    },
                )
            )

    def test_feed_freshness_defaults_and_longer_threshold_reason(self):
        declaration = complete_profile_declaration()
        feed = declaration.feeds["feed:1"]
        for invalid in (
            replace(feed, refresh_interval_ms=99),
            replace(feed, weight="0"),
            replace(feed, weight="-1"),
            replace(feed, stale_threshold_ms=6000),
            replace(feed, refresh_interval_ms=0, stale_threshold_ms=1000),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        feeds={**declaration.feeds, "feed:1": invalid},
                    )
                )
        profile = DeploymentProfile.validate(
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:1": replace(
                        feed,
                        stale_threshold_ms=6000,
                        stale_threshold_reason="source:publication-lag",
                    ),
                },
            )
        )
        self.assertEqual(profile.feed("feed:1").stale_threshold_ms, 6000)

    def test_feed_freshness_intervals_have_safe_operational_maxima(self):
        """Catches unbounded durations that cannot be safely applied as timedeltas."""
        declaration = complete_profile_declaration()
        feed = declaration.feeds["feed:1"]

        maximum_default = DeploymentProfile.validate(
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:1": replace(
                        feed,
                        refresh_interval_ms=31_622_400_000,
                        stale_threshold_ms=None,
                    ),
                },
            )
        )
        self.assertEqual(
            maximum_default.feed("feed:1").stale_threshold_ms,
            158_112_000_000,
        )

        maximum_explicit = DeploymentProfile.validate(
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:1": replace(
                        feed,
                        stale_threshold_ms=158_112_000_000,
                        stale_threshold_reason="source:long-reference-period",
                    ),
                },
            )
        )
        self.assertEqual(
            maximum_explicit.feed("feed:1").stale_threshold_ms,
            158_112_000_000,
        )

        for invalid in (
            replace(feed, refresh_interval_ms=31_622_400_001),
            replace(
                feed,
                stale_threshold_ms=158_112_000_001,
                stale_threshold_reason="source:long-reference-period",
            ),
            replace(feed, refresh_interval_ms=10**33),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        feeds={**declaration.feeds, "feed:1": invalid},
                    )
                )

    def test_feed_intervals_require_exact_builtin_integers(self):
        """Catches profiles born invalid because construction retained int subclasses."""
        declaration = complete_profile_declaration()
        feed = declaration.feeds["feed:1"]

        for invalid in (
            replace(feed, refresh_interval_ms=_IntSubclass(1000)),
            replace(feed, stale_threshold_ms=_IntSubclass(5000)),
            replace(feed, refresh_interval_ms=True),
            replace(feed, stale_threshold_ms=False),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        feeds={**declaration.feeds, "feed:1": invalid},
                    )
                )

    def test_categorical_signal_requires_complete_label_stress_mapping(self):
        signal = "body.clock.sync_state"
        declaration = complete_profile_declaration()
        aggregation = replace(
            factor_declaration(
                declaration, FactorName.EVIDENCE_DENSITY
            ).aggregation,
            signals=(signal,),
        )
        updated = replace(
            declaration,
            risk_factors=with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            ).risk_factors,
            feeds=feeds_replacing_signal(
                declaration, SIGNALS[0], signal, "state"
            ),
            normalizations={
                key: value
                for key, value in declaration.normalizations.items()
                if key != SIGNALS[0]
            },
            label_sets={
                signal: LabelSetDeclaration(
                    labels=("synchronized", "unsynchronized"),
                    stress_by_label={"synchronized": "0", "unsynchronized": "1"},
                    source_id="clock:status",
                )
            },
        )
        profile = DeploymentProfile.validate(updated)
        self.assertEqual(
            profile.label_sets[signal].stress_by_label["unsynchronized"],
            Decimal("1"),
        )
        with self.assertRaises(ValidationError):
            DeploymentProfile.validate(
                replace(
                    updated,
                    label_sets={
                        signal: replace(
                            updated.label_sets[signal],
                            stress_by_label={"synchronized": "0"},
                        )
                    },
                )
            )

    def test_label_stress_errors_do_not_echo_untrusted_labels(self):
        signal = "body.clock.sync_state"
        label = "state\x85INJECTED"
        declaration = complete_profile_declaration()
        aggregation = replace(
            factor_declaration(
                declaration, FactorName.EVIDENCE_DENSITY
            ).aggregation,
            signals=(signal,),
        )
        updated = replace(
            declaration,
            risk_factors=with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            ).risk_factors,
            feeds=feeds_replacing_signal(
                declaration, SIGNALS[0], signal, "state"
            ),
            normalizations={
                key: value
                for key, value in declaration.normalizations.items()
                if key != SIGNALS[0]
            },
            label_sets={
                signal: LabelSetDeclaration(
                    labels=(label, "synchronized"),
                    stress_by_label={label: "0.5", "synchronized": "0"},
                    source_id="clock:status",
                )
            },
        )
        profile = DeploymentProfile.validate(updated)
        self.assertEqual(profile.label_sets[signal].labels, (label, "synchronized"))

        with self.assertRaises(ValidationError) as caught:
            DeploymentProfile.validate(
                replace(
                    updated,
                    label_sets={
                        signal: replace(
                            updated.label_sets[signal],
                            stress_by_label={label: "not-a-number", "synchronized": "0"},
                        )
                    },
                )
            )
        message = str(caught.exception)
        self.assertNotIn(label, message)
        self.assertNotIn("\x85", message)
        self.assertNotIn("INJECTED", message)

    def test_populated_duplicate_alias_requires_exact_selection(self):
        signal = "body.network.interface_count"
        declaration = complete_profile_declaration()
        aggregation = replace(
            factor_declaration(
                declaration, FactorName.EVIDENCE_DENSITY
            ).aggregation,
            signals=(signal,),
        )
        updated = replace(
            declaration,
            risk_factors=with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            ).risk_factors,
            feeds=feeds_replacing_signal(
                declaration, SIGNALS[0], signal, "count"
            ),
            normalizations={
                **{
                    key: value
                    for key, value in declaration.normalizations.items()
                    if key != SIGNALS[0]
                },
                signal: MinMaxNormalization("0", "16"),
            },
            alias_selections={"network_interface_count": signal},
        )
        self.assertEqual(
            DeploymentProfile.validate(updated).alias_selections[
                "network_interface_count"
            ],
            signal,
        )
        with self.assertRaises(ValidationError):
            DeploymentProfile.validate(replace(updated, alias_selections={}))

    def test_mapping_snapshot_failures_are_controlled_validation_errors(self):
        for actions in (
            _DisappearingMapping(),
            _RuntimeMutationMapping(),
            _ExternalFailureMapping(iteration_error=ValueError("iterate")),
            _ExternalFailureMapping(lookup_error=ValueError("lookup")),
        ):
            with (
                self.subTest(actions=actions),
                self.assertRaisesRegex(ValidationError, "changed during validation"),
            ):
                DeploymentProfile.validate(
                    replace(complete_profile_declaration(), actions=actions)
                )

    def test_mapping_snapshot_does_not_swallow_process_control_signals(self):
        for actions, expected in (
            (
                _ExternalFailureMapping(iteration_error=KeyboardInterrupt()),
                KeyboardInterrupt,
            ),
            (_ExternalFailureMapping(lookup_error=SystemExit()), SystemExit),
        ):
            with self.subTest(actions=actions), self.assertRaises(expected):
                DeploymentProfile.validate(
                    replace(complete_profile_declaration(), actions=actions)
                )

    def test_profile_mapping_keys_require_exact_authoritative_types(self):
        declaration = complete_profile_declaration()
        policy = declaration.actions["deploy"]

        _RaisingStringSubclass.calls = 0
        _DeceptiveStringSubclass.calls = 0
        for key in (
            _StringSubclass("deploy"),
            _RaisingStringSubclass("deploy"),
            _DeceptiveStringSubclass("deploy"),
            _UnhashableString("deploy"),
            True,
            [],
            object(),
        ):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValidationError, "exact str"),
            ):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        actions=_KeySequenceMapping((key,), policy),
                    )
                )
        self.assertEqual(_RaisingStringSubclass.calls, 0)
        self.assertEqual(_DeceptiveStringSubclass.calls, 0)

        with self.assertRaisesRegex(ValidationError, "duplicate keys"):
            DeploymentProfile.validate(
                replace(
                    declaration,
                    actions=_KeySequenceMapping(("deploy", "deploy"), policy),
                )
            )

    def test_profile_mapping_snapshot_accepts_normal_owned_mappings(self):
        declaration = complete_profile_declaration()
        policy = declaration.actions["deploy"]
        for actions in (
            {"deploy": policy},
            MappingProxyType({"deploy": policy}),
        ):
            with self.subTest(actions=actions):
                profile = DeploymentProfile.validate(
                    replace(declaration, actions=actions)
                )
                self.assertEqual(tuple(profile.actions), ("deploy",))
                self.assertIs(type(next(iter(profile.actions))), str)

    def test_authoritative_identifier_tuples_reject_string_subclasses_first(self):
        declaration = complete_profile_declaration()
        hostile_values = (
            _ToggleHashString("soul.framework.primary"),
            _RaisingEqualityString("soul.framework.primary"),
            _RaisingStringSubclass("soul.framework.primary"),
        )
        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        _RaisingEqualityString.calls = 0
        _RaisingStringSubclass.calls = 0
        try:
            for hostile in hostile_values:
                with self.subTest(hostile_type=type(hostile).__name__):
                    with self.assertRaisesRegex(ValidationError, "exact string"):
                        DeploymentProfile.validate(
                            replace(declaration, soul_frameworks=(hostile,))
                        )
        finally:
            _ToggleHashString.armed = False

        self.assertEqual(_ToggleHashString.calls, 0)
        self.assertEqual(_RaisingEqualityString.calls, 0)
        self.assertEqual(_RaisingStringSubclass.calls, 0)

    def test_signal_identifier_tuples_reject_string_subclasses_first(self):
        declaration = complete_profile_declaration()
        aggregation = factor_declaration(
            declaration, FactorName.EVIDENCE_DENSITY
        ).aggregation
        hostile = _ToggleHashString(aggregation.signals[0])
        aggregation = replace(
            aggregation, signals=(hostile,)
        )
        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        try:
            with self.assertRaisesRegex(ValidationError, "exact string"):
                DeploymentProfile.validate(
                    with_factor_aggregation(
                        declaration,
                        FactorName.EVIDENCE_DENSITY,
                        aggregation,
                    )
                )
        finally:
            _ToggleHashString.armed = False
        self.assertEqual(_ToggleHashString.calls, 0)

    def test_weighted_average_requires_exact_positive_signal_weights(self):
        for weights in ({}, {SIGNALS[0]: "-1"}, {SIGNALS[0]: "1", "missing": "1"}):
            declaration = complete_profile_declaration()
            aggregation = FactorAggregationDeclaration(
                signals=(SIGNALS[0],),
                method="weighted_average",
                signal_weights=weights,
            )
            with self.subTest(weights=weights), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    with_factor_aggregation(
                        declaration,
                        FactorName.EVIDENCE_DENSITY,
                        aggregation,
                    )
                )

    def test_profile_owns_shared_risk_values_and_canonical_digest(self):
        signal_weights = {SIGNALS[0]: "1"}
        risk_factors = complete_risk_factors()
        risk_factors = replace(
            risk_factors,
            evidence_density=replace(
                risk_factors.evidence_density,
                aggregation=replace(
                    risk_factors.evidence_density.aggregation,
                    method="weighted_average",
                    signal_weights=signal_weights,
                ),
            ),
        )
        domain_weights = {
            RiskDomain.NODE: "0.30",
            RiskDomain.NEIGHBORHOOD: "0.40",
            RiskDomain.GLOBAL: "0.30",
        }
        constraint_units = {"rate": "ops-per-minute"}
        actions = {
            "deploy": ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units=constraint_units,
                normative_gates=(),
            )
        }
        declaration = complete_profile_declaration(
            risk_factors=risk_factors,
            risk_domain_weights=domain_weights,
            actions=actions,
        )
        profile = DeploymentProfile.validate(declaration)
        original_digest = profile.digest

        self.assertEqual(
            profile.risk_domain_weights,
            {
                RiskDomain.NODE: Decimal("0.30"),
                RiskDomain.NEIGHBORHOOD: Decimal("0.40"),
                RiskDomain.GLOBAL: Decimal("0.30"),
            },
        )
        self.assertEqual(profile.ref.profile_id, "profile.full-core")
        self.assertEqual(profile.ref.version, 4)
        self.assertEqual(profile.action_demand_unit, "trust-points")
        self.assertEqual(profile, DeploymentProfile.validate(declaration))
        self.assertEqual(len(profile.digest), 64)
        self.assertIsInstance(profile.risk_domain_weights, Mapping)
        self.assertIsInstance(profile.actions, Mapping)

        domain_weights.clear()
        signal_weights[SIGNALS[0]] = "999"
        actions.clear()
        constraint_units["rate"] = "changed"
        self.assertEqual(len(profile.risk_domain_weights), 3)
        self.assertEqual(
            profile.factor(FactorName.EVIDENCE_DENSITY)
            .aggregation.signal_weights[SIGNALS[0]],
            Decimal("1"),
        )
        validated_signal_weights = (
            profile.factor(FactorName.EVIDENCE_DENSITY).aggregation.signal_weights
        )
        with self.assertRaises(TypeError):
            validated_signal_weights[SIGNALS[0]] = Decimal("999")
        self.assertEqual(validated_signal_weights[SIGNALS[0]], Decimal("1"))
        self.assertEqual(profile.digest, original_digest)
        self.assertEqual(
            profile.action_policy("deploy").constraint_units["rate"],
            "ops-per-minute",
        )
        with self.assertRaises(TypeError):
            profile.risk_domain_weights[RiskDomain.NODE] = Decimal("1")
        with self.assertRaises((AttributeError, TypeError)):
            profile.peer_share = Decimal("20")

    def test_custom_domain_weights_are_exact_and_complete(self):
        profile = DeploymentProfile.validate(
            complete_profile_declaration(
                risk_domain_weights={
                    RiskDomain.NODE: "0.25",
                    RiskDomain.NEIGHBORHOOD: "0.50",
                    RiskDomain.GLOBAL: "0.25",
                }
            )
        )
        self.assertEqual(
            profile.domain_weight(RiskDomain.NEIGHBORHOOD), Decimal("0.50")
        )

    def test_moment_criticality_structurally_cannot_claim_signals(self):
        with self.assertRaises(TypeError):
            MomentCriticalityFactorDeclaration(
                weight="0.15",
                supplier="action-api",
                unit="stress-0-1",
                signals=("world.optical.illuminance",),
            )

    def test_rejects_incomplete_factor_and_domain_sets_and_inexact_sums(self):
        base = complete_profile_declaration()
        cases = []

        missing_domain = dict(base.risk_domain_weights)
        missing_domain.pop(RiskDomain.GLOBAL)
        cases.append(replace(base, risk_domain_weights=missing_domain))

        invalid_domain_weights = dict(base.risk_domain_weights)
        invalid_domain_weights[RiskDomain.GLOBAL] = "0.31"
        cases.append(replace(base, risk_domain_weights=invalid_domain_weights))

        cases.append(
            replace(
                base,
                risk_factors=replace(
                    base.risk_factors,
                    trust_trend=replace(
                        base.risk_factors.trust_trend,
                        weight="0.21",
                    ),
                ),
            )
        )
        cases.append(replace(base, risk_factors=object()))

        for declaration in cases:
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                DeploymentProfile.validate(declaration)

    def test_rejects_unknown_duplicate_aliased_and_empty_signal_subsets(self):
        aliases = (
            "time.sync.clock_offset",
            "body.clock.offset_magnitude",
        )
        invalid_subsets = (
            (),
            ("world.fake.missing",),
            (SIGNALS[0], SIGNALS[0]),
            aliases,
        )
        for signals in invalid_subsets:
            declaration = complete_profile_declaration()
            aggregation = replace(
                factor_declaration(
                    declaration, FactorName.EVIDENCE_DENSITY
                ).aggregation,
                signals=signals,
            )
            declaration = with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            )
            with self.subTest(signals=signals), self.assertRaises(ValidationError):
                DeploymentProfile.validate(declaration)

    def test_rejects_invalid_aggregation_methods_and_signal_weights(self):
        for changes in (
            {"method": "median"},
            {"signal_weights": {SIGNALS[0]: "1"}},
        ):
            declaration = complete_profile_declaration()
            aggregation = replace(
                factor_declaration(
                    declaration, FactorName.EVIDENCE_DENSITY
                ).aggregation,
                **changes,
            )
            declaration = with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            )
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                DeploymentProfile.validate(declaration)

    def test_hostile_profile_numerics_fail_at_the_shared_scalar_boundary(self):
        for hostile in (
            "1e6145",
            "9" * 35,
            ("0" * 128) + "1",
        ):
            declaration = complete_profile_declaration()
            aggregation = replace(
                factor_declaration(
                    declaration, FactorName.EVIDENCE_DENSITY
                ).aggregation,
                method="weighted_average",
                signal_weights={SIGNALS[0]: hostile},
            )
            declaration = with_factor_aggregation(
                declaration, FactorName.EVIDENCE_DENSITY, aggregation
            )
            with self.subTest(hostile=hostile[:40]), self.assertRaises(ValidationError):
                DeploymentProfile.validate(declaration)

    def test_rejects_invalid_profile_identity_soul_and_external_policy(self):
        base = complete_profile_declaration()
        cases = (
            replace(base, profile_id="Profile"),
            replace(base, version=0),
            replace(base, version=True),
            replace(base, version=_IntSubclass(4)),
            replace(base, soul_frameworks=()),
            replace(base, soul_frameworks=("soul.one", "soul.one")),
            replace(base, soul_frameworks=["soul.one"]),
            replace(
                base,
                risk_factors=replace(
                    base.risk_factors,
                    moment_criticality=replace(
                        base.risk_factors.moment_criticality,
                        supplier="",
                    ),
                ),
            ),
        )
        for declaration in cases:
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                DeploymentProfile.validate(declaration)

    def test_peer_root_and_decay_boundaries(self):
        for field, valid_values, invalid_values in (
            ("peer_share", ("0", "10", "20"), ("0.1", "9.99", "20.01")),
            (
                "external_root_hop_bound",
                (1, 12),
                (0, 13, True, _IntSubclass(6)),
            ),
            ("standing_decay_rate", ("2", "20"), ("1.99", "20.01")),
        ):
            for value in valid_values:
                with self.subTest(field=field, valid=value):
                    profile = DeploymentProfile.validate(
                        replace(complete_profile_declaration(), **{field: value})
                    )
                    self.assertIsNotNone(profile)
            for value in invalid_values:
                with (
                    self.subTest(field=field, invalid=value),
                    self.assertRaises(ValidationError),
                ):
                    DeploymentProfile.validate(
                        replace(complete_profile_declaration(), **{field: value})
                    )

    def test_profile_integers_reject_subclasses_before_observable_hooks(self):
        for field_name, hostile in (
            ("version", _ToggleInt(4)),
            ("external_root_hop_bound", _ToggleInt(6)),
        ):
            _ToggleInt.reset(armed=True)
            try:
                with (
                    self.subTest(field_name=field_name),
                    self.assertRaises(ValidationError),
                ):
                    DeploymentProfile.validate(
                        replace(
                            complete_profile_declaration(),
                            **{field_name: hostile},
                        )
                    )
            finally:
                _ToggleInt.armed = False
            with self.subTest(field_name=field_name, assertion="hook count"):
                self.assertEqual(_ToggleInt.calls, 0)

    def test_thresholds_require_exact_veto_before_allow(self):
        base = complete_profile_declaration()
        for veto, allow in (("0.40", "0.40"), ("0.41", "0.40")):
            with (
                self.subTest(veto=veto, allow=allow),
                self.assertRaises(ValidationError),
            ):
                DeploymentProfile.validate(
                    replace(
                        base,
                        envelope_thresholds=EnvelopeThresholds(
                            veto=veto,
                            allow=allow,
                            metacognitive_floor="0.20",
                            assisted_floor="0.10",
                        ),
                    )
                )

        profile = DeploymentProfile.validate(replace(base, envelope_thresholds=None))
        self.assertIsNone(profile.envelope_thresholds)

    def test_action_policies_are_exact_declared_and_owned(self):
        with self.assertRaises(TypeError):
            ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units={"rate": "ops-per-minute"},
            )
        base = complete_profile_declaration()
        invalid_actions = (
            {
                "other": ActionPolicy(
                    action_class="deploy",
                    demand_min=Decimal("0"),
                    demand_max=Decimal("100"),
                    constraint_units={"rate": "ops-per-minute"},
                    normative_gates=(),
                )
            },
            {
                "deploy": ActionPolicy(
                    action_class="deploy",
                    demand_min=Decimal("-1"),
                    demand_max=Decimal("100"),
                    constraint_units={"rate": "ops-per-minute"},
                    normative_gates=(),
                )
            },
            {
                "deploy": ActionPolicy(
                    action_class="deploy",
                    demand_min=Decimal("100"),
                    demand_max=Decimal("10"),
                    constraint_units={"rate": "ops-per-minute"},
                    normative_gates=(),
                )
            },
            {},
        )
        for actions in invalid_actions:
            with self.subTest(actions=actions), self.assertRaises(ValidationError):
                DeploymentProfile.validate(replace(base, actions=actions))

        profile = DeploymentProfile.validate(base)
        self.assertEqual(profile.action_policy("deploy").demand_max, Decimal("100"))
        with self.assertRaises(ValidationError):
            profile.action_policy("missing")

    def test_normative_gate_policy_inventory_is_typed_unique_and_digest_bound(self):
        gate = NormativeGatePolicy(
            gate_id="gate:change-control",
            schema_uri="https://schemas.example/gates/change-control/v1",
            required=True,
        )
        declaration = complete_profile_declaration()
        action = replace(declaration.actions["deploy"], normative_gates=(gate,))
        profile = DeploymentProfile.validate(
            replace(declaration, actions={"deploy": action})
        )

        self.assertEqual(profile.action_policy("deploy").normative_gates, (gate,))
        object.__setattr__(gate, "schema_uri", "https://schemas.example/forged")
        self.assertNotEqual(
            profile.action_policy("deploy").normative_gates[0].schema_uri,
            gate.schema_uri,
        )
        self.assertIs(require_validated_profile(profile), profile)

        invalid = (
            [gate],
            (
                NormativeGatePolicy(
                    gate_id="gate:duplicate",
                    schema_uri="https://schemas.example/gates/one/v1",
                    required=True,
                ),
                NormativeGatePolicy(
                    gate_id="gate:duplicate",
                    schema_uri="https://schemas.example/gates/two/v1",
                    required=False,
                ),
            ),
            (
                NormativeGatePolicy(
                    gate_id="gate:bad-uri",
                    schema_uri="not-an-absolute-uri",
                    required=True,
                ),
            ),
            (
                NormativeGatePolicy(
                    gate_id="gate:bad-required",
                    schema_uri="https://schemas.example/gates/required/v1",
                    required=1,
                ),
            ),
        )
        for gates in invalid:
            with self.subTest(gates=gates), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        actions={
                            "deploy": replace(
                                declaration.actions["deploy"],
                                normative_gates=gates,
                            )
                        },
                    )
                )

    def test_normative_gate_configured_scale_is_uncapped_and_linear(self):
        gate_count = 129
        policies = tuple(
            NormativeGatePolicy(
                gate_id=f"gate:configured:{index}",
                schema_uri=f"https://schemas.example/gates/{index}/v1",
                required=index % 2 == 0,
            )
            for index in range(gate_count)
        )
        declaration = complete_profile_declaration()
        configured_declaration = replace(
            declaration,
            actions={
                "deploy": replace(
                    declaration.actions["deploy"], normative_gates=policies
                )
            },
        )
        uri_validation_code = profile_module.validate_absolute_uri.__code__
        uri_validation_calls = 0

        def count_calls(frame, event, _argument):
            nonlocal uri_validation_calls
            if event == "call" and frame.f_code is uri_validation_code:
                uri_validation_calls += 1

        sys.setprofile(count_calls)
        try:
            configured = DeploymentProfile.validate(configured_declaration)
        finally:
            sys.setprofile(None)

        self.assertEqual(uri_validation_calls, gate_count)
        self.assertEqual(
            len(configured.action_policy("deploy").normative_gates), gate_count
        )

        duplicate_at_end = (
            *policies,
            replace(policies[-1], gate_id=policies[0].gate_id),
        )
        with self.assertRaisesRegex(ValidationError, "duplicate normative gate"):
            DeploymentProfile.validate(
                replace(
                    declaration,
                    actions={
                        "deploy": replace(
                            declaration.actions["deploy"],
                            normative_gates=duplicate_at_end,
                        )
                    },
                )
            )

        tokens = tuple(
            NormativeGateToken(
                gate_id=policy.gate_id,
                schema_uri=policy.schema_uri,
                decision=NormativeGateDecision.CLEAR,
                authority="https://policy.example/authority",
                observed_at=UTC_NOW,
                provenance_id=f"gate-token:{index}",
            )
            for index, policy in enumerate(policies)
        )
        action = ValidatedActionDemand.validate(
            complete_action(normative_gate_tokens=tokens),
            profile=configured,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        self.assertEqual(len(action.normative_gate_tokens), gate_count)
        with self.assertRaisesRegex(ValidationError, "exceeds policy inventory"):
            ValidatedActionDemand.validate(
                complete_action(
                    normative_gate_tokens=(
                        *tokens,
                        replace(
                            tokens[-1],
                            gate_id="gate:configured:overflow",
                            provenance_id="gate-token:overflow",
                        ),
                    )
                ),
                profile=configured,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            )

    def test_constraint_vocabulary_is_distinct_from_generic_identifiers(self):
        with self.assertRaises(ValidationError):
            validate_identifier("maxVelocityMps", name="generic identifier")

        declaration = complete_profile_declaration()
        invalid_units = (
            {_StringSubclass("maxVelocityMps"): "m/s"},
            {"maxVelocityMps": _StringSubclass("m/s")},
            {"maxVelocityMps": "m//s"},
            {"maxVelocityMps": "m/"},
            {"joint:elbow::maxPositionRad": "rad"},
            {"x" * 257: "m"},
            {"maxVelocityMps": "m" * 65},
        )
        for units in invalid_units:
            with self.subTest(units=units), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        actions={
                            "deploy": replace(
                                declaration.actions["deploy"],
                                constraint_units=units,
                            )
                        },
                    )
                )

    def test_action_demand_policy_is_bounded_to_the_normative_zero_to_100_scale(self):
        declaration = complete_profile_declaration()
        for changes in (
            {"demand_min": Decimal("101"), "demand_max": Decimal("101")},
            {"demand_max": Decimal("100.0000000000000000000000000000001")},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(
                        declaration,
                        actions={
                            "deploy": replace(
                                declaration.actions["deploy"],
                                **changes,
                            )
                        },
                    )
                )

    def test_action_demand_unit_is_required_owned_and_digest_bound(self):
        declaration = complete_profile_declaration()
        declaration_fields = {
            field.name: getattr(declaration, field.name)
            for field in fields(declaration)
        }
        declaration_fields.pop("action_demand_unit")
        with self.assertRaises(TypeError):
            DeploymentProfileDeclaration(**declaration_fields)

        for invalid in ("", "Trust Points", 3):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                DeploymentProfile.validate(
                    replace(declaration, action_demand_unit=invalid)
                )

        alternate = DeploymentProfile.validate(
            replace(declaration, action_demand_unit="risk-points")
        )
        default = DeploymentProfile.validate(declaration)
        self.assertEqual(alternate.action_demand_unit, "risk-points")
        self.assertNotEqual(alternate.digest, default.digest)


class ActionValidationTests(unittest.TestCase):
    def setUp(self):
        self.profile = DeploymentProfile.validate(complete_profile_declaration())

    def test_action_and_capability_subjects_must_be_absolute_uris(self):
        capability = ValidatedCapability.validate(
            complete_capability(subject="agent:one"),
            profile=self.profile,
            cutoff=UTC_NOW,
        )
        action = ValidatedActionDemand.validate(
            complete_action(subject="agent:one"),
            profile=self.profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        self.assertEqual(capability.subject, "agent:one")
        self.assertEqual(action.subject, "agent:one")

        with self.subTest(boundary="capability"), self.assertRaises(ValidationError):
            ValidatedCapability.validate(
                complete_capability(subject="agent-one"),
                profile=self.profile,
                cutoff=UTC_NOW,
            )
        with self.subTest(boundary="action"), self.assertRaisesRegex(
            ValidationError, "action subject must be an absolute URI"
        ):
            ValidatedActionDemand.validate(
                complete_action(subject="agent-one"),
                profile=self.profile,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            )

    def test_capability_is_profile_validated_constructor_guarded_and_owned(self):
        capability = ValidatedCapability.validate(
            complete_capability(), profile=self.profile, cutoff=UTC_NOW
        )
        self.assertEqual(capability.profile_ref, self.profile.ref)
        self.assertEqual(capability.profile_digest, self.profile.digest)
        self.assertIsInstance(capability.constraint_ceiling, MappingProxyType)
        self.assertEqual(len(capability.digest), 64)
        with self.assertRaises(TypeError):
            ValidatedCapability()

    def test_capability_rejects_every_action_class_unknown_to_profile(self):
        with self.assertRaisesRegex(ValidationError, "undeclared action class"):
            ValidatedCapability.validate(
                complete_capability(action_classes=("deploy", "unknown")),
                profile=self.profile,
                cutoff=UTC_NOW,
            )

    def test_capability_action_classes_reject_string_subclasses_before_hooks(self):
        hostile_values = (
            _ToggleHashString("deploy"),
            _RaisingEqualityString("deploy"),
            _RaisingStringSubclass("deploy"),
        )
        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        _RaisingEqualityString.calls = 0
        _RaisingStringSubclass.calls = 0
        try:
            for hostile in hostile_values:
                with self.subTest(hostile_type=type(hostile).__name__):
                    with self.assertRaisesRegex(ValidationError, "exact string"):
                        ValidatedCapability.validate(
                            complete_capability(action_classes=(hostile,)),
                            profile=self.profile,
                            cutoff=UTC_NOW,
                        )
        finally:
            _ToggleHashString.armed = False
        self.assertEqual(_ToggleHashString.calls, 0)
        self.assertEqual(_RaisingEqualityString.calls, 0)
        self.assertEqual(_RaisingStringSubclass.calls, 0)

    def test_capability_rejects_same_constraint_name_with_different_units(self):
        """Catches one numeric ceiling acquiring incompatible unit meanings."""
        actions = {
            "deploy": ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units={"rate": "ops-per-minute"},
                normative_gates=(),
            ),
            "inspect": ActionPolicy(
                action_class="inspect",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units={"rate": "megabytes-per-second"},
                normative_gates=(),
            ),
        }
        profile = DeploymentProfile.validate(
            complete_profile_declaration(actions=actions)
        )

        with self.assertRaisesRegex(ValidationError, "constraint envelope"):
            ValidatedCapability.validate(
                complete_capability(action_classes=("deploy", "inspect")),
                profile=profile,
                cutoff=UTC_NOW,
            )

    def test_valid_action_exact_matches_profile_and_owns_canonical_inputs(self):
        granted = {"rate": "20"}
        requested = {"rate": "10"}
        capability_ceiling = {"rate": "25"}
        declaration = complete_action(
            granted_constraints=granted,
            requested_constraints=requested,
        )
        action = ValidatedActionDemand.validate(
            declaration,
            profile=self.profile,
            capability=complete_capability(constraint_ceiling=capability_ceiling),
            cutoff=UTC_NOW,
        )

        self.assertEqual(action.demand, Decimal("40"))
        self.assertEqual(action.profile_ref, self.profile.ref)
        self.assertEqual(action.profile_digest, self.profile.digest)
        self.assertEqual(action.demand_source, "demand-api")
        self.assertEqual(action.validation_cutoff, UTC_NOW)
        self.assertEqual(action.action_policy, self.profile.action_policy("deploy"))
        self.assertEqual(
            action.moment_criticality_factor,
            self.profile.risk_factors.moment_criticality,
        )
        self.assertEqual(
            action.misattestation_adjudicator,
            self.profile.misattestation_adjudicator,
        )
        self.assertEqual(action.capability.subject, "agent:one")
        self.assertEqual(action.capability.action_classes, ("deploy",))
        self.assertEqual(action.capability.not_before, UTC_NOW - timedelta(minutes=1))
        self.assertEqual(action.capability.not_after, UTC_NOW + timedelta(minutes=1))
        self.assertEqual(action.capability.provenance_id, "capability:one")
        self.assertEqual(action.capability.constraint_ceiling["rate"], Decimal("25"))

        provenance_variant = ValidatedActionDemand.validate(
            declaration,
            profile=self.profile,
            capability=complete_capability(provenance_id="capability:two"),
            cutoff=UTC_NOW,
        )
        cutoff_variant = ValidatedActionDemand.validate(
            declaration,
            profile=self.profile,
            capability=complete_capability(),
            cutoff=UTC_NOW + timedelta(seconds=30),
        )
        source_variant = ValidatedActionDemand.validate(
            complete_action(demand_source="demand-api-two"),
            profile=self.profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        self.assertNotEqual(action.digest, provenance_variant.digest)
        self.assertNotEqual(action.digest, cutoff_variant.digest)
        self.assertNotEqual(action.digest, source_variant.digest)
        self.assertEqual(action.moment_criticality.value, Decimal("0.75"))
        self.assertEqual(action.granted_constraints["rate"], Decimal("20"))
        self.assertEqual(action.requested_constraints["rate"], Decimal("10"))
        self.assertEqual(
            action,
            ValidatedActionDemand.validate(
                declaration,
                profile=self.profile,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            ),
        )
        self.assertEqual(len(action.digest), 64)
        self.assertIsInstance(action.requested_constraints, MappingProxyType)
        granted["rate"] = "99"
        requested["rate"] = "99"
        capability_ceiling["rate"] = "99"
        self.assertEqual(action.granted_constraints["rate"], Decimal("20"))
        self.assertEqual(action.requested_constraints["rate"], Decimal("10"))
        self.assertEqual(action.capability.constraint_ceiling["rate"], Decimal("25"))

    def test_rejects_unknown_action_class_subject_capability_and_demand(self):
        cases = (
            (complete_action(action_class="missing"), complete_capability()),
            (complete_action(subject="agent:two"), complete_capability()),
            (complete_action(demand="-0.01"), complete_capability()),
            (complete_action(demand="100.01"), complete_capability()),
            (complete_action(demand_source=""), complete_capability()),
            (complete_action(demand_unit="risk-points"), complete_capability()),
            (
                complete_action(),
                complete_capability(action_classes=("inspect",)),
            ),
            (
                complete_action(),
                complete_capability(not_before=UTC_NOW + timedelta(seconds=1)),
            ),
            (
                complete_action(),
                complete_capability(not_after=UTC_NOW - timedelta(seconds=1)),
            ),
        )
        for declaration, capability in cases:
            with (
                self.subTest(declaration=declaration, capability=capability),
                self.assertRaises(ValidationError),
            ):
                ValidatedActionDemand.validate(
                    declaration,
                    profile=self.profile,
                    capability=capability,
                    cutoff=UTC_NOW,
                )

    def test_action_demand_unit_is_required_preserved_and_digest_bound(self):
        declaration = complete_action()
        declaration_fields = {
            field.name: getattr(declaration, field.name)
            for field in fields(declaration)
        }
        declaration_fields.pop("demand_unit")
        with self.assertRaises(TypeError):
            ActionDemandDeclaration(**declaration_fields)

        action = ValidatedActionDemand.validate(
            declaration,
            profile=self.profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        self.assertEqual(action.demand_unit, "trust-points")
        alternate_profile = DeploymentProfile.validate(
            replace(
                complete_profile_declaration(),
                action_demand_unit="risk-points",
            )
        )
        alternate = ValidatedActionDemand.validate(
            complete_action(demand_unit="risk-points"),
            profile=alternate_profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        self.assertNotEqual(action.digest, alternate.digest)

    def test_constraints_exact_match_and_only_tighten(self):
        cases = (
            complete_action(granted_constraints={}),
            complete_action(requested_constraints={}),
            complete_action(granted_constraints={"rate": "20", "burst": "1"}),
            complete_action(requested_constraints={"rate": "21"}),
            complete_action(granted_constraints={"rate": "26"}),
            complete_action(requested_constraints={"rate": "-1"}),
        )
        for declaration in cases:
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(ValidationError),
            ):
                ValidatedActionDemand.validate(
                    declaration,
                    profile=self.profile,
                    capability=complete_capability(),
                    cutoff=UTC_NOW,
                )

    def test_cross_field_mutable_constraint_aliases_are_rejected(self):
        ceiling_and_grant = {"rate": "20"}
        ceiling_and_request = {"rate": "10"}
        grant_and_request = {"rate": "10"}
        cases = (
            (
                complete_capability(constraint_ceiling=ceiling_and_grant),
                complete_action(granted_constraints=ceiling_and_grant),
            ),
            (
                complete_capability(constraint_ceiling=ceiling_and_request),
                complete_action(
                    granted_constraints={"rate": "10"},
                    requested_constraints=ceiling_and_request,
                ),
            ),
            (
                complete_capability(),
                complete_action(
                    granted_constraints=grant_and_request,
                    requested_constraints=grant_and_request,
                ),
            ),
        )
        for capability, declaration in cases:
            with (
                self.subTest(capability=capability, declaration=declaration),
                self.assertRaisesRegex(ValidationError, "mutable aliases"),
            ):
                ValidatedActionDemand.validate(
                    declaration,
                    profile=self.profile,
                    capability=capability,
                    cutoff=UTC_NOW,
                )

    def test_proxy_backed_aliases_reject_and_independent_proxies_are_owned(self):
        shared_backing = {"rate": "20"}
        shared_proxy = MappingProxyType(shared_backing)
        with self.assertRaisesRegex(ValidationError, "mutable aliases"):
            ValidatedActionDemand.validate(
                complete_action(granted_constraints=shared_proxy),
                profile=self.profile,
                capability=complete_capability(constraint_ceiling=shared_proxy),
                cutoff=UTC_NOW,
            )

        ceiling_backing = {"rate": "25"}
        grant_backing = {"rate": "20"}
        request_backing = {"rate": "10"}
        action = ValidatedActionDemand.validate(
            complete_action(
                granted_constraints=MappingProxyType(grant_backing),
                requested_constraints=MappingProxyType(request_backing),
            ),
            profile=self.profile,
            capability=complete_capability(
                constraint_ceiling=MappingProxyType(ceiling_backing)
            ),
            cutoff=UTC_NOW,
        )
        ceiling_backing["rate"] = "0"
        grant_backing["rate"] = "999"
        request_backing.clear()
        self.assertEqual(action.capability.constraint_ceiling["rate"], Decimal("25"))
        self.assertEqual(action.granted_constraints["rate"], Decimal("20"))
        self.assertEqual(action.requested_constraints["rate"], Decimal("10"))

    def test_moment_criticality_requires_policy_value_time_and_provenance(self):
        valid = complete_action().moment_criticality
        invalid_moments = (
            replace(valid, value="-0.01"),
            replace(valid, value="1.01"),
            replace(valid, supplier="other-api"),
            replace(valid, unit="other-unit"),
            replace(valid, observed_at=UTC_NOW.replace(tzinfo=None)),
            replace(valid, provenance_id=""),
        )
        for moment in invalid_moments:
            with self.subTest(moment=moment), self.assertRaises(ValidationError):
                ValidatedActionDemand.validate(
                    complete_action(moment_criticality=moment),
                    profile=self.profile,
                    capability=complete_capability(),
                    cutoff=UTC_NOW,
                )

    def test_moment_criticality_rejects_hostile_shell_before_attribute_hooks(self):
        hostile = _ArmedMomentShell()
        _ArmedMomentShell.reset(armed=True)
        try:
            with self.assertRaisesRegex(
                ValidationError, "moment criticality must use the explicit declaration"
            ):
                ValidatedActionDemand.validate(
                    complete_action(moment_criticality=hostile),
                    profile=self.profile,
                    capability=complete_capability(),
                    cutoff=UTC_NOW,
                )
        finally:
            _ArmedMomentShell.armed = False
        self.assertEqual(_ArmedMomentShell.calls, 0)

    def test_normative_gate_tokens_validate_but_cannot_rewrite_arithmetic(self):
        policies = tuple(
            NormativeGatePolicy(
                gate_id=f"schema:{state}",
                schema_uri=f"https://schemas.example/gates/{state}/v1",
                required=False,
            )
            for state in ("clear", "veto", "undetermined")
        )
        declaration = complete_profile_declaration()
        gated_profile = DeploymentProfile.validate(
            replace(
                declaration,
                actions={
                    "deploy": replace(
                        declaration.actions["deploy"],
                        normative_gates=policies,
                    )
                },
            )
        )
        plain = ValidatedActionDemand.validate(
            complete_action(),
            profile=gated_profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        source_tokens = (
            NormativeGateToken(
                gate_id="schema:clear",
                schema_uri="https://schemas.example/gates/clear/v1",
                decision=NormativeGateDecision.CLEAR,
                authority="https://policy.example/authority",
                observed_at=UTC_NOW,
                provenance_id="gate-token:clear",
            ),
            NormativeGateToken(
                gate_id="schema:veto",
                schema_uri="https://schemas.example/gates/veto/v1",
                decision=NormativeGateDecision.VETO,
                authority="https://policy.example/authority",
                observed_at=UTC_NOW,
                provenance_id="gate-token:veto",
            ),
            NormativeGateToken(
                gate_id="schema:undetermined",
                schema_uri="https://schemas.example/gates/undetermined/v1",
                decision=NormativeGateDecision.UNDETERMINED,
                authority="https://policy.example/authority",
                observed_at=UTC_NOW,
                provenance_id="gate-token:undetermined",
            ),
        )
        gated = ValidatedActionDemand.validate(
            complete_action(normative_gate_tokens=source_tokens),
            profile=gated_profile,
            capability=complete_capability(),
            cutoff=UTC_NOW,
        )
        self.assertEqual(gated.demand, plain.demand)
        self.assertEqual(gated.granted_constraints, plain.granted_constraints)
        self.assertEqual(gated.requested_constraints, plain.requested_constraints)
        self.assertEqual(gated.moment_criticality, plain.moment_criticality)
        self.assertNotEqual(gated.digest, plain.digest)
        object.__setattr__(source_tokens[1], "decision", NormativeGateDecision.CLEAR)
        self.assertEqual(
            tuple(token.decision for token in gated.normative_gate_tokens),
            tuple(NormativeGateDecision),
        )
        self.assertIsInstance(gated.normative_gate_tokens, tuple)

        invalid_tokens = (
            (
                NormativeGateToken(
                    gate_id="schema:one",
                    schema_uri="https://schemas.example/gates/clear/v1",
                    decision="allow",
                    authority="https://policy.example/authority",
                    observed_at=UTC_NOW,
                    provenance_id="gate-token:invalid",
                ),
            ),
            (
                NormativeGateToken(
                    gate_id="schema:clear",
                    schema_uri="https://schemas.example/gates/clear/v1",
                    decision=NormativeGateDecision.CLEAR,
                    authority="https://policy.example/authority",
                    observed_at=UTC_NOW.replace(tzinfo=None),
                    provenance_id="gate-token:invalid-time",
                ),
            ),
            (
                NormativeGateToken(
                    gate_id="schema:clear",
                    schema_uri="https://schemas.example/gates/clear/v1",
                    decision=NormativeGateDecision.CLEAR,
                    authority="https://policy.example/authority",
                    observed_at=UTC_NOW,
                    provenance_id="gate-token:duplicate:one",
                ),
                NormativeGateToken(
                    gate_id="schema:clear",
                    schema_uri="https://schemas.example/gates/clear/v1",
                    decision=NormativeGateDecision.VETO,
                    authority="https://policy.example/authority",
                    observed_at=UTC_NOW,
                    provenance_id="gate-token:duplicate:two",
                ),
            ),
        )
        for tokens in invalid_tokens:
            with self.subTest(tokens=tokens), self.assertRaises(ValidationError):
                ValidatedActionDemand.validate(
                    complete_action(normative_gate_tokens=tokens),
                    profile=gated_profile,
                    capability=complete_capability(),
                    cutoff=UTC_NOW,
                )


if __name__ == "__main__":
    unittest.main()
