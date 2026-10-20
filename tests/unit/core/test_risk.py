"""Authoritative Task 4 risk, effective-trust, tier, and velocity tests."""

from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_DOWN, getcontext, localcontext, setcontext
import sys

import kinetic_trust_library.models.profile as profile_module
from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT
from kinetic_trust_library.core.evidence import prepare_evidence
from kinetic_trust_library.core.risk import calculate_risk
from kinetic_trust_library.core.soul import assess_soul
from kinetic_trust_library.core.standing import prepare_standing
from kinetic_trust_library.core.trust import (
    _effective_trust,
    _trust_tier,
    calculate_effective_trust,
    calculate_velocity,
    require_validated_trust_snapshot,
    require_validated_trust_velocity,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import (
    MomentCriticalityDeclaration,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.evidence import (
    EnumeratedMeasurementEnvelope,
    ObservationClass,
    ObservationWindow,
    PopulationState,
    PublishedObservationPeriod,
    UndefinedReason,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    FactorAggregationDeclaration,
    FactorName,
    FeedDeclaration,
    IdentityNormalization,
    MomentCriticalityFactorDeclaration,
    RiskDomain,
    RiskFactorsDeclaration,
    SignalRiskFactorDeclaration,
    SignalRouteDeclaration,
)
from kinetic_trust_library.models.risk import (
    DomainFactorResult,
    DomainRiskResult,
    MomentCriticalityResult,
    RiskContext,
    RiskInput,
    RiskResult,
    SignalFactorResult,
)
from kinetic_trust_library.models.soul import SoulResponseDeclaration
from kinetic_trust_library.models.trust import TrustSnapshot, TrustTier, TrustVelocity
from tests.unit.core.test_evidence import (
    CUTOFF,
    SIGNALS,
    observation,
    profile_declaration,
)
from tests.unit.core.test_standing_contract import (
    INDEPENDENT_ID,
    declaration as standing_declaration,
    por_attestation,
)
from tests.unit.models.test_profile import complete_action, complete_capability


_CLASSES = (
    ObservationClass.DIRECT,
    ObservationClass.ENUMERATED,
    ObservationClass.ADJUDICATED,
    ObservationClass.PUBLISHED,
    ObservationClass.DERIVED_STATE,
)

ROUNDING_SIGNALS = (
    "body.compute.gpu_utilization",
    "body.compute.gpu_memory_used",
    "body.compute.compute_utilization",
    "body.compute.preemption_rate",
    "body.compute.cpu_steal_ratio",
)

_ROUNDING_STRESSES = {
    RiskDomain.NODE: (
        "0.5166598430582796695987586706783366",
        "0.5416990216616256713595323676897144",
        "0.8650118476072767214095313462118597",
        "0.3106799458037969861349387356231299",
        "0.1638829550532779147533726654735180",
    ),
    RiskDomain.NEIGHBORHOOD: (
        "0.5024803016761237043322512452739420",
        "0.2363263594040813668875897848890682",
        "0.3429495449302108541096757552445197",
        "0.6256190543675737119935028892131680",
        "0.9749200623117150924085201608637980",
    ),
    RiskDomain.GLOBAL: (
        "0.2006735007014694046353328984479206",
        "0.3061361295173613589379478991034359",
        "0.9292349817124689035497129874372232",
        "0.9898441859908406426334364892847158",
        "0.2091085852145686292960452283234476",
    ),
}


class _ExplodingString(str):
    def __hash__(self):
        raise AssertionError("hostile string hashing executed")

    def __eq__(self, other):
        raise AssertionError("hostile string equality executed")

    def __str__(self):
        raise AssertionError("hostile string coercion executed")


class _ArmedDomain(str):
    calls = 0

    def __eq__(self, _other):
        type(self).calls += 1
        raise AssertionError("hostile domain equality executed")


class _HostileTrustShell:
    calls = 0

    def __getattribute__(self, _name):
        type(self).calls += 1
        raise AssertionError("hostile trust shell hook executed")


class _HostileRiskShell:
    calls = 0

    def __getattribute__(self, _name):
        type(self).calls += 1
        raise AssertionError("hostile risk shell hook executed")


def configured_profile(*, factor_aggregations=None) -> DeploymentProfile:
    declaration = profile_declaration()
    if factor_aggregations is not None:
        member_by_factor = {
            FactorName.EVIDENCE_DENSITY: "evidence_density",
            FactorName.TRUST_TREND: "trust_trend",
            FactorName.ADVERSARIAL_PRESSURE: "adversarial_pressure",
            FactorName.UPDATE_RESISTANCE: "update_resistance",
            FactorName.ATTESTATION_COVERAGE: "attestation_coverage",
        }
        replacements = {
            member_by_factor[factor]: replace(
                getattr(declaration.risk_factors, member_by_factor[factor]),
                aggregation=aggregation,
            )
            for factor, aggregation in factor_aggregations.items()
        }
        declaration = replace(
            declaration,
            risk_factors=replace(declaration.risk_factors, **replacements),
        )
    return DeploymentProfile.validate(declaration)


def validated_action(
    configured: DeploymentProfile,
    cutoff: datetime,
    *,
    moment: str | Decimal = "0.75",
    action_id: str = "action:risk:one",
):
    return ValidatedActionDemand.validate(
        complete_action(
            action_id=action_id,
            subject=INDEPENDENT_ID,
            moment_criticality=MomentCriticalityDeclaration(
                value=moment,
                supplier="action-api",
                unit="stress-0-1",
                observed_at=cutoff,
                provenance_id=f"moment:{action_id}",
            ),
        ),
        profile=configured,
        capability=complete_capability(
            subject=INDEPENDENT_ID,
            not_before=cutoff - timedelta(minutes=1),
            not_after=cutoff + timedelta(minutes=1),
        ),
        cutoff=cutoff,
    )


def soul_clear(configured, action, cutoff):
    declarations = tuple(
        SoulResponseDeclaration(
            framework_id=framework,
            profile_ref=configured.ref,
            profile_digest=configured.digest,
            action_id=action.action_id,
            action_digest=action.digest,
            query_cutoff=cutoff,
            state="clear",
            observed_at=cutoff,
            provenance_id=f"soul:{framework}",
        )
        for framework in configured.soul_frameworks
    )
    return assess_soul(configured, declarations, action, cutoff)


def soul_not_clear(configured, action, cutoff):
    return assess_soul(configured, (), action, cutoff)


def raw_value(index: int, stress: Decimal) -> int | str:
    if index == 0:
        return str(stress * Decimal(200))
    if index == 1:
        return str(stress)
    if index == 2:
        integer = stress * Decimal(10)
        if integer != integer.to_integral_value():
            raise AssertionError("the fixture's count stress must yield an integer")
        return int(integer)
    if index == 3:
        return str(Decimal(300) - stress * Decimal(200))
    if stress == 0:
        return "synchronized"
    if stress == 1:
        return "unsynchronized"
    raise AssertionError("the fixture's derived-state stress must be zero or one")


def evidence_declarations(cutoff: datetime, by_domain):
    declarations = []
    for domain in RiskDomain:
        stresses = tuple(Decimal(value) for value in by_domain[domain])
        for index, (signal, observation_class, stress) in enumerate(
            zip(SIGNALS, _CLASSES, stresses, strict=True)
        ):
            observed_at = cutoff - timedelta(seconds=2)
            changes = {
                "observation_id": f"observation:{domain.value}:{index}",
                "sequence": index + 1,
                "signal": signal,
                "source": f"feed:{domain.value}:{index}",
                "domain": domain,
                "raw": raw_value(index, stress),
                "observation_class": observation_class,
                "observed_at": observed_at,
                "ingested_at": cutoff - timedelta(seconds=1),
            }
            if observation_class is ObservationClass.PUBLISHED:
                changes.update(
                    window=None,
                    published_period=PublishedObservationPeriod(
                        observed_at - timedelta(days=30),
                        observed_at,
                        observed_at,
                        0,
                        "vintage:risk",
                    ),
                )
            elif observation_class is ObservationClass.DERIVED_STATE:
                changes.update(
                    window=None,
                    valid_until=cutoff + timedelta(minutes=1),
                )
            declarations.append(observation(**changes))
    return tuple(declarations)


def evidence(configured, cutoff, by_domain):
    return prepare_evidence(
        configured,
        evidence_declarations(cutoff, by_domain),
        cutoff,
        operation_id="operation:risk",
    )


def uniform_vectors(values):
    return {domain: tuple(values) for domain in RiskDomain}


def risk_state(
    configured,
    cutoff,
    values,
    *,
    moment,
    action_id="action:risk:one",
):
    action = validated_action(
        configured,
        cutoff,
        moment=moment,
        action_id=action_id,
    )
    soul = soul_clear(configured, action, cutoff)
    prepared = evidence(configured, cutoff, uniform_vectors(values))
    return (
        action,
        soul,
        prepared,
        calculate_risk(configured, prepared, soul, action, cutoff),
    )


def rounding_profile() -> DeploymentProfile:
    base = profile_declaration()
    weights = ("0.10", "0.20", "0.15", "0.20", "0.10")
    declarations = tuple(
        SignalRiskFactorDeclaration(
            weight,
            FactorAggregationDeclaration((signal,), "maximum"),
        )
        for weight, signal in zip(weights, ROUNDING_SIGNALS, strict=True)
    )
    feeds = {}
    for domain in RiskDomain:
        for index, signal in enumerate(ROUNDING_SIGNALS):
            source = f"feed:rounding:{domain.value}:{index}"
            feeds[source] = FeedDeclaration(
                source_id=source,
                routes=(SignalRouteDeclaration(signal, domain, "ratio"),),
                refresh_interval_ms=1_000,
                stale_threshold_ms=30_000,
                stale_threshold_reason="source:rounding-window",
            )
    return DeploymentProfile.validate(
        replace(
            base,
            risk_factors=RiskFactorsDeclaration(
                evidence_density=declarations[0],
                trust_trend=declarations[1],
                adversarial_pressure=declarations[2],
                update_resistance=declarations[3],
                attestation_coverage=declarations[4],
                moment_criticality=MomentCriticalityFactorDeclaration(
                    "0.25", "action-api", "stress-0-1"
                ),
            ),
            risk_domain_weights={
                RiskDomain.NODE: "0.30",
                RiskDomain.NEIGHBORHOOD: "0.40",
                RiskDomain.GLOBAL: "0.30",
            },
            feeds=feeds,
            normalizations={
                signal: IdentityNormalization(invert=False)
                for signal in ROUNDING_SIGNALS
            },
            label_sets={},
        )
    )


def rounding_evidence(configured: DeploymentProfile):
    declarations = []
    observed_at = CUTOFF - timedelta(seconds=2)
    for domain in RiskDomain:
        for index, (signal, stress) in enumerate(
            zip(ROUNDING_SIGNALS, _ROUNDING_STRESSES[domain], strict=True)
        ):
            declarations.append(
                observation(
                    observation_id=f"observation:rounding:{domain.value}:{index}",
                    sequence=index + 1,
                    signal=signal,
                    source=f"feed:rounding:{domain.value}:{index}",
                    domain=domain,
                    raw=stress,
                    unit="ratio",
                    observation_class=ObservationClass.ENUMERATED,
                    measurement_envelope=EnumeratedMeasurementEnvelope(
                        subject_boundary=f"host:{domain.value}",
                        population=f"scheduler:{domain.value}",
                        membership_rule="task:admitted",
                        reset_semantics="window:reset",
                        membership_mode="enumerated",
                    ),
                    population_state=PopulationState.OBSERVED,
                    observed_at=observed_at,
                    ingested_at=CUTOFF - timedelta(seconds=1),
                    window=ObservationWindow(
                        observed_at - timedelta(seconds=1), observed_at
                    ),
                )
            )
    return prepare_evidence(
        configured,
        tuple(declarations),
        CUTOFF,
        operation_id="operation:risk:rounding",
    )


def context_values(value: RiskContext) -> tuple[Decimal, ...]:
    return (
        value.evidence_density,
        value.trust_trend,
        value.adversarial_pressure,
        value.update_resistance,
        value.attestation_coverage,
        value.moment_criticality,
    )


def standing(configured, cutoff):
    return prepare_standing(
        configured,
        standing_declaration(),
        cutoff,
    )


class RiskTests(unittest.TestCase):
    def test_shared_factors_produce_one_context_and_three_domain_audits(self):
        configured = configured_profile()
        action, soul, prepared, result = risk_state(
            configured,
            CUTOFF,
            ("0.10", "0.20", "0.30", "0.40", "0"),
            moment="0.75",
        )

        self.assertIsInstance(result.context, RiskContext)
        self.assertEqual(len(result.factors), 6)
        self.assertEqual(len(result.domains), 3)
        moment = result.factor(FactorName.MOMENT_CRITICALITY)
        self.assertIsInstance(moment, MomentCriticalityResult)
        self.assertIs(moment.supplied_value, action.moment_criticality)
        self.assertEqual(moment.context_stress, Decimal("0.75"))
        self.assertFalse(any(hasattr(domain, "factors") for domain in result.domains))
        for factor in result.factors[:-1]:
            self.assertIsInstance(factor, SignalFactorResult)
            self.assertEqual(len(factor.domains), 3)
            for domain in factor.domains:
                self.assertIsInstance(domain, DomainFactorResult)
                for item in domain.inputs:
                    self.assertIsInstance(item, RiskInput)
                    self.assertIs(item.factor, factor.name)
                    self.assertIs(item.domain, domain.domain)
                    self.assertIn(item.signal_id, configured.factor(factor.name).aggregation.signals)

    def test_context_first_arithmetic_uses_shared_profile_bound_factors(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF)
        soul = soul_clear(configured, action, CUTOFF)
        prepared = evidence(
            configured,
            CUTOFF,
            {
                RiskDomain.NODE: ("0.1", "0.2", "0.3", "0.4", "0"),
                RiskDomain.NEIGHBORHOOD: ("0.2", "0.3", "0.4", "0.5", "1"),
                RiskDomain.GLOBAL: ("0.3", "0.4", "0.5", "0.6", "0"),
            },
        )

        result = calculate_risk(configured, prepared, soul, action, CUTOFF)

        self.assertEqual(result.domain(RiskDomain.NODE).risk, Decimal("0.2775"))
        self.assertEqual(
            result.domain("neighborhood").risk,
            Decimal("0.4975"),
        )
        self.assertEqual(result.domain("global").risk, Decimal("0.4175"))
        self.assertEqual(result.risk, Decimal("0.4075"))
        self.assertEqual(
            tuple(item.name for item in result.factors),
            tuple(FactorName),
        )
        self.assertEqual(
            context_values(result.context),
            tuple(Decimal(value) for value in ("0.2", "0.3", "0.4", "0.5", "0.4", "0.75")),
        )
        moment = result.factor(FactorName.MOMENT_CRITICALITY)
        self.assertEqual(moment.supplied_value.provenance_id, "moment:action:risk:one")
        self.assertEqual(moment.supplied_value.supplier, "action-api")
        self.assertEqual(moment.supplied_value.unit, "stress-0-1")
        self.assertEqual(moment.supplied_value.observed_at, CUTOFF)

    def test_profile_aggregation_methods_and_active_weight_renormalization(self):
        aggregations = {
            FactorName.EVIDENCE_DENSITY: FactorAggregationDeclaration(
                (SIGNALS[0], SIGNALS[1]),
                "weighted_average",
                {SIGNALS[0]: "1", SIGNALS[1]: "3"},
            ),
            FactorName.TRUST_TREND: FactorAggregationDeclaration(
                (SIGNALS[0], SIGNALS[1]), "minimum"
            ),
            FactorName.ADVERSARIAL_PRESSURE: FactorAggregationDeclaration(
                (SIGNALS[0], SIGNALS[1], SIGNALS[2]), "maximum"
            ),
        }
        configured = configured_profile(factor_aggregations=aggregations)
        action = validated_action(configured, CUTOFF)
        soul = soul_clear(configured, action, CUTOFF)
        by_domain = {
            RiskDomain.NODE: ("0.8", "0.2", "0.3", "0.4", "0"),
            RiskDomain.NEIGHBORHOOD: ("0.6", "0.4", "0.1", "0.4", "0"),
            RiskDomain.GLOBAL: ("0.1", "0.9", "0.2", "0.4", "0"),
        }
        prepared = evidence(
            configured,
            CUTOFF,
            by_domain,
        )

        result = calculate_risk(configured, prepared, soul, action, CUTOFF)
        density = result.factor("evidence_density")
        self.assertEqual(
            tuple(item.stress for item in density.domains),
            tuple(Decimal(value) for value in ("0.35", "0.45", "0.7")),
        )
        self.assertEqual(density.context_stress, Decimal("0.495"))
        self.assertEqual(
            tuple(item.stress for item in result.factor("trust_trend").domains),
            tuple(Decimal(value) for value in ("0.2", "0.4", "0.1")),
        )
        self.assertEqual(
            tuple(item.stress for item in result.factor("adversarial_pressure").domains),
            tuple(Decimal(value) for value in ("0.8", "0.6", "0.9")),
        )

        without_first = tuple(
            item
            for item in evidence_declarations(
                CUTOFF,
                by_domain,
            )
            if not (item.domain is RiskDomain.NODE and item.signal_id == SIGNALS[0])
        )
        partial = prepare_evidence(
            configured,
            without_first,
            CUTOFF,
            operation_id="operation:risk",
        )
        factor = calculate_risk(configured, partial, soul, action, CUTOFF).factor(
            "evidence_density"
        )
        self.assertEqual(factor.domains[0].stress, Decimal("0.2"))
        self.assertFalse(factor.domains[0].defaulted)
        self.assertEqual(factor.context_stress, Decimal("0.45"))
        self.assertEqual(
            factor.domains[0].inputs[0].undefined_reason,
            UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )
        self.assertTrue(factor.domains[0].inputs[0].feed_outcome_digests)

    def test_empty_denominators_fail_closed_to_one_and_preserve_provenance(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF)
        soul = soul_clear(configured, action, CUTOFF)
        prepared = prepare_evidence(
            configured, (), CUTOFF, operation_id="operation:empty"
        )

        result = calculate_risk(configured, prepared, soul, action, CUTOFF)

        factor = result.factor("trust_trend")
        node = factor.domains[0]
        self.assertEqual(node.stress, Decimal(1))
        self.assertTrue(node.defaulted)
        self.assertEqual(
            node.inputs[0].undefined_reason,
            UndefinedReason.NO_ELIGIBLE_OBSERVATION,
        )
        self.assertTrue(node.inputs[0].feed_outcome_digests)
        self.assertIn(node.inputs[0], result.undefined_inputs)
        self.assertTrue(all(type(item) is RiskInput for item in result.undefined_inputs))
        self.assertEqual(result.risk, Decimal("0.9625"))

    def test_stale_and_unavailable_signals_fail_closed_with_exact_reason(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF)
        soul = soul_clear(configured, action, CUTOFF)
        current = evidence_declarations(
            CUTOFF,
            uniform_vectors(("0.1", "0.2", "0.3", "0.4", "0")),
        )
        base = tuple(
            item
            for item in current
            if not (item.domain is RiskDomain.NODE and item.signal_id == SIGNALS[1])
        )
        cases = (
            (
                observation(
                    observation_id="observation:node:stale",
                    signal=SIGNALS[1],
                    source="feed:node:1",
                    domain=RiskDomain.NODE,
                    raw="0.2",
                    observation_class=ObservationClass.ENUMERATED,
                    observed_at=CUTOFF - timedelta(seconds=40),
                    ingested_at=CUTOFF - timedelta(seconds=39),
                ),
                UndefinedReason.STALE,
            ),
            (
                observation(
                    observation_id="observation:node:unavailable",
                    signal=SIGNALS[1],
                    source="feed:node:1",
                    domain=RiskDomain.NODE,
                    raw=None,
                    population_state=PopulationState.UNAVAILABLE,
                    observation_class=ObservationClass.ENUMERATED,
                ),
                UndefinedReason.SOURCE_UNAVAILABLE,
            ),
        )
        for declaration, expected in cases:
            with self.subTest(expected=expected):
                prepared = prepare_evidence(
                    configured,
                    (*base, declaration),
                    CUTOFF,
                    operation_id="operation:risk:missingness",
                )
                factor = calculate_risk(
                    configured, prepared, soul, action, CUTOFF
                ).factor("trust_trend")
                node = factor.domains[0]
                self.assertEqual(node.stress, Decimal(1))
                self.assertTrue(node.defaulted)
                self.assertIs(node.inputs[0].undefined_reason, expected)
                self.assertTrue(node.inputs[0].feed_outcome_digests)

    def test_context_first_rounding_vector_is_pinned_and_ambient_independent(self):
        configured = rounding_profile()
        action = validated_action(
            configured,
            CUTOFF,
            moment="0.5759706812213538364519786497538815",
        )
        soul = soul_clear(configured, action, CUTOFF)
        prepared = rounding_evidence(configured)

        result = calculate_risk(configured, prepared, soul, action, CUTOFF)

        self.assertEqual(
            result.context.evidence_density,
            Decimal("0.4161921237983742040031279688474540"),
        )
        self.assertEqual(
            result.context.trust_trend,
            Decimal("0.3488810891153286558442799939935724"),
        )
        self.assertEqual(
            result.context.adversarial_pressure,
            Decimal("0.6754538667680080291316436021925328"),
        )
        self.assertEqual(
            result.context.update_resistance,
            Decimal("0.6404048612854207734279137231576209"),
        )
        self.assertEqual(
            result.context.attestation_coverage,
            Decimal("0.5018654870050400001782334324846089"),
        )
        self.assertEqual(
            result.context.moment_criticality,
            Decimal("0.5759706812213538364519786497538815"),
        )
        self.assertEqual(
            tuple(item.contribution for item in result.factors),
            tuple(
                Decimal(value)
                for value in (
                    "0.04161921237983742040031279688474540",
                    "0.06977621782306573116885599879871448",
                    "0.1013180800152012043697465403288799",
                    "0.1280809722570841546855827446315242",
                    "0.05018654870050400001782334324846089",
                    "0.1439926703053384591129946624384704",
                )
            ),
        )
        self.assertEqual(
            tuple(item.domain for item in result.domains),
            (RiskDomain.NODE, RiskDomain.NEIGHBORHOOD, RiskDomain.GLOBAL),
        )
        self.assertEqual(
            tuple(item.risk for item in result.domains),
            tuple(
                Decimal(value)
                for value in (
                    "0.5122745207506702572585317186480038",
                    "0.5155642211979849826797417011593696",
                    "0.5835521892554529983528663009088211",
                )
            ),
        )
        self.assertEqual(
            result.risk,
            Decimal("0.5349737014810309697553160863307953"),
        )
        with localcontext(KTP_CONTEXT):
            domain_first = sum(
                (domain.weight * domain.risk for domain in result.domains),
                Decimal(0),
            )
        self.assertEqual(
            domain_first,
            Decimal("0.5349737014810309697553160863307952"),
        )
        self.assertNotEqual(domain_first, result.risk)

        with localcontext() as ambient:
            ambient.prec = 6
            ambient.rounding = ROUND_DOWN
            repeated = calculate_risk(
                configured, prepared, soul, action, CUTOFF
            )
        self.assertEqual(context_values(repeated.context), context_values(result.context))
        self.assertEqual(
            tuple(item.contribution for item in repeated.factors),
            tuple(item.contribution for item in result.factors),
        )
        self.assertEqual(repeated.domains, result.domains)
        self.assertEqual(repeated.risk, result.risk)
        self.assertEqual(repeated.digest, result.digest)

    def test_missing_domain_factor_does_not_renormalize_alpha_or_beta(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF, moment="0.75")
        soul = soul_clear(configured, action, CUTOFF)
        declarations = tuple(
            item
            for item in evidence_declarations(
                CUTOFF,
                uniform_vectors(("0.1", "0.2", "0.3", "0.4", "0")),
            )
            if not (
                item.domain is RiskDomain.NODE
                and item.signal_id == SIGNALS[1]
            )
        )
        prepared = prepare_evidence(
            configured,
            declarations,
            CUTOFF,
            operation_id="operation:risk:no-renormalization",
        )

        result = calculate_risk(configured, prepared, soul, action, CUTOFF)
        trust_trend = result.factor(FactorName.TRUST_TREND)

        self.assertEqual(
            tuple(item.stress for item in trust_trend.domains),
            (Decimal(1), Decimal("0.2"), Decimal("0.2")),
        )
        self.assertEqual(result.context.trust_trend, Decimal("0.44"))
        self.assertEqual(trust_trend.contribution, Decimal("0.088"))
        self.assertEqual(result.risk, Decimal("0.3255"))
        self.assertEqual(
            tuple((item.factor, item.domain) for item in result.undefined_inputs),
            ((FactorName.TRUST_TREND, RiskDomain.NODE),),
        )

    def test_soul_veto_or_undetermined_short_circuits_before_evidence_authority(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF)
        not_clear = soul_not_clear(configured, action, CUTOFF)

        with self.assertRaisesRegex(ValidationError, "Soul assessment must be clear"):
            calculate_risk(configured, object(), not_clear, action, CUTOFF)

    def test_exact_bindings_mutation_and_resealing_are_rejected(self):
        configured = configured_profile()
        action, soul, prepared, result = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0.75",
        )
        self.assertIs(result.factor("evidence_density").name, FactorName.EVIDENCE_DENSITY)

        object.__setattr__(result, "risk", Decimal("0.1"))
        object.__setattr__(
            result,
            "digest",
            canonical_sha256({"forged_risk": result.risk}),
        )
        with self.assertRaises(ValidationError):
            result.factor("evidence_density")
        with self.assertRaises(ValidationError):
            result.domain("node")

        other_action = validated_action(
            configured, CUTOFF, action_id="action:risk:other"
        )
        other_soul = soul_clear(configured, other_action, CUTOFF)
        with self.assertRaises(ValidationError):
            calculate_risk(configured, prepared, other_soul, action, CUTOFF)
        with self.assertRaises(ValidationError):
            calculate_risk(
                configured,
                prepared,
                soul,
                action,
                CUTOFF + timedelta(microseconds=1),
            )

    def test_accessors_and_structural_boundary_reject_hostile_names_before_hooks(self):
        configured = configured_profile()
        _action, _soul, _prepared, result = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0.75",
        )
        with self.assertRaises(ValidationError):
            result.domain(_ExplodingString("node"))
        with self.assertRaises(ValidationError):
            result.factor(_ExplodingString("trust_trend"))

        _action, _soul, _prepared, nested = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0.75",
        )
        hostile = _HostileRiskShell()
        object.__setattr__(nested, "factors", (hostile, *nested.factors[1:]))
        _HostileRiskShell.calls = 0
        with self.assertRaises(ValidationError):
            nested.factor("trust_trend")
        self.assertEqual(_HostileRiskShell.calls, 0)

    def test_domain_factor_rejects_hostile_domain_before_equality_hooks(self):
        configured = configured_profile()
        _action, _soul, _prepared, result = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0.75",
        )
        hostile = _ArmedDomain("node")
        object.__setattr__(result.factors[0].domains[0], "domain", hostile)
        _ArmedDomain.calls = 0

        with self.assertRaises(ValidationError):
            result.factor("evidence_density")

        self.assertEqual(_ArmedDomain.calls, 0)

    def test_domain_risk_rejects_hostile_domain_before_equality_hooks(self):
        configured = configured_profile()
        _action, _soul, _prepared, result = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0.75",
        )
        hostile = _ArmedDomain("node")
        object.__setattr__(result.domains[0], "domain", hostile)
        _ArmedDomain.calls = 0

        with self.assertRaises(ValidationError):
            result.domain("node")

        self.assertEqual(_ArmedDomain.calls, 0)

    def test_results_are_guarded_immutable_and_decimal_context_independent(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF)
        soul = soul_clear(configured, action, CUTOFF)
        prepared = evidence(
            configured,
            CUTOFF,
            uniform_vectors(("0.1", "0.2", "0.3", "0.4", "0")),
        )
        original = getcontext().copy()
        try:
            first = calculate_risk(configured, prepared, soul, action, CUTOFF)
            getcontext().prec = 6
            second = calculate_risk(configured, prepared, soul, action, CUTOFF)
        finally:
            setcontext(original)
        self.assertEqual(first, second)
        self.assertEqual(first.digest, second.digest)
        for constructor in (
            RiskInput,
            RiskContext,
            DomainFactorResult,
            SignalFactorResult,
            MomentCriticalityResult,
            DomainRiskResult,
            RiskResult,
        ):
            with self.subTest(constructor=constructor), self.assertRaises(TypeError):
                constructor()
        with self.assertRaises(FrozenInstanceError):
            first.risk = Decimal(0)


class EffectiveTrustTests(unittest.TestCase):
    def test_published_core_effective_trust_vectors_are_exact(self):
        self.assertEqual(_effective_trust(Decimal(95), Decimal("0.1")), Decimal("85.5"))
        self.assertEqual(_effective_trust(Decimal(95), Decimal("0.7")), Decimal("28.5"))
        self.assertEqual(
            _effective_trust(Decimal(95), Decimal("0.95")), Decimal("4.75")
        )

    def test_effective_trust_consumes_standing_and_risk_without_scalar_escape_hatch(
        self,
    ):
        configured = configured_profile()
        action, soul, _prepared, risk = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0.75",
        )
        base = standing(configured, CUTOFF)

        trust = calculate_effective_trust(configured, base, risk, soul, action, CUTOFF)

        self.assertEqual(
            trust.base_trust,
            Decimal("34.77121254719662437295027903255115"),
        )
        self.assertEqual(trust.risk, risk.risk)
        self.assertEqual(
            trust.effective_trust,
            Decimal("25.12220106534956110945657660101821"),
        )
        self.assertIs(trust.tier, TrustTier.OBSERVER)
        self.assertEqual(trust.standing_digest, base.digest)
        self.assertEqual(trust.risk_digest, risk.digest)
        self.assertIs(
            require_validated_trust_snapshot(trust, profile=configured), trust
        )

    def test_soul_short_circuits_before_standing_and_risk_validation(self):
        configured = configured_profile()
        action = validated_action(configured, CUTOFF)
        not_clear = soul_not_clear(configured, action, CUTOFF)
        with self.assertRaisesRegex(ValidationError, "Soul assessment must be clear"):
            calculate_effective_trust(
                configured, object(), object(), not_clear, action, CUTOFF
            )

    def test_exact_tier_thresholds_have_no_epsilon_plateau(self):
        cases = (
            ("85", TrustTier.ADMIN),
            ("84.99999999999999999999999999999999", TrustTier.OPERATOR),
            ("72", TrustTier.OPERATOR),
            ("71.99999999999999999999999999999999", TrustTier.ANALYST),
            ("58", TrustTier.ANALYST),
            ("57.99999999999999999999999999999999", TrustTier.OBSERVER),
            ("22", TrustTier.OBSERVER),
            ("21.99999999999999999999999999999999", TrustTier.HIBERNATION),
        )
        for value, expected in cases:
            with self.subTest(expected=expected, value=value):
                self.assertIs(_trust_tier(Decimal(value)), expected)
        with self.assertRaises(ValidationError):
            _trust_tier(85.0)

    def test_subject_binding_total_risk_and_mutation_are_checked(self):
        configured = configured_profile()
        base = standing(configured, CUTOFF)
        action, soul, _prepared, risk = risk_state(
            configured,
            CUTOFF,
            ("1", "1", "1", "1", "1"),
            moment="1",
        )
        trust = calculate_effective_trust(configured, base, risk, soul, action, CUTOFF)
        self.assertEqual(trust.effective_trust, Decimal(0))
        self.assertIs(trust.tier, TrustTier.HIBERNATION)

        object.__setattr__(trust, "effective_trust", Decimal(100))
        with self.assertRaises(ValidationError):
            require_validated_trust_snapshot(trust)

        wrong_standing = prepare_standing(
            configured,
            standing_declaration(
                agent_id="agent:independent:3gen:acme-line:agent-two",
                por_attestations=(
                    por_attestation(
                        agent_id="agent:independent:3gen:acme-line:agent-two",
                    ),
                ),
            ),
            CUTOFF,
        )
        with self.assertRaisesRegex(ValidationError, "subject"):
            calculate_effective_trust(
                configured, wrong_standing, risk, soul, action, CUTOFF
            )

    def test_velocity_uses_two_validated_snapshots_and_exact_elapsed_seconds(self):
        configured = configured_profile()
        previous_action, previous_soul, _evidence, previous_risk = risk_state(
            configured,
            CUTOFF,
            ("0.75", "0", "0", "0", "0"),
            moment="0",
            action_id="action:velocity:previous",
        )
        previous = calculate_effective_trust(
            configured,
            standing(configured, CUTOFF),
            previous_risk,
            previous_soul,
            previous_action,
            CUTOFF,
        )
        current_at = CUTOFF + timedelta(microseconds=500_000)
        current_action, current_soul, _evidence, current_risk = risk_state(
            configured,
            current_at,
            ("0.4", "1", "0", "0", "0"),
            moment="0",
            action_id="action:velocity:current",
        )
        current = calculate_effective_trust(
            configured,
            standing(configured, current_at),
            current_risk,
            current_soul,
            current_action,
            current_at,
        )

        velocity = calculate_velocity(previous, current)

        self.assertEqual(velocity.elapsed_seconds, Decimal("0.5"))
        with localcontext(KTP_CONTEXT):
            expected_velocity = (
                current.effective_trust - previous.effective_trust
            ) / Decimal("0.5")
        self.assertEqual(velocity.value, expected_velocity)
        self.assertEqual(velocity.previous_digest, previous.digest)
        self.assertEqual(velocity.current_digest, current.digest)
        validation_code = profile_module.require_validated_profile.__code__
        validation_calls = 0

        def count_calls(frame, event, _argument):
            nonlocal validation_calls
            if event == "call" and frame.f_code is validation_code:
                validation_calls += 1

        sys.setprofile(count_calls)
        try:
            self.assertIs(require_validated_trust_velocity(velocity), velocity)
        finally:
            sys.setprofile(None)
        self.assertEqual(validation_calls, 1)

        forged_velocity = copy.copy(velocity)
        hostile_previous = _HostileTrustShell()
        object.__setattr__(forged_velocity, "_previous", hostile_previous)
        _HostileTrustShell.calls = 0
        with self.assertRaises(ValidationError):
            require_validated_trust_velocity(forged_velocity)
        self.assertEqual(_HostileTrustShell.calls, 0)

        with self.assertRaises(ValidationError):
            calculate_velocity(previous, previous)
        with self.assertRaises(ValidationError):
            calculate_velocity(current, previous)
        object.__setattr__(velocity, "value", Decimal(0))
        with self.assertRaises(ValidationError):
            require_validated_trust_velocity(velocity)

    def test_trust_models_cannot_be_directly_constructed(self):
        for constructor in (TrustSnapshot, TrustVelocity):
            with self.subTest(constructor=constructor), self.assertRaises(TypeError):
                constructor()


if __name__ == "__main__":
    unittest.main()
