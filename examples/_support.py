from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Literal

from kinetic_trust_library import EvaluationBundle, EvaluationRequest, RejectedRequest
from kinetic_trust_library.core import evaluate
from kinetic_trust_library.models.action import (
    ActionDemandDeclaration,
    CapabilityDeclaration,
    MomentCriticalityDeclaration,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.evidence import (
    AdjudicatedMeasurementEnvelope,
    DerivedStateMeasurementEnvelope,
    DirectMeasurementEnvelope,
    EnumeratedMeasurementEnvelope,
    MeasurementEnvelope,
    ObservationClass,
    ObservationDeclaration,
    ObservationWindow,
    PopulationState,
    PublishedMeasurementEnvelope,
    PublishedObservationPeriod,
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
    SignalRiskFactorDeclaration,
    SignalRouteDeclaration,
)
from kinetic_trust_library.models.soul import (
    SoulConstraintType,
    SoulResponseDeclaration,
    SoulUndeterminedReason,
)
from kinetic_trust_library.models.standing import (
    ExternalTerminatorDeclaration,
    ExternalTerminatorKind,
    FrictionCategory,
    PoRAttestationDeclaration,
    RootInstrumentDeclaration,
    RootIssuanceDeclaration,
    StandingDeclaration,
)

CUTOFF = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
OPERATION_ID = "operation:example:core-and-envelope"
AGENT_ID = "agent:independent:3gen:example-line:example-agent"
SIGNALS = (
    "world.optical.illuminance",
    "body.compute.compute_utilization",
    "body.hardware.active_alarms",
    "world.economic.consumer_price_index",
    "body.clock.sync_state",
)
UNITS = {
    SIGNALS[0]: "lx",
    SIGNALS[1]: "ratio",
    SIGNALS[2]: "count",
    SIGNALS[3]: "index",
    SIGNALS[4]: "state",
}
OBSERVATION_CLASSES = (
    ObservationClass.DIRECT,
    ObservationClass.ENUMERATED,
    ObservationClass.ADJUDICATED,
    ObservationClass.PUBLISHED,
    ObservationClass.DERIVED_STATE,
)
RAW_VALUES = ("20", "0.2", 3, "220", "synchronized")
SIGNAL_FACTORS = (
    FactorName.EVIDENCE_DENSITY,
    FactorName.TRUST_TREND,
    FactorName.ADVERSARIAL_PRESSURE,
    FactorName.UPDATE_RESISTANCE,
    FactorName.ATTESTATION_COVERAGE,
)


def _risk_factors() -> RiskFactorsDeclaration:
    aggregations = {
        factor: FactorAggregationDeclaration((signal,), "maximum")
        for factor, signal in zip(SIGNAL_FACTORS, SIGNALS, strict=True)
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


def build_profile() -> DeploymentProfile:
    feeds = {
        f"feed:{domain.value}:{index}": FeedDeclaration(
            source_id=f"feed:{domain.value}:{index}",
            routes=(SignalRouteDeclaration(signal, domain, UNITS[signal]),),
            refresh_interval_ms=1_000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="application:freshness-policy",
        )
        for domain in RiskDomain
        for index, signal in enumerate(SIGNALS)
    }
    declaration = DeploymentProfileDeclaration(
        profile_id="profile.example.core-and-envelope",
        version=1,
        action_demand_unit="trust-points",
        risk_factors=_risk_factors(),
        risk_domain_weights={
            RiskDomain.NODE: "0.30",
            RiskDomain.NEIGHBORHOOD: "0.40",
            RiskDomain.GLOBAL: "0.30",
        },
        soul_frameworks=("soul.framework.example",),
        peer_share="0",
        external_root_hop_bound=6,
        misattestation_adjudicator="adjudicator:example",
        standing_decay_rate="16",
        envelope_thresholds=EnvelopeThresholds(
            veto=Decimal("0"),
            allow=Decimal("0.40"),
            metacognitive_floor=Decimal("0.20"),
            assisted_floor=Decimal("0.10"),
        ),
        actions={
            "deploy": ActionPolicy(
                action_class="deploy",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units={"rate": "ops-per-minute"},
                normative_gates=(),
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
    return DeploymentProfile.validate(declaration)


def build_validated_action(profile: DeploymentProfile) -> ValidatedActionDemand:
    capability = CapabilityDeclaration(
        subject=AGENT_ID,
        action_classes=("deploy",),
        constraint_ceiling={"rate": "25"},
        not_before=CUTOFF - timedelta(minutes=1),
        not_after=CUTOFF + timedelta(minutes=1),
        provenance_id="capability:example",
    )
    action = ActionDemandDeclaration(
        action_id="action:example:deploy",
        subject=AGENT_ID,
        action_class="deploy",
        demand="40",
        demand_unit="trust-points",
        demand_source="application:action-api",
        granted_constraints={"rate": "20"},
        requested_constraints={"rate": "10"},
        moment_criticality=MomentCriticalityDeclaration(
            value="0.75",
            supplier="action-api",
            unit="stress-0-1",
            observed_at=CUTOFF,
            provenance_id="moment:example",
        ),
    )
    return ValidatedActionDemand.validate(
        action, profile=profile, capability=capability, cutoff=CUTOFF
    )


def build_standing() -> StandingDeclaration:
    legal_entity = "urn:ktp:legal-entity:example"
    return StandingDeclaration(
        agent_id=AGENT_ID,
        generation=3,
        identity_assurance_level=3,
        trajectory_length=10_000,
        por_attestations=(
            PoRAttestationDeclaration(
                attestation_id="attestation:example:1",
                agent_id=AGENT_ID,
                transaction_ref="transaction:example:1",
                friction="0.6",
                friction_category=FrictionCategory.HIGH,
                action_risk="1",
                outcome="success",
                timestamp=CUTOFF - timedelta(minutes=1),
                oracle_id="oracle:example",
                verification_ref="verification:example:por:1",
            ),
        ),
        root_instruments=(
            RootInstrumentDeclaration(
                instrument_id="root:example:1",
                attestor="entity:example-attestor",
                issuance=RootIssuanceDeclaration(
                    issued_at=CUTOFF - timedelta(days=1),
                    end_time=CUTOFF + timedelta(days=1),
                    verification_ref="verification:example:root:1",
                ),
                sponsor_standing=None,
                stake_percentage=None,
                exposure_class="legal-liability",
                declared_exposure="100",
                anchored_capacity="100",
                chain=(legal_entity,),
                terminator=ExternalTerminatorDeclaration(
                    kind=ExternalTerminatorKind.LEGAL_ENTITY,
                    identifier=legal_entity,
                    verification_ref="verification:example:terminator:1",
                ),
                withdrawal_claim=None,
                adjudication_finding=None,
            ),
        ),
        peer=None,
        additional_ceilings=(),
        advancement_floor="0",
    )


def build_soul_responses(
    profile: DeploymentProfile,
    action: ValidatedActionDemand,
    *,
    state: Literal["clear", "veto", "undetermined"] = "clear",
) -> tuple[SoulResponseDeclaration, ...]:
    values = {
        "constraint_type": SoulConstraintType.CARE if state == "veto" else None,
        "constraint_id": "constraint:example:care" if state == "veto" else None,
        "authority": "https://authority.example/constraints/care"
        if state == "veto"
        else None,
        "undetermined_reason": SoulUndeterminedReason.UNREACHABLE
        if state == "undetermined"
        else None,
    }
    return tuple(
        SoulResponseDeclaration(
            framework_id=framework,
            profile_ref=profile.ref,
            profile_digest=profile.digest,
            action_id=action.action_id,
            action_digest=action.digest,
            query_cutoff=CUTOFF,
            state=state,
            observed_at=CUTOFF,
            provenance_id=f"soul-response:{framework}",
            **values,
        )
        for framework in profile.soul_frameworks
    )


def _measurement_envelope(index: int, observed_at: datetime) -> MeasurementEnvelope:
    if index == 0:
        return DirectMeasurementEnvelope(
            subject="urn:ktp:environment:example",
            modality="photometric",
            instrument_make_model="meter:example-illuminance",
            calibration_at=observed_at - timedelta(days=1),
            calibration_reference="calibration:example:illuminance",
        )
    if index == 1:
        return EnumeratedMeasurementEnvelope(
            subject_boundary="urn:ktp:host:example",
            population="scheduler:tasks",
            membership_rule="task:admitted",
            reset_semantics="window:rolling",
            membership_mode="enumerated",
        )
    if index == 2:
        return AdjudicatedMeasurementEnvelope(
            issuing_authority="authority:security-operations",
            authority_scope="platform:example",
            measurement_party="sensor:alarm-api",
            record_set="alarms:active",
            adjudication_criteria="criteria:active-alarm",
            criteria_version="version:1",
        )
    if index == 3:
        return PublishedMeasurementEnvelope(
            publisher_universe_reference="universe:economic-index",
            population_reference="population:economic-index",
            publisher="publisher:example-statistics",
            series_id="series:example-index",
        )
    if index == 4:
        return DerivedStateMeasurementEnvelope(
            scope="urn:ktp:host:example",
            authoritative_source="clock:example-service",
            source_version="version:1",
        )
    raise ValueError(f"unsupported example signal index: {index}")


def build_observations() -> tuple[ObservationDeclaration, ...]:
    observed_at, ingested_at = (
        CUTOFF - timedelta(seconds=2),
        CUTOFF - timedelta(seconds=1),
    )
    observations: list[ObservationDeclaration] = []
    for domain in RiskDomain:
        for index, (signal, observation_class, raw_value) in enumerate(
            zip(SIGNALS, OBSERVATION_CLASSES, RAW_VALUES, strict=True)
        ):
            uses_window = observation_class in (
                ObservationClass.DIRECT,
                ObservationClass.ENUMERATED,
                ObservationClass.ADJUDICATED,
            )
            uses_population = observation_class in (
                ObservationClass.ENUMERATED,
                ObservationClass.ADJUDICATED,
                ObservationClass.PUBLISHED,
            )
            observations.append(
                ObservationDeclaration(
                    observation_id=f"observation:{domain.value}:{index}",
                    source_id=f"feed:{domain.value}:{index}",
                    sequence=index + 1,
                    signal_id=signal,
                    domain=domain,
                    observation_class=observation_class,
                    measurement_envelope=_measurement_envelope(index, observed_at),
                    raw_value=raw_value,
                    unit=UNITS[signal],
                    observed_at=observed_at,
                    ingested_at=ingested_at,
                    valid_until=(
                        CUTOFF + timedelta(minutes=1)
                        if observation_class is ObservationClass.DERIVED_STATE
                        else None
                    ),
                    population_state=(
                        PopulationState.OBSERVED if uses_population else None
                    ),
                    window=(
                        ObservationWindow(
                            observed_at - timedelta(seconds=1), observed_at
                        )
                        if uses_window
                        else None
                    ),
                    published_period=(
                        PublishedObservationPeriod(
                            start=observed_at - timedelta(days=30),
                            end=observed_at,
                            published_at=observed_at,
                            publication_lag_ms=0,
                            vintage="2026-08",
                        )
                        if observation_class is ObservationClass.PUBLISHED
                        else None
                    ),
                )
            )
    return tuple(observations)


def build_request(
    *,
    soul_state: Literal["clear", "veto", "undetermined"] = "clear",
    observations: tuple[ObservationDeclaration, ...] | None = None,
    operation_id: str = OPERATION_ID,
) -> EvaluationRequest:
    profile = build_profile()
    action = build_validated_action(profile)
    return EvaluationRequest(
        operation_id=operation_id,
        profile=profile,
        action=action,
        standing=build_standing(),
        observations=build_observations() if observations is None else observations,
        soul_responses=build_soul_responses(profile, action, state=soul_state),
        cutoff=CUTOFF,
    )


def evaluate_clear_request() -> EvaluationBundle:
    outcome = evaluate(build_request())
    if type(outcome) is RejectedRequest:
        raise RuntimeError(
            f"shared CLEAR request was rejected at {outcome.failed_stage.value}"
        )
    return outcome
