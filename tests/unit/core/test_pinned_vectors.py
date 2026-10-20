"""Pinned public-API evidence for the official ROS2 envelope vectors."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Context, Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import unittest

from kinetic_trust_library.models.action import (
    ActionDemandDeclaration,
    CapabilityDeclaration,
    MomentCriticalityDeclaration,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.evidence import (
    DirectMeasurementEnvelope,
    EnumeratedMeasurementEnvelope,
    ObservationClass,
    ObservationDeclaration,
    ObservationWindow,
    PopulationState,
)
from kinetic_trust_library.models.profile import (
    ActionPolicy,
    DeploymentProfile,
    DeploymentProfileDeclaration,
    EnvelopeThresholds,
    FactorAggregationDeclaration,
    FactorName,
    FeedDeclaration,
    MinMaxNormalization,
    MomentCriticalityFactorDeclaration,
    RiskDomain,
    RiskFactorsDeclaration,
    SignalRouteDeclaration,
    SignalRiskFactorDeclaration,
)
import kinetic_trust_library.models.profile as profile_module
from kinetic_trust_library.models.soul import SoulResponseDeclaration
from kinetic_trust_library.models.standing import (
    CeilingDeclaration,
    ExternalTerminatorDeclaration,
    ExternalTerminatorKind,
    FrictionCategory,
    PoRAttestationDeclaration,
    RootInstrumentDeclaration,
    RootIssuanceDeclaration,
    StandingDeclaration,
)
from kinetic_trust_library.core.evidence import prepare_evidence
from kinetic_trust_library.core.envelope import compute_envelope, require_validated_envelope_result
from kinetic_trust_library.core.risk import calculate_risk
from kinetic_trust_library.core.soul import assess_soul
from kinetic_trust_library.core.standing import prepare_standing
from kinetic_trust_library.core.trust import calculate_effective_trust


_VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "spec"
    / "v2.1.0"
    / "conformance"
    / "ros2-reference-v0.1.json"
)
_VECTOR_SHA256 = "fbb11fefe441c10154c5bf99bd88b63d79a6885b5b1f3a70852f83d325a8b024"
_CONTEXT = Context(prec=34)
_CUTOFF = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
_SUBJECT = "agent:independent:3gen:acme-line:agent-one"
_OBSTACLE_SIGNAL = "world.spatial.nearest_obstacle"
_PERSON_SIGNAL = "world.presence.person_count"
_PHYSICAL_SIGNALS = (_OBSTACLE_SIGNAL, _PERSON_SIGNAL)
_BASE_CAPACITY = Decimal("20")
_OPERATION_PREFIX = "operation:ros2-reference"
_COMMON_PHYSICAL_FIELDS = frozenset(
    {"humanDetected", "nearestObstacleMeters", "trajectoryNovel"}
)
_DEMAND_FIELD_BY_REQUEST = {
    ("ros2:///cmd_vel", "publish"): "currentVelocityMps",
    ("ros2:///wrench", "publish"): "currentForceNewtons",
    ("ros2:///joint_commands", "publish"): "currentTorqueNm",
}
_DECISION_BY_SUPERVISION = {
    "stable": "allow",
    "metacognitive": "escalate",
    "assisted": "escalate",
    "regulated": "escalate",
    "silent_veto": "deny",
}

_SIGNAL_FACTORS = (
    FactorName.EVIDENCE_DENSITY,
    FactorName.TRUST_TREND,
    FactorName.ADVERSARIAL_PRESSURE,
    FactorName.UPDATE_RESISTANCE,
    FactorName.ATTESTATION_COVERAGE,
)
_FACTOR_WEIGHTS = {
    **{factor: "0.10" for factor in _SIGNAL_FACTORS},
    FactorName.MOMENT_CRITICALITY: "0.50",
}
_DOMAIN_WEIGHTS = {
    RiskDomain.NODE: "0.50",
    RiskDomain.NEIGHBORHOOD: "0.25",
    RiskDomain.GLOBAL: "0.25",
}
_ROS2_UNITS = {
    "maxVelocityMps": "m/s",
    "maxForceNewtons": "N",
    "maxTorqueNm": "N·m",
    "maxJerkMps3": "m/s³",
    "maxAngularVelocityRps": "rad/s",
    "proximityMinMeters": "m",
    "joint:elbow:maxPositionRad": "rad",
    "joint:elbow:maxVelocityRps": "rad/s",
    "joint:elbow:maxEffortNm": "N·m",
}
_GRANTED_CONSTRAINTS = {
    "maxVelocityMps": "1.5",
    "maxForceNewtons": "150",
    "maxTorqueNm": "40",
    "maxJerkMps3": "100",
    "maxAngularVelocityRps": "2",
    "proximityMinMeters": "1",
    "joint:elbow:maxPositionRad": "3.14",
    "joint:elbow:maxVelocityRps": "2",
    "joint:elbow:maxEffortNm": "40",
}


@dataclass(frozen=True, slots=True)
class _ROS2PhysicalContext:
    current_velocity_mps: Decimal | None
    current_force_newtons: Decimal | None
    current_torque_nm: Decimal | None
    human_detected: bool
    nearest_obstacle_meters: Decimal
    trajectory_novel: bool


@dataclass(frozen=True, slots=True)
class _ROS2ReferenceRequest:
    resource_uri: str
    action: str
    physical_context: _ROS2PhysicalContext


@dataclass(frozen=True, slots=True)
class _ROS2ReferenceKinematics:
    request: _ROS2ReferenceRequest
    demand_ratio: Fraction
    capacity_factor: Fraction
    reference_margin: Fraction
    capacity_known: bool
    moment_stress: Decimal


@dataclass(frozen=True, slots=True)
class _TestOnlyMarginScaledVelocityPolicy:
    """Conservative test policy, not a shipped KTP tightening formula."""

    maximum_velocity_mps: Fraction = Fraction(3, 2)

    def requested_constraints(
        self,
        kinematics: _ROS2ReferenceKinematics,
    ) -> dict[str, Decimal]:
        requested = {
            magnitude: Decimal(value)
            for magnitude, value in _GRANTED_CONSTRAINTS.items()
        }
        is_stable = (
            kinematics.capacity_known and kinematics.reference_margin >= Fraction(1, 2)
        )
        is_veto = kinematics.reference_margin <= 0
        if (
            kinematics.request.resource_uri == "ros2:///cmd_vel"
            and not is_stable
            and not is_veto
        ):
            ceiling = self.maximum_velocity_mps * max(
                kinematics.reference_margin,
                Fraction(0),
            )
            requested["maxVelocityMps"] = _decimal_at_most(ceiling)
        return requested


@dataclass(frozen=True, slots=True)
class _TestOnlyROS2ReferenceProvider:
    """Translate official physical context into public Core test inputs only."""

    maximum_velocity_mps: Fraction = Fraction(3, 2)
    maximum_force_newtons: Fraction = Fraction(150)
    maximum_torque_nm: Fraction = Fraction(40)

    def parse_request(self, vector: dict[str, object]) -> _ROS2ReferenceRequest:
        request = vector["request"]
        if type(request) is not dict or set(request) != {
            "resource",
            "action",
            "physicalContext",
        }:
            raise AssertionError("official ROS2 request field inventory is invalid")
        physical = request["physicalContext"]
        resource = request["resource"]
        action = request["action"]
        if (
            type(resource) is not str
            or type(action) is not str
            or (resource, action) not in _DEMAND_FIELD_BY_REQUEST
        ):
            raise AssertionError("official ROS2 request identity is malformed")
        expected_physical_fields = _COMMON_PHYSICAL_FIELDS | {
            _DEMAND_FIELD_BY_REQUEST[(resource, action)]
        }
        if type(physical) is not dict or set(physical) != expected_physical_fields:
            raise AssertionError(
                "official ROS2 physical-context field inventory is invalid"
            )
        return _ROS2ReferenceRequest(
            resource_uri=resource,
            action=action,
            physical_context=_ROS2PhysicalContext(
                current_velocity_mps=_optional_decimal(
                    physical,
                    "currentVelocityMps",
                ),
                current_force_newtons=_optional_decimal(
                    physical,
                    "currentForceNewtons",
                ),
                current_torque_nm=_optional_decimal(
                    physical,
                    "currentTorqueNm",
                ),
                human_detected=_required_bool(physical, "humanDetected"),
                nearest_obstacle_meters=_required_decimal(
                    physical,
                    "nearestObstacleMeters",
                ),
                trajectory_novel=_required_bool(physical, "trajectoryNovel"),
            ),
        )

    def calculate(
        self,
        request: _ROS2ReferenceRequest,
    ) -> _ROS2ReferenceKinematics:
        physical = request.physical_context
        demand_ratio = max(
            _fraction_or_zero(physical.current_velocity_mps)
            / self.maximum_velocity_mps,
            _fraction_or_zero(physical.current_force_newtons)
            / self.maximum_force_newtons,
            _fraction_or_zero(physical.current_torque_nm) / self.maximum_torque_nm,
        )
        proximity = min(
            Fraction(physical.nearest_obstacle_meters),
            Fraction(1),
        )
        human = Fraction(1, 2) if physical.human_detected else Fraction(1)
        novelty = Fraction(3, 5) if physical.trajectory_novel else Fraction(1)
        capacity_factor = proximity * human * novelty
        reference_margin = (
            Fraction(0)
            if capacity_factor == 0
            else Fraction(1) - (demand_ratio / capacity_factor)
        )

        # Public Library evaluation has no ROS2 ActionContext input. This test-only
        # bridge carries real obstacle/person declarations through evidence and
        # places only the remaining exact capacity reduction in the declared
        # external moment term. Novelty deliberately withholds Node sensing so
        # the public result independently exposes unknown capacity.
        proximity_reduction = Fraction(1) - proximity
        obstacle_stress = min(proximity_reduction / Fraction(1, 2), Fraction(1))
        person_stress = Fraction(1) if physical.human_detected else Fraction(0)
        physical_signal_stress = max(obstacle_stress, person_stress)
        signal_contribution = (
            Fraction(1, 4) + Fraction(1, 4) * physical_signal_stress
            if physical.trajectory_novel
            else Fraction(1, 2) * physical_signal_stress
        )
        target_risk = Fraction(1) - capacity_factor
        moment_stress = (target_risk - signal_contribution) / Fraction(1, 2)
        if not Fraction(0) <= moment_stress <= Fraction(1):
            raise AssertionError("test-only ROS2 bridge moment is outside [0,1]")
        return _ROS2ReferenceKinematics(
            request=request,
            demand_ratio=demand_ratio,
            capacity_factor=capacity_factor,
            reference_margin=reference_margin,
            capacity_known=not physical.trajectory_novel,
            moment_stress=_exact_decimal(moment_stress),
        )


@dataclass(frozen=True, slots=True)
class _ReferenceCase:
    vector: dict[str, object]
    profile: DeploymentProfile
    action: ValidatedActionDemand
    standing_declaration: StandingDeclaration
    observations: tuple[ObservationDeclaration, ...]
    soul_declarations: tuple[SoulResponseDeclaration, ...]
    soul: object
    trust: object
    envelope: object
    operation_id: str
    reference_request: _ROS2ReferenceRequest
    kinematics: _ROS2ReferenceKinematics


_REFERENCE_PROVIDER = _TestOnlyROS2ReferenceProvider()
_TIGHTENING_POLICY = _TestOnlyMarginScaledVelocityPolicy()


def _exact_decimal(value: Fraction) -> Decimal:
    converted = _context_decimal(value)
    if Fraction(converted) != value:
        raise AssertionError("test-only ROS2 value is not an exact Decimal")
    return converted


def _context_decimal(value: Fraction) -> Decimal:
    with localcontext(_CONTEXT):
        return Decimal(value.numerator) / Decimal(value.denominator)


def _decimal_at_most(value: Fraction) -> Decimal:
    with localcontext(_CONTEXT):
        converted = Decimal(value.numerator) / Decimal(value.denominator)
        if Fraction(converted) > value:
            converted = converted.next_minus()
    if Fraction(converted) > value:
        raise AssertionError("test-only conservative ceiling rounded upward")
    return converted


def _fraction_or_zero(value: Decimal | None) -> Fraction:
    return Fraction(0) if value is None else Fraction(value)


def _optional_decimal(
    physical: dict[str, object],
    name: str,
) -> Decimal | None:
    value = physical.get(name)
    if value is None:
        return None
    if type(value) is not Decimal:
        raise AssertionError(f"official ROS2 {name} must be numeric")
    return value


def _required_decimal(physical: dict[str, object], name: str) -> Decimal:
    value = _optional_decimal(physical, name)
    if value is None:
        raise AssertionError(f"official ROS2 {name} is required")
    return value


def _required_bool(physical: dict[str, object], name: str) -> bool:
    value = physical.get(name)
    if type(value) is not bool:
        raise AssertionError(f"official ROS2 {name} must be boolean")
    return value


def _load_vectors() -> tuple[bytes, dict[str, object]]:
    payload = _VECTOR_PATH.read_bytes()
    document = json.loads(payload, parse_float=Decimal, parse_int=Decimal)
    return payload, document


def _test_only_core_projection_profile() -> DeploymentProfile:
    """Build a synthetic Library evaluation carrier, not an RFC ROS2 deployment profile.

    The profile ID remains the official vector binding. The extra standing,
    evidence, and risk declarations exist only because the public Core API does
    not accept the ROS2 ``ActionContext`` directly.
    """

    aggregations = {
        factor: FactorAggregationDeclaration(
            signals=_PHYSICAL_SIGNALS,
            method="maximum",
            signal_weights=None,
        )
        for factor in _SIGNAL_FACTORS
    }
    risk_factors = RiskFactorsDeclaration(
        evidence_density=SignalRiskFactorDeclaration(
            _FACTOR_WEIGHTS[FactorName.EVIDENCE_DENSITY],
            aggregations[FactorName.EVIDENCE_DENSITY],
        ),
        trust_trend=SignalRiskFactorDeclaration(
            _FACTOR_WEIGHTS[FactorName.TRUST_TREND],
            aggregations[FactorName.TRUST_TREND],
        ),
        adversarial_pressure=SignalRiskFactorDeclaration(
            _FACTOR_WEIGHTS[FactorName.ADVERSARIAL_PRESSURE],
            aggregations[FactorName.ADVERSARIAL_PRESSURE],
        ),
        update_resistance=SignalRiskFactorDeclaration(
            _FACTOR_WEIGHTS[FactorName.UPDATE_RESISTANCE],
            aggregations[FactorName.UPDATE_RESISTANCE],
        ),
        attestation_coverage=SignalRiskFactorDeclaration(
            _FACTOR_WEIGHTS[FactorName.ATTESTATION_COVERAGE],
            aggregations[FactorName.ATTESTATION_COVERAGE],
        ),
        moment_criticality=MomentCriticalityFactorDeclaration(
            _FACTOR_WEIGHTS[FactorName.MOMENT_CRITICALITY],
            "test-only-ros2-reference-adapter",
            "stress-0-1",
        ),
    )
    feeds = {
        f"feed:ros2-reference:{domain.value}": FeedDeclaration(
            source_id=f"feed:ros2-reference:{domain.value}",
            routes=(
                SignalRouteDeclaration(
                    signal_id=_OBSTACLE_SIGNAL,
                    domain=domain,
                    unit="m",
                ),
                SignalRouteDeclaration(
                    signal_id=_PERSON_SIGNAL,
                    domain=domain,
                    unit="person-count",
                ),
            ),
            refresh_interval_ms=1_000,
            stale_threshold_ms=30_000,
            stale_threshold_reason="source:ros2-reference:freshness",
        )
        for domain in RiskDomain
    }
    declaration = DeploymentProfileDeclaration(
        profile_id="ros2-reference-v0.1",
        version=1,
        action_demand_unit="trust-points",
        risk_factors=risk_factors,
        risk_domain_weights=dict(_DOMAIN_WEIGHTS),
        soul_frameworks=("soul.framework.ros2-reference",),
        peer_share="0",
        external_root_hop_bound=6,
        misattestation_adjudicator="adjudicator:ros2-reference",
        standing_decay_rate="16",
        envelope_thresholds=EnvelopeThresholds(
            veto=Decimal("0"),
            allow=Decimal("0.50"),
            metacognitive_floor=Decimal("0.33"),
            assisted_floor=Decimal("0.15"),
        ),
        actions={
            "publish": ActionPolicy(
                action_class="publish",
                demand_min=Decimal("0"),
                demand_max=Decimal("100"),
                constraint_units=_ROS2_UNITS,
                normative_gates=(),
            )
        },
        feeds=feeds,
        alias_selections={},
        normalizations={
            _OBSTACLE_SIGNAL: MinMaxNormalization(
                minimum="0.5",
                maximum="1",
                invert=True,
                clamp=True,
            ),
            _PERSON_SIGNAL: MinMaxNormalization(
                minimum="0",
                maximum="1",
                invert=False,
                clamp=True,
            ),
        },
        label_sets={},
    )
    return DeploymentProfile.validate(declaration)


def _standing_declaration() -> StandingDeclaration:
    return StandingDeclaration(
        agent_id=_SUBJECT,
        generation=3,
        identity_assurance_level=3,
        trajectory_length=10_000,
        por_attestations=(
            PoRAttestationDeclaration(
                attestation_id="attestation:ros2-reference:one",
                agent_id=_SUBJECT,
                transaction_ref="transaction:ros2-reference:one",
                friction="0.6",
                friction_category=FrictionCategory.HIGH,
                action_risk="1",
                outcome="success",
                timestamp=_CUTOFF - timedelta(minutes=1),
                oracle_id="oracle:ros2-reference",
                verification_ref="verification:ros2-reference:por",
            ),
        ),
        root_instruments=(
            RootInstrumentDeclaration(
                instrument_id="root:ros2-reference",
                attestor="entity:ros2-reference-attestor",
                issuance=RootIssuanceDeclaration(
                    issued_at=_CUTOFF - timedelta(days=1),
                    end_time=_CUTOFF + timedelta(days=1),
                    verification_ref="verification:ros2-reference:issuance",
                ),
                sponsor_standing=None,
                stake_percentage=None,
                exposure_class="legal-liability",
                declared_exposure="100",
                anchored_capacity="100",
                chain=("legal:ros2-reference-root",),
                terminator=ExternalTerminatorDeclaration(
                    kind=ExternalTerminatorKind.LEGAL_ENTITY,
                    identifier="legal:ros2-reference-root",
                    verification_ref="verification:ros2-reference:terminator",
                ),
                withdrawal_claim=None,
                adjudication_finding=None,
            ),
        ),
        peer=None,
        additional_ceilings=(
            CeilingDeclaration(
                name="ros2-reference-capacity",
                value=_BASE_CAPACITY,
                provenance_id="ceiling:ros2-reference-capacity",
            ),
        ),
        advancement_floor="0",
    )


def _observations(
    request: _ROS2ReferenceRequest,
    *,
    capacity_known: bool,
) -> tuple[ObservationDeclaration, ...]:
    observed_at = _CUTOFF - timedelta(seconds=2)
    values: list[ObservationDeclaration] = []
    for domain in RiskDomain:
        if not capacity_known and domain is RiskDomain.NODE:
            continue
        source_id = f"feed:ros2-reference:{domain.value}"
        window = ObservationWindow(
            start=observed_at - timedelta(seconds=1),
            end=observed_at,
        )
        values.extend(
            (
                ObservationDeclaration(
                    observation_id=(
                        f"observation:ros2-reference:{domain.value}:obstacle"
                    ),
                    source_id=source_id,
                    sequence=1,
                    signal_id=_OBSTACLE_SIGNAL,
                    domain=domain,
                    observation_class=ObservationClass.DIRECT,
                    measurement_envelope=DirectMeasurementEnvelope(
                        subject=request.resource_uri,
                        modality="range",
                        instrument_make_model="test-only:ros2-range-sensor",
                        calibration_at=_CUTOFF - timedelta(days=1),
                        calibration_reference="calibration:ros2-reference:range",
                    ),
                    raw_value=request.physical_context.nearest_obstacle_meters,
                    unit="m",
                    observed_at=observed_at,
                    ingested_at=_CUTOFF - timedelta(seconds=1),
                    valid_until=None,
                    population_state=None,
                    window=window,
                    published_period=None,
                    on_demand_binding=None,
                ),
                ObservationDeclaration(
                    observation_id=(
                        f"observation:ros2-reference:{domain.value}:persons"
                    ),
                    source_id=source_id,
                    sequence=2,
                    signal_id=_PERSON_SIGNAL,
                    domain=domain,
                    observation_class=ObservationClass.ENUMERATED,
                    measurement_envelope=EnumeratedMeasurementEnvelope(
                        subject_boundary=request.resource_uri,
                        population="persons-in-action-space",
                        membership_rule="detected-person-in-action-space",
                        reset_semantics="per-action-context",
                        membership_mode="enumerated",
                        instrument_identity="test-only:ros2-person-detector",
                        instrument_version="reference-v0.1",
                    ),
                    raw_value=(1 if request.physical_context.human_detected else 0),
                    unit="person-count",
                    observed_at=observed_at,
                    ingested_at=_CUTOFF - timedelta(seconds=1),
                    valid_until=None,
                    population_state=PopulationState.OBSERVED,
                    window=window,
                    published_period=None,
                    on_demand_binding=None,
                ),
            )
        )
    return tuple(values)


def _build_case(
    index: int,
    *,
    demand_override: Decimal | None = None,
    vector_override: dict[str, object] | None = None,
) -> _ReferenceCase:
    _, document = _load_vectors()
    vector = document["vectors"][index] if vector_override is None else vector_override
    reference_request = _REFERENCE_PROVIDER.parse_request(vector)
    if reference_request.action != "publish":
        raise AssertionError("test-only ROS2 profile supports publish only")
    kinematics = _REFERENCE_PROVIDER.calculate(reference_request)
    demand = _context_decimal(Fraction(_BASE_CAPACITY) * kinematics.demand_ratio)
    if demand_override is not None:
        demand = demand_override
    profile = _test_only_core_projection_profile()
    operation_id = f"{_OPERATION_PREFIX}:{index + 1}"
    capability = CapabilityDeclaration(
        subject=_SUBJECT,
        action_classes=("publish",),
        constraint_ceiling=dict(_GRANTED_CONSTRAINTS),
        not_before=_CUTOFF - timedelta(minutes=1),
        not_after=_CUTOFF + timedelta(minutes=1),
        provenance_id=f"capability:ros2-reference:{index + 1}",
    )
    action = ValidatedActionDemand.validate(
        ActionDemandDeclaration(
            action_id=f"action:ros2-reference:{index + 1}",
            subject=_SUBJECT,
            action_class="publish",
            demand=demand,
            demand_unit="trust-points",
            demand_source="test-only-ros2-reference-adapter",
            granted_constraints=dict(_GRANTED_CONSTRAINTS),
            requested_constraints=_TIGHTENING_POLICY.requested_constraints(kinematics),
            moment_criticality=MomentCriticalityDeclaration(
                value=kinematics.moment_stress,
                supplier="test-only-ros2-reference-adapter",
                unit="stress-0-1",
                observed_at=_CUTOFF,
                provenance_id=f"moment:ros2-reference:{index + 1}",
            ),
            normative_gate_tokens=(),
        ),
        profile=profile,
        capability=capability,
        cutoff=_CUTOFF,
    )
    soul_declarations = tuple(
        SoulResponseDeclaration(
            framework_id=framework,
            profile_ref=profile.ref,
            profile_digest=profile.digest,
            action_id=action.action_id,
            action_digest=action.digest,
            query_cutoff=_CUTOFF,
            state="clear",
            observed_at=_CUTOFF,
            provenance_id=f"soul:ros2-reference:{index + 1}",
        )
        for framework in profile.soul_frameworks
    )
    soul = assess_soul(profile, soul_declarations, action, _CUTOFF)
    standing_declaration = _standing_declaration()
    standing = prepare_standing(profile, standing_declaration, _CUTOFF)
    observations = _observations(
        reference_request,
        capacity_known=kinematics.capacity_known,
    )
    evidence = prepare_evidence(
        profile,
        observations,
        _CUTOFF,
        operation_id=operation_id,
    )
    risk = calculate_risk(profile, evidence, soul, action, _CUTOFF)
    trust = calculate_effective_trust(
        profile,
        standing,
        risk,
        soul,
        action,
        _CUTOFF,
    )
    result = compute_envelope(
        profile,
        action,
        soul,
        trust,
        operation_id=operation_id,
    )
    expected_capacity = _exact_decimal(
        Fraction(_BASE_CAPACITY) * kinematics.capacity_factor
    )
    if trust.effective_trust != expected_capacity:
        raise AssertionError("reference fixture did not derive its declared capacity")
    return _ReferenceCase(
        vector=vector,
        profile=profile,
        action=action,
        standing_declaration=standing_declaration,
        observations=observations,
        soul_declarations=soul_declarations,
        soul=soul,
        trust=trust,
        envelope=result,
        operation_id=operation_id,
        reference_request=reference_request,
        kinematics=kinematics,
    )


class PinnedROS2EnvelopeVectorTests(unittest.TestCase):
    def _assert_vector(
        self,
        index: int,
        *,
        vector_override: dict[str, object] | None = None,
    ) -> None:
        payload, document = _load_vectors()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), _VECTOR_SHA256)
        self.assertEqual(document["profile"], "ros2-reference-v0.1")
        self.assertEqual(len(document["vectors"]), 7)

        case = _build_case(index, vector_override=vector_override)
        expected = case.vector["expect"]
        result = case.envelope
        self.assertIs(require_validated_envelope_result(result), result)
        self.assertEqual(result.supervision.value, expected["supervision"])
        self.assertEqual(result.policy_code, expected.get("policyCode"))
        self.assertIs(result.capacity_known, expected["capacityKnown"])
        self.assertEqual(
            _DECISION_BY_SUPERVISION[result.supervision.value],
            expected["decision"],
        )

        ceilings = {
            ceiling.magnitude: ceiling.maximum
            for ceiling in result.tightened_constraints.ceilings
        }
        for magnitude, maximum in expected.get("tightenedAtMost", {}).items():
            self.assertIn(magnitude, ceilings)
            self.assertLessEqual(ceilings[magnitude], maximum)

        # The official artifact explicitly marks referenceMargin informative.
        # It is loaded to prove the exact pinned vector shape but is not used as
        # an assertion against this implementation's internal A/E formula.
        self.assertIn("referenceMargin", expected)

    def test_mutated_decision_and_capacity_expectations_are_rejected(self):
        _, document = _load_vectors()
        for field, replacement in (
            ("decision", "deny"),
            ("capacityKnown", False),
        ):
            altered = copy.deepcopy(document["vectors"][0])
            altered["expect"][field] = replacement
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self._assert_vector(0, vector_override=altered)

    def test_v1_cmd_vel_safe(self):
        self._assert_vector(0)

    def test_v2_cmd_vel_near_margin(self):
        self._assert_vector(1)

    def test_v3_human_near(self):
        self._assert_vector(2)

    def test_v4_force_over_limit(self):
        self._assert_vector(3)

    def test_v5_obstacle_proximity(self):
        self._assert_vector(4)

    def test_v6_torque_over_limit(self):
        self._assert_vector(5)

    def test_v7_novel_workspace_unknown_capacity(self):
        self._assert_vector(6)


class TestOnlyROS2AdapterIntegrityTests(unittest.TestCase):
    def test_preserves_the_official_resource_action_and_physical_context(self):
        for index in range(7):
            case = _build_case(index)
            raw_request = case.vector["request"]
            raw_physical = raw_request["physicalContext"]
            request = case.reference_request
            physical = request.physical_context
            with self.subTest(vector=case.vector["id"]):
                self.assertEqual(request.resource_uri, raw_request["resource"])
                self.assertEqual(request.action, raw_request["action"])
                self.assertEqual(
                    physical.current_velocity_mps,
                    raw_physical.get("currentVelocityMps"),
                )
                self.assertEqual(
                    physical.current_force_newtons,
                    raw_physical.get("currentForceNewtons"),
                )
                self.assertEqual(
                    physical.current_torque_nm,
                    raw_physical.get("currentTorqueNm"),
                )
                self.assertIs(
                    physical.human_detected,
                    raw_physical["humanDetected"],
                )
                self.assertEqual(
                    physical.nearest_obstacle_meters,
                    raw_physical["nearestObstacleMeters"],
                )
                self.assertIs(
                    physical.trajectory_novel,
                    raw_physical["trajectoryNovel"],
                )

                self.assertNotIn(
                    "world.optical.illuminance",
                    case.profile.normalizations,
                )
                self.assertIn(
                    "world.spatial.nearest_obstacle",
                    case.profile.normalizations,
                )
                self.assertIn(
                    "world.presence.person_count",
                    case.profile.normalizations,
                )

    def test_adapter_rejects_unknown_and_mismatched_request_shapes(self):
        _, document = _load_vectors()
        base = document["vectors"][0]
        cases = []

        unknown_request = copy.deepcopy(base)
        unknown_request["request"]["ignored"] = "value"
        cases.append(unknown_request)

        unknown_context = copy.deepcopy(base)
        unknown_context["request"]["physicalContext"]["ignored"] = Decimal(1)
        cases.append(unknown_context)

        wrong_resource = copy.deepcopy(base)
        wrong_resource["request"]["resource"] = "ros2:///wrench"
        cases.append(wrong_resource)

        wrong_action = copy.deepcopy(base)
        wrong_action["request"]["action"] = "subscribe"
        cases.append(wrong_action)

        missing_demand = copy.deepcopy(base)
        del missing_demand["request"]["physicalContext"]["currentVelocityMps"]
        cases.append(missing_demand)

        for index, vector in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(AssertionError):
                _REFERENCE_PROVIDER.parse_request(vector)

    def test_physical_counterfactuals_are_monotone_and_never_loosen(self):
        baseline = _build_case(0)
        supervision_rank = {
            "stable": 0,
            "metacognitive": 1,
            "assisted": 2,
            "regulated": 3,
            "silent_veto": 4,
        }
        mutations = (
            ("currentVelocityMps", Decimal("0.9")),
            ("nearestObstacleMeters", Decimal("0.8")),
            ("humanDetected", True),
            ("trajectoryNovel", True),
        )
        for name, replacement in mutations:
            vector = copy.deepcopy(baseline.vector)
            vector["request"]["physicalContext"][name] = replacement
            changed = _build_case(0, vector_override=vector)
            with self.subTest(field=name):
                self.assertGreaterEqual(
                    changed.kinematics.demand_ratio,
                    baseline.kinematics.demand_ratio,
                )
                self.assertLessEqual(
                    changed.kinematics.capacity_factor,
                    baseline.kinematics.capacity_factor,
                )
                self.assertLessEqual(
                    changed.kinematics.reference_margin,
                    baseline.kinematics.reference_margin,
                )
                self.assertGreaterEqual(
                    supervision_rank[changed.envelope.supervision.value],
                    supervision_rank[baseline.envelope.supervision.value],
                )
                self.assertLessEqual(
                    changed.action.requested_constraints["maxVelocityMps"],
                    baseline.action.requested_constraints["maxVelocityMps"],
                )

    def test_official_expectation_mutation_cannot_change_adapter_inputs(self):
        for index in range(7):
            case = _build_case(index)
            altered_vector = copy.deepcopy(case.vector)
            altered_vector["expect"] = {
                "decision": "deny",
                "supervision": "silent_veto",
                "policyCode": "MUTATED_EXPECTATION",
                "referenceMargin": Decimal("999"),
                "capacityKnown": not case.kinematics.capacity_known,
                "tightenedAtMost": {"maxVelocityMps": Decimal("999")},
            }

            altered = _build_case(index, vector_override=altered_vector)

            with self.subTest(vector=case.vector["id"]):
                self.assertEqual(
                    altered.action.requested_constraints,
                    case.action.requested_constraints,
                )
                self.assertEqual(
                    altered.trust.effective_trust, case.trust.effective_trust
                )
                self.assertEqual(altered.envelope.digest, case.envelope.digest)

    def test_test_policy_scales_velocity_from_exact_reference_margin(self):
        for index in (1, 2, 4, 6):
            case = _build_case(index)
            expected_ceiling = _exact_decimal(
                Fraction(3, 2) * max(case.kinematics.reference_margin, Fraction(0))
            )
            with self.subTest(vector=case.vector["id"]):
                self.assertEqual(
                    case.action.requested_constraints["maxVelocityMps"],
                    expected_ceiling,
                )

    def test_capacity_known_is_project_owned_adapter_interface_coverage(self):
        for index in range(7):
            case = _build_case(index)
            with self.subTest(vector=case.vector["id"]):
                self.assertIs(
                    case.kinematics.capacity_known,
                    not case.reference_request.physical_context.trajectory_novel,
                )
                self.assertIs(
                    case.envelope.capacity_known,
                    case.kinematics.capacity_known,
                )


if __name__ == "__main__":
    unittest.main()
