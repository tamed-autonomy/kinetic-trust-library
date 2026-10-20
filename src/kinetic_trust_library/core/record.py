"""Deterministic, explicit DecisionRecord projection and structural validation."""

from __future__ import annotations

import re
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import _canonical_derived_margin, canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT, require_derived_margin
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import (
    utc_time,
    validate_identifier,
)
from kinetic_trust_library.models._uri import validate_absolute_uri
from kinetic_trust_library.models.action import (
    MomentCriticality,
    NormativeGateDecision,
    NormativeGateToken,
)
from kinetic_trust_library.models.capacity import CapacityRelation
from kinetic_trust_library.models.envelope import (
    ConstraintCeiling,
    EvaluationBundle,
    EvaluationStage,
    NormativeGateOutcome,
    NormativeGateState,
    Supervision,
    TightenedConstraints,
    UndefinedInput,
)
from kinetic_trust_library.models.evidence import UndefinedReason
from kinetic_trust_library.models.profile import FactorName, ProfileRef, RiskDomain
from kinetic_trust_library.models.record import DecisionRecord
from kinetic_trust_library.models.risk import (
    DomainFactorResult,
    DomainRiskResult,
    MomentCriticalityResult,
    RiskContext,
    RiskInput,
    SignalFactorResult,
)
from kinetic_trust_library.models.soul import (
    SoulAssessmentState,
    SoulConstraint,
    SoulFrameworkOutcome,
)
from kinetic_trust_library.models.trust import TrustTier

from .capacity import _capacity_relation
from .envelope import (
    _margin,
    _require_constraints_structure,
    _require_undefined_structure,
)
from .evaluate import require_validated_evaluation_bundle
from .soul import _require_constraint_structure, _require_outcome_structure
from .trust import _effective_trust, _trust_tier


def build_decision_record(evaluation: EvaluationBundle, /) -> DecisionRecord:
    bundle = require_validated_evaluation_bundle(evaluation)
    standing = bundle.standing
    evidence = bundle.evidence
    risk_result = bundle.risk
    trust = bundle.trust
    core_capacity = bundle.core_capacity
    result = bundle.envelope
    values: dict[str, object] = {
        "record_profile": "ktp-python-decision-record-v1",
        "record_id": bundle.operation_id,
        "evaluated_at": bundle.cutoff.replace(
            microsecond=(bundle.cutoff.microsecond // 1000) * 1000
        ),
        "profile_ref": bundle.profile_ref,
        "profile_digest": bundle.profile_digest,
        "subject": bundle.action.subject,
        "action_id": bundle.action.action_id,
        "action_digest": bundle.action.digest,
        "autonomy_demand": bundle.action.demand,
        "evaluation_digest": bundle.digest,
        "soul_digest": bundle.soul.digest,
        "standing_digest": None if standing is None else standing.digest,
        "evidence_digest": None if evidence is None else evidence.digest,
        "risk_digest": None if risk_result is None else risk_result.digest,
        "trust_digest": None if trust is None else trust.digest,
        "velocity_digest": None if bundle.velocity is None else bundle.velocity.digest,
        "core_capacity_digest": None if core_capacity is None else core_capacity.digest,
        "capacity_relation": None if core_capacity is None else core_capacity.relation,
        "envelope_digest": result.digest,
        "soul_state": bundle.soul.state,
        "soul_outcomes": bundle.soul.outcomes,
        "soul_constraints": bundle.soul.constraints,
        "undetermined_frameworks": bundle.soul.undetermined_frameworks,
        "risk_context": None if risk_result is None else risk_result.context,
        "risk_factors": None if risk_result is None else risk_result.factors,
        "domain_risks": None if risk_result is None else risk_result.domains,
        "base_trust": None if standing is None else standing.base_trust,
        "risk": None if risk_result is None else risk_result.risk,
        "effective_trust": None if trust is None else trust.effective_trust,
        "tier": None if trust is None else trust.tier,
        "velocity": None if bundle.velocity is None else bundle.velocity.value,
        "environmental_capacity": result.environmental_capacity,
        "capacity_known": result.capacity_known,
        "margin": result.margin,
        "supervision": result.supervision,
        "tightened_constraints": result.tightened_constraints,
        "policy_code": result.policy_code,
        "normative_gate_outcomes": result.normative_gate_outcomes,
        "rationale": result.rationale,
        "undefined_inputs": result.undefined_inputs,
        "trace": result.trace,
    }
    record = object.__new__(DecisionRecord)
    for name, value in values.items():
        object.__setattr__(record, name, value)
    object.__setattr__(
        record,
        "digest",
        canonical_sha256(_record_projection(record, include_digest=False)),
    )
    return require_validated_decision_record(record)


def _risk_factor_projection(value: object) -> dict[str, object]:
    if type(value) is SignalFactorResult:
        return {
            "kind": "signal",
            "name": value.name,
            "weight": value.weight,
            "context_stress": value.context_stress,
            "contribution": value.contribution,
            "domains": tuple(_domain_factor_projection(item) for item in value.domains),
        }
    if type(value) is MomentCriticalityResult:
        return {
            "kind": "moment_criticality",
            "name": value.name,
            "weight": value.weight,
            "context_stress": value.context_stress,
            "contribution": value.contribution,
            "supplied_value": {
                "value": value.supplied_value.value,
                "supplier": value.supplied_value.supplier,
                "unit": value.supplied_value.unit,
                "observed_at": value.supplied_value.observed_at,
                "provenance_id": value.supplied_value.provenance_id,
            },
        }
    raise ValidationError("record risk factor is invalid")


def _profile_ref_projection(value: ProfileRef) -> dict[str, object]:
    return {"profile_id": value.profile_id, "version": value.version}


def _soul_constraint_projection(value: SoulConstraint) -> dict[str, object]:
    return {
        "framework_id": value.framework_id,
        "constraint_type": value.constraint_type,
        "constraint_id": value.constraint_id,
        "authority": value.authority,
        "provenance_id": value.provenance_id,
    }


def _soul_outcome_projection(value: SoulFrameworkOutcome) -> dict[str, object]:
    return {
        "framework_id": value.framework_id,
        "state": value.state,
        "observed_at": value.observed_at,
        "provenance_id": value.provenance_id,
        "constraint": (
            None
            if value.constraint is None
            else _soul_constraint_projection(value.constraint)
        ),
        "undetermined_reason": value.undetermined_reason,
    }


def _risk_context_projection(value: RiskContext) -> dict[str, object]:
    return {
        "evidence_density": value.evidence_density,
        "trust_trend": value.trust_trend,
        "adversarial_pressure": value.adversarial_pressure,
        "update_resistance": value.update_resistance,
        "attestation_coverage": value.attestation_coverage,
        "moment_criticality": value.moment_criticality,
    }


def _domain_factor_projection(value: DomainFactorResult) -> dict[str, object]:
    return {
        "domain": value.domain,
        "stress": value.stress,
        "defaulted": value.defaulted,
        "inputs": tuple(_risk_input_projection(item) for item in value.inputs),
    }


def _risk_input_projection(value: RiskInput) -> dict[str, object]:
    return {
        "factor": value.factor,
        "domain": value.domain,
        "signal_id": value.signal_id,
        "stress": value.stress,
        "observation_digests": value.observation_digests,
        "feed_outcome_digests": value.feed_outcome_digests,
        "undefined_reason": value.undefined_reason,
    }


def _domain_risk_projection(value: DomainRiskResult) -> dict[str, object]:
    return {"domain": value.domain, "weight": value.weight, "risk": value.risk}


def _constraints_projection(value: TightenedConstraints) -> dict[str, object]:
    return {
        "profile_ref": _profile_ref_projection(value.profile_ref),
        "profile_digest": value.profile_digest,
        "action_class": value.action_class,
        "ceilings": tuple(_ceiling_projection(item) for item in value.ceilings),
        "digest": value.digest,
    }


def _ceiling_projection(value: ConstraintCeiling) -> dict[str, object]:
    return {
        "magnitude": value.magnitude,
        "unit": value.unit,
        "maximum": value.maximum,
    }


def _gate_outcome_projection(value: NormativeGateOutcome) -> dict[str, object]:
    return {
        "gate_id": value.gate_id,
        "schema_uri": value.schema_uri,
        "required": value.required,
        "state": value.state,
        "token": None if value.token is None else _gate_token_projection(value.token),
    }


def _gate_token_projection(value: NormativeGateToken) -> dict[str, object]:
    return {
        "gate_id": value.gate_id,
        "schema_uri": value.schema_uri,
        "decision": value.decision,
        "authority": value.authority,
        "observed_at": value.observed_at,
        "provenance_id": value.provenance_id,
    }


def _undefined_projection(value: UndefinedInput) -> dict[str, object]:
    return {
        "input_id": value.input_id,
        "layer": value.layer,
        "reason": value.reason,
        "provenance_ids": value.provenance_ids,
    }


def _record_projection(
    value: DecisionRecord,
    *,
    include_digest: bool,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "record_profile": value.record_profile,
        "record_id": value.record_id,
        "evaluated_at": value.evaluated_at,
        "profile_ref": _profile_ref_projection(value.profile_ref),
        "profile_digest": value.profile_digest,
        "subject": value.subject,
        "action_id": value.action_id,
        "action_digest": value.action_digest,
        "autonomy_demand": value.autonomy_demand,
        "evaluation_digest": value.evaluation_digest,
        "soul_digest": value.soul_digest,
        "standing_digest": value.standing_digest,
        "evidence_digest": value.evidence_digest,
        "risk_digest": value.risk_digest,
        "trust_digest": value.trust_digest,
        "velocity_digest": value.velocity_digest,
        "core_capacity_digest": value.core_capacity_digest,
        "capacity_relation": value.capacity_relation,
        "envelope_digest": value.envelope_digest,
        "soul_state": value.soul_state,
        "soul_outcomes": tuple(
            _soul_outcome_projection(item) for item in value.soul_outcomes
        ),
        "soul_constraints": tuple(
            _soul_constraint_projection(item) for item in value.soul_constraints
        ),
        "undetermined_frameworks": value.undetermined_frameworks,
        "risk_context": (
            None
            if value.risk_context is None
            else _risk_context_projection(value.risk_context)
        ),
        "risk_factors": (
            None
            if value.risk_factors is None
            else tuple(_risk_factor_projection(item) for item in value.risk_factors)
        ),
        "domain_risks": (
            None
            if value.domain_risks is None
            else tuple(_domain_risk_projection(item) for item in value.domain_risks)
        ),
        "base_trust": value.base_trust,
        "risk": value.risk,
        "effective_trust": value.effective_trust,
        "tier": value.tier,
        "velocity": value.velocity,
        "environmental_capacity": value.environmental_capacity,
        "capacity_known": value.capacity_known,
        "margin": (
            None if value.margin is None else _canonical_derived_margin(value.margin)
        ),
        "supervision": value.supervision,
        "tightened_constraints": _constraints_projection(value.tightened_constraints),
        "policy_code": value.policy_code,
        "normative_gate_outcomes": (
            None
            if value.normative_gate_outcomes is None
            else tuple(
                _gate_outcome_projection(item) for item in value.normative_gate_outcomes
            )
        ),
        "rationale": value.rationale,
        "undefined_inputs": tuple(
            _undefined_projection(item) for item in value.undefined_inputs
        ),
        "trace": value.trace,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def require_validated_decision_record(value: object, /) -> DecisionRecord:
    if type(value) is not DecisionRecord:
        raise ValidationError("value is not a decision record")
    try:
        _require_record_structure(value)
        expected = canonical_sha256(_record_projection(value, include_digest=False))
        if value.digest != expected:
            raise ValidationError("decision record digest is invalid")
    except (AttributeError, KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ValidationError("decision record integrity is invalid") from exc
    return value


def _bare_digest(value: object) -> None:
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValidationError("record digest must be bare lowercase SHA-256")


def _decimal(
    value: object, *, minimum: int | None = None, maximum: int | None = None
) -> None:
    if type(value) is not Decimal or not value.is_finite():
        raise ValidationError("record scalar must be an exact finite Decimal")
    if (minimum is not None and value < minimum) or (
        maximum is not None and value > maximum
    ):
        raise ValidationError("record scalar is outside its allowed range")


def _record_time(value: object, record: DecisionRecord) -> None:
    observed = utc_time(value, name="record observation time")
    if (
        observed.replace(microsecond=(observed.microsecond // 1000) * 1000)
        != record.evaluated_at
    ):
        raise ValidationError("record observation time belongs to another evaluation")


def _require_record_structure(value: DecisionRecord) -> None:
    if (
        type(value.record_profile) is not str
        or value.record_profile != "ktp-python-decision-record-v1"
    ):
        raise ValidationError("record profile is invalid")
    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.version) is not int
        or value.profile_ref.version < 1
    ):
        raise ValidationError("record profile reference is invalid")
    for name, identifier in (
        ("record ID", value.record_id),
        ("record profile ID", value.profile_ref.profile_id),
        ("record action ID", value.action_id),
    ):
        validate_identifier(identifier, name=name)
    validate_absolute_uri(value.subject, name="record subject")
    utc_time(value.evaluated_at, name="record evaluated-at")
    if value.evaluated_at.microsecond % 1000:
        raise ValidationError("record evaluated-at must be millisecond-floored")
    for digest in (
        value.profile_digest,
        value.action_digest,
        value.evaluation_digest,
        value.soul_digest,
        value.envelope_digest,
        value.digest,
    ):
        _bare_digest(digest)
    for digest in (
        value.standing_digest,
        value.evidence_digest,
        value.risk_digest,
        value.trust_digest,
        value.velocity_digest,
        value.core_capacity_digest,
    ):
        if digest is not None:
            _bare_digest(digest)
    _decimal(value.autonomy_demand, minimum=0, maximum=100)
    if (
        type(value.soul_state) is not SoulAssessmentState
        or type(value.supervision) is not Supervision
        or type(value.capacity_known) is not bool
    ):
        raise ValidationError("record state is invalid")
    for sequence in (
        value.soul_outcomes,
        value.soul_constraints,
        value.undetermined_frameworks,
        value.rationale,
        value.undefined_inputs,
        value.trace,
    ):
        if type(sequence) is not tuple:
            raise ValidationError("record collections must be exact tuples")
    for outcome in value.soul_outcomes:
        _require_outcome_structure(outcome)
        if outcome.observed_at is not None:
            _record_time(outcome.observed_at, value)
    for constraint in value.soul_constraints:
        _require_constraint_structure(constraint)
    for framework in value.undetermined_frameworks:
        validate_identifier(framework, name="record undetermined framework ID")
    if value.soul_constraints != tuple(
        outcome.constraint
        for outcome in value.soul_outcomes
        if outcome.constraint is not None
    ):
        raise ValidationError("record Soul constraints are incoherent")
    if value.undetermined_frameworks != tuple(
        outcome.framework_id
        for outcome in value.soul_outcomes
        if outcome.state is SoulAssessmentState.UNDETERMINED
    ):
        raise ValidationError("record undetermined frameworks are incoherent")
    expected_soul_state = (
        SoulAssessmentState.VETO
        if value.soul_constraints
        else SoulAssessmentState.UNDETERMINED
        if value.undetermined_frameworks
        else SoulAssessmentState.CLEAR
    )
    if value.soul_state is not expected_soul_state:
        raise ValidationError("record Soul state is incoherent")
    if type(value.tightened_constraints) is not TightenedConstraints:
        raise ValidationError("record tightened constraints are invalid")
    _require_constraints_structure(value.tightened_constraints)
    if (
        value.tightened_constraints.profile_ref != value.profile_ref
        or value.tightened_constraints.profile_digest != value.profile_digest
    ):
        raise ValidationError("record tightened constraints belong to another profile")
    if value.policy_code is not None:
        if type(value.policy_code) is not str or not value.policy_code:
            raise ValidationError("record policy code is invalid")
    if any(type(item) is not str for item in value.rationale):
        raise ValidationError("record rationale is invalid")
    for item in value.undefined_inputs:
        _require_undefined_structure(item)
    if any(type(stage) is not EvaluationStage for stage in value.trace):
        raise ValidationError("record trace is invalid")

    complete_members = (
        value.standing_digest,
        value.evidence_digest,
        value.risk_digest,
        value.trust_digest,
        value.core_capacity_digest,
        value.capacity_relation,
        value.risk_context,
        value.risk_factors,
        value.domain_risks,
        value.base_trust,
        value.risk,
        value.effective_trust,
        value.tier,
        value.environmental_capacity,
        value.margin,
        value.normative_gate_outcomes,
    )
    if (value.core_capacity_digest is None) != (value.capacity_relation is None):
        raise ValidationError("record Core capacity binding is incoherent")
    if value.soul_state is not SoulAssessmentState.CLEAR:
        if (
            any(
                item is not None
                for item in (*complete_members, value.velocity_digest, value.velocity)
            )
            or value.capacity_known
        ):
            raise ValidationError("unevaluated record authority must remain absent")
        if value.supervision is not Supervision.SILENT_VETO or value.trace != (
            EvaluationStage.CAPABILITY,
            EvaluationStage.SOUL,
            EvaluationStage.ENVELOPE,
        ):
            raise ValidationError("short-path record envelope is incoherent")
        return
    if any(item is None for item in complete_members):
        raise ValidationError("complete record authority must be present")
    if value.trace != tuple(EvaluationStage):
        raise ValidationError("complete record trace is incoherent")
    if type(value.tier) is not TrustTier:
        raise ValidationError("record trust tier is invalid")
    if type(value.capacity_relation) is not CapacityRelation:
        raise ValidationError("record Core capacity relation is invalid")
    for scalar in (
        value.base_trust,
        value.effective_trust,
        value.environmental_capacity,
    ):
        _decimal(scalar, minimum=0, maximum=100)
    _decimal(value.risk, minimum=0, maximum=1)
    require_derived_margin(value.margin)
    if value.environmental_capacity != value.effective_trust:
        raise ValidationError("record capacity does not match effective trust")
    if value.capacity_relation is not _capacity_relation(
        value.autonomy_demand, value.effective_trust
    ):
        raise ValidationError("record Core capacity relation is incoherent")
    if (
        value.capacity_relation is CapacityRelation.ABOVE_CAPACITY
        and value.supervision is not Supervision.SILENT_VETO
    ):
        raise ValidationError("above-capacity record must retain silent veto")
    if (value.velocity_digest is None) != (value.velocity is None):
        raise ValidationError("record velocity binding is incoherent")
    if value.velocity is not None:
        _decimal(value.velocity)
    _require_risk_context_structure(value.risk_context)
    if type(value.risk_factors) is not tuple or len(value.risk_factors) != len(
        FactorName
    ):
        raise ValidationError("record risk factors are invalid")
    for factor, name in zip(value.risk_factors, FactorName, strict=True):
        _require_risk_factor_structure(factor, name=name, record=value)
    if type(value.domain_risks) is not tuple or len(value.domain_risks) != len(
        RiskDomain
    ):
        raise ValidationError("record domain risks are invalid")
    for domain, name in zip(value.domain_risks, RiskDomain, strict=True):
        if (
            type(domain) is not DomainRiskResult
            or type(domain.domain) is not RiskDomain
            or domain.domain is not name
        ):
            raise ValidationError("record domain risk structure is invalid")
        _decimal(domain.weight, minimum=0, maximum=1)
        _decimal(domain.risk, minimum=0, maximum=1)
    if type(value.normative_gate_outcomes) is not tuple:
        raise ValidationError("record normative gate outcomes are invalid")
    for outcome in value.normative_gate_outcomes:
        _require_gate_structure(outcome, record=value)

    # Recompute only relationships whose complete terms the record retains.
    # Source aggregation, profile authority, and evidence provenance are not
    # reconstructed by this standalone integrity boundary.
    with localcontext(KTP_CONTEXT):
        for factor in value.risk_factors:
            if factor.contribution != factor.weight * factor.context_stress:
                raise ValidationError("record factor contribution is incoherent")
            if type(factor) is SignalFactorResult:
                context_stress = sum(
                    (
                        domain.weight * domain_factor.stress
                        for domain, domain_factor in zip(
                            value.domain_risks, factor.domains, strict=True
                        )
                    ),
                    Decimal(0),
                )
                if factor.context_stress != context_stress:
                    raise ValidationError("record signal context is incoherent")
        if value.risk != sum(
            (factor.contribution for factor in value.risk_factors), Decimal(0)
        ):
            raise ValidationError("record authoritative risk is incoherent")
        moment = value.risk_factors[-1]
        for index, domain in enumerate(value.domain_risks):
            contributions = [
                factor.weight * factor.domains[index].stress
                for factor in value.risk_factors
                if type(factor) is SignalFactorResult
            ]
            contributions.append(moment.weight * moment.context_stress)
            if domain.risk != sum(contributions, Decimal(0)):
                raise ValidationError("record domain risk is incoherent")
    if value.effective_trust != _effective_trust(value.base_trust, value.risk):
        raise ValidationError("record effective trust is incoherent")
    if value.tier is not _trust_tier(value.effective_trust):
        raise ValidationError("record trust tier is incoherent")
    if value.margin != _margin(value.autonomy_demand, value.environmental_capacity):
        raise ValidationError("record environmental margin is incoherent")


def _require_risk_context_structure(value: object) -> None:
    if type(value) is not RiskContext:
        raise ValidationError("record risk context is invalid")
    for name in FactorName:
        _decimal(getattr(value, name.value), minimum=0, maximum=1)


def _require_risk_factor_structure(
    value: object, *, name: FactorName, record: DecisionRecord
) -> None:
    expected_type = (
        MomentCriticalityResult
        if name is FactorName.MOMENT_CRITICALITY
        else SignalFactorResult
    )
    if (
        type(value) is not expected_type
        or type(value.name) is not FactorName
        or value.name is not name
    ):
        raise ValidationError("record risk factor type or name is invalid")
    for scalar in (value.weight, value.context_stress, value.contribution):
        _decimal(scalar, minimum=0, maximum=1)
    if value.weight == 0 or value.context_stress != getattr(
        record.risk_context, name.value
    ):
        raise ValidationError("record risk factor is incoherent")
    if type(value) is MomentCriticalityResult:
        supplied = value.supplied_value
        if type(supplied) is not MomentCriticality:
            raise ValidationError("record supplied moment criticality is invalid")
        _decimal(supplied.value, minimum=0, maximum=1)
        validate_identifier(supplied.supplier, name="record moment supplier")
        validate_identifier(supplied.unit, name="record moment unit")
        validate_identifier(supplied.provenance_id, name="record moment provenance ID")
        observed = utc_time(supplied.observed_at, name="record moment observed-at")
        if (
            observed.replace(microsecond=(observed.microsecond // 1000) * 1000)
            > record.evaluated_at
        ):
            raise ValidationError("record moment must not follow the evaluation")
        if supplied.value != value.context_stress:
            raise ValidationError("record moment context stress is incoherent")
        return
    if type(value.domains) is not tuple or len(value.domains) != len(RiskDomain):
        raise ValidationError("record factor domains are invalid")
    for domain, expected_domain in zip(value.domains, RiskDomain, strict=True):
        if (
            type(domain) is not DomainFactorResult
            or type(domain.domain) is not RiskDomain
            or domain.domain is not expected_domain
            or type(domain.defaulted) is not bool
            or type(domain.inputs) is not tuple
            or not domain.inputs
        ):
            raise ValidationError("record factor domain structure is invalid")
        _decimal(domain.stress, minimum=0, maximum=1)
        for item in domain.inputs:
            _require_risk_input_structure(item, factor=name, domain=expected_domain)


def _require_risk_input_structure(
    value: object, *, factor: FactorName, domain: RiskDomain
) -> None:
    if (
        type(value) is not RiskInput
        or type(value.factor) is not FactorName
        or value.factor is not factor
        or type(value.domain) is not RiskDomain
        or value.domain is not domain
    ):
        raise ValidationError("record risk input identity is invalid")
    validate_identifier(value.signal_id, name="record risk signal ID")
    if value.stress is not None:
        _decimal(value.stress, minimum=0, maximum=1)
    if (
        value.undefined_reason is not None
        and type(value.undefined_reason) is not UndefinedReason
    ):
        raise ValidationError("record risk undefined reason is invalid")
    if (value.stress is None) != (value.undefined_reason is not None):
        raise ValidationError("record risk input absence is incoherent")
    if (
        type(value.observation_digests) is not tuple
        or type(value.feed_outcome_digests) is not tuple
        or not value.feed_outcome_digests
    ):
        raise ValidationError("record risk input provenance is invalid")
    for digest in (*value.observation_digests, *value.feed_outcome_digests):
        _bare_digest(digest)


def _require_gate_structure(value: object, *, record: DecisionRecord) -> None:
    if (
        type(value) is not NormativeGateOutcome
        or type(value.required) is not bool
        or type(value.state) is not NormativeGateState
    ):
        raise ValidationError("record normative gate structure is invalid")
    validate_identifier(value.gate_id, name="record normative gate ID")
    validate_absolute_uri(value.schema_uri, name="record normative gate schema URI")
    if value.state is NormativeGateState.MISSING:
        if value.token is not None:
            raise ValidationError("missing record gate must not carry a token")
        return
    token = value.token
    if (
        type(token) is not NormativeGateToken
        or type(token.decision) is not NormativeGateDecision
    ):
        raise ValidationError("record normative gate token is invalid")
    validate_identifier(token.gate_id, name="record normative token gate ID")
    validate_absolute_uri(token.schema_uri, name="record normative token schema URI")
    validate_absolute_uri(token.authority, name="record normative token authority URI")
    validate_identifier(
        token.provenance_id, name="record normative token provenance ID"
    )
    _record_time(token.observed_at, record)
    if (
        token.gate_id != value.gate_id
        or token.schema_uri != value.schema_uri
        or value.state.value != token.decision.value
    ):
        raise ValidationError("record normative gate token binding is incoherent")


__all__ = ["build_decision_record", "require_validated_decision_record"]
