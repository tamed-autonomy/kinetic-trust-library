"""Calculate canonical KTP Risk Context and Authoritative Risk."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import (
    MomentCriticality,
    ValidatedActionDemand,
    _require_validated_action_with_context,
    _require_validated_moment_criticality,
)
from kinetic_trust_library.models._common import utc_time, validate_identifier
from kinetic_trust_library.models.evidence import (
    EvidenceEntry,
    EvidenceSnapshot,
    UndefinedReason,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    FactorAggregationDeclaration,
    FactorName,
    MomentCriticalityFactorProfile,
    ProfileRef,
    RiskDomain,
    _DOMAIN_ORDER,
    _FACTOR_ORDER,
    _SIGNAL_FACTOR_ORDER,
    _ValidatedProfileContext,
    _bind_profile_to_context,
    _profile_from_context,
    _risk_factor_member,
    _signal_risk_factor_member,
    _validated_profile_context,
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
from kinetic_trust_library.models.soul import SoulAssessment, SoulAssessmentState

from .evidence import _require_validated_evidence_snapshot_with_context
from .soul import _require_validated_soul_assessment_with_context


_CONTEXT_MEMBER = {
    FactorName.EVIDENCE_DENSITY: "evidence_density",
    FactorName.TRUST_TREND: "trust_trend",
    FactorName.ADVERSARIAL_PRESSURE: "adversarial_pressure",
    FactorName.UPDATE_RESISTANCE: "update_resistance",
    FactorName.ATTESTATION_COVERAGE: "attestation_coverage",
    FactorName.MOMENT_CRITICALITY: "moment_criticality",
}


def calculate_risk(
    profile: DeploymentProfile,
    evidence: EvidenceSnapshot,
    soul: SoulAssessment,
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> RiskResult:
    """Derive authoritative R from validated facts, never caller arithmetic."""

    return _calculate_risk_with_context(
        _validated_profile_context(profile), evidence, soul, action, cutoff
    )


def _calculate_risk_with_context(
    context: object,
    evidence: EvidenceSnapshot,
    soul: SoulAssessment,
    action: ValidatedActionDemand,
    cutoff: datetime,
) -> RiskResult:
    effective_profile = _profile_from_context(context)
    effective_cutoff = utc_time(cutoff, name="risk cutoff")
    effective_action = _require_validated_action_with_context(action, context)
    if effective_action.validation_cutoff != effective_cutoff:
        raise ValidationError("risk cutoff must exactly match the action cutoff")
    effective_soul = _require_validated_soul_assessment_with_context(
        soul,
        context,
        action=effective_action,
    )
    if effective_soul.cutoff != effective_cutoff:
        raise ValidationError("risk cutoff must exactly match the Soul cutoff")
    if effective_soul.state is not SoulAssessmentState.CLEAR:
        raise ValidationError("Soul assessment must be clear before risk calculation")

    effective_evidence = _require_validated_evidence_snapshot_with_context(
        evidence, context
    )
    if effective_evidence.cutoff != effective_cutoff:
        raise ValidationError("risk cutoff must exactly match the evidence cutoff")

    domain_factors = _calculate_domain_factor_stresses(
        profile=effective_profile,
        evidence=effective_evidence,
    )
    risk_context = _calculate_risk_context(
        profile=effective_profile,
        domain_factors=domain_factors,
        moment=effective_action.moment_criticality,
    )
    factor_results, risk = _calculate_authoritative_risk(
        profile=effective_profile,
        context=risk_context,
        domain_factors=domain_factors,
        moment=effective_action.moment_criticality,
    )
    domain_results = _calculate_domain_risks(
        profile=effective_profile,
        domain_factors=domain_factors,
        moment=effective_action.moment_criticality.value,
    )

    result = object.__new__(RiskResult)
    for name, value in (
        ("profile_ref", effective_profile.ref),
        ("profile_digest", effective_profile.digest),
        ("evidence_operation_id", effective_evidence.operation_id),
        ("evidence_digest", effective_evidence.digest),
        ("soul_digest", effective_soul.digest),
        ("action_id", effective_action.action_id),
        ("action_digest", effective_action.digest),
        ("cutoff", effective_cutoff),
        ("context", risk_context),
        ("factors", factor_results),
        ("domains", domain_results),
        ("risk", risk),
        ("_profile", effective_profile),
        ("_evidence", effective_evidence),
        ("_soul", effective_soul),
        ("_action", effective_action),
    ):
        object.__setattr__(result, name, value)
    object.__setattr__(
        result,
        "digest",
        canonical_sha256(_risk_projection(result, include_digest=False)),
    )
    return result


def _calculate_domain_factor_stresses(
    *,
    profile: DeploymentProfile,
    evidence: EvidenceSnapshot,
) -> dict[FactorName, tuple[DomainFactorResult, ...]]:
    with localcontext(KTP_CONTEXT):
        entries = {
            (entry.domain, entry.signal_id): entry for entry in evidence.entries
        }
        results: dict[FactorName, tuple[DomainFactorResult, ...]] = {}
        for factor_name in _SIGNAL_FACTOR_ORDER:
            aggregation = _signal_risk_factor_member(
                profile.risk_factors, factor_name
            ).aggregation
            results[factor_name] = tuple(
                _signal_factor(
                    factor_name,
                    aggregation,
                    domain=domain,
                    entries=entries,
                )
                for domain in _DOMAIN_ORDER
            )
        return results


def _calculate_risk_context(
    *,
    profile: DeploymentProfile,
    domain_factors: dict[FactorName, tuple[DomainFactorResult, ...]],
    moment: MomentCriticality,
) -> RiskContext:
    with localcontext(KTP_CONTEXT):
        stresses = {
            factor_name: sum(
                (
                    profile.risk_domain_weights[domain_result.domain]
                    * domain_result.stress
                    for domain_result in domain_factors[factor_name]
                ),
                Decimal(0),
            )
            for factor_name in _SIGNAL_FACTOR_ORDER
        }
        stresses[FactorName.MOMENT_CRITICALITY] = moment.value
        return _build_risk_context(stresses)


def _calculate_authoritative_risk(
    *,
    profile: DeploymentProfile,
    context: RiskContext,
    domain_factors: dict[FactorName, tuple[DomainFactorResult, ...]],
    moment: MomentCriticality,
) -> tuple[
    tuple[SignalFactorResult | MomentCriticalityResult, ...],
    Decimal,
]:
    with localcontext(KTP_CONTEXT):
        results: list[SignalFactorResult | MomentCriticalityResult] = []
        for factor_name in _SIGNAL_FACTOR_ORDER:
            factor_profile = _signal_risk_factor_member(
                profile.risk_factors, factor_name
            )
            context_stress = _risk_context_value(context, factor_name)
            results.append(
                _build_signal_factor_result(
                    factor_name,
                    weight=factor_profile.weight,
                    context_stress=context_stress,
                    contribution=factor_profile.weight * context_stress,
                    domains=domain_factors[factor_name],
                )
            )
        moment_profile = _risk_factor_member(
            profile.risk_factors, FactorName.MOMENT_CRITICALITY
        )
        if type(moment_profile) is not MomentCriticalityFactorProfile:
            raise ValidationError("Moment Criticality profile is invalid")
        results.append(
            _build_moment_result(
                weight=moment_profile.weight,
                context_stress=context.moment_criticality,
                contribution=moment_profile.weight * context.moment_criticality,
                supplied_value=moment,
            )
        )
        immutable_results = tuple(results)
        risk = sum(
            (result.contribution for result in immutable_results),
            Decimal(0),
        )
        return immutable_results, risk


def _calculate_domain_risks(
    *,
    profile: DeploymentProfile,
    domain_factors: dict[FactorName, tuple[DomainFactorResult, ...]],
    moment: Decimal,
) -> tuple[DomainRiskResult, ...]:
    with localcontext(KTP_CONTEXT):
        moment_profile = _risk_factor_member(
            profile.risk_factors, FactorName.MOMENT_CRITICALITY
        )
        if type(moment_profile) is not MomentCriticalityFactorProfile:
            raise ValidationError("Moment Criticality profile is invalid")
        results: list[DomainRiskResult] = []
        for domain_index, domain in enumerate(_DOMAIN_ORDER):
            contributions = [
                _signal_risk_factor_member(
                    profile.risk_factors, factor_name
                ).weight
                * domain_factors[factor_name][domain_index].stress
                for factor_name in _SIGNAL_FACTOR_ORDER
            ]
            contributions.append(moment_profile.weight * moment)
            results.append(
                _build_domain_risk_result(
                    domain,
                    weight=profile.risk_domain_weights[domain],
                    risk=sum(contributions, Decimal(0)),
                )
            )
        return tuple(results)


def _signal_factor(
    name: FactorName,
    aggregation: FactorAggregationDeclaration,
    *,
    domain: RiskDomain,
    entries: dict[tuple[RiskDomain, str], EvidenceEntry],
) -> DomainFactorResult:
    inputs: list[RiskInput] = []
    for signal_id in aggregation.signals:
        try:
            entry = entries[(domain, signal_id)]
        except KeyError as exc:
            raise ValidationError(
                "evidence inventory does not match the profile"
            ) from exc
        inputs.append(_risk_input(name, domain, entry))

    active = tuple(item for item in inputs if item.stress is not None)
    with localcontext(KTP_CONTEXT):
        if not active:
            stress = Decimal(1)
            defaulted = True
        elif aggregation.method == "maximum":
            stress = max(_present_stress(item) for item in active)
            defaulted = False
        elif aggregation.method == "minimum":
            stress = min(_present_stress(item) for item in active)
            defaulted = False
        elif aggregation.method == "weighted_average":
            if aggregation.signal_weights is None:
                raise ValidationError("weighted aggregation has no signal weights")
            denominator = sum(
                (aggregation.signal_weights[item.signal_id] for item in active),
                Decimal(0),
            )
            if denominator == 0:
                stress = Decimal(1)
                defaulted = True
            else:
                numerator = sum(
                    (
                        _present_stress(item)
                        * aggregation.signal_weights[item.signal_id]
                        for item in active
                    ),
                    Decimal(0),
                )
                stress = numerator / denominator
                defaulted = False
        else:
            raise ValidationError("unsupported factor aggregation method")
    return _build_domain_factor_result(
        domain,
        stress,
        defaulted=defaulted,
        inputs=tuple(inputs),
    )


def _risk_input(
    factor: FactorName,
    domain: RiskDomain,
    entry: EvidenceEntry,
) -> RiskInput:
    result = object.__new__(RiskInput)
    for name, value in (
        ("factor", factor),
        ("domain", domain),
        ("signal_id", entry.signal_id),
        ("stress", entry.normalized),
        (
            "observation_digests",
            tuple(item.provenance_digest for item in entry.selected_observations),
        ),
        (
            "feed_outcome_digests",
            tuple(item.provenance_digest for item in entry.feed_outcomes),
        ),
        ("undefined_reason", entry.undefined_reason),
    ):
        object.__setattr__(result, name, value)
    return result


def _build_risk_context(stresses: dict[FactorName, Decimal]) -> RiskContext:
    result = object.__new__(RiskContext)
    for factor_name in _FACTOR_ORDER:
        object.__setattr__(
            result,
            _CONTEXT_MEMBER[factor_name],
            stresses[factor_name],
        )
    return result


def _build_domain_factor_result(
    domain: RiskDomain,
    stress: Decimal,
    *,
    defaulted: bool,
    inputs: tuple[RiskInput, ...],
) -> DomainFactorResult:
    result = object.__new__(DomainFactorResult)
    for name, value in (
        ("domain", domain),
        ("stress", stress),
        ("defaulted", defaulted),
        ("inputs", inputs),
    ):
        object.__setattr__(result, name, value)
    return result


def _build_signal_factor_result(
    name: FactorName,
    *,
    weight: Decimal,
    context_stress: Decimal,
    contribution: Decimal,
    domains: tuple[DomainFactorResult, ...],
) -> SignalFactorResult:
    result = object.__new__(SignalFactorResult)
    for member, value in (
        ("name", name),
        ("weight", weight),
        ("context_stress", context_stress),
        ("contribution", contribution),
        ("domains", domains),
    ):
        object.__setattr__(result, member, value)
    return result


def _build_moment_result(
    *,
    weight: Decimal,
    context_stress: Decimal,
    contribution: Decimal,
    supplied_value: MomentCriticality,
) -> MomentCriticalityResult:
    result = object.__new__(MomentCriticalityResult)
    for name, value in (
        ("name", FactorName.MOMENT_CRITICALITY),
        ("weight", weight),
        ("context_stress", context_stress),
        ("contribution", contribution),
        ("supplied_value", supplied_value),
    ):
        object.__setattr__(result, name, value)
    return result


def _build_domain_risk_result(
    domain: RiskDomain,
    *,
    weight: Decimal,
    risk: Decimal,
) -> DomainRiskResult:
    result = object.__new__(DomainRiskResult)
    object.__setattr__(result, "domain", domain)
    object.__setattr__(result, "weight", weight)
    object.__setattr__(result, "risk", risk)
    return result


def _risk_context_value(context: RiskContext, name: FactorName) -> Decimal:
    return getattr(context, _CONTEXT_MEMBER[name])


def _present_stress(value: RiskInput) -> Decimal:
    if value.stress is None:
        raise ValidationError("undefined risk input entered active aggregation")
    return value.stress


def _require_validated_risk_result(
    value: object,
    *,
    profile: DeploymentProfile | None = None,
    soul: SoulAssessment | None = None,
    action: ValidatedActionDemand | None = None,
) -> RiskResult:
    """Structurally rederive risk from its represented validated inputs."""

    if type(value) is not RiskResult:
        raise ValidationError("value is not a validated risk result")
    try:
        context = _validated_profile_context(
            value._profile if profile is None else profile
        )
    except Exception as exc:
        raise ValidationError("risk result integrity is invalid") from exc
    return _require_validated_risk_result_with_context(
        value,
        context,
        profile_supplied=profile is not None,
        soul=soul,
        action=action,
    )


def _require_validated_risk_result_with_context(
    value: object,
    context: object,
    *,
    profile_supplied: bool = True,
    soul: SoulAssessment | None = None,
    action: ValidatedActionDemand | None = None,
) -> RiskResult:
    """Private risk rederivation against one already validated profile."""

    if type(value) is not RiskResult:
        raise ValidationError("value is not a validated risk result")
    try:
        effective_profile = _bind_profile_to_context(context, value._profile)
        _require_risk_structure(value, context=context)
        rederived = _calculate_risk_with_context(
            context,
            value._evidence,
            value._soul,
            value._action,
            value.cutoff,
        )
        if canonical_json_bytes(_risk_projection(value)) != canonical_json_bytes(
            _risk_projection(rederived)
        ) or value != rederived:
            raise ValidationError("risk result does not match represented inputs")
    except Exception as exc:
        raise ValidationError("risk result integrity is invalid") from exc

    if profile_supplied and (
        value.profile_ref != effective_profile.ref
        or value.profile_digest != effective_profile.digest
    ):
        raise ValidationError("risk result belongs to another profile")
    if action is not None:
        effective_action = _require_validated_action_with_context(action, context)
        if (
            value.action_id != effective_action.action_id
            or value.action_digest != effective_action.digest
            or value.cutoff != effective_action.validation_cutoff
        ):
            raise ValidationError("risk result belongs to another action")
    if soul is not None:
        effective_soul = _require_validated_soul_assessment_with_context(
            soul,
            context,
            action=action,
        )
        if (
            value.soul_digest != effective_soul.digest
            or value.cutoff != effective_soul.cutoff
        ):
            raise ValidationError("risk result belongs to another Soul assessment")
    return value


def _risk_projection(
    value: RiskResult,
    *,
    include_digest: bool = True,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "profile_ref": value.profile_ref,
        "profile_digest": value.profile_digest,
        "evidence_operation_id": value.evidence_operation_id,
        "evidence_digest": value.evidence_digest,
        "soul_digest": value.soul_digest,
        "action_id": value.action_id,
        "action_digest": value.action_digest,
        "cutoff": value.cutoff,
        "context": {
            _CONTEXT_MEMBER[name]: _risk_context_value(value.context, name)
            for name in _FACTOR_ORDER
        },
        "factors": tuple(_factor_projection(item) for item in value.factors),
        "domains": tuple(
            {
                "domain": item.domain,
                "weight": item.weight,
                "risk": item.risk,
            }
            for item in value.domains
        ),
        "risk": value.risk,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _factor_projection(
    value: SignalFactorResult | MomentCriticalityResult,
) -> dict[str, object]:
    if type(value) is MomentCriticalityResult:
        return {
            "name": value.name,
            "weight": value.weight,
            "context_stress": value.context_stress,
            "contribution": value.contribution,
            "supplied_value": value.supplied_value,
        }
    return {
        "name": value.name,
        "weight": value.weight,
        "context_stress": value.context_stress,
        "contribution": value.contribution,
        "domains": tuple(
            {
                "domain": domain.domain,
                "stress": domain.stress,
                "defaulted": domain.defaulted,
                "inputs": tuple(
                    {
                        "factor": item.factor,
                        "domain": item.domain,
                        "signal_id": item.signal_id,
                        "stress": item.stress,
                        "observation_digests": item.observation_digests,
                        "feed_outcome_digests": item.feed_outcome_digests,
                        "undefined_reason": item.undefined_reason,
                    }
                    for item in domain.inputs
                ),
            }
            for domain in value.domains
        ),
    }


def _require_risk_structure(
    value: RiskResult,
    *,
    context: _ValidatedProfileContext,
) -> None:
    if (
        type(value.profile_ref) is not ProfileRef
        or type(value.profile_ref.profile_id) is not str
        or type(value.profile_ref.version) is not int
        or type(value.profile_digest) is not str
        or type(value.evidence_operation_id) is not str
        or type(value.evidence_digest) is not str
        or type(value.soul_digest) is not str
        or type(value.action_id) is not str
        or type(value.action_digest) is not str
        or type(value.cutoff) is not datetime
        or value.cutoff.tzinfo is not timezone.utc
        or type(value.context) is not RiskContext
        or type(value.factors) is not tuple
        or len(value.factors) != len(_FACTOR_ORDER)
        or any(
            type(value.factors[index]) is not SignalFactorResult
            for index in range(len(_SIGNAL_FACTOR_ORDER))
        )
        or type(value.factors[-1]) is not MomentCriticalityResult
        or type(value.domains) is not tuple
        or len(value.domains) != len(_DOMAIN_ORDER)
        or any(type(item) is not DomainRiskResult for item in value.domains)
        or type(value.risk) is not Decimal
        or type(value.digest) is not str
        or type(value._profile) is not DeploymentProfile
        or type(value._evidence) is not EvidenceSnapshot
        or type(value._soul) is not SoulAssessment
        or type(value._action) is not ValidatedActionDemand
    ):
        raise ValidationError("risk result structure is invalid")

    validate_identifier(value.profile_ref.profile_id, name="risk profile ID")
    validate_identifier(value.evidence_operation_id, name="risk evidence operation ID")
    validate_identifier(value.action_id, name="risk action ID")
    for name, digest in (
        ("risk profile digest", value.profile_digest),
        ("risk evidence digest", value.evidence_digest),
        ("risk Soul digest", value.soul_digest),
        ("risk action digest", value.action_digest),
        ("risk result digest", value.digest),
    ):
        _digest(digest, name=name)
    utc_time(value.cutoff, name="risk cutoff")
    _bounded_decimal(value.risk, name="risk result")

    effective_profile = _profile_from_context(context)
    effective_action = _require_validated_action_with_context(value._action, context)
    if effective_action.validation_cutoff != value.cutoff:
        raise ValidationError("risk result action cutoff is invalid")

    for factor_name in _FACTOR_ORDER:
        _bounded_decimal(
            _risk_context_value(value.context, factor_name),
            name=f"{factor_name.value} Risk Context",
        )

    for index, factor_name in enumerate(_SIGNAL_FACTOR_ORDER):
        factor = value.factors[index]
        if type(factor) is not SignalFactorResult:
            raise ValidationError("signal factor result structure is invalid")
        factor_profile = _signal_risk_factor_member(
            effective_profile.risk_factors, factor_name
        )
        if (
            type(factor.name) is not FactorName
            or factor.name is not factor_name
            or type(factor.weight) is not Decimal
            or factor.weight != factor_profile.weight
            or type(factor.context_stress) is not Decimal
            or factor.context_stress != _risk_context_value(value.context, factor_name)
            or type(factor.contribution) is not Decimal
            or type(factor.domains) is not tuple
            or len(factor.domains) != len(_DOMAIN_ORDER)
            or any(type(item) is not DomainFactorResult for item in factor.domains)
        ):
            raise ValidationError("signal factor result structure is invalid")
        _bounded_decimal(factor.weight, name="factor weight", positive=True)
        _bounded_decimal(factor.context_stress, name="factor context stress")
        _bounded_decimal(factor.contribution, name="factor contribution")
        if any(type(item.domain) is not RiskDomain for item in factor.domains):
            raise ValidationError("factor domain order is invalid")
        if any(
            item.domain is not expected
            for item, expected in zip(factor.domains, _DOMAIN_ORDER, strict=True)
        ):
            raise ValidationError("factor domain order is invalid")
        for domain in factor.domains:
            _require_domain_factor_structure(
                domain,
                factor=factor_name,
                selected_signals=factor_profile.aggregation.signals,
            )

    moment = value.factors[-1]
    if type(moment) is not MomentCriticalityResult:
        raise ValidationError("Moment Criticality result structure is invalid")
    moment_profile = _risk_factor_member(
        effective_profile.risk_factors, FactorName.MOMENT_CRITICALITY
    )
    if type(moment_profile) is not MomentCriticalityFactorProfile or (
        type(moment.name) is not FactorName
        or moment.name is not FactorName.MOMENT_CRITICALITY
        or type(moment.weight) is not Decimal
        or moment.weight != moment_profile.weight
        or type(moment.context_stress) is not Decimal
        or moment.context_stress != value.context.moment_criticality
        or type(moment.contribution) is not Decimal
        or type(moment.supplied_value) is not MomentCriticality
    ):
        raise ValidationError("Moment Criticality result structure is invalid")
    _bounded_decimal(moment.weight, name="Moment Criticality weight", positive=True)
    _bounded_decimal(moment.context_stress, name="Moment Criticality stress")
    _bounded_decimal(moment.contribution, name="Moment Criticality contribution")
    supplied_moment = _require_validated_moment_criticality(
        moment.supplied_value,
        factor=effective_action.moment_criticality_factor,
        cutoff=value.cutoff,
    )
    if (
        moment.context_stress != supplied_moment.value
        or supplied_moment != effective_action.moment_criticality
    ):
        raise ValidationError("Moment Criticality result is incoherent")

    if any(type(item.domain) is not RiskDomain for item in value.domains):
        raise ValidationError("risk result domain order is invalid")
    if any(
        item.domain is not expected
        for item, expected in zip(value.domains, _DOMAIN_ORDER, strict=True)
    ):
        raise ValidationError("risk result domain order is invalid")
    for domain in value.domains:
        if (
            type(domain.domain) is not RiskDomain
            or type(domain.weight) is not Decimal
            or domain.weight != effective_profile.risk_domain_weights[domain.domain]
            or type(domain.risk) is not Decimal
        ):
            raise ValidationError("domain risk structure is invalid")
        _bounded_decimal(domain.weight, name="domain weight", positive=True)
        _bounded_decimal(domain.risk, name="domain risk")


def _require_domain_factor_structure(
    value: DomainFactorResult,
    *,
    factor: FactorName,
    selected_signals: tuple[str, ...],
) -> None:
    if (
        type(value.domain) is not RiskDomain
        or type(value.stress) is not Decimal
        or type(value.defaulted) is not bool
        or type(value.inputs) is not tuple
        or not value.inputs
        or any(type(item) is not RiskInput for item in value.inputs)
    ):
        raise ValidationError("domain factor result structure is invalid")
    _bounded_decimal(value.stress, name="domain factor stress")
    for item in value.inputs:
        if (
            type(item.factor) is not FactorName
            or item.factor is not factor
            or type(item.domain) is not RiskDomain
            or item.domain is not value.domain
            or type(item.signal_id) is not str
            or item.signal_id not in selected_signals
            or (
                item.stress is not None
                and type(item.stress) is not Decimal
            )
            or type(item.observation_digests) is not tuple
            or any(type(digest) is not str for digest in item.observation_digests)
            or type(item.feed_outcome_digests) is not tuple
            or not item.feed_outcome_digests
            or any(type(digest) is not str for digest in item.feed_outcome_digests)
            or (
                item.undefined_reason is not None
                and type(item.undefined_reason) is not UndefinedReason
            )
            or ((item.stress is None) != (item.undefined_reason is not None))
        ):
            raise ValidationError("risk input structure is invalid")
        validate_identifier(item.signal_id, name="risk signal ID")
        if item.stress is not None:
            _bounded_decimal(item.stress, name="risk input stress")
        for digest in (*item.observation_digests, *item.feed_outcome_digests):
            _digest(digest, name="risk provenance digest")


def _bounded_decimal(
    value: Decimal,
    *,
    name: str,
    positive: bool = False,
) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ValidationError(f"{name} must be a finite Decimal")
    minimum = Decimal(0)
    if value < minimum or value > Decimal(1) or (positive and value == minimum):
        raise ValidationError(f"{name} is outside its allowed range")
    return value


def _digest(value: str, *, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


__all__ = ["calculate_risk"]
