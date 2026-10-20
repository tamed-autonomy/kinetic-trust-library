"""Immutable represented values for canonical KTP risk context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from kinetic_trust_library.errors import ValidationError

from .action import MomentCriticality
from .evidence import UndefinedReason
from .profile import FactorName, ProfileRef, RiskDomain

if TYPE_CHECKING:
    from .action import ValidatedActionDemand
    from .evidence import EvidenceSnapshot
    from .profile import DeploymentProfile
    from .soul import SoulAssessment


@dataclass(frozen=True, slots=True, init=False)
class RiskInput:
    """One self-identifying signal input and its complete provenance."""

    factor: FactorName
    domain: RiskDomain
    signal_id: str
    stress: Decimal | None
    observation_digests: tuple[str, ...]
    feed_outcome_digests: tuple[str, ...]
    undefined_reason: UndefinedReason | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("RiskInput values are created by calculate_risk()")


@dataclass(frozen=True, slots=True, init=False)
class RiskContext:
    evidence_density: Decimal
    trust_trend: Decimal
    adversarial_pressure: Decimal
    update_resistance: Decimal
    attestation_coverage: Decimal
    moment_criticality: Decimal

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("RiskContext values are created by calculate_risk()")


@dataclass(frozen=True, slots=True, init=False)
class DomainFactorResult:
    domain: RiskDomain
    stress: Decimal
    defaulted: bool
    inputs: tuple[RiskInput, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("DomainFactorResult values are created by calculate_risk()")


@dataclass(frozen=True, slots=True, init=False)
class SignalFactorResult:
    name: FactorName
    weight: Decimal
    context_stress: Decimal
    contribution: Decimal
    domains: tuple[DomainFactorResult, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("SignalFactorResult values are created by calculate_risk()")


@dataclass(frozen=True, slots=True, init=False)
class MomentCriticalityResult:
    name: FactorName
    weight: Decimal
    context_stress: Decimal
    contribution: Decimal
    supplied_value: MomentCriticality

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "MomentCriticalityResult values are created by calculate_risk()"
        )


@dataclass(frozen=True, slots=True, init=False)
class DomainRiskResult:
    domain: RiskDomain
    weight: Decimal
    risk: Decimal

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("DomainRiskResult values are created by calculate_risk()")


@dataclass(frozen=True, slots=True, init=False)
class RiskResult:
    profile_ref: ProfileRef
    profile_digest: str
    evidence_operation_id: str
    evidence_digest: str
    soul_digest: str
    action_id: str
    action_digest: str
    cutoff: datetime
    context: RiskContext
    factors: tuple[SignalFactorResult | MomentCriticalityResult, ...]
    domains: tuple[DomainRiskResult, ...]
    risk: Decimal
    digest: str
    _profile: DeploymentProfile = field(repr=False, compare=False)
    _evidence: EvidenceSnapshot = field(repr=False, compare=False)
    _soul: SoulAssessment = field(repr=False, compare=False)
    _action: ValidatedActionDemand = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("RiskResult values are created by calculate_risk()")

    def factor(
        self, name: FactorName | str
    ) -> SignalFactorResult | MomentCriticalityResult:
        from kinetic_trust_library.core.risk import _require_validated_risk_result

        _require_validated_risk_result(self)
        if type(name) not in (FactorName, str):
            raise ValidationError("risk factor name is invalid")
        try:
            factor_name = name if type(name) is FactorName else FactorName(name)
        except (TypeError, ValueError) as exc:
            raise ValidationError("risk factor name is invalid") from exc
        for result in self.factors:
            if result.name is factor_name:
                return result
        raise ValidationError(f"risk result has no factor: {factor_name.value}")

    def domain(self, name: RiskDomain | str) -> DomainRiskResult:
        from kinetic_trust_library.core.risk import _require_validated_risk_result

        _require_validated_risk_result(self)
        if type(name) not in (RiskDomain, str):
            raise ValidationError("risk domain name is invalid")
        try:
            domain_name = name if type(name) is RiskDomain else RiskDomain(name)
        except (TypeError, ValueError) as exc:
            raise ValidationError("risk domain name is invalid") from exc
        for result in self.domains:
            if result.domain is domain_name:
                return result
        raise ValidationError(f"risk result has no domain: {domain_name.value}")

    @property
    def undefined_inputs(self) -> tuple[RiskInput, ...]:
        from kinetic_trust_library.core.risk import _require_validated_risk_result

        _require_validated_risk_result(self)
        return tuple(
            item
            for factor in self.factors
            if type(factor) is SignalFactorResult
            for domain in factor.domains
            for item in domain.inputs
            if item.undefined_reason is not None
        )


__all__ = [
    "DomainFactorResult",
    "DomainRiskResult",
    "MomentCriticalityResult",
    "RiskContext",
    "RiskInput",
    "RiskResult",
    "SignalFactorResult",
]
