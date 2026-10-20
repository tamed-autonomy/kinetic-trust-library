"""Explicit deployment declarations and immutable validated profiles."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from fractions import Fraction
from types import MappingProxyType
from typing import Literal
from unicodedata import normalize

from kinetic_trust_library._catalog import (
    ALIASES,
    CATALOG,
    validate_signal_id,
    validate_signal_subset,
)
from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library._owned_mapping import (
    _OwnedMapping,
    _owned_mapping_from_dict,
    _require_owned_mapping_items,
)
from kinetic_trust_library.errors import ValidationError

from ._uri import validate_absolute_uri
from ._common import (
    validate_constraint_magnitude,
    validate_engineering_unit,
    validate_identifier,
)


class RiskDomain(StrEnum):
    NODE = "node"
    NEIGHBORHOOD = "neighborhood"
    GLOBAL = "global"


class FactorName(StrEnum):
    EVIDENCE_DENSITY = "evidence_density"
    TRUST_TREND = "trust_trend"
    ADVERSARIAL_PRESSURE = "adversarial_pressure"
    UPDATE_RESISTANCE = "update_resistance"
    ATTESTATION_COVERAGE = "attestation_coverage"
    MOMENT_CRITICALITY = "moment_criticality"


_SIGNAL_FACTOR_ORDER = (
    FactorName.EVIDENCE_DENSITY,
    FactorName.TRUST_TREND,
    FactorName.ADVERSARIAL_PRESSURE,
    FactorName.UPDATE_RESISTANCE,
    FactorName.ATTESTATION_COVERAGE,
)
_FACTOR_ORDER = _SIGNAL_FACTOR_ORDER + (FactorName.MOMENT_CRITICALITY,)
_DOMAIN_ORDER = (
    RiskDomain.NODE,
    RiskDomain.NEIGHBORHOOD,
    RiskDomain.GLOBAL,
)
_FACTOR_MEMBERS = MappingProxyType(
    {
        FactorName.EVIDENCE_DENSITY: "evidence_density",
        FactorName.TRUST_TREND: "trust_trend",
        FactorName.ADVERSARIAL_PRESSURE: "adversarial_pressure",
        FactorName.UPDATE_RESISTANCE: "update_resistance",
        FactorName.ATTESTATION_COVERAGE: "attestation_coverage",
        FactorName.MOMENT_CRITICALITY: "moment_criticality",
    }
)
_AGGREGATION_METHODS = frozenset(("weighted_average", "maximum", "minimum"))
# Implementation safety bounds, not KTP normative maxima. One leap-year refresh
# admits slow published sources; five times that preserves the RFC default.
_MAX_REFRESH_INTERVAL_MS = 366 * 24 * 60 * 60 * 1000
_MAX_STALE_THRESHOLD_MS = 5 * _MAX_REFRESH_INTERVAL_MS


@dataclass(frozen=True, slots=True)
class FactorAggregationDeclaration:
    signals: tuple[str, ...]
    method: Literal["weighted_average", "maximum", "minimum"]
    signal_weights: Mapping[str, DecimalLike] | None = None


@dataclass(frozen=True, slots=True)
class SignalRouteDeclaration:
    signal_id: str
    domain: RiskDomain
    unit: str


@dataclass(frozen=True, slots=True)
class FeedDeclaration:
    source_id: str
    routes: tuple[SignalRouteDeclaration, ...]
    refresh_interval_ms: int
    weight: DecimalLike = 1
    stale_threshold_ms: int | None = None
    stale_threshold_reason: str | None = None


@dataclass(frozen=True, slots=True)
class IdentityNormalization:
    """An explicit identity mapping for a signal already on [0, 1]."""

    invert: bool = False


@dataclass(frozen=True, slots=True)
class MinMaxNormalization:
    minimum: DecimalLike
    maximum: DecimalLike
    invert: bool = False
    clamp: bool = True


@dataclass(frozen=True, slots=True)
class LabelSetDeclaration:
    labels: tuple[str, ...]
    stress_by_label: Mapping[str, DecimalLike]
    source_id: str | None = None
    predicate: str | None = None


@dataclass(frozen=True, slots=True)
class SignalRiskFactorDeclaration:
    weight: DecimalLike
    aggregation: FactorAggregationDeclaration


@dataclass(frozen=True, slots=True)
class MomentCriticalityFactorDeclaration:
    weight: DecimalLike
    supplier: str
    unit: str


@dataclass(frozen=True, slots=True)
class RiskFactorsDeclaration:
    evidence_density: SignalRiskFactorDeclaration
    trust_trend: SignalRiskFactorDeclaration
    adversarial_pressure: SignalRiskFactorDeclaration
    update_resistance: SignalRiskFactorDeclaration
    attestation_coverage: SignalRiskFactorDeclaration
    moment_criticality: MomentCriticalityFactorDeclaration


@dataclass(frozen=True, slots=True)
class NormativeGatePolicy:
    gate_id: str
    schema_uri: str
    required: bool


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    action_class: str
    demand_min: Decimal
    demand_max: Decimal
    constraint_units: Mapping[str, str]
    normative_gates: tuple[NormativeGatePolicy, ...]


@dataclass(frozen=True, slots=True)
class EnvelopeThresholds:
    veto: Decimal
    allow: Decimal
    metacognitive_floor: Decimal
    assisted_floor: Decimal


@dataclass(frozen=True, slots=True)
class DeploymentProfileDeclaration:
    profile_id: str
    version: int
    action_demand_unit: str
    risk_factors: RiskFactorsDeclaration
    risk_domain_weights: Mapping[RiskDomain, DecimalLike]
    soul_frameworks: tuple[str, ...]
    peer_share: DecimalLike
    external_root_hop_bound: int
    misattestation_adjudicator: str
    standing_decay_rate: DecimalLike
    envelope_thresholds: EnvelopeThresholds | None
    actions: Mapping[str, ActionPolicy]
    feeds: Mapping[str, FeedDeclaration]
    alias_selections: Mapping[str, str]
    normalizations: Mapping[str, IdentityNormalization | MinMaxNormalization]
    label_sets: Mapping[str, LabelSetDeclaration]


@dataclass(frozen=True, slots=True)
class SignalRiskFactorProfile:
    name: FactorName
    weight: Decimal
    aggregation: FactorAggregationDeclaration


@dataclass(frozen=True, slots=True)
class MomentCriticalityFactorProfile:
    name: FactorName
    weight: Decimal
    supplier: str
    unit: str


@dataclass(frozen=True, slots=True)
class RiskFactorsProfile:
    evidence_density: SignalRiskFactorProfile
    trust_trend: SignalRiskFactorProfile
    adversarial_pressure: SignalRiskFactorProfile
    update_resistance: SignalRiskFactorProfile
    attestation_coverage: SignalRiskFactorProfile
    moment_criticality: MomentCriticalityFactorProfile


@dataclass(frozen=True, slots=True)
class ProfileRef:
    profile_id: str
    version: int

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, name="profile ID")
        _positive_int(self.version, name="profile version")


@dataclass(frozen=True, slots=True, init=False)
class DeploymentProfile:
    ref: ProfileRef
    action_demand_unit: str
    risk_factors: RiskFactorsProfile
    risk_domain_weights: Mapping[RiskDomain, Decimal]
    soul_frameworks: tuple[str, ...]
    peer_share: Decimal
    external_root_hop_bound: int
    misattestation_adjudicator: str
    standing_decay_rate: Decimal
    envelope_thresholds: EnvelopeThresholds | None
    actions: Mapping[str, ActionPolicy]
    feeds: Mapping[str, FeedDeclaration]
    alias_selections: Mapping[str, str]
    normalizations: Mapping[str, IdentityNormalization | MinMaxNormalization]
    label_sets: Mapping[str, LabelSetDeclaration]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("DeploymentProfile values are created by validate()")

    @property
    def profile_id(self) -> str:
        return self.ref.profile_id

    @property
    def version(self) -> int:
        return self.ref.version

    @classmethod
    def validate(cls, declaration: DeploymentProfileDeclaration) -> DeploymentProfile:
        from kinetic_trust_library._canonical import canonical_sha256

        if type(declaration) is not DeploymentProfileDeclaration:
            raise ValidationError(
                "deployment profile must use the explicit declaration"
            )

        ref = ProfileRef(declaration.profile_id, declaration.version)
        action_demand_unit = validate_identifier(
            declaration.action_demand_unit, name="action demand unit"
        )
        seen_mutable: set[int] = set()
        risk_factors = _validate_risk_factors(
            declaration.risk_factors, seen_mutable=seen_mutable
        )
        risk_domain_weights = _validate_risk_domain_weights(
            declaration.risk_domain_weights, seen_mutable=seen_mutable
        )
        frameworks = _validate_identifier_tuple(
            declaration.soul_frameworks,
            name="Soul frameworks",
            require_nonempty=True,
        )
        peer_share = as_decimal(declaration.peer_share, name="peer share")
        if peer_share != 0 and not Decimal(10) <= peer_share <= Decimal(20):
            raise ValidationError(
                "peer share must be exactly 0 or within 10 through 20"
            )
        hop_bound = _bounded_int(
            declaration.external_root_hop_bound,
            name="external root hop bound",
            minimum=1,
            maximum=12,
        )
        adjudicator = validate_identifier(
            declaration.misattestation_adjudicator,
            name="misattestation adjudicator",
        )
        decay = as_decimal(
            declaration.standing_decay_rate,
            name="standing decay rate",
            minimum=2,
            maximum=20,
        )
        thresholds = _validate_thresholds(declaration.envelope_thresholds)
        actions = _validate_actions(declaration.actions, seen_mutable=seen_mutable)
        aggregated = _aggregated_signal_pairs(risk_factors)
        feeds = _validate_feeds(
            declaration.feeds,
            required_pairs=aggregated,
            seen_mutable=seen_mutable,
        )
        populated_signals = frozenset(signal for _, signal in aggregated)
        aliases = _validate_alias_selections(
            declaration.alias_selections,
            populated_signals=populated_signals,
            seen_mutable=seen_mutable,
        )
        normalizations, label_sets = _validate_signal_mappings(
            declaration.normalizations,
            declaration.label_sets,
            signals=populated_signals,
            seen_mutable=seen_mutable,
        )

        value = object.__new__(cls)
        for name, member in (
            ("ref", ref),
            ("action_demand_unit", action_demand_unit),
            ("risk_factors", risk_factors),
            ("risk_domain_weights", risk_domain_weights),
            ("soul_frameworks", frameworks),
            ("peer_share", peer_share),
            ("external_root_hop_bound", hop_bound),
            ("misattestation_adjudicator", adjudicator),
            ("standing_decay_rate", decay),
            ("envelope_thresholds", thresholds),
            ("actions", actions),
            ("feeds", feeds),
            ("alias_selections", aliases),
            ("normalizations", normalizations),
            ("label_sets", label_sets),
        ):
            object.__setattr__(value, name, member)
        object.__setattr__(
            value, "digest", canonical_sha256(_profile_digest_input(value))
        )
        return value

    def factor(
        self, name: FactorName
    ) -> SignalRiskFactorProfile | MomentCriticalityFactorProfile:
        require_validated_profile(self)
        if type(name) is not FactorName:
            raise ValidationError("risk factor must be a FactorName")
        return _risk_factor_member(self.risk_factors, name)

    def domain_weight(self, name: RiskDomain) -> Decimal:
        require_validated_profile(self)
        if type(name) is not RiskDomain:
            raise ValidationError("risk domain must be a RiskDomain")
        return self.risk_domain_weights[name]

    def action_policy(self, action_class: str) -> ActionPolicy:
        require_validated_profile(self)
        validated = validate_identifier(action_class, name="action class")
        try:
            return self.actions[validated]
        except KeyError as exc:
            raise ValidationError(f"undeclared action class: {validated}") from exc

    def feed(self, source_id: str) -> FeedDeclaration:
        require_validated_profile(self)
        validated = validate_identifier(source_id, name="feed source ID")
        try:
            return self.feeds[validated]
        except KeyError as exc:
            raise ValidationError(f"undeclared feed source: {validated}") from exc

    def signal_route(
        self, source_id: str, *, signal_id: str, domain: RiskDomain
    ) -> SignalRouteDeclaration:
        feed = self.feed(source_id)
        if type(domain) is not RiskDomain:
            raise ValidationError("feed route domain must be a RiskDomain")
        try:
            signal = validate_signal_id(signal_id)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        for route in feed.routes:
            if route.signal_id == signal and route.domain is domain:
                return route
        raise ValidationError(
            f"source {feed.source_id} does not populate {domain.value}/{signal}"
        )

    def normalization(
        self, signal_id: str
    ) -> IdentityNormalization | MinMaxNormalization | LabelSetDeclaration:
        require_validated_profile(self)
        try:
            signal = validate_signal_id(signal_id)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if signal in self.normalizations:
            return self.normalizations[signal]
        try:
            return self.label_sets[signal]
        except KeyError as exc:
            raise ValidationError(
                f"signal has no declared normalization: {signal}"
            ) from exc


def require_validated_profile(value: object) -> DeploymentProfile:
    """Return a structurally valid profile with an exact canonical digest."""
    if type(value) is not DeploymentProfile:
        raise ValidationError("value is not a validated deployment profile")
    try:
        declaration, stored_digest = _profile_declaration_from_value(value)
        normalized = DeploymentProfile.validate(declaration)
    except (AttributeError, KeyError, TypeError, ValidationError) as exc:
        raise ValidationError("deployment profile integrity is invalid") from exc
    if stored_digest != normalized.digest:
        raise ValidationError("deployment profile integrity is invalid")
    return value


def _require_owned_profile_structure(value: object) -> tuple[str, int, str]:
    """Return a captured binding for a complete owned retained-profile graph."""
    from kinetic_trust_library._canonical import canonical_sha256

    if type(value) is not DeploymentProfile:
        raise ValidationError("value is not an owned deployment profile")
    try:
        declaration, stored_digest = _profile_declaration_from_value(value)
        recomputed_digest = canonical_sha256(
            _profile_digest_input_from_declaration(declaration)
        )
    except (AttributeError, TypeError, ValidationError) as exc:
        raise ValidationError("deployment profile ownership is invalid") from exc
    if stored_digest != recomputed_digest:
        raise ValidationError("deployment profile ownership is invalid")
    return declaration.profile_id, declaration.version, stored_digest


class _ValidatedProfileContext:
    """Call-local capability for one fully validated effective profile."""

    __slots__ = ("profile", "binding", "_validated_profiles")

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("validated profile contexts are created internally")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("validated profile contexts are immutable")


def _validated_profile_context(
    value: object,
) -> _ValidatedProfileContext:
    """Create one private capability after unconditional full validation."""

    profile = require_validated_profile(value)
    binding = _require_owned_profile_structure(profile)
    context = object.__new__(_ValidatedProfileContext)
    object.__setattr__(context, "profile", profile)
    object.__setattr__(context, "binding", binding)
    object.__setattr__(
        context,
        "_validated_profiles",
        {id(profile): (profile, binding)},
    )
    return context


def _profile_from_context(context: _ValidatedProfileContext) -> DeploymentProfile:
    if type(context) is not _ValidatedProfileContext:
        raise ValidationError("validated profile context is invalid")
    profile = object.__getattribute__(context, "profile")
    binding = object.__getattribute__(context, "binding")
    validated_profiles = object.__getattribute__(context, "_validated_profiles")
    if (
        type(profile) is not DeploymentProfile
        or type(binding) is not tuple
        or len(binding) != 3
        or type(binding[0]) is not str
        or type(binding[1]) is not int
        or type(binding[2]) is not str
        or type(validated_profiles) is not dict
    ):
        raise ValidationError("validated profile context is invalid")
    return profile


def _bind_profile_to_context(
    context: _ValidatedProfileContext,
    stored: object,
) -> DeploymentProfile:
    """Preflight and memoize one retained profile before binding exact scalars."""

    profile = _profile_from_context(context)
    expected = object.__getattribute__(context, "binding")
    validated_profiles = object.__getattribute__(context, "_validated_profiles")
    identity = id(stored)
    cached = dict.get(validated_profiles, identity)
    if cached is not None:
        if (
            type(cached) is not tuple
            or len(cached) != 2
            or cached[0] is not stored
            or cached[1] != expected
        ):
            raise ValidationError("validated profile context is invalid")
        return profile
    binding = _require_owned_profile_structure(stored)
    if binding != expected:
        raise ValidationError("retained value belongs to another profile")
    dict.__setitem__(validated_profiles, identity, (stored, binding))
    return profile


def _profile_mapping_items(
    value: object,
    *,
    name: str,
) -> tuple[tuple[object, object], ...]:
    return _require_owned_mapping_items(value, name=name)


def _profile_declaration_from_value(
    value: DeploymentProfile,
) -> tuple[DeploymentProfileDeclaration, str]:
    """Rebuild the explicit declaration after checking owned value structure."""
    ref = value.ref
    action_demand_unit = value.action_demand_unit
    factor_values = value.risk_factors
    domain_weight_values = value.risk_domain_weights
    soul_frameworks = value.soul_frameworks
    peer_share = value.peer_share
    external_root_hop_bound = value.external_root_hop_bound
    misattestation_adjudicator = value.misattestation_adjudicator
    standing_decay_rate = value.standing_decay_rate
    threshold_values = value.envelope_thresholds
    action_values = value.actions
    feed_values = value.feeds
    alias_values = value.alias_selections
    normalization_values = value.normalizations
    label_set_values = value.label_sets
    stored_digest = value.digest
    if (
        type(ref) is not ProfileRef
        or type(ref.profile_id) is not str
        or type(ref.version) is not int
        or type(action_demand_unit) is not str
        or type(external_root_hop_bound) is not int
        or type(misattestation_adjudicator) is not str
        or type(stored_digest) is not str
    ):
        raise ValidationError("deployment profile structure is invalid")

    if type(factor_values) is not RiskFactorsProfile:
        raise ValidationError("validated risk-factor structure is invalid")
    factor_declarations: dict[FactorName, SignalRiskFactorDeclaration] = {}
    for factor_name in _SIGNAL_FACTOR_ORDER:
        factor = _risk_factor_member(factor_values, factor_name)
        if (
            type(factor) is not SignalRiskFactorProfile
            or factor.name is not factor_name
            or type(factor.weight) is not Decimal
        ):
            raise ValidationError("validated risk-factor structure is invalid")
        aggregation = factor.aggregation
        if (
            type(aggregation) is not FactorAggregationDeclaration
            or type(aggregation.signals) is not tuple
            or type(aggregation.method) is not str
            or any(type(signal) is not str for signal in aggregation.signals)
        ):
            raise ValidationError("validated aggregation structure is invalid")
        signal_weights: dict[str, Decimal] | None = None
        if aggregation.signal_weights is not None:
            signal_weights = {}
            for signal, number in _profile_mapping_items(
                aggregation.signal_weights,
                name="validated aggregation weights",
            ):
                if type(signal) is not str or type(number) is not Decimal:
                    raise ValidationError("validated aggregation weights are invalid")
                signal_weights[signal] = number
        factor_declarations[factor_name] = SignalRiskFactorDeclaration(
            weight=factor.weight,
            aggregation=FactorAggregationDeclaration(
                signals=aggregation.signals,
                method=aggregation.method,
                signal_weights=(
                    None
                    if signal_weights is None
                    else _owned_mapping_from_dict(signal_weights)
                ),
            ),
        )
    moment = factor_values.moment_criticality
    if (
        type(moment) is not MomentCriticalityFactorProfile
        or moment.name is not FactorName.MOMENT_CRITICALITY
        or type(moment.weight) is not Decimal
        or type(moment.supplier) is not str
        or type(moment.unit) is not str
    ):
        raise ValidationError("validated moment factor structure is invalid")
    risk_factors = RiskFactorsDeclaration(
        evidence_density=factor_declarations[FactorName.EVIDENCE_DENSITY],
        trust_trend=factor_declarations[FactorName.TRUST_TREND],
        adversarial_pressure=factor_declarations[FactorName.ADVERSARIAL_PRESSURE],
        update_resistance=factor_declarations[FactorName.UPDATE_RESISTANCE],
        attestation_coverage=factor_declarations[FactorName.ATTESTATION_COVERAGE],
        moment_criticality=MomentCriticalityFactorDeclaration(
            weight=moment.weight,
            supplier=moment.supplier,
            unit=moment.unit,
        ),
    )
    domain_weights: dict[RiskDomain, Decimal] = {}
    for domain, weight in _profile_mapping_items(
        domain_weight_values,
        name="validated risk domain weights",
    ):
        if type(domain) is not RiskDomain or type(weight) is not Decimal:
            raise ValidationError("validated domain-weight structure is invalid")
        domain_weights[domain] = weight
    if type(soul_frameworks) is not tuple or any(
        type(framework) is not str for framework in soul_frameworks
    ):
        raise ValidationError("validated Soul frameworks must be immutable")
    if type(peer_share) is not Decimal:
        raise ValidationError("validated peer share must be a Decimal")
    if type(standing_decay_rate) is not Decimal:
        raise ValidationError("validated standing decay must be a Decimal")

    thresholds = threshold_values
    if thresholds is not None:
        if type(thresholds) is not EnvelopeThresholds or any(
            type(number) is not Decimal
            for number in (
                thresholds.veto,
                thresholds.allow,
                thresholds.metacognitive_floor,
                thresholds.assisted_floor,
            )
        ):
            raise ValidationError("validated threshold structure is invalid")
        thresholds = EnvelopeThresholds(
            veto=thresholds.veto,
            allow=thresholds.allow,
            metacognitive_floor=thresholds.metacognitive_floor,
            assisted_floor=thresholds.assisted_floor,
        )

    actions: dict[str, ActionPolicy] = {}
    for action_class, policy in _profile_mapping_items(
        action_values,
        name="validated action policies",
    ):
        if (
            type(action_class) is not str
            or type(policy) is not ActionPolicy
            or type(policy.action_class) is not str
            or type(policy.demand_min) is not Decimal
            or type(policy.demand_max) is not Decimal
            or type(policy.normative_gates) is not tuple
        ):
            raise ValidationError("validated action-policy structure is invalid")
        constraint_units: dict[str, str] = {}
        for constraint, unit in _profile_mapping_items(
            policy.constraint_units,
            name="validated constraint units",
        ):
            if type(constraint) is not str or type(unit) is not str:
                raise ValidationError("validated action-policy structure is invalid")
            constraint_units[constraint] = unit
        gates: list[NormativeGatePolicy] = []
        for gate in policy.normative_gates:
            if (
                type(gate) is not NormativeGatePolicy
                or type(gate.gate_id) is not str
                or type(gate.schema_uri) is not str
                or type(gate.required) is not bool
            ):
                raise ValidationError("validated action-policy structure is invalid")
            gates.append(
                NormativeGatePolicy(
                    gate_id=gate.gate_id,
                    schema_uri=gate.schema_uri,
                    required=gate.required,
                )
            )
        actions[action_class] = ActionPolicy(
            action_class=policy.action_class,
            demand_min=policy.demand_min,
            demand_max=policy.demand_max,
            constraint_units=_owned_mapping_from_dict(constraint_units),
            normative_gates=tuple(gates),
        )

    feeds: dict[str, FeedDeclaration] = {}
    for source_id, feed in _profile_mapping_items(
        feed_values,
        name="validated feeds",
    ):
        if (
            type(source_id) is not str
            or type(feed) is not FeedDeclaration
            or type(feed.source_id) is not str
            or type(feed.routes) is not tuple
            or type(feed.weight) is not Decimal
            or type(feed.refresh_interval_ms) is not int
            or type(feed.stale_threshold_ms) is not int
            or (
                feed.stale_threshold_reason is not None
                and type(feed.stale_threshold_reason) is not str
            )
        ):
            raise ValidationError("validated feed structure is invalid")
        routes: list[SignalRouteDeclaration] = []
        for route in feed.routes:
            if (
                type(route) is not SignalRouteDeclaration
                or type(route.signal_id) is not str
                or type(route.domain) is not RiskDomain
                or type(route.unit) is not str
            ):
                raise ValidationError("validated feed structure is invalid")
            routes.append(
                SignalRouteDeclaration(
                    signal_id=route.signal_id,
                    domain=route.domain,
                    unit=route.unit,
                )
            )
        feeds[source_id] = FeedDeclaration(
            source_id=feed.source_id,
            routes=tuple(routes),
            refresh_interval_ms=feed.refresh_interval_ms,
            weight=feed.weight,
            stale_threshold_ms=feed.stale_threshold_ms,
            stale_threshold_reason=feed.stale_threshold_reason,
        )
    aliases: dict[str, str] = {}
    for name, signal in _profile_mapping_items(
        alias_values,
        name="validated alias selections",
    ):
        if type(name) is not str or type(signal) is not str:
            raise ValidationError("validated alias-selection structure is invalid")
        aliases[name] = signal
    normalizations: dict[str, IdentityNormalization | MinMaxNormalization] = {}
    for signal, normalization in _profile_mapping_items(
        normalization_values,
        name="validated normalizations",
    ):
        if type(signal) is not str:
            raise ValidationError("validated normalization structure is invalid")
        if type(normalization) is IdentityNormalization:
            if type(normalization.invert) is not bool:
                raise ValidationError("validated normalization structure is invalid")
            owned_normalization: IdentityNormalization | MinMaxNormalization = (
                IdentityNormalization(invert=normalization.invert)
            )
        elif type(normalization) is MinMaxNormalization:
            if (
                type(normalization.minimum) is not Decimal
                or type(normalization.maximum) is not Decimal
                or type(normalization.invert) is not bool
                or type(normalization.clamp) is not bool
            ):
                raise ValidationError("validated normalization structure is invalid")
            owned_normalization = MinMaxNormalization(
                minimum=normalization.minimum,
                maximum=normalization.maximum,
                invert=normalization.invert,
                clamp=normalization.clamp,
            )
        else:
            raise ValidationError("validated normalization structure is invalid")
        normalizations[signal] = owned_normalization
    label_sets: dict[str, LabelSetDeclaration] = {}
    for signal, label_set in _profile_mapping_items(
        label_set_values,
        name="validated label sets",
    ):
        if (
            type(signal) is not str
            or type(label_set) is not LabelSetDeclaration
            or type(label_set.labels) is not tuple
            or any(type(label) is not str for label in label_set.labels)
            or (
                label_set.source_id is not None and type(label_set.source_id) is not str
            )
            or (
                label_set.predicate is not None and type(label_set.predicate) is not str
            )
        ):
            raise ValidationError("validated label-set structure is invalid")
        stress: dict[str, Decimal] = {}
        for label, number in _profile_mapping_items(
            label_set.stress_by_label,
            name="validated label stress mapping",
        ):
            if type(label) is not str or type(number) is not Decimal:
                raise ValidationError("validated label-set structure is invalid")
            stress[label] = number
        label_sets[signal] = LabelSetDeclaration(
            labels=label_set.labels,
            stress_by_label=_owned_mapping_from_dict(stress),
            source_id=label_set.source_id,
            predicate=label_set.predicate,
        )

    declaration = DeploymentProfileDeclaration(
        profile_id=ref.profile_id,
        version=ref.version,
        action_demand_unit=action_demand_unit,
        risk_factors=risk_factors,
        risk_domain_weights=_owned_mapping_from_dict(domain_weights),
        soul_frameworks=soul_frameworks,
        peer_share=peer_share,
        external_root_hop_bound=external_root_hop_bound,
        misattestation_adjudicator=misattestation_adjudicator,
        standing_decay_rate=standing_decay_rate,
        envelope_thresholds=thresholds,
        actions=_owned_mapping_from_dict(actions),
        feeds=_owned_mapping_from_dict(feeds),
        alias_selections=_owned_mapping_from_dict(aliases),
        normalizations=_owned_mapping_from_dict(normalizations),
        label_sets=_owned_mapping_from_dict(label_sets),
    )
    return declaration, stored_digest


def _profile_digest_input(value: DeploymentProfile) -> Mapping[str, object]:
    return {
        "ref": value.ref,
        "action_demand_unit": value.action_demand_unit,
        "risk_semantics": "shared-factors-context-first-v1",
        "risk_factors": {
            _FACTOR_MEMBERS[name]: _risk_factor_member(value.risk_factors, name)
            for name in _FACTOR_ORDER
        },
        "risk_domain_weights": {
            name.value: value.risk_domain_weights[name] for name in _DOMAIN_ORDER
        },
        "soul_frameworks": value.soul_frameworks,
        "peer_share": value.peer_share,
        "external_root_hop_bound": value.external_root_hop_bound,
        "misattestation_adjudicator": value.misattestation_adjudicator,
        "standing_decay_rate": value.standing_decay_rate,
        "envelope_thresholds": value.envelope_thresholds,
        "actions": value.actions,
        "feeds": value.feeds,
        "alias_selections": value.alias_selections,
        "normalizations": value.normalizations,
        "label_sets": value.label_sets,
    }


def _profile_digest_input_from_declaration(
    value: DeploymentProfileDeclaration,
) -> Mapping[str, object]:
    return {
        "ref": {
            "profile_id": value.profile_id,
            "version": value.version,
        },
        "action_demand_unit": value.action_demand_unit,
        "risk_semantics": "shared-factors-context-first-v1",
        "risk_factors": {
            _FACTOR_MEMBERS[name]: (
                {
                    "name": name,
                    "weight": getattr(
                        value.risk_factors, _FACTOR_MEMBERS[name]
                    ).weight,
                    "aggregation": getattr(
                        value.risk_factors, _FACTOR_MEMBERS[name]
                    ).aggregation,
                }
                if name is not FactorName.MOMENT_CRITICALITY
                else {
                    "name": name,
                    "weight": value.risk_factors.moment_criticality.weight,
                    "supplier": value.risk_factors.moment_criticality.supplier,
                    "unit": value.risk_factors.moment_criticality.unit,
                }
            )
            for name in _FACTOR_ORDER
        },
        "risk_domain_weights": {
            name.value: value.risk_domain_weights[name] for name in _DOMAIN_ORDER
        },
        "soul_frameworks": value.soul_frameworks,
        "peer_share": value.peer_share,
        "external_root_hop_bound": value.external_root_hop_bound,
        "misattestation_adjudicator": value.misattestation_adjudicator,
        "standing_decay_rate": value.standing_decay_rate,
        "envelope_thresholds": value.envelope_thresholds,
        "actions": value.actions,
        "feeds": value.feeds,
        "alias_selections": value.alias_selections,
        "normalizations": value.normalizations,
        "label_sets": value.label_sets,
    }


def _risk_factor_member(
    factors: RiskFactorsProfile,
    name: FactorName,
) -> SignalRiskFactorProfile | MomentCriticalityFactorProfile:
    return getattr(factors, _FACTOR_MEMBERS[name])


def _signal_risk_factor_member(
    factors: RiskFactorsProfile,
    name: FactorName,
) -> SignalRiskFactorProfile:
    member = _risk_factor_member(factors, name)
    if type(member) is not SignalRiskFactorProfile:
        raise ValidationError("signal factor lookup resolved to Moment Criticality")
    return member


def _validate_risk_factors(
    value: RiskFactorsDeclaration,
    *,
    seen_mutable: set[int],
) -> RiskFactorsProfile:
    if type(value) is not RiskFactorsDeclaration:
        raise ValidationError("risk factors must use the explicit declaration")
    profiles: dict[FactorName, SignalRiskFactorProfile] = {}
    weights: list[Decimal] = []
    for factor in _SIGNAL_FACTOR_ORDER:
        declaration = getattr(value, _FACTOR_MEMBERS[factor])
        if type(declaration) is not SignalRiskFactorDeclaration:
            raise ValidationError("signal factor must use the explicit declaration")
        weight = as_decimal(
            declaration.weight,
            name=f"{factor.value} factor weight",
            minimum=0,
            maximum=1,
        )
        if weight == 0:
            raise ValidationError("factor weights must be positive")
        profiles[factor] = SignalRiskFactorProfile(
            name=factor,
            weight=weight,
            aggregation=_validate_factor_aggregation(
                declaration.aggregation,
                factor=factor,
                seen_mutable=seen_mutable,
            ),
        )
        weights.append(weight)
    moment_declaration = value.moment_criticality
    if type(moment_declaration) is not MomentCriticalityFactorDeclaration:
        raise ValidationError(
            "moment criticality must use the explicit factor declaration"
        )
    moment_weight = as_decimal(
        moment_declaration.weight,
        name="moment_criticality factor weight",
        minimum=0,
        maximum=1,
    )
    if moment_weight == 0:
        raise ValidationError("factor weights must be positive")
    weights.append(moment_weight)
    if not _exact_sum_is_one(weights):
        raise ValidationError("factor weights must sum exactly to 1")
    moment = MomentCriticalityFactorProfile(
        name=FactorName.MOMENT_CRITICALITY,
        weight=moment_weight,
        supplier=validate_identifier(
            moment_declaration.supplier, name="moment supplier"
        ),
        unit=validate_identifier(moment_declaration.unit, name="moment unit"),
    )
    return RiskFactorsProfile(
        evidence_density=profiles[FactorName.EVIDENCE_DENSITY],
        trust_trend=profiles[FactorName.TRUST_TREND],
        adversarial_pressure=profiles[FactorName.ADVERSARIAL_PRESSURE],
        update_resistance=profiles[FactorName.UPDATE_RESISTANCE],
        attestation_coverage=profiles[FactorName.ATTESTATION_COVERAGE],
        moment_criticality=moment,
    )


def _validate_risk_domain_weights(
    value: Mapping[RiskDomain, DecimalLike],
    *,
    seen_mutable: set[int],
) -> Mapping[RiskDomain, Decimal]:
    entries = _mapping_entries(
        value,
        name="risk domain weights",
        key_type=RiskDomain,
        seen_mutable=seen_mutable,
    )
    weights: dict[RiskDomain, Decimal] = {}
    for domain, raw_weight in entries:
        if type(domain) is not RiskDomain:
            raise ValidationError("domain weights must use RiskDomain keys")
        weight = as_decimal(
            raw_weight,
            name=f"{domain.value} domain weight",
            minimum=0,
            maximum=1,
        )
        if weight == 0:
            raise ValidationError("domain weights must be positive")
        weights[domain] = weight
    ordered_names = tuple(
        sorted(weights, key=lambda item: _DOMAIN_ORDER.index(item))
    )
    if ordered_names != _DOMAIN_ORDER:
        raise ValidationError(
            "profile must declare exactly node, neighborhood, and global domain weights"
        )
    if not _exact_sum_is_one(weights.values()):
        raise ValidationError("domain weights must sum exactly to 1")
    return _owned_mapping_from_dict(
        {domain: weights[domain] for domain in _DOMAIN_ORDER}
    )


def _validate_factor_aggregation(
    value: FactorAggregationDeclaration,
    *,
    factor: FactorName,
    seen_mutable: set[int],
) -> FactorAggregationDeclaration:
    if type(value) is not FactorAggregationDeclaration:
        raise ValidationError("factor aggregation must use the explicit declaration")
    if type(value.signals) is not tuple or not value.signals:
        raise ValidationError("factor aggregation signals must be a non-empty tuple")
    try:
        signals = validate_signal_subset(value.signals)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if type(value.method) is not str:
        raise ValidationError("aggregation method must be an exact string")
    if value.method not in _AGGREGATION_METHODS:
        raise ValidationError("unsupported factor aggregation method")
    weights: Mapping[str, Decimal] | None = None
    if value.method == "weighted_average":
        if value.signal_weights is None:
            raise ValidationError("weighted-average aggregation requires signal weights")
        weights = _validate_signal_weights(
            value.signal_weights,
            signals=signals,
            name=f"{factor.value} signal weights",
            seen_mutable=seen_mutable,
        )
    elif value.signal_weights is not None:
        raise ValidationError(
            "maximum and minimum aggregations must not declare signal weights"
        )
    return FactorAggregationDeclaration(
        signals=signals,
        method=value.method,
        signal_weights=weights,
    )


def _validate_signal_weights(
    value: Mapping[str, DecimalLike],
    *,
    signals: tuple[str, ...],
    name: str,
    seen_mutable: set[int],
) -> Mapping[str, Decimal]:
    entries = _mapping_entries(
        value, name=name, key_type=str, seen_mutable=seen_mutable
    )
    weights: dict[str, Decimal] = {}
    for key, raw_value in entries:
        try:
            signal = validate_signal_id(key)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if signal in weights:
            raise ValidationError(f"duplicate {name} key: {signal}")
        weight = as_decimal(raw_value, name=f"{name} {signal}", minimum=0)
        if weight == 0:
            raise ValidationError("signal weights must be positive")
        weights[signal] = weight
    if frozenset(weights) != frozenset(signals):
        raise ValidationError("signal weights must exactly match aggregation signals")
    return _owned_mapping_from_dict(weights)


def _aggregated_signal_pairs(
    factors: RiskFactorsProfile,
) -> frozenset[tuple[RiskDomain, str]]:
    return frozenset(
        (domain, signal)
        for domain in _DOMAIN_ORDER
        for factor_name in _SIGNAL_FACTOR_ORDER
        for signal in _signal_risk_factor_member(
            factors, factor_name
        ).aggregation.signals
    )


def _validate_feeds(
    value: Mapping[str, FeedDeclaration],
    *,
    required_pairs: frozenset[tuple[RiskDomain, str]],
    seen_mutable: set[int],
) -> Mapping[str, FeedDeclaration]:
    entries = _mapping_entries(
        value, name="feeds", key_type=str, seen_mutable=seen_mutable
    )
    feeds: dict[str, FeedDeclaration] = {}
    routed_pairs: set[tuple[RiskDomain, str]] = set()
    units: dict[str, str] = {}
    for key, declaration in entries:
        source_id = validate_identifier(key, name="feed source ID")
        if source_id in feeds:
            raise ValidationError(f"duplicate feed source: {source_id}")
        if type(declaration) is not FeedDeclaration:
            raise ValidationError("feed must use the explicit declaration")
        declared_source = validate_identifier(
            declaration.source_id, name="declared feed source ID"
        )
        if source_id != declared_source:
            raise ValidationError(
                "feed source ID must exactly match its declaration key"
            )
        if type(declaration.routes) is not tuple or not declaration.routes:
            raise ValidationError("feed routes must be a non-empty tuple")
        routes: list[SignalRouteDeclaration] = []
        local_pairs: set[tuple[RiskDomain, str]] = set()
        for route in declaration.routes:
            if type(route) is not SignalRouteDeclaration:
                raise ValidationError("feed route must use the explicit declaration")
            if type(route.domain) is not RiskDomain:
                raise ValidationError("feed route domain must be a RiskDomain")
            try:
                signal = validate_signal_id(route.signal_id)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            unit = _validate_unit(route.unit, name=f"{signal} unit")
            pair = (route.domain, signal)
            if pair in local_pairs:
                raise ValidationError("feed routes must be unique")
            local_pairs.add(pair)
            previous_unit = units.setdefault(signal, unit)
            if previous_unit != unit:
                raise ValidationError("all routes for a signal must use one exact unit")
            routes.append(
                SignalRouteDeclaration(signal_id=signal, domain=route.domain, unit=unit)
            )
        refresh = _feed_interval(
            declaration.refresh_interval_ms, name="feed refresh interval"
        )
        weight = as_decimal(declaration.weight, name="feed weight", minimum=0)
        if weight == 0:
            raise ValidationError("feed weight must be positive")
        if declaration.stale_threshold_ms is None:
            stale = 0 if refresh == 0 else refresh * 5
        else:
            stale = _stale_interval(declaration.stale_threshold_ms)
        if (refresh == 0) != (stale == 0):
            raise ValidationError(
                "on-demand feeds require refresh and stale thresholds of zero"
            )
        default_stale = 0 if refresh == 0 else refresh * 5
        reason = declaration.stale_threshold_reason
        if stale > default_stale and reason is None:
            raise ValidationError("a longer stale threshold requires a recorded reason")
        normalized_reason = (
            None
            if reason is None
            else validate_identifier(reason, name="stale-threshold reason")
        )
        feeds[source_id] = FeedDeclaration(
            source_id=source_id,
            routes=tuple(routes),
            refresh_interval_ms=refresh,
            weight=weight,
            stale_threshold_ms=stale,
            stale_threshold_reason=normalized_reason,
        )
        routed_pairs.update(local_pairs)
    if routed_pairs != set(required_pairs):
        raise ValidationError(
            "feed routes must cover exactly every domain signal aggregation"
        )
    return _owned_mapping_from_dict(feeds)


def _validate_alias_selections(
    value: Mapping[str, str],
    *,
    populated_signals: frozenset[str],
    seen_mutable: set[int],
) -> Mapping[str, str]:
    entries = _mapping_entries(
        value,
        name="alias selections",
        key_type=str,
        seen_mutable=seen_mutable,
    )
    selections: dict[str, str] = {}
    for raw_name, raw_signal in entries:
        name = validate_identifier(raw_name, name="alias set name")
        if name in selections:
            raise ValidationError(f"duplicate alias selection: {name}")
        try:
            signal = validate_signal_id(raw_signal)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        selections[name] = signal
    required: dict[str, str] = {}
    for name, members in ALIASES.items():
        populated = members & populated_signals
        if len(populated) > 1:
            raise ValidationError(
                f"deployment populates multiple duplicate aliases in {name}"
            )
        if populated:
            required[name] = next(iter(populated))
    if selections != required:
        raise ValidationError(
            "alias selections must exactly name every populated duplicate alias set"
        )
    return _owned_mapping_from_dict(selections)


def _validate_signal_mappings(
    normalization_value: Mapping[str, IdentityNormalization | MinMaxNormalization],
    label_value: Mapping[str, LabelSetDeclaration],
    *,
    signals: frozenset[str],
    seen_mutable: set[int],
) -> tuple[
    Mapping[str, IdentityNormalization | MinMaxNormalization],
    Mapping[str, LabelSetDeclaration],
]:
    numeric = frozenset(
        signal
        for signal in signals
        if CATALOG[signal].value_type in {"int", "float", "duration"}
    )
    categorical = frozenset(
        signal
        for signal in signals
        if CATALOG[signal].value_type in {"bool", "enum", "string"}
    )
    unsupported = signals - numeric - categorical
    if unsupported:
        raise ValidationError(
            "profile uses signal types without a deterministic KTP-Core normalization"
        )

    normalization_entries = _mapping_entries(
        normalization_value,
        name="normalizations",
        key_type=str,
        seen_mutable=seen_mutable,
    )
    normalizations: dict[str, IdentityNormalization | MinMaxNormalization] = {}
    for raw_signal, declaration in normalization_entries:
        try:
            signal = validate_signal_id(raw_signal)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if signal in normalizations:
            raise ValidationError(f"duplicate normalization: {signal}")
        if type(declaration) is IdentityNormalization:
            if CATALOG[signal].zero_one not in {"ratio", "synthetic", "determined"}:
                raise ValidationError(
                    "identity normalization requires a declared 0-1 signal"
                )
            if type(declaration.invert) is not bool:
                raise ValidationError("identity normalization invert must be boolean")
            normalized: IdentityNormalization | MinMaxNormalization = (
                IdentityNormalization(invert=declaration.invert)
            )
        elif type(declaration) is MinMaxNormalization:
            minimum = as_decimal(
                declaration.minimum, name=f"{signal} normalization minimum"
            )
            maximum = as_decimal(
                declaration.maximum, name=f"{signal} normalization maximum"
            )
            if minimum >= maximum:
                raise ValidationError("normalization minimum must be less than maximum")
            if (
                type(declaration.invert) is not bool
                or type(declaration.clamp) is not bool
            ):
                raise ValidationError("normalization invert and clamp must be booleans")
            normalized = MinMaxNormalization(
                minimum=minimum,
                maximum=maximum,
                invert=declaration.invert,
                clamp=declaration.clamp,
            )
        else:
            raise ValidationError("unsupported signal normalization method")
        normalizations[signal] = normalized
    if frozenset(normalizations) != numeric:
        raise ValidationError(
            "normalizations must exactly cover numeric aggregated signals"
        )

    label_entries = _mapping_entries(
        label_value,
        name="label sets",
        key_type=str,
        seen_mutable=seen_mutable,
    )
    label_sets: dict[str, LabelSetDeclaration] = {}
    for raw_signal, declaration in label_entries:
        try:
            signal = validate_signal_id(raw_signal)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if signal in label_sets:
            raise ValidationError(f"duplicate label set: {signal}")
        if type(declaration) is not LabelSetDeclaration:
            raise ValidationError("label set must use the explicit declaration")
        labels = _validate_labels(declaration.labels)
        if CATALOG[signal].value_type == "bool" and frozenset(labels) != frozenset(
            ("false", "true")
        ):
            raise ValidationError(
                "boolean signal labels must be exactly false and true"
            )
        stress_entries = _mapping_entries(
            declaration.stress_by_label,
            name=f"{signal} label stress mapping",
            key_type=str,
            seen_mutable=seen_mutable,
        )
        stress: dict[str, Decimal] = {}
        for raw_label, raw_stress in stress_entries:
            label = _validate_label(raw_label)
            if label in stress:
                raise ValidationError("duplicate label stress value")
            stress[label] = as_decimal(
                raw_stress,
                name=f"{signal} label stress",
                minimum=0,
                maximum=1,
            )
        if frozenset(stress) != frozenset(labels):
            raise ValidationError("label stress mapping must exactly match labels")
        source_id = (
            None
            if declaration.source_id is None
            else validate_identifier(declaration.source_id, name="label-set source ID")
        )
        predicate = (
            None
            if declaration.predicate is None
            else validate_identifier(declaration.predicate, name="label-set predicate")
        )
        label_sets[signal] = LabelSetDeclaration(
            labels=labels,
            stress_by_label=_owned_mapping_from_dict(stress),
            source_id=source_id,
            predicate=predicate,
        )
    if frozenset(label_sets) != categorical:
        raise ValidationError(
            "label sets must exactly cover categorical aggregated signals"
        )
    return _owned_mapping_from_dict(normalizations), _owned_mapping_from_dict(
        label_sets
    )


def _validate_labels(value: tuple[str, ...]) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) < 2:
        raise ValidationError("label sets require at least two labels")
    labels = tuple(_validate_label(label) for label in value)
    if len(frozenset(labels)) != len(labels):
        raise ValidationError("label-set labels must be unique")
    return labels


def _validate_label(value: str) -> str:
    if type(value) is not str or not value or len(value) > 128:
        raise ValidationError("labels must be non-empty bounded strings")
    if any(
        ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        raise ValidationError("labels contain invalid characters")
    if normalize("NFC", value) != value:
        raise ValidationError("labels must be NFC-normalized")
    return value


def _validate_unit(value: str, *, name: str) -> str:
    if type(value) is not str or not value or len(value) > 64:
        raise ValidationError(f"{name} must be a non-empty bounded string")
    if any(
        ord(character) < 33 or 0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        raise ValidationError(f"{name} contains invalid characters")
    if normalize("NFC", value) != value:
        raise ValidationError(f"{name} must be NFC-normalized")
    return value


def _feed_interval(value: int, *, name: str) -> int:
    if type(value) is not int or (value != 0 and value < 100):
        raise ValidationError(f"{name} must be zero or at least 100 milliseconds")
    if value > _MAX_REFRESH_INTERVAL_MS:
        raise ValidationError(f"{name} exceeds the implementation safety maximum")
    return value


def _stale_interval(value: int) -> int:
    if type(value) is not int or (value != 0 and value < 1000):
        raise ValidationError(
            "feed stale threshold must be zero or at least 1000 milliseconds"
        )
    if value > _MAX_STALE_THRESHOLD_MS:
        raise ValidationError(
            "feed stale threshold exceeds the implementation safety maximum"
        )
    return value


def _validate_thresholds(value: EnvelopeThresholds | None) -> EnvelopeThresholds | None:
    if value is None:
        return None
    if type(value) is not EnvelopeThresholds:
        raise ValidationError("envelope thresholds must use the explicit declaration")
    veto = as_decimal(value.veto, name="veto threshold")
    allow = as_decimal(value.allow, name="allow threshold")
    metacognitive_floor = as_decimal(
        value.metacognitive_floor, name="metacognitive floor"
    )
    assisted_floor = as_decimal(value.assisted_floor, name="assisted floor")
    if not veto < assisted_floor < metacognitive_floor < allow:
        raise ValidationError(
            "envelope thresholds must order veto, assisted, metacognitive, and allow"
        )
    return EnvelopeThresholds(
        veto=veto,
        allow=allow,
        metacognitive_floor=metacognitive_floor,
        assisted_floor=assisted_floor,
    )


def _validate_actions(
    value: Mapping[str, ActionPolicy], *, seen_mutable: set[int]
) -> Mapping[str, ActionPolicy]:
    entries = _mapping_entries(
        value, name="actions", key_type=str, seen_mutable=seen_mutable
    )
    actions: dict[str, ActionPolicy] = {}
    for key, declaration in entries:
        action_class = validate_identifier(key, name="action class key")
        if action_class in actions:
            raise ValidationError(f"duplicate action class: {action_class}")
        actions[action_class] = _validate_action_policy(
            action_class,
            declaration,
            seen_mutable=seen_mutable,
        )
    if not actions:
        raise ValidationError("profile must declare at least one action class")
    return _owned_mapping_from_dict(actions)


def _validate_action_policy(
    action_class: str,
    declaration: ActionPolicy,
    *,
    seen_mutable: set[int],
) -> ActionPolicy:
    if type(declaration) is not ActionPolicy:
        raise ValidationError("action policy must use the explicit declaration")
    declared_class = validate_identifier(
        declaration.action_class, name="action policy class"
    )
    if declared_class != action_class:
        raise ValidationError(
            "action policy class must exactly match its declaration key"
        )
    demand_min = as_decimal(
        declaration.demand_min,
        name=f"{action_class} demand minimum",
        minimum=0,
        maximum=100,
    )
    demand_max = as_decimal(
        declaration.demand_max,
        name=f"{action_class} demand maximum",
        minimum=0,
        maximum=100,
    )
    if demand_min > demand_max:
        raise ValidationError("action demand minimum must not exceed maximum")
    units = _validate_constraint_units(
        declaration.constraint_units,
        action_class=action_class,
        seen_mutable=seen_mutable,
    )
    gates = _validate_normative_gates(declaration.normative_gates)
    return ActionPolicy(
        action_class=action_class,
        demand_min=demand_min,
        demand_max=demand_max,
        constraint_units=units,
        normative_gates=gates,
    )


def _validate_normative_gates(
    value: tuple[NormativeGatePolicy, ...],
) -> tuple[NormativeGatePolicy, ...]:
    if type(value) is not tuple:
        raise ValidationError("normative gate policies must be a tuple")
    result: list[NormativeGatePolicy] = []
    seen: set[str] = set()
    for policy in value:
        if type(policy) is not NormativeGatePolicy:
            raise ValidationError(
                "normative gate policy must use the explicit declaration"
            )
        gate_id = validate_identifier(policy.gate_id, name="normative gate ID")
        if gate_id in seen:
            raise ValidationError(f"duplicate normative gate ID: {gate_id}")
        seen.add(gate_id)
        if type(policy.required) is not bool:
            raise ValidationError("normative gate required semantics must be boolean")
        result.append(
            NormativeGatePolicy(
                gate_id=gate_id,
                schema_uri=validate_absolute_uri(
                    policy.schema_uri, name="normative gate schema URI"
                ),
                required=policy.required,
            )
        )
    return tuple(result)


def _validate_constraint_units(
    value: Mapping[str, str],
    *,
    action_class: str,
    seen_mutable: set[int],
) -> Mapping[str, str]:
    entries = _mapping_entries(
        value,
        name=f"{action_class} constraint units",
        key_type=str,
        seen_mutable=seen_mutable,
    )
    units: dict[str, str] = {}
    for key, unit in entries:
        constraint = validate_constraint_magnitude(key, name="constraint name")
        if constraint in units:
            raise ValidationError(f"duplicate constraint: {constraint}")
        units[constraint] = validate_engineering_unit(unit, name=f"{constraint} unit")
    return _owned_mapping_from_dict(units)


def _validate_identifier_tuple(
    value: tuple[str, ...], *, name: str, require_nonempty: bool
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValidationError(f"{name} must be a tuple")
    if require_nonempty and not value:
        raise ValidationError(f"{name} must not be empty")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        validated = validate_identifier(
            item, name=name[:-1] if name.endswith("s") else name
        )
        if validated in seen:
            raise ValidationError(f"{name} must be unique")
        seen.add(validated)
        result.append(validated)
    return tuple(result)


def _mapping_entries(
    value: Mapping[object, object],
    *,
    name: str,
    key_type: type[object],
    seen_mutable: set[int],
) -> tuple[tuple[object, object], ...]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{name} must be a mapping")
    if type(value) is _OwnedMapping:
        raw_entries = _require_owned_mapping_items(value, name=name)
        entries: list[tuple[object, object]] = []
        keys: set[object] = set()
        for raw_key, raw_value in raw_entries:
            if key_type is str:
                if type(raw_key) is not str:
                    raise ValidationError(f"{name} keys must use exact str")
                key: object = raw_key
            else:
                if type(raw_key) is not key_type:
                    raise ValidationError(f"{name} keys must use {key_type.__name__}")
                key = raw_key
            if key in keys:
                raise ValidationError(f"{name} contains duplicate keys")
            keys.add(key)
            entries.append((key, raw_value))
        return tuple(entries)
    if not isinstance(value, MappingProxyType):
        identity = id(value)
        if identity in seen_mutable:
            raise ValidationError("mutable aliases are not permitted")
        seen_mutable.add(identity)
    entries: list[tuple[object, object]] = []
    keys: set[object] = set()
    try:
        iterator = iter(value)
    except Exception as exc:
        raise ValidationError(f"{name} changed during validation") from exc
    while True:
        try:
            raw_key = next(iterator)
        except StopIteration:
            break
        except Exception as exc:
            raise ValidationError(f"{name} changed during validation") from exc
        if key_type is str:
            if type(raw_key) is not str:
                raise ValidationError(f"{name} keys must use exact str")
            key: object = raw_key
        else:
            if type(raw_key) is not key_type:
                raise ValidationError(f"{name} keys must use {key_type.__name__}")
            key = raw_key
        if key in keys:
            raise ValidationError(f"{name} contains duplicate keys")
        keys.add(key)
        try:
            raw_value = value[raw_key]
        except Exception as exc:
            raise ValidationError(f"{name} changed during validation") from exc
        entries.append((key, raw_value))
    return tuple(entries)


def _exact_sum_is_one(values: object) -> bool:
    return sum((Fraction(value) for value in values), start=Fraction(0)) == 1


def _positive_int(value: object, *, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValidationError(f"{name} must be a positive integer")
    return value


def _bounded_int(value: object, *, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ValidationError(
            f"{name} must be an integer from {minimum} through {maximum}"
        )
    return value


__all__ = [
    "ActionPolicy",
    "DeploymentProfile",
    "DeploymentProfileDeclaration",
    "EnvelopeThresholds",
    "FeedDeclaration",
    "FactorAggregationDeclaration",
    "FactorName",
    "IdentityNormalization",
    "LabelSetDeclaration",
    "MinMaxNormalization",
    "MomentCriticalityFactorDeclaration",
    "MomentCriticalityFactorProfile",
    "NormativeGatePolicy",
    "ProfileRef",
    "RiskDomain",
    "RiskFactorsDeclaration",
    "RiskFactorsProfile",
    "SignalRouteDeclaration",
    "SignalRiskFactorDeclaration",
    "SignalRiskFactorProfile",
    "require_validated_profile",
]
