"""Explicit reference-form enclosure profile, separate from five-factor R.

The installed source owns current topology, signed enclosure/gateway evidence,
normalization, overlap policy and absence of protected-inner feedback. The
reference form is a selected informative profile, never a universal RFC formula.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library._decimal import as_decimal, DecimalLike
from ._exact import finite_decimal
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from .core_risk import NativeRiskAssessment
from .evidence_state import UndefinedInputState, canonical_undefined_inputs


@dataclass(frozen=True, slots=True)
class EnclosureInputs:
    depth: int
    class_step: bool
    reach: DecimalLike
    attenuation: DecimalLike
    signed_risk: DecimalLike | None
    gateway_risk: DecimalLike | None

    def __post_init__(self):
        if type(self.depth) is not int or not 0 <= self.depth <= 5 or type(self.class_step) is not bool:
            raise ValidationError("invalid enclosure depth/class step")
        for name in ("reach", "attenuation", "signed_risk", "gateway_risk"):
            value = getattr(self, name)
            if value is None and name in ("signed_risk", "gateway_risk"):
                continue
            object.__setattr__(self, name, as_decimal(value, name=name, minimum=0, maximum=1))
        if (self.depth == 0 and (self.reach != 0 or self.class_step or self.signed_risk is not None or self.gateway_risk is not None)
                or self.depth > 0 and self.reach == 0):
            raise ValidationError("enclosure domain is disabled only at depth zero")


@dataclass(frozen=True, slots=True, init=False)
class EnclosureRiskProjection:
    local: NativeRiskAssessment
    inputs: EnclosureInputs
    heat: Decimal | None

    def __init__(self, *args, **kwargs):
        raise TypeError("enclosure risk is derived from the selected reference profile")


def apply_enclosure_risk(local: NativeRiskAssessment, inputs: EnclosureInputs) -> NativeRiskAssessment:
    if type(local) is not NativeRiskAssessment or type(inputs) is not EnclosureInputs or local.enclosure_projection is not None:
        raise ValidationError("enclosure requires an unmodified native local assessment")
    undefined = list(local.undefined_inputs)
    if inputs.depth == 0:
        heat, measured, decision = None, local.measured_risk, local.decision_risk
    elif inputs.signed_risk is None or inputs.gateway_risk is None:
        heat, measured, decision = None, None, Decimal(1)
        for name, value in (("signed_risk", inputs.signed_risk), ("gateway_risk", inputs.gateway_risk)):
            if value is None:
                undefined.append(UndefinedInputState("enclosure."+name, "term", "unanswered"))
    else:
        attenuation = Fraction(inputs.attenuation) if inputs.class_step else Fraction(1)
        exact_heat = max(attenuation*Fraction(inputs.signed_risk), Fraction(inputs.gateway_risk))
        heat = finite_decimal(exact_heat)
        def raised(value):
            baseline = Fraction(value)
            return finite_decimal(baseline+Fraction(inputs.reach)*max(Fraction(0), exact_heat-baseline))
        measured = None if local.measured_risk is None else raised(local.measured_risk)
        decision = raised(local.decision_risk)
    projection = object.__new__(EnclosureRiskProjection)
    for name, value in (("local", local), ("inputs", inputs), ("heat", heat)):
        object.__setattr__(projection, name, value)
    result = object.__new__(NativeRiskAssessment)
    for name, value in (("factors", local.factors), ("measured_risk", measured), ("decision_risk", decision),
                        ("undefined_inputs", canonical_undefined_inputs(tuple(undefined))), ("enclosure_projection", projection)):
        object.__setattr__(result, name, value)
    return result


class EnclosureUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedEnclosureEvidence:
    body_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class NativeEnclosureAssessment:
    inputs: EnclosureInputs
    profile_bytes: bytes
    deployment_digest: str
    operation_digest: str
    evaluated_at: int
    expires_at: int
    authenticated_body_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError("enclosure assessments are derived by an installed verifier")


def _profile(raw):
    profile = _parse_jcs_object(raw)
    if (set(profile) != {"id", "version", "formula", "zone_id", "depth", "reach", "attenuation_per_class_step", "overlap_policy_id"}
            or profile["formula"] != "reference-floor-v1" or not _time(profile["version"]) or profile["version"] == 0):
        raise ValidationError("installed reference enclosure profile is invalid")
    for name in ("id", "zone_id", "overlap_policy_id"):
        if type(profile[name]) is not str or not profile[name] or any(char.isspace() for char in profile[name]):
            raise ValidationError("installed enclosure profile identifiers are invalid")
    EnclosureInputs(profile["depth"], False, profile["reach"], profile["attenuation_per_class_step"], None, None)
    return profile


@dataclass(frozen=True, slots=True)
class InstalledEnclosureVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.source, "resolve", None)) or self.algorithm not in ("sha256", "sha384")):
            raise ValidationError("installed enclosure verifier is invalid")
        _parse_jcs_object(self.deployment_profile_bytes)
        _profile(self.profile_bytes)

    def evaluate(self, *, actual_operation: dict, evaluated_at: int, clock_healthy: bool) -> NativeEnclosureAssessment:
        from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
        from .demand_supplier import _digest
        if not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("enclosure assessment requires a healthy current clock")
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        profile = _profile(self.profile_bytes)
        deployment = _digest(_parse_jcs_object(self.deployment_profile_bytes), self.algorithm)
        operation = digest_demand_operation(_parse_jcs_object(operation_bytes), algorithm=self.algorithm)
        source = self.source.resolve(deployment_profile_bytes=self.deployment_profile_bytes, profile_bytes=self.profile_bytes,
                                      operation_bytes=operation_bytes, evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedEnclosureEvidence or type(source.body_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("enclosure source returned invalid authenticated evidence")
        body = _parse_jcs_object(source.body_bytes)
        if (set(body) != {"deployment_digest", "operation_digest", "profile_digest", "checked_at", "zone_id", "depth", "topology_epoch",
                          "zone_class", "enclosure_class", "enclosure_zone", "registry_reach", "signed_enclosure_risk", "gateway_risk", "expires_at"}
                or body["deployment_digest"] != deployment or body["operation_digest"] != operation
                or body["profile_digest"] != _digest(profile, self.algorithm)
                or not _time(body["checked_at"]) or body["checked_at"] != evaluated_at
                or not _time(body["depth"]) or body["depth"] != profile["depth"] or not _time(body["topology_epoch"])
                or body["zone_id"] != profile["zone_id"] or not _time(body["expires_at"]) or body["expires_at"] <= evaluated_at):
            raise ValidationError("enclosure evidence differs from current invocation/profile/topology")
        classes = {"green": 0, "cyan": 1, "blue": 2, "deep_blue": 3}
        if type(body["zone_class"]) is not str or body["zone_class"] not in classes:
            raise ValidationError("invalid receiving enforcement class")
        registry_reach = as_decimal(body["registry_reach"], name="registry enclosure reach", minimum=0, maximum=1)
        if profile["depth"] == 0:
            if body["enclosure_class"] is not None or body["enclosure_zone"] is not None or registry_reach != 0:
                raise ValidationError("depth zero cannot accept a Wild enclosure")
            class_step = False
        else:
            if (type(body["enclosure_class"]) is not str or body["enclosure_class"] not in classes
                    or classes[body["zone_class"]] < classes[body["enclosure_class"]]
                    or type(body["enclosure_zone"]) is not str or not body["enclosure_zone"]
                    or body["enclosure_zone"] == body["zone_id"] or registry_reach == 0):
                raise ValidationError("invalid current enclosure relationship/reach")
            class_step = body["zone_class"] != body["enclosure_class"]
        inputs = EnclosureInputs(profile["depth"], class_step, profile["reach"], profile["attenuation_per_class_step"],
                                 body["signed_enclosure_risk"], body["gateway_risk"])
        result = object.__new__(NativeEnclosureAssessment)
        for name, value in dict(inputs=inputs, profile_bytes=self.profile_bytes, deployment_digest=deployment,
                                operation_digest=operation, evaluated_at=evaluated_at, expires_at=body["expires_at"],
                                authenticated_body_bytes=source.body_bytes, source_evidence_bytes=source.evidence_bytes).items():
            object.__setattr__(result, name, value)
        return result


__all__ = ("EnclosureInputs", "EnclosureRiskProjection", "apply_enclosure_risk", "InstalledEnclosureVerifier",
           "NativeEnclosureAssessment", "AuthenticatedEnclosureEvidence", "EnclosureUnavailable")
