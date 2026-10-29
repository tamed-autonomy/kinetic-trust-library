"""Exact-scope human eligibility from independently authenticated live state.

No person score, tier, capacity or permission is created. The resolver owns
identity/session and actor classification, approved criteria/registry meaning,
current complete active maps, grants/delegation and correction propagation.
Unsigned decision bodies remain personal information, not authorization tokens.
"""
from dataclasses import dataclass
from typing import TYPE_CHECKING
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes
from .root_lifecycle import _time

if TYPE_CHECKING:
    from .native_evaluation import NativeEvaluationResult


class HumanContextUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedHumanContext:
    actual_request_bytes: bytes
    context_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class HumanEligibilityResult:
    reason: str
    conformance_level: int
    checked_at: int
    operation_bytes: bytes
    decision_body_bytes: bytes | None
    actual_request_bytes: bytes | None
    authenticated_context_bytes: bytes | None
    source_evidence_bytes: bytes | None
    deployment_profile_digest: str
    receiving_zone: str
    expires_at: int | None

    def __init__(self,*args,**kwargs):
        raise TypeError("human eligibility is derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledHumanEligibilityVerifier:
    deployment_profile_bytes: bytes
    human_profile_bytes: bytes
    adapter: object
    conformance_level: int
    receiving_zone: str
    purpose_id: str

    def __post_init__(self):
        from . import _human_reference as h
        if (type(self.deployment_profile_bytes) is not bytes or type(self.human_profile_bytes) is not bytes
                or type(self.conformance_level) is not int or self.conformance_level not in (1,2,3)
                or not callable(getattr(self.adapter,"resolve",None))):
            raise ValidationError("installed human eligibility policy is invalid")
        deployment=_parse_jcs_object(self.deployment_profile_bytes)
        profile=_parse_jcs_object(self.human_profile_bytes)
        try:
            h.literal(self.receiving_zone);h.literal(self.purpose_id)
            h.validate("profile",profile,self.conformance_level)
            expected=dict(mode="operation-eligibility-v1",profile_id=profile["profile_id"],version=profile["version"],digest=h.digest(profile,self.conformance_level))
            if h.canonical(deployment.get("human_policy"))!=h.canonical(expected):
                raise h.InvalidRecord("human policy is not the exact installed profile")
        except h.InvalidRecord as error:
            raise ValidationError(str(error)) from error

    def evaluate(self, claims_bytes: bytes, *, actual_operation: dict,
                 evaluated_at: int, clock_healthy: bool) -> HumanEligibilityResult:
        from . import _human_reference as h
        if type(claims_bytes) is not bytes or not _time(evaluated_at):
            raise ValidationError("human eligibility requires immutable claims and trusted time")
        operation_bytes=canonical_demand_operation_bytes(actual_operation)
        operation=_parse_jcs_object(operation_bytes)
        values=dict(reason="HUMAN_UNAVAILABLE",conformance_level=self.conformance_level,checked_at=evaluated_at,operation_bytes=operation_bytes,decision_body_bytes=None,
            actual_request_bytes=None,authenticated_context_bytes=None,source_evidence_bytes=None,
            deployment_profile_digest=h.digest_bytes(self.deployment_profile_bytes,self.conformance_level),receiving_zone=self.receiving_zone,expires_at=None)
        def result():
            value=object.__new__(HumanEligibilityResult)
            for name,member in values.items():object.__setattr__(value,name,member)
            return value
        if clock_healthy is not True:return result()
        try:
            source=self.adapter.resolve(deployment_profile_bytes=self.deployment_profile_bytes,human_profile_bytes=self.human_profile_bytes,
                operation_bytes=operation_bytes,checked_at=evaluated_at,conformance_level=self.conformance_level,
                receiving_zone=self.receiving_zone,purpose_id=self.purpose_id)
        except HumanContextUnavailable:
            return result()
        if (type(source) is not AuthenticatedHumanContext
                or any(type(raw) is not bytes for raw in (source.actual_request_bytes,source.context_bytes,source.evidence_bytes))
                or not source.evidence_bytes):
            raise ValidationError("human resolver returned invalid authenticated state")
        try:
            request=_parse_jcs_object(source.actual_request_bytes)
            context_body=_parse_jcs_object(source.context_bytes)
            context=h.TrustedContext(**context_body)
            if not _time(context.checked_at) or context.checked_at!=evaluated_at:return result()
            if (context.principal_id!=operation["subject"] or context.actor_id!=operation["actor"]
                    or request["request_id"]!=operation["request_id"] or request["operation_id"]!=operation["operation"]
                    or request["scope"]["zone_id"]!=self.receiving_zone or request["scope"]["purpose_id"]!=self.purpose_id
                    or request["scope"]["resource_id"]!=operation["resource"]
                    or request["scope"]["parameters_digest"]!=h.digest(operation["parameters"],self.conformance_level)):
                raise h.InvalidRecord("human eligibility does not match actual invocation/identity/scope")
            if len(claims_bytes)>262144:raise h.InvalidRecord("human evidence exceeds installed byte limit")
            claims=_parse_jcs_object(claims_bytes)
            if set(claims)!={"evidence","grants","delegations"}:raise h.InvalidRecord("unknown human claim field")
            body=h.evaluate_eligibility(_parse_jcs_object(self.human_profile_bytes),request,claims["evidence"],claims["grants"],claims["delegations"],
                context=context,now=evaluated_at,level=self.conformance_level)
        except (ValueError,ValidationError,ProofFormatError,KeyError,TypeError,UnicodeError,RecursionError):
            values["reason"]="HUMAN_INVALID"
            return result()
        values.update(reason="HUMAN_ELIGIBLE" if body["result"]=="eligible" else "HUMAN_INELIGIBLE",decision_body_bytes=h.canonical(body),
            actual_request_bytes=source.actual_request_bytes,authenticated_context_bytes=source.context_bytes,
            source_evidence_bytes=source.evidence_bytes,expires_at=body["expires_at"])
        return result()


@dataclass(frozen=True, slots=True, init=False)
class HumanOriginEvaluationResult:
    reason: str
    checked_at: int
    native: "NativeEvaluationResult"
    human: HumanEligibilityResult
    supervision: str
    tightened_constraints_bytes: bytes | None
    expires_at: int | None

    def __init__(self,*args,**kwargs):
        raise TypeError("human-origin evaluation is derived from verified prerequisites")


def combine_human_origin(native: "NativeEvaluationResult", human: HumanEligibilityResult, *, now: int, clock_healthy: bool) -> HumanOriginEvaluationResult:
    """Add human-origin restriction; never transfer qualification or capacity.

    Selection of this route must follow independently authenticated principal
    type. This in-process binding is not a human JWT or wire authorization
    format. Direct human execution needs its separately reviewed adapter.
    """
    import rfc8785
    from .native_evaluation import NativeEvaluationResult
    if type(native) is not NativeEvaluationResult or type(human) is not HumanEligibilityResult or not _time(now):
        raise ValidationError("human origin requires derived native/eligibility results and trusted time")
    def result(reason,supervision="silent_veto",expiry=None):
        value=object.__new__(HumanOriginEvaluationResult)
        for name,member in (("reason",reason),("checked_at",now),("native",native),("human",human),("supervision",supervision),
            ("tightened_constraints_bytes",native.tightened_constraints_bytes),("expires_at",expiry)):
            object.__setattr__(value,name,member)
        return value
    if clock_healthy is not True or native.checked_at!=now or human.checked_at!=now:
        return result("HUMAN_UNAVAILABLE")
    if native.reason!="NATIVE_PREREQUISITES_VALID":return result(native.reason)
    if human.reason!="HUMAN_ELIGIBLE":return result(human.reason)
    actual=_parse_jcs_object(native.association.canonical_request_bytes)
    operation={k:v for k,v in actual.items() if k not in ("version","demand","classification_profile")}
    body=_parse_jcs_object(human.decision_body_bytes)
    if body["actor_type"]!="agent":return result("HUMAN_EXECUTOR_ADAPTER_REQUIRED")
    readiness=native.readiness.readiness
    claims=_parse_jcs_object(native.readiness.proof_verification.authenticated_payload_bytes)
    if (rfc8785.dumps(operation)!=human.operation_bytes or body["principal_id"]!=actual["subject"] or body["actor_id"]!=actual["actor"]
            or human.deployment_profile_digest!=readiness.deployment_profile_digest
            or human.conformance_level!=readiness.conformance_level or human.receiving_zone!=claims["ktp"]["zone"]):
        return result("HUMAN_CONTEXT_MISMATCH")
    expiry=min(native.expires_at,human.expires_at)
    if now>=expiry:return result("HUMAN_UNAVAILABLE")
    return result("HUMAN_ORIGIN_PREREQUISITES_VALID",native.supervision,expiry)


__all__=["InstalledHumanEligibilityVerifier","AuthenticatedHumanContext","HumanEligibilityResult","HumanContextUnavailable",
    "combine_human_origin","HumanOriginEvaluationResult"]
