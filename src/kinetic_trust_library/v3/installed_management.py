"""Attested membership history, final demotion hand-backs and public denial.

Source owns actual ingress identity, surface, complete classification/audit
history and retained historical operations. A managed classification is never
clearance. Persisted prior assessments detect history rewriting across calls.
"""
from dataclasses import dataclass
import hashlib
from kinetic_trust_library.errors import ValidationError
from .hand_back import InstalledHandBackVerifier,_instant
from .management import project_management_history,unmanaged_response
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time


def _profile(p):
    if (set(p)-{"delivery_profile_digest"}!={"id","version","zone","formula","hand_back_profile_digest","registry","append_protocol",
            "hostile_facing","wire_silence","admission_endpoint","surface","timing_uniformity_limit"}
            or any(not _name(p[k]) for k in ("id","zone","registry","append_protocol","admission_endpoint","surface"))
            or type(p["timing_uniformity_limit"]) is not str or not 0<len(p["timing_uniformity_limit"])<=4096
            or not _time(p["version"]) or p["version"]==0 or p["formula"]!="attested-management-history-v1"
            or not is_digest(p["hand_back_profile_digest"]) or type(p["hostile_facing"]) is not bool
            or type(p["wire_silence"]) is not bool or p["wire_silence"] and not p["hostile_facing"]):
        raise ValidationError("invalid selected management/surface policy")
    if "delivery_profile_digest" in p and not is_digest(p["delivery_profile_digest"]):raise ValidationError("invalid management delivery selection")
    return p


def _extend_history(current,old,evaluated_at):
    """Validate Source-authenticated or sealed prior history, never raw claims.

    An expired checkpoint still witnesses history; it confers no current
    permission. Source authenticates durable restoration and actual origin.
    """
    scope=("deployment_digest","profile_digest","subject","zone","registry","append_protocol")
    if (type(old) is not dict or set(old)!=set(current) or any(old[k]!=current[k] for k in scope)
            or not _time(old["checked_at"]) or old["checked_at"]>evaluated_at
            or not _time(old["expires_at"]) or old["expires_at"]<=old["checked_at"]
            or type(old["ledger_head"]) is not dict or set(old["ledger_head"])!={"anchor","sequence"}
            or not _name(old["ledger_head"]["anchor"])):
        raise ValidationError("prior management history checkpoint scope/time is invalid")
    project_management_history(history=old["history"],declared_regime=old["regime"],event_count=old["event_count"],
        ledger_head_sequence=old["ledger_head"]["sequence"],evaluated_at=old["checked_at"])
    count=old["event_count"]
    if (current["history"][:count]!=old["history"]
            or any(e["sequence"]<=old["ledger_head"]["sequence"] for e in current["history"][count:])
            or current["ledger_head"]["sequence"]<old["ledger_head"]["sequence"]
            or current["ledger_head"]["sequence"]==old["ledger_head"]["sequence"] and current["ledger_head"]["anchor"]!=old["ledger_head"]["anchor"]):
        raise ValidationError("actual management history rewrites retained classification checkpoint")


@dataclass(frozen=True,slots=True)
class HistoricalDemotionHandBack:
    operation_bytes: bytes
    hand_back_bytes: bytes


@dataclass(frozen=True,slots=True)
class AuthenticatedManagementContext:
    state_bytes: bytes
    hand_backs: tuple
    evidence_bytes: bytes
    retained_checkpoint_bytes: bytes | None=None


@dataclass(frozen=True,slots=True,init=False)
class ManagementAssessment:
    valid: bool
    action_permitted: bool
    management: object
    public_response: object
    hand_backs: tuple
    hand_back_required: bool
    delivery_validation_required: bool
    deliveries: tuple
    verifier: object
    evaluated_at: int
    expires_at: int
    operation_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    retained_checkpoint_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("management requires authenticated complete history")


@dataclass(frozen=True,slots=True)
class InstalledManagementVerifier:
    hand_back_verifier: InstalledHandBackVerifier
    profile_bytes: bytes
    context_source: object
    delivery_verifier: object=None

    def __post_init__(self):
        if (type(self.hand_back_verifier) is not InstalledHandBackVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed management verifier")
        p=_profile(_parse_jcs_object(self.profile_bytes));hb=self.hand_back_verifier;hp=_parse_jcs_object(hb.profile_bytes)
        if p["zone"]!=hp["zone"] or p["hand_back_profile_digest"]!=_digest(hp,hb.algorithm):
            raise ValidationError("management hand-back deployment/profile differs")
        if ("delivery_profile_digest" in p)!=(self.delivery_verifier is not None):
            raise ValidationError("management delivery selection must be symmetric")
        if self.delivery_verifier is not None:
            from .installed_delivery import InstalledHandBackDeliveryVerifier
            dv=self.delivery_verifier
            if (type(dv) is not InstalledHandBackDeliveryVerifier or dv.hand_back_verifier is not hb
                    or p["delivery_profile_digest"]!=_digest(_parse_jcs_object(dv.profile_bytes),hb.algorithm)):
                raise ValidationError("management delivery verifier differs from installed hand-back graph")

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy,credential_bytes=None,previous_assessment=None):
        if (not _time(evaluated_at) or clock_healthy is not True
                or credential_bytes is not None and type(credential_bytes) is not bytes):
            raise ValidationError("current trusted management time and immutable credential required")
        hb=self.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes))
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        credential_digest=None if credential_bytes is None else "sha256:"+hashlib.sha256(credential_bytes).hexdigest()
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,credential_bytes=credential_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedManagementContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes
                or source.retained_checkpoint_bytes is not None and (type(source.retained_checkpoint_bytes) is not bytes or len(source.retained_checkpoint_bytes)>262144)
                or type(source.hand_backs) is not tuple or len(source.hand_backs)>4096):
            raise ValidationError("management Source must authenticate complete classification history")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at",
                "registry","append_protocol","credential_digest","request_kind","regime","history","event_count","ledger_head","surface"}
                or s["deployment_digest"]!=_digest(_parse_jcs_object(hb.deployment_profile_bytes),hb.algorithm)
                or s["profile_digest"]!=_digest(p,hb.algorithm) or s["operation_digest"]!=digest_demand_operation(op,algorithm=hb.algorithm)
                or s["subject"]!=op["actor"] or s["zone"]!=p["zone"] or s["registry"]!=p["registry"]
                or s["append_protocol"]!=p["append_protocol"] or s["surface"]!=p["surface"]
                or s["credential_digest"]!=credential_digest or s["request_kind"] not in ("action","admission")
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or type(s["ledger_head"]) is not dict or set(s["ledger_head"])!={"anchor","sequence"}
                or not _name(s["ledger_head"]["anchor"])):
            raise ValidationError("management history differs from actual ingress/deployment/current scope")
        management=project_management_history(history=s["history"],declared_regime=s["regime"],event_count=s["event_count"],
            ledger_head_sequence=s["ledger_head"]["sequence"],evaluated_at=evaluated_at)
        if source.retained_checkpoint_bytes is not None:
            _extend_history(s,_parse_jcs_object(source.retained_checkpoint_bytes),evaluated_at)
        if previous_assessment is not None:
            previous=previous_assessment
            if type(previous) is not ManagementAssessment or previous.verifier is not self or previous.evaluated_at>evaluated_at:
                raise ValidationError("prior management history must be a bound installed checkpoint")
            old=_parse_jcs_object(previous.authenticated_state_bytes)
            _extend_history(s,old,evaluated_at)
        records={};total=0
        for item in source.hand_backs:
            if (type(item) is not HistoricalDemotionHandBack or type(item.operation_bytes) is not bytes
                    or type(item.hand_back_bytes) is not bytes or len(item.operation_bytes)>262144 or len(item.hand_back_bytes)>262144):
                raise ValidationError("historical demotion requires original immutable operation/hand-back")
            total+=len(item.operation_bytes)+len(item.hand_back_bytes)
            if total>1048576:raise ValidationError("historical hand-back archive exceeds selected adapter bound")
            digest=hb.algorithm+":"+hashlib.new(hb.algorithm,item.hand_back_bytes).hexdigest()
            if digest in records:raise ValidationError("duplicate historical final hand-back")
            records[digest]=item
        if set(records)-set(management.demotion_digests):raise ValidationError("orphan final hand-back outside attested history")
        assessments=[];deliveries=[];missing=False;expiry=s["expires_at"];delivery_required=False
        for event in s["history"]:
            if event["kind"]!="demoted":continue
            item=records.get(event["hand_back_digest"])
            if item is None:missing=True;delivery_required=True;continue
            historical_op=_parse_jcs_object(item.operation_bytes)
            if historical_op.get("actor")!=s["subject"]:missing=True;delivery_required=True;continue
            assessment=hb.evaluate(item.hand_back_bytes,actual_operation=historical_op,evaluated_at=evaluated_at,clock_healthy=True)
            if not assessment.valid:missing=True;delivery_required=True;continue
            wire=_parse_jcs_object(item.hand_back_bytes)
            if wire["reason"]!="demotion" or _instant(wire["issued_at"])!=event["occurred_at"]:
                missing=True;delivery_required=True;continue
            assessments.append(assessment);expiry=min(expiry,assessment.expires_at)
            if self.delivery_verifier is None:delivery_required=True
            else:
                delivery=self.delivery_verifier.evaluate(item.hand_back_bytes,actual_operation=historical_op,
                    evaluated_at=evaluated_at,clock_healthy=True)
                deliveries.append(delivery);expiry=min(expiry,delivery.expires_at)
                if (delivery.hand_back_digest!=event["hand_back_digest"] or not delivery.effort_current
                        or delivery.projection.delivery_state!="delivered" or delivery.projection.acknowledgment_due):delivery_required=True
        public=None
        if management.regime=="unmanaged":
            public=unmanaged_response(hostile_facing=p["hostile_facing"],wire_silence=p["wire_silence"] and not delivery_required,
                admission=s["request_kind"]=="admission",admission_endpoint=p["admission_endpoint"],credential_bytes=credential_bytes)
        r=object.__new__(ManagementAssessment)
        for k,v in dict(valid=not missing,action_permitted=False,management=management,public_response=public,hand_backs=tuple(assessments),
            hand_back_required=missing,delivery_validation_required=delivery_required,deliveries=tuple(deliveries),verifier=self,evaluated_at=evaluated_at,expires_at=expiry,
            operation_bytes=op_bytes,authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(r,k,v)
        object.__setattr__(r,"retained_checkpoint_bytes",source.retained_checkpoint_bytes)
        return r
