"""Installed registered hand-back validation, not clearance or delivery.

Raw wire is untrusted until schema AND authenticated template/scope/context
checks pass. Source owns real registry/authority, ciphertext content and key
custody, registered redaction, actual recipient capacity/receipt facts. Library
checks complete bindings and returns recording/routing/delivery obligations;
it never asserts durable delivery, grants clearance or opens a record itself.
"""
from dataclasses import dataclass
from datetime import datetime,timezone
from fractions import Fraction
from functools import lru_cache
from importlib.resources import files
import hashlib,json,re
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest


def _instant(text):
    """Compare RFC3339 fractional seconds exactly, never truncate to microseconds."""
    match=re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})",text)
    if match is None:raise ValidationError("invalid hand-back instant")
    date,clock,fraction,offset=match.groups()
    dt=datetime.fromisoformat(date+"T"+clock+("+00:00" if offset in ("Z","z") else offset))
    delta=dt.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
    result=Fraction(delta.days*86400+delta.seconds)+(Fraction(int(fraction),10**len(fraction)) if fraction else 0)
    if not 0<=result<=2**53-1:raise ValidationError("hand-back instant outside supported clock range")
    return result


def _strings(items):
    if type(items) is not list or len(items)>4096 or any(not _name(i) for i in items) or len(set(items))!=len(items):
        raise ValidationError("complete distinct hand-back identity inventory required")
    return set(items)


@lru_cache(maxsize=1)
def _wire_validator():
    from jsonschema import Draft202012Validator
    from .schema_formats import installed_format_checker
    raw=files("kinetic_trust_library.v3").joinpath("schemas/hand-back.json").read_bytes()
    if hashlib.sha256(raw).hexdigest()!="16b35ea7f651d08551b35c5cd978d2b52889438640974fa27d963ce5510a8be4":
        raise ValidationError("installed hand-back schema differs from retained RFC pin")
    schema=json.loads(raw)
    return Draft202012Validator(schema,format_checker=installed_format_checker())


def _profile(p):
    if (set(p)!={"id","version","zone","defect_endpoint","formula","classes"}
            or any(not _name(p[k]) for k in ("id","zone","defect_endpoint")) or not _time(p["version"]) or p["version"]==0
            or p["formula"] not in ("registered-template-and-sealed-context-v1","registered-template-and-sealed-context-v2") or type(p["classes"]) is not dict
            or set(p["classes"])!={"Logistics","Coordination","Relational"}):
        raise ValidationError("invalid selected hand-back profile")
    for kind,c in p["classes"].items():
        if (type(c) is not dict or set(c)!={"ack_sla_seconds","minimum_reissue_seconds"}
                or not _time(c["ack_sla_seconds"]) or c["ack_sla_seconds"]==0 or not _time(c["minimum_reissue_seconds"])
                or kind!="Logistics" and c["minimum_reissue_seconds"]==0):
            raise ValidationError("hand-back classes require declared SLA and reissue floor")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedHandBackContext:
    state_bytes: bytes
    ciphertext_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class HandBackAssessment:
    valid: bool
    reason: str
    action_permitted: bool
    hand_back_bytes: bytes | None
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int | None
    delivery_state: str | None
    delivery_effort_required: bool
    protocol_error_record_required: bool
    defect_route_required: bool
    defect_endpoint: str
    authenticated_state_bytes: bytes | None
    ciphertext_bytes: bytes | None
    source_evidence_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("hand-backs require installed registered-template validation")


@dataclass(frozen=True,slots=True)
class InstalledHandBackVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed hand-back verifier")
        _parse_jcs_object(self.deployment_profile_bytes);_profile(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,hand_back_bytes,*,actual_operation,evaluated_at,clock_healthy):
        if type(hand_back_bytes) is not bytes or not _time(evaluated_at):
            raise ValidationError("hand-back verification requires immutable bytes and current time")
        operation_bytes=canonical_demand_operation_bytes(actual_operation)
        op=_parse_jcs_object(operation_bytes);p=_profile(_parse_jcs_object(self.profile_bytes))
        source=None
        def result(valid,delivery=None):
            r=object.__new__(HandBackAssessment)
            for k,v in dict(valid=valid,reason="HAND_BACK_VALID" if valid else "HAND_BACK_PROTOCOL_ERROR",action_permitted=False,
                    hand_back_bytes=hand_back_bytes if valid else None,profile_bytes=self.profile_bytes,operation_bytes=operation_bytes,
                    evaluated_at=evaluated_at,expires_at=state["expires_at"] if valid else None,delivery_state=delivery,
                    delivery_effort_required=valid and delivery=="parked",protocol_error_record_required=not valid,defect_route_required=not valid,
                    defect_endpoint=p["defect_endpoint"],authenticated_state_bytes=None if source is None else source.state_bytes,
                    ciphertext_bytes=source.ciphertext_bytes if valid else None,
                    source_evidence_bytes=None if source is None else source.evidence_bytes).items():object.__setattr__(r,k,v)
            return r
        if clock_healthy is not True or len(hand_back_bytes)>262144:return result(False)
        try:
            wire=_parse_jcs_object(hand_back_bytes)
            if not _wire_validator().is_valid(wire):return result(False)
            issued=_instant(wire["issued_at"]);reissue=_instant(wire["reissue_not_before"])
        except (ValidationError,ProofFormatError,ValueError,TypeError,UnicodeError,RecursionError):return result(False)
        # Operational Source failures propagate. An unavailable registry is not
        # evidence that the requester supplied a malformed hand-back.
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=operation_bytes,hand_back_bytes=hand_back_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedHandBackContext or type(source.state_bytes) is not bytes
                or len(source.state_bytes)>262144 or type(source.ciphertext_bytes) is not bytes or not 0<len(source.ciphertext_bytes)<=1048576
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("hand-back Source must authenticate complete template/context/delivery facts")
        try:
            state=_parse_jcs_object(source.state_bytes)
            delivery=self._validate(state,wire,issued,reissue,p,op,evaluated_at,source.ciphertext_bytes)
        except (ValidationError,ProofFormatError,ValueError,TypeError,KeyError,UnicodeError,RecursionError):return result(False)
        return result(True,delivery)

    def _validate(self,s,w,issued,reissue,p,op,now,ciphertext):
        expected={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","subject","subject_profile","zone",
                "consequence_class","action_id","reason","stop_origin","delegator","operator","operator_affiliates","measurers","lease",
                "issued_at","reissue_not_before","template","bundle","delivery"}
        if p["formula"]=="registered-template-and-sealed-context-v2":expected.add("sovereign_authority")
        if (set(s)!=expected
                or s["deployment_digest"]!=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
                or s["profile_digest"]!=_digest(p,self.algorithm) or s["operation_digest"]!=digest_demand_operation(op,algorithm=self.algorithm)
                or s["subject"]!=op["actor"] or s["subject_profile"] not in ("software","person") or s["zone"]!=p["zone"]
                or not _time(s["checked_at"]) or s["checked_at"]!=now or not _time(s["expires_at"]) or s["expires_at"]<=now
                or s["consequence_class"] not in p["classes"] or s["action_id"]!=w["action"] or s["reason"]!=w["reason"]
                or s["stop_origin"] not in ("system","principal","sovereign","undetermined") or issued>now
                or issued!=_instant(s["issued_at"]) or reissue!=_instant(s["reissue_not_before"])
                or not _name(s["delegator"]) or not _name(s["operator"])):
            raise ValidationError("hand-back differs from actual stop scope")
        c=p["classes"][s["consequence_class"]]
        if reissue<issued+c["minimum_reissue_seconds"]:raise ValidationError("reissue below declared class floor")
        from .hand_back_template import validate_template,select_recourse,V2
        if p["formula"]==V2 and not (s["stop_origin"]=="sovereign" and _name(s["sovereign_authority"])
                or s["stop_origin"]!="sovereign" and s["sovereign_authority"] is None):
            raise ValidationError("actual sovereign authority binding differs from stop origin")
        t=validate_template(s,p,issued)
        lease=s["lease"]
        if lease is not None:
            if (type(lease) is not dict or set(lease)!={"id","subject","consequence_class","issued_at","template_digest"}
                    or not _name(lease["id"]) or lease["subject"]!=s["subject"] or lease["consequence_class"]!=s["consequence_class"]
                    or not _time(lease["issued_at"]) or not t["registered_at"]<=lease["issued_at"]<=issued
                    or lease["template_digest"]!=_digest(t,self.algorithm)):
                raise ValidationError("hand-back template differs from actual registered grant template")
        recipient=t["recipient"]
        if w["recipient"]!={k:recipient[k] for k in ("endpoint","ack_sla_seconds")}:
            raise ValidationError("wire recipient differs from registered template")
        repair=t["repair"]
        if w["repair"]!=repair["ref"]:
            raise ValidationError("registered repair route must answer the same subject")
        recourse=select_recourse(t,p,s["stop_origin"],s.get("sovereign_authority"))
        if any(w["recourse"][k]!=recourse[k] for k in ("kind","ref")):
            raise ValidationError("recourse differs from registered template")
        kind=recourse["kind"]
        expected={"system":"contest","principal":"contest","sovereign":"closed_by_authority","undetermined":"undetermined"}[s["stop_origin"]]
        if kind!=expected or (s["reason"]=="exceeded_soul")!=(s["stop_origin"]=="sovereign"):
            raise ValidationError("stop origin requires its own recourse arm")
        bundle=s["bundle"];digest=self.algorithm+":"+hashlib.new(self.algorithm,ciphertext).hexdigest()
        if (type(bundle) is not dict or set(bundle)!={"sealed_to","ciphertext_digest","recipient_endpoint","sections","tier","redaction_policy_digest","agent_can_read"}
                or bundle["sealed_to"]!=recipient["key_id"] or bundle["recipient_endpoint"]!=recipient["endpoint"]
                or bundle["ciphertext_digest"]!=digest or w["context"]!={"sealed_to":bundle["sealed_to"],"ciphertext_digest":digest}
                or bundle["redaction_policy_digest"]!=t["redaction_policy_digest"] or bundle["agent_can_read"] is not False
                or bundle["tier"]!="full" or _strings(bundle["sections"])!={"action","lease_history","environment_attestations","work_product"}):
            raise ValidationError("hand-back requires actual full sealed recipient context")
        d=s["delivery"]
        if (type(d) is not dict or set(d)!={"channel_reachable","capacity","accepted_at","receipt_ref","attempts"}
                or type(d["channel_reachable"]) is not bool or d["capacity"] not in ("available","exhausted","unknown")
                or not _time(d["attempts"]) or not (d["accepted_at"] is None and d["receipt_ref"] is None
                    or _time(d["accepted_at"]) and issued<=d["accepted_at"]<=now and _name(d["receipt_ref"]))):
            raise ValidationError("actual capacity-aware delivery evidence required")
        delivery="delivered" if d["channel_reachable"] and d["capacity"]=="available" and d["accepted_at"] is not None else "parked"
        if "delivery" in w and (w["delivery"]["state"]!=delivery or w["delivery"].get("attempts",d["attempts"])!=d["attempts"]):
            raise ValidationError("wire delivery assertion differs from actual capacity/receipt")
        return delivery
