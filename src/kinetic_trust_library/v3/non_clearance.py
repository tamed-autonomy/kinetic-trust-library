"""Installed Expired/Revoked/Exceeded projections for managed hand-back.

This is a private SDK sum projection, not a newly specified RFC clearance wire.
Source authenticates current managed-relation/lease/intent/stop registry facts.
Clear construction is deliberately unsupported until the complete template,
fresh native decision and relational/hysteresis gates are composed. No result
from this module authorizes action or asserts delivery/record persistence.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from .hand_back import InstalledHandBackVerifier,HandBackAssessment,_instant
from .lease import LeaseProjection,project_lease
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .demand_supplier import _digest
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest


def _profile(p):
    if (set(p)!={"id","version","zone","formula","hand_back_profile_digest","lease_authority","principal_token_max_age_seconds","reissue_path"}
            or any(not _name(p[k]) for k in ("id","zone","lease_authority","reissue_path"))
            or not _time(p["version"]) or p["version"]==0 or not _time(p["principal_token_max_age_seconds"])
            or p["principal_token_max_age_seconds"]==0 or p["formula"]!="authoritative-non-clearance-v1"
            or not is_digest(p["hand_back_profile_digest"])):
        raise ValidationError("invalid selected non-clearance policy")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedNonClearanceContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class NonClearanceAssessment:
    valid: bool
    reason: str
    kind: str | None
    action_permitted: bool
    hand_back: HandBackAssessment | None
    lease: LeaseProjection | None
    reissue_path: str | None
    human_handoff_required: bool
    hysteresis_countable: bool
    adjudication_required_for_counting: bool
    protocol_error_record_required: bool
    defect_route_required: bool
    defect_endpoint: str
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int | None
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("non-clearance requires installed current registry validation")


@dataclass(frozen=True,slots=True)
class InstalledNonClearanceVerifier:
    hand_back_verifier: InstalledHandBackVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.hand_back_verifier) is not InstalledHandBackVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed non-clearance verifier")
        p=_profile(_parse_jcs_object(self.profile_bytes));hb=self.hand_back_verifier
        if p["hand_back_profile_digest"]!=_digest(_parse_jcs_object(hb.profile_bytes),hb.algorithm) or p["zone"]!=_parse_jcs_object(hb.profile_bytes)["zone"]:
            raise ValidationError("non-clearance differs from selected hand-back profile/zone")

    def evaluate(self,message_bytes,*,actual_operation,evaluated_at,clock_healthy):
        if type(message_bytes) is not bytes or not _time(evaluated_at):raise ValidationError("immutable clearance projection and trusted time required")
        hb=self.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes))
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=None;hand_back=None;lease=None;expiry=None
        def result(kind=None,reason="CLEARANCE_PROTOCOL_ERROR"):
            valid=kind is not None;r=object.__new__(NonClearanceAssessment)
            for k,v in dict(valid=valid,reason="CLEARANCE_"+kind.upper() if valid else reason,kind=kind,action_permitted=False,
                hand_back=hand_back if valid else None,lease=lease if valid else None,reissue_path=p["reissue_path"] if kind=="Expired" else None,
                human_handoff_required=valid and kind!="Expired",hysteresis_countable=False,adjudication_required_for_counting=valid and kind!="Expired",
                protocol_error_record_required=not valid,defect_route_required=not valid,
                defect_endpoint=_parse_jcs_object(hb.profile_bytes)["defect_endpoint"],profile_bytes=self.profile_bytes,operation_bytes=op_bytes,
                evaluated_at=evaluated_at,expires_at=expiry if valid else None,
                authenticated_state_bytes=None if source is None else source.state_bytes,
                source_evidence_bytes=None if source is None else source.evidence_bytes).items():object.__setattr__(r,k,v)
            return r
        if clock_healthy is not True or len(message_bytes)>262144:return result()
        try:
            message=_parse_jcs_object(message_bytes);kind=message.get("kind")
            if kind=="Clear":return result(reason="CLEARANCE_CLEAR_UNSUPPORTED")
            if (kind not in ("Expired","Revoked","Exceeded") or set(message)!=({"kind","reissue_path"} if kind=="Expired" else {"kind","hand_back"})):
                return result()
        except (ValidationError,ProofFormatError,ValueError,TypeError,UnicodeError,RecursionError):return result()
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedNonClearanceContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("non-clearance requires authenticated actual current managed-relation state")
        in_hand_back_verifier=False
        try:
            s=_parse_jcs_object(source.state_bytes)
            if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","managed_relation_id","checked_at","expires_at",
                    "principal","consequence_class","mutates_relation","current_grant_epoch","template_digest","lease","intent","adverse_stop"}
                    or s["deployment_digest"]!=_digest(_parse_jcs_object(hb.deployment_profile_bytes),hb.algorithm)
                    or s["profile_digest"]!=_digest(p,hb.algorithm) or s["operation_digest"]!=digest_demand_operation(op,algorithm=hb.algorithm)
                    or s["subject"]!=op["actor"] or s["zone"]!=p["zone"] or not _name(s["managed_relation_id"])
                    or not _name(s["principal"]) or s["consequence_class"] not in ("Logistics","Coordination","Relational")
                    or type(s["mutates_relation"]) is not bool or s["mutates_relation"] and s["consequence_class"]!="Relational"
                    or not _time(s["current_grant_epoch"])
                    or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at):
                return result()
            expiry=s["expires_at"]
            if s["lease"] is not None:
                lease=project_lease(s["lease"],s["intent"],actual_actor=op["actor"],actual_operation_digest=s["operation_digest"],
                    actual_consequence_class=s["consequence_class"],mutates_relation=s["mutates_relation"],principal=s["principal"],
                    lease_authority=p["lease_authority"],template_digest=s["template_digest"],current_grant_epoch=s["current_grant_epoch"],
                    principal_token_max_age_seconds=p["principal_token_max_age_seconds"],evaluated_at=evaluated_at)
            elif s["intent"] is not None:return result()
            adverse=s["adverse_stop"]
            if kind=="Expired":
                if adverse is not None or lease is None or lease.reason!="LEASE_EXPIRED" or message["reissue_path"]!=p["reissue_path"]:
                    return result()
                return result("Expired")
            if (type(adverse) is not dict or set(adverse)!={"id","kind","reason","issued_at","hand_back_digest"}
                    or not _name(adverse["id"]) or adverse["kind"]!=kind or not is_digest(adverse["hand_back_digest"])
                    or _instant(adverse["issued_at"])>evaluated_at):return result()
            revoked={"revoked_by_principal","revoked_by_counterparty","demotion"}
            if (adverse["reason"] in revoked)!=(kind=="Revoked"):return result()
            import rfc8785
            if _digest(message["hand_back"],hb.algorithm)!=adverse["hand_back_digest"]:return result()
            in_hand_back_verifier=True
            hand_back=hb.evaluate(rfc8785.dumps(message["hand_back"]),actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            in_hand_back_verifier=False
            if not hand_back.valid:return result()
            wire=_parse_jcs_object(hand_back.hand_back_bytes);hs=_parse_jcs_object(hand_back.authenticated_state_bytes)
            if (wire["reason"]!=adverse["reason"] or _instant(wire["issued_at"])!=_instant(adverse["issued_at"])
                    or hs["consequence_class"]!=s["consequence_class"] or hs["delegator"]!=s["principal"]
                    or (hs["lease"] is None)!=(lease is None)):return result()
            if lease is not None and (hs["lease"]["id"]!=lease.lease_id or hs["lease"]["issued_at"]!=lease.issued_at
                    or hs["lease"]["template_digest"]!=lease.template_digest):return result()
            expiry=min(expiry,hand_back.expires_at)
            return result(kind)
        except (ValidationError,ProofFormatError,ValueError,TypeError,KeyError,UnicodeError,RecursionError):
            if in_hand_back_verifier:raise
            return result()
