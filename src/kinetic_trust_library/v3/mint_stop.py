"""Installed mint-refusal and authority-silence record obligations (§6.3).

This private adapter monitors pending/refused requests. Successful issuance is
validated through lease/formation/current-clearance composition, not here.
Source authenticates the complete actual request/response/record history.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .hand_back import InstalledHandBackVerifier, HandBackAssessment, _instant
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
from .execution_observation import _name, _digest as is_digest
from .root_lifecycle import _time
from .bootstrap_hand_back import InstalledBootstrapHandBackVerifier,BootstrapHandBackAssessment


def _profile(p):
    if (set(p)-{"bootstrap_profile_digest"}!={"id","version","zone","formula","hand_back_profile_digest","authority",
            "response_sla_seconds","default_hand_back_endpoint"}
            or any(not _name(p[k]) for k in ("id","zone","authority","default_hand_back_endpoint"))
            or not _time(p["version"]) or p["version"]==0
            or not _time(p["response_sla_seconds"]) or p["response_sla_seconds"]==0
            or p["formula"]!="mint-refusal-and-silence-v1" or not is_digest(p["hand_back_profile_digest"])):
        raise ValidationError("invalid selected mint-stop profile")
    if "bootstrap_profile_digest" in p and not is_digest(p["bootstrap_profile_digest"]):raise ValidationError("invalid selected bootstrap profile")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedMintStopContext:
    state_bytes: bytes
    hand_back_bytes: bytes | None
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class MintStopAssessment:
    valid: bool
    reason: str
    status: str | None
    action_permitted: bool
    attributed_to: str
    route: str | None
    deadline: int | None
    silence_record_required: bool
    routing_required: bool
    hand_back_required: bool
    hand_back: HandBackAssessment | BootstrapHandBackAssessment | None
    expires_at: int | None
    evaluated_at: int
    profile_bytes: bytes
    operation_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("mint-stop assessment requires installed authority history")


@dataclass(frozen=True,slots=True)
class InstalledMintStopVerifier:
    hand_back_verifier: InstalledHandBackVerifier
    profile_bytes: bytes
    context_source: object
    bootstrap_verifier: InstalledBootstrapHandBackVerifier | None=None

    def __post_init__(self):
        if (type(self.hand_back_verifier) is not InstalledHandBackVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed mint-stop verifier")
        p=_profile(_parse_jcs_object(self.profile_bytes));hb=self.hand_back_verifier
        hp=_parse_jcs_object(hb.profile_bytes)
        if p["hand_back_profile_digest"]!=_digest(hp,hb.algorithm) or p["zone"]!=hp["zone"]:
            raise ValidationError("mint-stop and hand-back profiles differ")
        bv=self.bootstrap_verifier
        if ("bootstrap_profile_digest" in p)!=(bv is not None):raise ValidationError("mint-stop bootstrap selection must be symmetric")
        if bv is not None:
            if (type(bv) is not InstalledBootstrapHandBackVerifier or bv.deployment_profile_bytes!=hb.deployment_profile_bytes
                    or bv.algorithm!=hb.algorithm or p["bootstrap_profile_digest"]!=_digest(_parse_jcs_object(bv.profile_bytes),hb.algorithm)):
                raise ValidationError("bootstrap differs from installed authority/deployment policy")
            bp=_parse_jcs_object(bv.profile_bytes)
            if (bp["zone"]!=p["zone"] or bp["lease_authority"]!=p["authority"]
                    or bp["default_endpoint"]!=p["default_hand_back_endpoint"] or bp["defect_endpoint"]!=hp["defect_endpoint"]
                    or any(any(bp["classes"][kind][key]!=c[key] for key in ("ack_sla_seconds","minimum_reissue_seconds")) for kind,c in hp["classes"].items())):
                raise ValidationError("bootstrap return defaults differ from actual hand-back/authority declarations")
            if bv.hysteresis_verifier is not hb.hysteresis_verifier:
                raise ValidationError("bootstrap must preserve the exact installed hand-back hysteresis policy")

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at):raise ValidationError("trusted mint-stop evaluation time required")
        hb=self.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes))
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,
            profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedMintStopContext or type(source.state_bytes) is not bytes
                or len(source.state_bytes)>262144 or type(source.evidence_bytes) is not bytes or not source.evidence_bytes
                or source.hand_back_bytes is not None and (type(source.hand_back_bytes) is not bytes or len(source.hand_back_bytes)>262144)):
            raise ValidationError("mint-stop Source requires complete actual authority request/response history")
        deadline=None;route=None;hand_back=None;expiry=None;debt=False;route_debt=False
        def result(status=None,reason="MINT_STOP_INVALID",needs_hand_back=False):
            r=object.__new__(MintStopAssessment)
            for k,v in dict(valid=status is not None,reason=reason,status=status,action_permitted=False,
                attributed_to=p["authority"],route=route,deadline=deadline,silence_record_required=debt,
                routing_required=route_debt,hand_back_required=needs_hand_back,hand_back=hand_back,
                expires_at=expiry if status is not None else None,evaluated_at=evaluated_at,profile_bytes=self.profile_bytes,
                operation_bytes=op_bytes,authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():
                object.__setattr__(r,k,v)
            return r
        if clock_healthy is not True:return result()
        child_call=False
        try:
            s=_parse_jcs_object(source.state_bytes)
            if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at",
                    "request","response","silence_record","authority_declaration"}
                    or s["deployment_digest"]!=_digest(_parse_jcs_object(hb.deployment_profile_bytes),hb.algorithm)
                    or s["profile_digest"]!=_digest(p,hb.algorithm)
                    or s["operation_digest"]!=digest_demand_operation(op,algorithm=hb.algorithm)
                    or s["subject"]!=op["actor"] or s["zone"]!=p["zone"]
                    or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                    or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at):return result()
            q=s["request"]
            request_fields={"id","anchor","requested_at","principal","principal_channel","consequence_class"}
            if self.bootstrap_verifier is not None:request_fields.add("template_digest")
            if (type(q) is not dict or set(q)!=request_fields
                    or any(not _name(q[k]) for k in ("id","anchor","principal"))
                    or q["principal_channel"] is not None and not _name(q["principal_channel"])
                    or q["consequence_class"] not in ("Logistics","Coordination","Relational")
                    or not _time(q["requested_at"]) or q["requested_at"]>evaluated_at):return result()
            if self.bootstrap_verifier is not None and q["template_digest"] is not None and not is_digest(q["template_digest"]):return result()
            declaration=s["authority_declaration"]
            if (type(declaration) is not dict or set(declaration)!={"anchor","profile_digest","declared_at"}
                    or not _name(declaration["anchor"]) or declaration["anchor"]==q["anchor"]
                    or declaration["profile_digest"]!=s["profile_digest"]
                    or not _time(declaration["declared_at"]) or declaration["declared_at"]>q["requested_at"]):return result()
            deadline=q["requested_at"]+p["response_sla_seconds"]
            route=q["principal_channel"] or p["default_hand_back_endpoint"]
            expiry=s["expires_at"];reply=s["response"];status="pending"
            if reply is not None:
                if type(reply) is dict and reply.get("kind")=="Minted":
                    return result(reason="MINT_SUCCESS_REQUIRES_CLEARANCE")
                if (type(reply) is not dict or set(reply)!={"kind","authority","request_id","anchor","responded_at","hand_back_digest"}
                        or reply["kind"]!="Refused" or reply["authority"]!=p["authority"] or reply["request_id"]!=q["id"]
                        or not _name(reply["anchor"]) or reply["anchor"]==q["anchor"]
                        or not _time(reply["responded_at"]) or not q["requested_at"]<=reply["responded_at"]<=evaluated_at
                        or not is_digest(reply["hand_back_digest"])):return result()
                status="Refused"
            silence=(reply["responded_at"]>deadline if reply is not None else evaluated_at>=deadline)
            debt=route_debt=silence
            record=s["silence_record"]
            if record is not None:
                if (not silence or type(record) is not dict or set(record)!={"anchor","authority","request_id","occurred_at","route","route_receipt"}
                        or not _name(record["anchor"]) or record["anchor"] in (q["anchor"],None if reply is None else reply["anchor"])
                        or record["authority"]!=p["authority"] or record["request_id"]!=q["id"] or record["route"]!=route
                        or not _time(record["occurred_at"]) or not deadline<=record["occurred_at"]<=evaluated_at):return result()
                debt=False
                receipt=record["route_receipt"]
                if receipt is not None:
                    if (type(receipt) is not dict or set(receipt)!={"anchor","accepted_at","endpoint","record_anchor","request_id"}
                            or not _name(receipt["anchor"]) or receipt["anchor"] in (q["anchor"],record["anchor"],None if reply is None else reply["anchor"])
                            or receipt["record_anchor"]!=record["anchor"] or receipt["request_id"]!=q["id"]
                            or receipt["endpoint"]!=route or not _time(receipt["accepted_at"])
                            or not record["occurred_at"]<=receipt["accepted_at"]<=evaluated_at):return result()
                    route_debt=False
            if status=="pending":
                if source.hand_back_bytes is not None:return result()
                if evaluated_at<deadline:expiry=min(expiry,deadline)
                return result(status,"MINT_AUTHORITY_PENDING")
            if source.hand_back_bytes is None:return result(reason="MINT_REFUSAL_HAND_BACK_REQUIRED",needs_hand_back=True)
            wire=_parse_jcs_object(source.hand_back_bytes)
            if _digest(wire,hb.algorithm)!=reply["hand_back_digest"]:return result()
            child_call=True
            bootstrap=self.bootstrap_verifier is not None and q["template_digest"] is None
            if bootstrap:
                hand_back=self.bootstrap_verifier.evaluate(source.hand_back_bytes,request_id=q["id"],request_anchor=q["anchor"],
                    actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            else:hand_back=hb.evaluate(source.hand_back_bytes,actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            child_call=False
            if not hand_back.valid:return result(needs_hand_back=True)
            hs=_parse_jcs_object(hand_back.authenticated_state_bytes)
            if bootstrap and hs["mint_request"]!=q:return result()
            if self.bootstrap_verifier is not None and not bootstrap and q["template_digest"]!=_digest(hs["template"],hb.algorithm):return result()
            if (wire["reason"]!="mint_refused" or _instant(wire["issued_at"])!=reply["responded_at"]
                    or hs["lease"] is not None or hs["stop_origin"]!="system" or hs["delegator"]!=q["principal"]
                    or hs["consequence_class"]!=q["consequence_class"]):return result()
            expiry=min(expiry,hand_back.expires_at)
            return result(status,"MINT_AUTHORITY_REFUSED")
        except (ValidationError,ProofFormatError,ValueError,TypeError,KeyError,UnicodeError,RecursionError):
            if child_call:raise
            return result()
