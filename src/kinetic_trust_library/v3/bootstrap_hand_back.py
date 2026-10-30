"""Sealed mint-refusal return path when no validated template exists (§6.3).

The requesting principal/default endpoint and independently predeclared return
policy replace no template: this distinct type can never establish Clear.
Source authenticates the actual mint request, historical registry absence,
policy declaration, accountable recipient/key, independent routes and ciphertext.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from .hand_back import _wire_validator,_instant,_sealed_delivery
from .hand_back_template import validate_return_path
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .demand_supplier import _digest
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time


def _profile(p):
    if (set(p)-{"hysteresis_profile_digest"}!={"id","version","zone","formula","lease_authority","template_registry","defect_endpoint","default_endpoint","classes"}
            or any(not _name(p[k]) for k in ("id","zone","lease_authority","template_registry","defect_endpoint","default_endpoint"))
            or not _time(p["version"]) or p["version"]==0 or p["formula"]!="mint-request-sealed-bootstrap-v1"
            or type(p["classes"]) is not dict or set(p["classes"])!={"Logistics","Coordination","Relational"}):
        raise ValidationError("invalid selected bootstrap return policy")
    if "hysteresis_profile_digest" in p and not is_digest(p["hysteresis_profile_digest"]):raise ValidationError("invalid selected bootstrap hysteresis")
    for kind,c in p["classes"].items():
        if (type(c) is not dict or set(c)!={"ack_sla_seconds","minimum_reissue_seconds","recourse_ref","repair_ref","redaction_policy_digest"}
                or not _time(c["ack_sla_seconds"]) or c["ack_sla_seconds"]==0 or not _time(c["minimum_reissue_seconds"])
                or kind!="Logistics" and c["minimum_reissue_seconds"]==0
                or any(not _name(c[k]) for k in ("recourse_ref","repair_ref")) or not is_digest(c["redaction_policy_digest"])):
            raise ValidationError("bootstrap classes require predeclared scaled return defaults")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedBootstrapHandBackContext:
    state_bytes: bytes
    ciphertext_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class BootstrapHandBackAssessment:
    valid: bool
    reason: str
    construction_origin: str
    clearance_capable: bool
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
    hysteresis: object

    def __init__(self,*args,**kwargs):raise TypeError("bootstrap hand-back requires authenticated mint-refusal fallback validation")


@dataclass(frozen=True,slots=True)
class InstalledBootstrapHandBackVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str
    hysteresis_verifier: object=None

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed bootstrap hand-back verifier")
        _parse_jcs_object(self.deployment_profile_bytes);p=_profile(_parse_jcs_object(self.profile_bytes))
        hv=self.hysteresis_verifier
        if ("hysteresis_profile_digest" in p)!=(hv is not None):raise ValidationError("bootstrap hysteresis selection must be symmetric")
        if hv is not None:
            from .installed_hysteresis import InstalledHandBackHysteresisVerifier
            if (type(hv) is not InstalledHandBackHysteresisVerifier or hv.deployment_profile_bytes!=self.deployment_profile_bytes
                    or hv.algorithm!=self.algorithm or p["hysteresis_profile_digest"]!=_digest(_parse_jcs_object(hv.profile_bytes),self.algorithm)):
                raise ValidationError("bootstrap hysteresis differs from installed deployment/profile")
            hp=_parse_jcs_object(hv.profile_bytes)
            if hp["zone"]!=p["zone"] or any(hp["classes"][kind]["minimum_seconds"]!=c["minimum_reissue_seconds"] for kind,c in p["classes"].items()):
                raise ValidationError("bootstrap/hysteresis class declarations differ")

    def evaluate(self,hand_back_bytes,*,request_id,request_anchor,actual_operation,evaluated_at,clock_healthy):
        if (type(hand_back_bytes) is not bytes or not _name(request_id) or not _name(request_anchor) or not _time(evaluated_at)):
            raise ValidationError("immutable refusal and actual mint-request references required")
        p=_profile(_parse_jcs_object(self.profile_bytes));op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=None;expiry=None;hysteresis=None
        def result(valid=False,delivery=None):
            r=object.__new__(BootstrapHandBackAssessment)
            for k,v in dict(valid=valid,reason="BOOTSTRAP_HAND_BACK_VALID" if valid else "HAND_BACK_PROTOCOL_ERROR",
                construction_origin="mint-request-fallback",clearance_capable=False,action_permitted=False,
                hand_back_bytes=hand_back_bytes if valid else None,profile_bytes=self.profile_bytes,operation_bytes=op_bytes,
                evaluated_at=evaluated_at,expires_at=expiry if valid else None,delivery_state=delivery,
                delivery_effort_required=valid and delivery=="parked",protocol_error_record_required=not valid,
                defect_route_required=not valid,defect_endpoint=p["defect_endpoint"],
                authenticated_state_bytes=None if source is None else source.state_bytes,
                ciphertext_bytes=source.ciphertext_bytes if valid else None,
                source_evidence_bytes=None if source is None else source.evidence_bytes,hysteresis=hysteresis).items():object.__setattr__(r,k,v)
            return r
        if clock_healthy is not True or len(hand_back_bytes)>262144:return result()
        try:
            w=_parse_jcs_object(hand_back_bytes)
            if not _wire_validator().is_valid(w) or w["reason"]!="mint_refused":return result()
            issued=_instant(w["issued_at"]);reissue=_instant(w["reissue_not_before"])
        except (ValidationError,ProofFormatError,ValueError,TypeError,UnicodeError,RecursionError):return result()
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            request_id=request_id,request_anchor=request_anchor,operation_bytes=op_bytes,hand_back_bytes=hand_back_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedBootstrapHandBackContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.ciphertext_bytes) is not bytes or not 0<len(source.ciphertext_bytes)<=1048576
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("bootstrap Source requires authenticated actual missing-template refusal and sealed return facts")
        try:
            s=_parse_jcs_object(source.state_bytes)
            expected={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","subject","subject_profile","zone",
                    "consequence_class","mutates_relation","action_id","delegator","operator","operator_affiliates","measurers","issued_at",
                    "reissue_not_before","bundle","delivery","lease_authority","reason","stop_origin","lease","mint_request","policy_declaration",
                    "template_lookup","fallback"}
            if self.hysteresis_verifier is not None:expected.add("stop_anchor")
            if (set(s)!=expected
                    or s["deployment_digest"]!=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
                    or s["profile_digest"]!=_digest(p,self.algorithm) or s["operation_digest"]!=digest_demand_operation(op,algorithm=self.algorithm)
                    or s["subject"]!=op["actor"] or s["subject_profile"] not in ("software","person") or s["zone"]!=p["zone"]
                    or s["lease_authority"]!=p["lease_authority"] or s["lease"] is not None or s["reason"]!="mint_refused" or s["stop_origin"]!="system"
                    or s["action_id"]!=w["action"] or not _name(s["delegator"]) or not _name(s["operator"])
                    or s["consequence_class"] not in p["classes"] or type(s["mutates_relation"]) is not bool
                    or s["mutates_relation"] and s["consequence_class"]!="Relational"
                    or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                    or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at or issued>evaluated_at
                    or issued!=_instant(s["issued_at"]) or reissue!=_instant(s["reissue_not_before"])):return result()
            q=s["mint_request"];d=s["policy_declaration"];lookup=s["template_lookup"];f=s["fallback"];c=p["classes"][s["consequence_class"]]
            if (type(q) is not dict or set(q)!={"id","anchor","requested_at","principal","principal_channel","consequence_class","template_digest"}
                    or q["id"]!=request_id or q["anchor"]!=request_anchor or q["template_digest"] is not None
                    or q["principal"]!=s["delegator"] or s["subject_profile"]=="person" and q["principal"]!=s["subject"]
                    or q["principal_channel"] is not None and not _name(q["principal_channel"])
                    or q["consequence_class"]!=s["consequence_class"] or not _time(q["requested_at"]) or q["requested_at"]>issued
                    or type(d) is not dict or set(d)!={"anchor","profile_digest","declared_at"}
                    or not _name(d["anchor"]) or d["anchor"]==request_anchor or d["profile_digest"]!=s["profile_digest"]
                    or not _time(d["declared_at"]) or d["declared_at"]>q["requested_at"]
                    or type(lookup) is not dict or set(lookup)!={"anchor","registry","as_of","request_anchor","template_digest"}
                    or not _name(lookup["anchor"]) or lookup["anchor"] in (d["anchor"],request_anchor)
                    or lookup["registry"]!=p["template_registry"] or lookup["request_anchor"]!=request_anchor or lookup["template_digest"] is not None
                    or not _time(lookup["as_of"]) or lookup["as_of"]!=q["requested_at"]
                    or type(f) is not dict or set(f)!={"recipient","recourse","repair","redaction_policy_digest"}
                    or f["redaction_policy_digest"]!=c["redaction_policy_digest"] or reissue<issued+c["minimum_reissue_seconds"]):return result()
            validate_return_path(s,p,f)
            recipient=f["recipient"]
            if (recipient["endpoint"]!=(q["principal_channel"] or p["default_endpoint"])
                    or w["recipient"]!={k:recipient[k] for k in ("endpoint","ack_sla_seconds")}
                    or f["recourse"]["kind"]!="contest" or f["recourse"]["ref"]!=c["recourse_ref"]
                    or w["recourse"]!={k:f["recourse"][k] for k in ("kind","ref")}
                    or f["repair"]["ref"]!=c["repair_ref"] or w["repair"]!=c["repair_ref"]):return result()
            delivery=_sealed_delivery(s,w,issued,evaluated_at,recipient,f["redaction_policy_digest"],source.ciphertext_bytes,self.algorithm)
            expiry=s["expires_at"]
        except (ValidationError,ProofFormatError,ValueError,TypeError,KeyError,UnicodeError,RecursionError):return result()
        if self.hysteresis_verifier is not None:
            if not is_digest(s["stop_anchor"]):return result()
            # Operational child-Source failures keep their provenance.
            hysteresis=self.hysteresis_verifier.evaluate(actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if (hysteresis.stop_anchor!=s["stop_anchor"] or hysteresis.subject!=s["subject"]
                    or hysteresis.consequence_class!=s["consequence_class"] or hysteresis.issued_at!=issued
                    or hysteresis.variant!="Exceeded" or hysteresis.projection.original_reissue_not_before!=reissue):return result()
            expiry=min(expiry,hysteresis.expires_at)
        return result(True,delivery)
