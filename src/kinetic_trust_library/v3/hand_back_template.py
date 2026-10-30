"""Registered original-template invariants and current installed verification.

The private v2 projection pre-registers every recourse branch, so stop-time
selection never edits the template the signed grant committed to. Source owns
actual registration, authority/endpoint/independence and redaction-policy facts.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .hand_back import InstalledHandBackVerifier,_profile,_strings
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .trust_proof_json import _parse_jcs_object

V2="registered-template-and-sealed-context-v2"


def _recourse(r,forbidden,kind):
    if type(r) is not dict or r.get("kind")!=kind or not _name(r.get("ref")):
        raise ValidationError("registered recourse branch is incomplete")
    if kind=="contest":
        if (set(r)!={"kind","ref","owner","independent_of"} or not _name(r["owner"])
                or r["owner"] in forbidden or not forbidden<=_strings(r["independent_of"])):
            raise ValidationError("contest must be independent including operator affiliates")
    elif kind=="closed_by_authority":
        if set(r)!={"kind","ref","authority","protocol"} or not _name(r["authority"]) or not _name(r["protocol"]):
            raise ValidationError("sovereign recourse must resolve authority and protocol")
    elif kind=="undetermined":
        if set(r)!={"kind","ref","registry"} or not _name(r["registry"]):
            raise ValidationError("undetermined recourse must identify consulted registry")
    else:raise ValidationError("unsupported recourse")


def validate_template(s,p,at):
    """Validate Source-authenticated facts; never establish their authenticity."""
    t=s["template"]
    if (type(t) is not dict or set(t)!={"id","version","subject","consequence_class","registered_at","recipient","recourse","repair","redaction_policy_digest"}
            or not _name(t["id"]) or not _time(t["version"]) or t["version"]==0 or t["subject"]!=s["subject"]
            or t["consequence_class"]!=s["consequence_class"] or not _time(t["registered_at"]) or t["registered_at"]>at
            or not is_digest(t["redaction_policy_digest"])):
        raise ValidationError("actual registered subject/class template required")
    return validate_return_path(s,p,t)


def validate_return_path(s,p,t):
    """Shared recipient/recourse invariants; does not establish registration.

    Registered templates still require validate_template's separate checks.
    Mint-refusal bootstrap paths use their own authenticated request/default
    declaration and never become templates or grant authority here.
    """
    c=p["classes"][s["consequence_class"]]
    if not is_digest(t["redaction_policy_digest"]):raise ValidationError("declared redaction policy required")
    recipient=t["recipient"]
    if (type(recipient) is not dict or set(recipient)!={"endpoint","principal","key_id","channel","ack_sla_seconds","liability_ref"}
            or any(not _name(recipient[k]) for k in ("endpoint","principal","key_id","channel","liability_ref"))
            or not _time(recipient["ack_sla_seconds"]) or not 0<recipient["ack_sla_seconds"]<=c["ack_sla_seconds"]
            or recipient["principal"]!=(s["subject"] if s["subject_profile"]=="person" else s["delegator"])):
        raise ValidationError("accountable return recipient/SLA mismatch")
    repair=t["repair"]
    if type(repair) is not dict or set(repair)!={"subject","ref"} or repair["subject"]!=s["subject"] or not _name(repair["ref"]):
        raise ValidationError("same-subject return repair route required")
    forbidden={s["subject"],s["operator"]}|_strings(s["operator_affiliates"])|_strings(s["measurers"])
    r=t["recourse"]
    if p["formula"]!=V2:
        _recourse(r,forbidden,r.get("kind") if type(r) is dict else None)
    else:
        if type(r) is not dict or set(r)!={"system","principal","sovereign","undetermined"}:
            raise ValidationError("template must register all recourse branches before grant")
        for origin in ("system","principal"):_recourse(r[origin],forbidden,"contest")
        _recourse(r["undetermined"],forbidden,"undetermined")
        if type(r["sovereign"]) is not list or len(r["sovereign"])>4096:
            raise ValidationError("complete registered sovereign routes required")
        authorities=set();refs=set()
        for branch in r["sovereign"]:
            _recourse(branch,forbidden,"closed_by_authority")
            if branch["authority"] in authorities or branch["ref"] in refs:
                raise ValidationError("duplicate registered sovereign route")
            authorities.add(branch["authority"]);refs.add(branch["ref"])
        if not _strings(s.get("required_sovereign_authorities",[]))<=authorities:
            raise ValidationError("applicable sovereign authority lacks a registered return path")
    return t


def select_recourse(t,p,origin,authority=None):
    if p["formula"]!=V2:return t["recourse"]
    if origin=="sovereign":
        for branch in t["recourse"][origin]:
            if branch["authority"]==authority:return branch
        raise ValidationError("actual sovereign authority has no registered branch")
    return t["recourse"][origin]


@dataclass(frozen=True,slots=True)
class AuthenticatedTemplateContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class HandBackTemplateAssessment:
    template_bytes: bytes
    template_digest: str
    profile_bytes: bytes
    deployment_digest: str
    operation_digest: str
    subject: str
    subject_profile: str
    principal: str
    zone: str
    consequence_class: str
    registered_at: int
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("templates require installed original-registration verification")


@dataclass(frozen=True,slots=True)
class InstalledHandBackTemplateVerifier:
    hand_back_verifier: InstalledHandBackVerifier
    context_source: object

    def __post_init__(self):
        if (type(self.hand_back_verifier) is not InstalledHandBackVerifier
                or _profile(_parse_jcs_object(self.hand_back_verifier.profile_bytes))["formula"]!=V2
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("clearance templates require installed v2 pre-registered recourse policy")

    def evaluate(self,*,template_digest,actual_operation,evaluated_at,clock_healthy):
        if not is_digest(template_digest) or not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("template verification requires exact digest and healthy current clock")
        hb=self.hand_back_verifier;p=_profile(_parse_jcs_object(hb.profile_bytes))
        operation_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(operation_bytes)
        deployment=_digest(_parse_jcs_object(hb.deployment_profile_bytes),hb.algorithm)
        invocation=digest_demand_operation(op,algorithm=hb.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,profile_bytes=hb.profile_bytes,
            template_digest=template_digest,operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedTemplateContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("template Source must authenticate actual current registration facts")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","subject_profile","zone","consequence_class",
                "delegator","operator","operator_affiliates","measurers","template","checked_at","expires_at","registration_status","required_sovereign_authorities"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=_digest(p,hb.algorithm) or s["operation_digest"]!=invocation
                or s["subject"]!=op["actor"] or s["subject_profile"] not in ("software","person") or s["zone"]!=p["zone"]
                or type(s["consequence_class"]) is not str or s["consequence_class"] not in p["classes"] or not _name(s["delegator"]) or not _name(s["operator"])
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or s["registration_status"]!="registered"):
            raise ValidationError("template differs from actual current registration/subject/profile scope")
        t=validate_template(s,p,evaluated_at)
        if _digest(t,hb.algorithm)!=template_digest:raise ValidationError("registry returned another grant template")
        import rfc8785
        result=object.__new__(HandBackTemplateAssessment)
        for key,value in dict(template_bytes=rfc8785.dumps(t),template_digest=template_digest,profile_bytes=hb.profile_bytes,
                deployment_digest=deployment,operation_digest=invocation,subject=s["subject"],subject_profile=s["subject_profile"],principal=s["subject"] if s["subject_profile"]=="person" else s["delegator"],
                zone=s["zone"],consequence_class=s["consequence_class"],registered_at=t["registered_at"],evaluated_at=evaluated_at,expires_at=s["expires_at"],
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,key,value)
        return result
