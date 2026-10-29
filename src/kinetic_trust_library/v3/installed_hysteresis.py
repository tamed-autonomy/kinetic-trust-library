"""Installed actual-stop pricing under a declared adjudicated ledger policy.

Source owns complete actual audit-backed history, head/order, governing profile,
owner/append/retention and current finding/expungement truth. This private
projection neither appends records nor implements a lease or standing sanction.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .hand_back_hysteresis import profile_terms,project_hysteresis,_at
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest


@dataclass(frozen=True,slots=True)
class AuthenticatedHysteresisContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class HandBackHysteresisAssessment:
    projection: object
    stop_anchor: str
    subject: str
    consequence_class: str
    variant: str
    issued_at: object
    profile_bytes: bytes
    profile_digest: str
    deployment_digest: str
    operation_digest: str
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    frame_bytes: bytes
    frame_digest: str

    def __init__(self,*args,**kwargs):raise TypeError("hysteresis requires installed complete current ledger verification")


@dataclass(frozen=True,slots=True)
class InstalledHandBackHysteresisVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed hysteresis verifier")
        _parse_jcs_object(self.deployment_profile_bytes);profile_terms(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("current hysteresis requires healthy trusted time")
        p=profile_terms(_parse_jcs_object(self.profile_bytes));policy=_digest(p,self.algorithm)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        operation_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(operation_bytes)
        invocation=digest_demand_operation(op,algorithm=self.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedHysteresisContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("complete authenticated actual ledger inventory required")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","zone","subject",
                "ledger_owner","append_protocol","retained_since","ledger_head","pricing_stop","history"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=policy or s["operation_digest"]!=invocation
                or s["zone"]!=p["zone"] or s["subject"]!=op["actor"] or s["ledger_owner"]!=p["ledger_owner"]
                or s["append_protocol"]!=p["append_protocol"] or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at):
            raise ValidationError("hysteresis ledger differs from actual current operation/profile/owner/time")
        head=s["ledger_head"];stop=s["pricing_stop"]
        if (type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"])
                or type(stop) is not dict or set(stop)!={"id","stop_anchor","subject","operation_digest","consequence_class","issued_at","sequence","hysteresis_profile_digest"}
                or not _name(stop["id"]) or not is_digest(stop["stop_anchor"]) or stop["subject"]!=op["actor"]
                or stop["operation_digest"]!=invocation or stop["hysteresis_profile_digest"]!=policy):
            raise ValidationError("pricing requires actual stop/head/governing profile bindings")
        issued=_at(stop["issued_at"]);retained=_at(s["retained_since"])
        if retained>max(0,evaluated_at-p["retention_seconds"]) or retained>max(0,issued-p["window_seconds"]):
            raise ValidationError("ledger does not cover required retained/prior history")
        projection=project_hysteresis(p,s["history"],subject=op["actor"],consequence_class=stop["consequence_class"],issued_at=issued,
            current_sequence=stop["sequence"],as_of=evaluated_at,ledger_head_sequence=head["sequence"])
        current=next((e for e in s["history"] if e["sequence"]==stop["sequence"]),None)
        if (current is None or current["stop_anchor"]!=stop["stop_anchor"] or current["id"]!=stop["id"]
                or current["variant"] not in ("Revoked","Exceeded")):
            raise ValidationError("complete pricing inventory must contain the actual priced adverse stop")
        expiry=s["expires_at"]
        for e in s["history"]:
            if e["variant"]=="Revoked" and any(a["outcome"]=="overturned" for a in e["adjudications"]):
                end=_at(e["occurred_at"])+p["window_seconds"]
                if end>=evaluated_at:expiry=min(expiry,int(end)+1)
        import rfc8785
        frame={key:value for key,value in s.items() if key not in ("checked_at","expires_at")}
        bound=projection.reissue_not_before
        frame["derived"]=dict(count=projection.prior_adverse_count,delay_seconds=projection.delay_seconds,priced_stop_expunged=projection.priced_stop_expunged,
            original_count=projection.original_prior_adverse_count,original_delay_seconds=projection.original_delay_seconds,
            reissue_not_before=dict(n=str(bound.numerator),d=str(bound.denominator)),
            expungement_required=list(projection.expungement_required),revoker_overturn_counts=[list(i) for i in projection.revoker_overturn_counts],
            revoker_accountability_required=[list(i) for i in projection.revoker_accountability_required])
        result=object.__new__(HandBackHysteresisAssessment)
        for key,value in dict(projection=projection,stop_anchor=stop["stop_anchor"],subject=op["actor"],consequence_class=stop["consequence_class"],variant=current["variant"],
                issued_at=issued,profile_bytes=self.profile_bytes,profile_digest=policy,deployment_digest=deployment,operation_digest=invocation,
                evaluated_at=evaluated_at,expires_at=expiry,authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
                frame_bytes=rfc8785.dumps(frame),frame_digest=_digest(frame,self.algorithm)).items():object.__setattr__(result,key,value)
        return result
