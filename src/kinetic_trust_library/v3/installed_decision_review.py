"""Installed audit-backed production review monitor, not Full clearance.

Source owns real uniform first-draw provenance, complete zone-wide decider
history/current outcome and review truth, registries and durable older backlog.
The selected adapter currently requires one governing profile throughout its
inventory. Historical-policy transitions must not be silently repriced or omitted.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .decision_review import profile_terms,project_decision_review
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .hand_back_hysteresis import _at


@dataclass(frozen=True,slots=True)
class AuthenticatedDecisionReviewContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class DecisionReviewAssessment:
    review_current: bool
    action_permitted: bool
    reason: str
    decided_by: str
    projection: object
    ledger_head_anchor: str
    ledger_head_sequence: int
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("review monitor requires installed actual production inventory/registries/backlog")


@dataclass(frozen=True,slots=True)
class InstalledDecisionReviewVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed production review verifier")
        _parse_jcs_object(self.deployment_profile_bytes);profile_terms(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,decided_by,actual_operation,evaluated_at,clock_healthy):
        if not _name(decided_by) or not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("actual decider and healthy current time required for production review")
        p=profile_terms(_parse_jcs_object(self.profile_bytes));policy=_digest(p,"sha256")
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),"sha256")
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            decided_by=decided_by,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedDecisionReviewContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("complete authenticated production review Source required")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","decided_by","zone","checked_at","expires_at","ledger_owner",
                "append_protocol","coverage_start","coverage_end","ledger_head","history","governing_profiles","open_obligations","sampler","reviewer"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=policy
                or s["operation_digest"]!=digest_demand_operation(op,algorithm="sha256") or s["decided_by"]!=decided_by or s["zone"]!=p["zone"]
                or s["ledger_owner"]!=p["ledger_owner"] or s["append_protocol"]!=p["append_protocol"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or _at(s["coverage_start"])>max(0,evaluated_at-p["window_seconds"]) or _at(s["coverage_end"])!=evaluated_at):
            raise ValidationError("production review Source differs from current scope/profile/complete coverage")
        head=s["ledger_head"]
        if type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"]):
            raise ValidationError("actual review ledger head required")
        projection=project_decision_review(p,s["history"],decided_by=decided_by,evaluated_at=evaluated_at,ledger_head_sequence=head["sequence"])
        mapping=s["governing_profiles"]
        if (type(mapping) is not dict or set(mapping)!={e["anchor"] for e in s["history"]} or any(d!=policy for d in mapping.values())):
            raise ValidationError("complete actual governing profile inventory required; historical transitions need an explicit adapter")
        sampler=s["sampler"];reviewer=s["reviewer"]
        parties={decided_by,op["actor"]}|{e["actor"] for e in s["history"]}
        if (type(sampler) is not dict or set(sampler)!={"id","owner","protocol","space","registered_at","withdrawn_at","anchor","independent_of"}
                or sampler["id"]!=p["sampler_id"] or not _name(sampler["owner"]) or sampler["owner"] in parties
                or sampler["protocol"]!="audited-uniform-draw-v1" or not _time(sampler["space"]) or sampler["space"]!=p["sampling_rate"]["denominator"]
                or not _time(sampler["registered_at"]) or sampler["registered_at"]>evaluated_at or sampler["withdrawn_at"] is not None
                or not is_digest(sampler["anchor"]) or type(sampler["independent_of"]) is not list or any(not _name(x) for x in sampler["independent_of"])
                or len(set(sampler["independent_of"]))!=len(sampler["independent_of"]) or not parties<=set(sampler["independent_of"])
                or any(sampler["registered_at"]>_at(e["sample"]["drawn_at"]) for e in s["history"])
                or type(reviewer) is not dict or set(reviewer)!={"id","registered_at","withdrawn_at","anchor"} or reviewer["id"]!=p["review_authority"]
                or reviewer["id"] in parties or not is_digest(reviewer["anchor"]) or not _time(reviewer["registered_at"])
                or reviewer["registered_at"]>evaluated_at or reviewer["withdrawn_at"] is not None
                or any(reviewer["registered_at"]>_at(r["completed_at"]) for e in s["history"] for r in e["reviews"] if r["reviewer"]==reviewer["id"])):
            raise ValidationError("actual independent registered sampler/review authority and historical registration required")
        backlog=s["open_obligations"]
        required={cause for _,cause,_ in projection.overdue_reviews+projection.pending_reviews}
        if type(backlog) is not list or any(not is_digest(x) for x in backlog) or len(set(backlog))!=len(backlog) or set(backlog)!=required:
            raise ValidationError("durable actual open-review backlog differs from complete production inventory")
        expiry=s["expires_at"]
        if projection.next_change_at is not None:expiry=min(expiry,projection.next_change_at)
        result=object.__new__(DecisionReviewAssessment)
        for key,value in dict(review_current=projection.review_current,action_permitted=False,
                reason="DECISION_REVIEW_RUBBER_STAMP_FINDING" if projection.rubber_stamp_finding else "DECISION_REVIEW_OVERDUE" if projection.overdue_reviews else "DECISION_REVIEW_CURRENT",
                decided_by=decided_by,projection=projection,ledger_head_anchor=head["anchor"],ledger_head_sequence=head["sequence"],
                profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,key,value)
        return result


__all__=("AuthenticatedDecisionReviewContext","DecisionReviewAssessment","InstalledDecisionReviewVerifier")
