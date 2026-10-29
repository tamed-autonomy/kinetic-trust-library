"""Installed audit-backed production review monitor, not Full clearance.

Source owns real uniform first-draw provenance, complete zone-wide decider
history/current outcome and review truth, registries and durable older backlog.
Actual historical policy bodies and role registries preserve original draws,
triggers, review authority and SLA. Current population diagnostics use the current
window/threshold; prior persisted findings are not implicitly discharged here.
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


def _validate_roles(p,roles,events,parties,now,*,current):
    if type(roles) is not dict or set(roles)!={"sampler","reviewer"}:
        raise ValidationError("actual historical sampler and review role registry required")
    sampler=roles["sampler"];reviewer=roles["reviewer"]
    def valid_interval(role):
        return (_time(role["registered_at"]) and role["registered_at"]<=now
                and (role["withdrawn_at"] is None or _time(role["withdrawn_at"]) and role["registered_at"]<=role["withdrawn_at"]<=now))
    def active_at(role,at):
        return role["registered_at"]<=at and (role["withdrawn_at"] is None or at<role["withdrawn_at"])
    if (type(sampler) is not dict or set(sampler)!={"id","owner","protocol","space","registered_at","withdrawn_at","anchor","independent_of"}
            or sampler["id"]!=p["sampler_id"] or not _name(sampler["owner"]) or sampler["owner"] in parties
            or sampler["protocol"]!="audited-uniform-draw-v1" or not _time(sampler["space"]) or sampler["space"]!=p["sampling_rate"]["denominator"]
            or not valid_interval(sampler) or current and not active_at(sampler,now)
            or not is_digest(sampler["anchor"]) or type(sampler["independent_of"]) is not list or any(not _name(x) for x in sampler["independent_of"])
            or len(set(sampler["independent_of"]))!=len(sampler["independent_of"]) or not parties<=set(sampler["independent_of"])
            or any(not active_at(sampler,_at(e["sample"]["drawn_at"])) for e in events)
            or type(reviewer) is not dict or set(reviewer)!={"id","registered_at","withdrawn_at","anchor"} or reviewer["id"]!=p["review_authority"]
            or reviewer["id"] in parties or not is_digest(reviewer["anchor"]) or not valid_interval(reviewer)
            or current and not active_at(reviewer,now)
            or any(not active_at(reviewer,_at(r["completed_at"])) for e in events for r in e["reviews"] if r["reviewer"]==reviewer["id"])):
        raise ValidationError("actual independent historical/current sampler and reviewer registration interval required")


def _findings(s,p,registry,roles,event_profiles,now):
    findings=s["findings"]
    if type(findings) is not list or len(findings)>4096:raise ValidationError("complete actual finding/resolution inventory required")
    anchors=set();positions=set();active=[];closed=[]
    for event in s["history"]:
        for record in [event,event["sample"],*event["outcomes"],*event["reviews"]]:
            anchors.add(record["anchor"]);positions.add(record["sequence"])
    def position(record):
        if (not is_digest(record["anchor"]) or record["anchor"] in anchors or not _time(record["sequence"])
                or not 0<record["sequence"]<=s["ledger_head"]["sequence"] or record["sequence"] in positions):
            raise ValidationError("findings/resolutions require distinct actual audit anchors/positions")
        anchors.add(record["anchor"]);positions.add(record["sequence"])
    for finding in findings:
        if (type(finding) is not dict or set(finding)!={"anchor","sequence","decided_by","profile_digest","found_at","kind","basis_decisions","resolution"}
                or finding["decided_by"]!=s["decided_by"] or type(finding["profile_digest"]) is not str or finding["profile_digest"] not in registry
                or finding["kind"]!="uniform-approval" or not _time(finding["found_at"]) or finding["found_at"]>now
                or type(finding["basis_decisions"]) is not list or any(not is_digest(x) for x in finding["basis_decisions"])
                or len(set(finding["basis_decisions"]))!=len(finding["basis_decisions"])):
            raise ValidationError("actual scoped historical finding and governing profile required")
        position(finding);q=registry[finding["profile_digest"]];at=finding["found_at"];seq=finding["sequence"]
        if _at(s["coverage_start"])>max(0,at-q["window_seconds"]):raise ValidationError("historical finding population coverage is incomplete")
        reviewer=roles[finding["profile_digest"]]["reviewer"]
        if reviewer["registered_at"]>at or reviewer["withdrawn_at"] is not None and at>=reviewer["withdrawn_at"]:
            raise ValidationError("historical finding review authority was not registered at its occurrence")
        snapshot=[];profiles={}
        for event in s["history"]:
            if (event["sequence"]>=seq or _at(event["decided_at"])>at or event["sample"]["sequence"]>=seq or _at(event["sample"]["drawn_at"])>at):continue
            e=dict(event)
            e["outcomes"]=[r for r in event["outcomes"] if r["sequence"]<seq and _at(r["observed_at"])<=at]
            e["reviews"]=[r for r in event["reviews"] if r["sequence"]<seq and _at(r["completed_at"])<=at]
            snapshot.append(e);profiles[e["anchor"]]=event_profiles[e["anchor"]]
        basis=project_decision_review(q,snapshot,decided_by=s["decided_by"],evaluated_at=at,ledger_head_sequence=seq-1,event_profiles=profiles)
        if not basis.rubber_stamp_finding or set(finding["basis_decisions"])!=set(basis.finding_decisions):
            raise ValidationError("historical finding differs from the actual complete then-known sampled population")
        resolution=finding["resolution"]
        if resolution is None:active.append(finding["anchor"]);continue
        if (type(resolution) is not dict or set(resolution)!={"anchor","sequence","resolved_at","authority","disposition","profile_digest"}
                or type(resolution["profile_digest"]) is not str or resolution["profile_digest"] not in registry
                or resolution["authority"]!=registry[resolution["profile_digest"]]["review_authority"] or resolution["disposition"]!="resolved"
                or resolution["authority"] in {e["actor"] for e in s["history"] if e["anchor"] in finding["basis_decisions"]}
                or not _time(resolution["resolved_at"]) or not at<=resolution["resolved_at"]<=now):
            raise ValidationError("finding requires an actual authorized forward resolution")
        position(resolution)
        authority=roles[resolution["profile_digest"]]["reviewer"]
        if (resolution["sequence"]<=seq or authority["registered_at"]>resolution["resolved_at"]
                or authority["withdrawn_at"] is not None and resolution["resolved_at"]>=authority["withdrawn_at"]):
            raise ValidationError("finding resolution precedes its cause or falls outside its actual historical authority interval")
        closed.append(finding["anchor"])
    return tuple(sorted(active)),tuple(sorted(closed))


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
    active_findings: tuple
    closed_findings: tuple
    finding_record_required: bool

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
                "append_protocol","coverage_start","coverage_end","ledger_head","history","governing_profiles","open_obligations","profile_registry","registries","findings","open_findings"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=policy
                or s["operation_digest"]!=digest_demand_operation(op,algorithm="sha256") or s["decided_by"]!=decided_by or s["zone"]!=p["zone"]
                or s["ledger_owner"]!=p["ledger_owner"] or s["append_protocol"]!=p["append_protocol"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or _at(s["coverage_start"])>max(0,evaluated_at-p["window_seconds"]) or _at(s["coverage_end"])!=evaluated_at):
            raise ValidationError("production review Source differs from current scope/profile/complete coverage")
        head=s["ledger_head"]
        if type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"]):
            raise ValidationError("actual review ledger head required")
        history=s["history"];mapping=s["governing_profiles"];registry=s["profile_registry"];roles=s["registries"]
        if (type(history) is not list or len(history)>4096 or any(type(e) is not dict or not is_digest(e.get("anchor")) for e in history)
                or type(mapping) is not dict or set(mapping)!={e["anchor"] for e in history}
                or type(registry) is not dict or len(registry)>4096 or type(roles) is not dict or set(roles)!=set(registry)):
            raise ValidationError("complete historical review policy/role inventory required")
        for digest,body in registry.items():
            q=profile_terms(body)
            if digest!=_digest(q,"sha256") or any(q[k]!=p[k] for k in ("zone","ledger_owner","append_protocol")):
                raise ValidationError("historical review policy body differs from its actual digest/ledger")
        if registry.get(policy)!=p or any(type(d) is not str or d not in registry for d in mapping.values()):
            raise ValidationError("actual current and historical governing review policies required")
        event_profiles={anchor:registry[digest] for anchor,digest in mapping.items()}
        projection=project_decision_review(p,history,decided_by=decided_by,evaluated_at=evaluated_at,
            ledger_head_sequence=head["sequence"],event_profiles=event_profiles)
        for digest,q in registry.items():
            selected=[e for e in history if mapping[e["anchor"]]==digest]
            parties={decided_by}|{e["actor"] for e in selected}
            if digest==policy:parties.add(op["actor"])
            _validate_roles(q,roles[digest],selected,parties,evaluated_at,current=digest==policy)
        active_findings,closed_findings=_findings(s,p,registry,roles,event_profiles,evaluated_at)
        markers=s["open_findings"]
        if (type(markers) is not list or any(not is_digest(x) for x in markers) or len(set(markers))!=len(markers)
                or set(markers)!=set(active_findings)):
            raise ValidationError("durable open-finding markers differ from actual finding/resolution inventory")
        resolved_pattern=any(f["anchor"] in closed_findings and f["profile_digest"]==policy
            and set(f["basis_decisions"])==set(projection.finding_decisions) for f in s["findings"])
        new_finding=projection.rubber_stamp_finding and not resolved_pattern
        backlog=s["open_obligations"]
        required={cause for _,cause,_ in projection.overdue_reviews+projection.pending_reviews}
        if type(backlog) is not list or any(not is_digest(x) for x in backlog) or len(set(backlog))!=len(backlog) or set(backlog)!=required:
            raise ValidationError("durable actual open-review backlog differs from complete production inventory")
        expiry=s["expires_at"]
        if projection.next_change_at is not None:expiry=min(expiry,projection.next_change_at)
        result=object.__new__(DecisionReviewAssessment)
        for key,value in dict(review_current=not projection.overdue_reviews and not new_finding and not active_findings,action_permitted=False,
                reason="DECISION_REVIEW_UNRESOLVED_FINDING" if active_findings else "DECISION_REVIEW_RUBBER_STAMP_FINDING" if new_finding else "DECISION_REVIEW_OVERDUE" if projection.overdue_reviews else "DECISION_REVIEW_RESOLVED_FINDING" if resolved_pattern else "DECISION_REVIEW_CURRENT",
                decided_by=decided_by,projection=projection,ledger_head_anchor=head["anchor"],ledger_head_sequence=head["sequence"],
                profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
                active_findings=active_findings,closed_findings=closed_findings,finding_record_required=new_finding).items():object.__setattr__(result,key,value)
        return result


__all__=("AuthenticatedDecisionReviewContext","DecisionReviewAssessment","InstalledDecisionReviewVerifier")
