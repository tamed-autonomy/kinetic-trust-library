"""Accountable relational decisions with an endogenous refusal-evidence gate.

The adjudication adapter authenticates the actual signed token. Independent
Source facts establish person/key/liability registration, the actual signed
decision record and an anchored declared refusal run. Humanity, review quality,
physical key custody and production sampling are governance/audit properties,
not proven by these projections. No action or nonce consumption is authorized.
"""
from dataclasses import dataclass
from hashlib import sha256
from kinetic_trust_library.errors import ValidationError
from .adjudication import InstalledAdjudicationVerifier
from .relational_reissue import InstalledRelationalReissueVerifier
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .execution_observation import ExecutionScope,ExecutionDecision,ExecutionObservation,classify_execution_observation


def _profile(p):
    if (set(p)!={"id","version","zone","formula","adjudication_profile_digest","relational_profile_digest",
                  "evidence_level","refusal_cases","max_run_age_seconds"}
            or not _name(p["id"]) or not _name(p["zone"]) or not _time(p["version"]) or p["version"]==0
            or p["formula"]!="accountable-adjudication-endogenous-v1" or p["evidence_level"]!="standard-endogenous"
            or not is_digest(p["adjudication_profile_digest"]) or not is_digest(p["relational_profile_digest"])
            or not _time(p["max_run_age_seconds"]) or p["max_run_age_seconds"]==0
            or type(p["refusal_cases"]) is not list or not 0<len(p["refusal_cases"])<=256):
        raise ValidationError("invalid relational decision policy or unsupported meaningfulness claim")
    ids=set();digests=set()
    for case in p["refusal_cases"]:
        if (type(case) is not dict or set(case)!={"id","case_digest","operation_digest","boundary_id"}
                or not _name(case["id"]) or not is_digest(case["case_digest"]) or not is_digest(case["operation_digest"]) or not _name(case["boundary_id"])
                or case["id"] in ids or case["case_digest"] in digests):raise ValidationError("distinct declared refusal cases required")
        ids.add(case["id"]);digests.add(case["case_digest"])
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedRelationalDecisionContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class RelationalDecisionAssessment:
    gate_required: bool
    gate_satisfied: bool
    action_permitted: bool
    reason: str
    decided_by: str | None
    lease_digest: str
    evidence_digest: str
    repair_ref: str
    reissue: object
    adjudication: object
    decision_anchor: str | None
    refusal_run_anchor: str | None
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int | None
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("relational decision gates require installed signed/current accountable evidence")


def _accountable(principal,decision,actor,adjudication,now):
    if (type(principal) is not dict or set(principal)!={"id","kind","issuer","key_id","key_holder","liability_ref","liability_anchor",
            "liability_signed_by","liability_signed_at","valid_from","valid_until","revoked_at"}
            or any(not _name(principal[k]) for k in ("id","issuer","key_id","key_holder","liability_ref","liability_signed_by"))
            or principal["kind"]!="person" or principal["id"]==actor or principal["id"]!=decision["decided_by"]
            or principal["key_holder"]!=principal["id"] or principal["liability_signed_by"]!=principal["id"]
            or not is_digest(principal["liability_anchor"]) or principal["issuer"]!=adjudication.verified_issuer
            or principal["key_id"]!=adjudication.verified_key_id or principal["revoked_at"] is not None
            or any(not _time(principal[k]) for k in ("liability_signed_at","valid_from","valid_until"))
            or not principal["valid_from"]<=decision["signed_at"]<=now<principal["valid_until"]
            or not principal["valid_from"]<=principal["liability_signed_at"]<=decision["signed_at"]):return False
    return True


def _observed_refusal(case,declared,run,p,actor):
    e=case["execution"]
    if (type(e) is not dict or set(e)!={"scope","decision","observation","enforcement_point_present"}
            or e["enforcement_point_present"] is not True or type(e["scope"]) is not dict
            or set(e["scope"])!={"actor","operation_digest","zone","topology_epoch"}
            or type(e["decision"]) is not dict or set(e["decision"])!={"decision_id","record_digest","decided_at","execution_permitted","supervision"}
            or type(e["observation"]) is not dict or set(e["observation"])!={"decision_id","decision_digest","boundary_id","kind","observed_at"}):return False
    try:
        scope=ExecutionScope(**e["scope"])
        decision=ExecutionDecision(scope=scope,**e["decision"])
        observation=ExecutionObservation(scope=scope,**e["observation"])
        expected=ExecutionScope(actor,declared["operation_digest"],p["zone"],run["topology_epoch"])
    except ValidationError:return False
    if (scope!=expected or decision.record_digest!=case["anchor"] or decision.decided_at!=case["decided_at"]
            or decision.execution_permitted is not False or observation.boundary_id!=declared["boundary_id"]
            or observation.observed_at>run["completed_at"]):return False
    projection=classify_execution_observation(scope=expected,decision=decision,observation=observation,enforcement_point_present=True)
    return projection.reportable_as_not_executed and not projection.bypass


def _refusal_run(run,p,decision,principal,actor,now):
    if (type(run) is not dict or set(run)!={"anchor","profile_digest","decided_by","started_at","completed_at","topology_epoch","cases"}
            or not is_digest(run["anchor"]) or run["profile_digest"]!=_digest(p,"sha256") or run["decided_by"]!=principal["id"]
            or not _time(run["started_at"]) or not _time(run["completed_at"])
            or not principal["valid_from"]<=run["started_at"]<=run["completed_at"]<=decision["signed_at"]
            or principal["liability_signed_at"]>run["started_at"]
            or not _time(run["completed_at"]+p["max_run_age_seconds"]) or now>=run["completed_at"]+p["max_run_age_seconds"]
            or not _time(run["topology_epoch"]) or type(run["cases"]) is not list or len(run["cases"])!=len(p["refusal_cases"])):return False
    expected={c["id"]:c for c in p["refusal_cases"]};seen=set();anchors={run["anchor"],decision["anchor"],principal["liability_anchor"]}
    if len(anchors)!=3:return False
    for case in run["cases"]:
        if (type(case) is not dict or set(case)!={"id","case_digest","anchor","decided_by","issuer","key_id","decided_at","choice","review_kind","execution"}
                or not _name(case["id"]) or case["id"] in seen or case["id"] not in expected or expected[case["id"]]["case_digest"]!=case["case_digest"]
                or not is_digest(case["anchor"]) or case["anchor"] in anchors or case["decided_by"]!=principal["id"]
                or case["issuer"]!=principal["issuer"] or case["key_id"]!=principal["key_id"]
                or not _time(case["decided_at"]) or not run["started_at"]<=case["decided_at"]<=run["completed_at"]
                or case["choice"]!="refuse" or case["review_kind"]!="review" or not _observed_refusal(case,expected[case["id"]],run,p,actor)):return False
        seen.add(case["id"]);anchors.add(case["anchor"])
    return seen==set(expected)


@dataclass(frozen=True,slots=True)
class InstalledRelationalDecisionVerifier:
    relational_verifier: InstalledRelationalReissueVerifier
    adjudication_verifier: InstalledAdjudicationVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.relational_verifier) is not InstalledRelationalReissueVerifier
                or type(self.adjudication_verifier) is not InstalledAdjudicationVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed relational decision verifier")
        rv=self.relational_verifier;av=self.adjudication_verifier;hv=rv.hysteresis_verifier
        p=_profile(_parse_jcs_object(self.profile_bytes));ap=_parse_jcs_object(av.profile_bytes)
        if (hv.algorithm!="sha256" or hv.deployment_profile_bytes!=av.deployment_profile_bytes
                or p["zone"]!=ap["zone_id"] or p["zone"]!=_parse_jcs_object(rv.profile_bytes)["zone"] or ap["gate_required"] is not True
                or p["adjudication_profile_digest"]!=_digest(ap,"sha256")
                or p["relational_profile_digest"]!=_digest(_parse_jcs_object(rv.profile_bytes),"sha256")):
            raise ValidationError("relational decision requires matching deployment/zone/required adjudication and selected SHA-256 policies")

    def evaluate(self,token_bytes,lease_bytes,*,evidence_digest,actual_operation,evaluated_at,clock_healthy):
        if (token_bytes is not None and type(token_bytes) is not bytes or not is_digest(evidence_digest)
                or not evidence_digest.startswith("sha256:") or not _time(evaluated_at)):
            raise ValidationError("relational decision requires immutable token and current exact evidence digest/time")
        p=_profile(_parse_jcs_object(self.profile_bytes));rv=self.relational_verifier;av=self.adjudication_verifier
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        reissue=rv.evaluate(lease_bytes,actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        adjudication=None;source=None;decider=None;decision_anchor=None;run_anchor=None
        def result(reason,expiry=None):
            r=object.__new__(RelationalDecisionAssessment)
            for key,value in dict(gate_required=True,gate_satisfied=reason=="RELATIONAL_DECISION_SATISFIED",action_permitted=False,reason=reason,
                    decided_by=decider,lease_digest=reissue.lease_digest,evidence_digest=evidence_digest,repair_ref=reissue.repair_ref,
                    reissue=reissue,adjudication=adjudication,decision_anchor=decision_anchor,refusal_run_anchor=run_anchor,
                    profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                    authenticated_state_bytes=source.state_bytes if source is not None else None,
                    source_evidence_bytes=source.evidence_bytes if source is not None else None).items():object.__setattr__(r,key,value)
            return r
        if not reissue.eligible:return result(reissue.reason)
        adjudication=av.evaluate(token_bytes,actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        if not adjudication.gate_required or not adjudication.gate_satisfied:return result(adjudication.reason)
        source=self.context_source.resolve(deployment_profile_bytes=av.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            adjudication_profile_bytes=av.profile_bytes,lease_bytes=lease_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedRelationalDecisionContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):raise ValidationError("authenticated actual relational decision/accountability/run facts required")
        s=_parse_jcs_object(source.state_bytes)
        if set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at","lease_digest",
                    "evidence_digest","current_grant_epoch","topology_epoch","ledger_head","principal","decision","run"}:
            raise ValidationError("complete current relational decision Source required")
        adjstate=_parse_jcs_object(adjudication.authenticated_state_bytes);token=_parse_jcs_object(adjudication.authenticated_payload_bytes)
        if (s["deployment_digest"]!=adjudication.deployment_digest or s["profile_digest"]!=_digest(p,"sha256")
                or s["operation_digest"]!=digest_demand_operation(op,algorithm="sha256") or s["subject"]!=op["actor"] or s["zone"]!=p["zone"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or s["lease_digest"]!=reissue.lease_digest or s["lease_digest"]!=adjstate["grant_digest"]
                or s["evidence_digest"]!=evidence_digest or s["evidence_digest"]!=adjstate["evidence_digest"]
                or not _time(s["current_grant_epoch"]) or s["current_grant_epoch"]!=reissue.current_grant_epoch
                or not _time(s["topology_epoch"]) or s["topology_epoch"]!=adjstate["topology_epoch"]
                or type(s["ledger_head"]) is not dict or set(s["ledger_head"])!={"anchor","sequence"}
                or not _time(s["ledger_head"]["sequence"]) or s["ledger_head"]["sequence"]!=reissue.ledger_head_sequence
                or s["ledger_head"]["anchor"]!=reissue.ledger_head_anchor):return result("RELATIONAL_DECISION_BINDING")
        d=s["decision"]
        if (type(d) is not dict or set(d)!={"anchor","token_digest","decided_by","issuer","key_id","signed_at","repair_ref","grant_digest",
                "evidence_digest","operation_digest","current_grant_epoch","topology_epoch","review_kind","acknowledged_at","reviewed_at","offered_outcomes","choice"}
                or not is_digest(d["anchor"]) or not _name(d["decided_by"]) or d["token_digest"]!="sha256:"+sha256(token_bytes).hexdigest()
                or d["issuer"]!=adjudication.verified_issuer or d["key_id"]!=adjudication.verified_key_id or not _time(d["signed_at"])
                or d["signed_at"]!=token["iat"] or d["repair_ref"]!=reissue.repair_ref
                or any(d[k]!=s[k] for k in ("evidence_digest","operation_digest","current_grant_epoch","topology_epoch"))
                or any(not _time(d[k]) for k in ("current_grant_epoch","topology_epoch")) or d["grant_digest"]!=s["lease_digest"]
                or d["review_kind"]!="review" or not _time(d["acknowledged_at"]) or not _time(d["reviewed_at"])
                or not d["acknowledged_at"]<=d["reviewed_at"]<=d["signed_at"] or d["choice"]!="approve"
                or type(d["offered_outcomes"]) is not list or len(d["offered_outcomes"])!=2
                or any(type(x) is not str for x in d["offered_outcomes"]) or set(d["offered_outcomes"])!={"approve","refuse"}):
            return result("RELATIONAL_DECISION_RECORD")
        principal=s["principal"]
        if not _accountable(principal,d,op["actor"],adjudication,evaluated_at):return result("RELATIONAL_DECIDER_ACCOUNTABILITY")
        decider=principal["id"];decision_anchor=d["anchor"]
        if not _refusal_run(s["run"],p,d,principal,op["actor"],evaluated_at):return result("RELATIONAL_REFUSAL_RUN_REQUIRED")
        run_anchor=s["run"]["anchor"]
        expiry=min(reissue.expires_at,adjudication.expires_at,s["expires_at"],principal["valid_until"],s["run"]["completed_at"]+p["max_run_age_seconds"])
        return result("RELATIONAL_DECISION_SATISFIED",expiry)


__all__=("AuthenticatedRelationalDecisionContext","RelationalDecisionAssessment","InstalledRelationalDecisionVerifier")
