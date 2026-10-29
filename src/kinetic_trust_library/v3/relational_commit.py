"""Immutable relational commit conditions, never execution or nonce storage.

Service must authenticate the actual current protected frame, check the complete
Clear/native/ordinary-authorization result, then compare and consume this nonce
with the exact protected mutation or durable dispatch intent in one authority
transaction. Remote effect confirmation is a separate contract. This library checks
conditions only. Serialized contract bytes are not authority or a receipt.
"""
from dataclasses import dataclass,field
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from .relational_decision import InstalledRelationalDecisionVerifier
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time

_PROTOCOL="compare-nonce-epoch-fences-with-effect-v1"
_FENCES=frozenset(("grant","nonce","human_decision","template","native_evidence","adverse_stop","authority"))
_STATE=frozenset(("deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at",
                  "authority","nonce","current_grant_epoch","topology_epoch","ledger_head","fences"))


def _profile(p):
    if (set(p)!={"id","version","zone","formula","decision_profile_digest","authority","nonce_namespace","commit_protocol","max_contract_age_seconds"}
            or any(not _name(p[k]) for k in ("id","zone","authority","nonce_namespace")) or not _time(p["version"]) or p["version"]==0
            or p["formula"]!="conditional-single-use-commit-v1" or not is_digest(p["decision_profile_digest"])
            or p["commit_protocol"]!=_PROTOCOL or not _time(p["max_contract_age_seconds"]) or p["max_contract_age_seconds"]==0):
        raise ValidationError("invalid selected relational commit policy")
    return p


def _valid_frame(s,now):
    if (type(s) is not dict or set(s)!=_STATE or any(not is_digest(s[k]) for k in ("deployment_digest","profile_digest","operation_digest"))
            or not _name(s["subject"]) or not _name(s["zone"]) or not _time(s["checked_at"]) or s["checked_at"]!=now
            or not _time(s["expires_at"]) or s["expires_at"]<=now or not _time(s["current_grant_epoch"]) or not _time(s["topology_epoch"])):return False
    a=s["authority"];n=s["nonce"];head=s["ledger_head"]
    if (type(a) is not dict or set(a)!={"id","protocol","nonce_namespace","registry_anchor","registered_at","withdrawn_at","revision"}
            or any(not _name(a[k]) for k in ("id","nonce_namespace")) or a["protocol"]!=_PROTOCOL or not is_digest(a["registry_anchor"])
            or not _time(a["registered_at"]) or a["registered_at"]>now or not _time(a["revision"])
            or a["withdrawn_at"] is not None and (not _time(a["withdrawn_at"]) or not a["registered_at"]<=a["withdrawn_at"]<=now)
            or type(n) is not dict or set(n)!={"lease_id","lease_digest","nonce","subject","grant_epoch","registered_at","consumed_at","revoked_at","revision","record_anchor"}
            or any(not _name(n[k]) for k in ("lease_id","nonce","subject")) or not is_digest(n["lease_digest"]) or not is_digest(n["record_anchor"])
            or any(not _time(n[k]) for k in ("grant_epoch","registered_at","revision")) or n["registered_at"]>now
            or any(n[k] is not None and (not _time(n[k]) or not n["registered_at"]<=n[k]<=now) for k in ("consumed_at","revoked_at"))
            or type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"])
            or type(s["fences"]) is not list or len(s["fences"])!=len(_FENCES)):return False
    names=set()
    for f in s["fences"]:
        if (type(f) is not dict or set(f)!={"name","anchor","revision"} or not _name(f["name"]) or f["name"] in names
                or not is_digest(f["anchor"]) or not _time(f["revision"])):return False
        names.add(f["name"])
    return names==_FENCES


@dataclass(frozen=True,slots=True)
class AuthenticatedRelationalCommitContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class RelationalCommitAssessment:
    conditional_commit: bool
    action_permitted: bool
    reason: str
    decision: object
    contract_bytes: bytes | None
    contract_digest: str | None
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int | None
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("commit conditions require installed current authority/nonce/fence facts")


@dataclass(frozen=True,slots=True)
class RelationalCommitCheck:
    conditions_match: bool
    reason: str
    action_permitted: bool = field(default=False,init=False)


def check_relational_commit(assessment,authenticated_frame_bytes,*,actual_operation,committed_at,clock_healthy):
    """Compare only, under Service's actual effect/consume transaction lock.

    Requires a local installed assessment; raw wire bytes cannot recreate one.
    The frame must independently authenticate actual current state at this exact
    time. A matching result is not native Clear or ordinary authorization and
    does not consume the nonce, persist a receipt, dispatch or confirm an effect.
    """
    if type(assessment) is not RelationalCommitAssessment:raise ValidationError("installed typed commit assessment required, not serialized authority")
    def result(reason):return RelationalCommitCheck(reason=="RELATIONAL_COMMIT_CONDITIONS_MATCH",reason)
    if (not assessment.conditional_commit or type(authenticated_frame_bytes) is not bytes or len(authenticated_frame_bytes)>262144
            or not _time(committed_at) or clock_healthy is not True or not assessment.evaluated_at<=committed_at<assessment.expires_at):
        return result("RELATIONAL_COMMIT_NOT_CURRENT")
    try:s=_parse_jcs_object(authenticated_frame_bytes)
    except (ValidationError,ProofFormatError):return result("RELATIONAL_COMMIT_FRAME_INVALID")
    if not _valid_frame(s,committed_at):return result("RELATIONAL_COMMIT_FRAME_INVALID")
    b=_parse_jcs_object(assessment.contract_bytes)
    op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
    if op_bytes!=assessment.operation_bytes or digest_demand_operation(op,algorithm="sha256")!=b["operation_digest"]:
        return result("RELATIONAL_COMMIT_OPERATION")
    if (any(s[k]!=b[k] for k in ("deployment_digest","profile_digest","operation_digest","subject","zone","current_grant_epoch","topology_epoch","ledger_head"))
            or s["authority"]!=b["authority_state"] or s["nonce"]!=b["nonce_state"]
            or sorted(s["fences"],key=lambda f:f["name"])!=b["fences"]
            or s["authority"]["withdrawn_at"] is not None or s["nonce"]["consumed_at"] is not None or s["nonce"]["revoked_at"] is not None):
        return result("RELATIONAL_COMMIT_STATE_CHANGED")
    return result("RELATIONAL_COMMIT_CONDITIONS_MATCH")


@dataclass(frozen=True,slots=True)
class InstalledRelationalCommitVerifier:
    decision_verifier: InstalledRelationalDecisionVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.decision_verifier) is not InstalledRelationalDecisionVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed relational commit verifier")
        p=_profile(_parse_jcs_object(self.profile_bytes));dv=self.decision_verifier
        if p["zone"]!=_parse_jcs_object(dv.profile_bytes)["zone"] or p["decision_profile_digest"]!=_digest(_parse_jcs_object(dv.profile_bytes),"sha256"):
            raise ValidationError("commit policy differs from selected accountable decision/zone")

    def evaluate(self,token_bytes,lease_bytes,*,evidence_digest,actual_operation,evaluated_at,clock_healthy,not_after=None):
        if not _time(evaluated_at):raise ValidationError("commit conditions require exact current time")
        if not_after is not None and (not _time(not_after) or not_after<=evaluated_at):
            raise ValidationError("commit validity must be bounded by fresh supporting evidence")
        p=_profile(_parse_jcs_object(self.profile_bytes));dv=self.decision_verifier
        decision=dv.evaluate(token_bytes,lease_bytes,evidence_digest=evidence_digest,actual_operation=actual_operation,
            evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        source=None
        def result(reason,body=None,expiry=None):
            import rfc8785
            r=object.__new__(RelationalCommitAssessment)
            for key,value in dict(conditional_commit=body is not None,action_permitted=False,reason=reason,decision=decision,
                    contract_bytes=None if body is None else rfc8785.dumps(body),contract_digest=None if body is None else _digest(body,"sha256"),
                    profile_bytes=self.profile_bytes,operation_bytes=decision.operation_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                    authenticated_state_bytes=None if source is None else source.state_bytes,source_evidence_bytes=None if source is None else source.evidence_bytes).items():
                object.__setattr__(r,key,value)
            return r
        if not decision.gate_satisfied:return result(decision.reason)
        source=self.context_source.resolve(deployment_profile_bytes=dv.adjudication_verifier.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            lease_bytes=lease_bytes,operation_bytes=decision.operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedRelationalCommitContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):raise ValidationError("actual registered authority/nonce/fence Source required")
        s=_parse_jcs_object(source.state_bytes)
        if not _valid_frame(s,evaluated_at):return result("RELATIONAL_COMMIT_FRAME_INVALID")
        lease=_parse_jcs_object(lease_bytes);op=_parse_jcs_object(decision.operation_bytes);rs=decision.reissue
        a=s["authority"];n=s["nonce"]
        expected_anchors=dict(grant=_parse_jcs_object(rs.authenticated_state_bytes)["grant"]["record_anchor"],nonce=n["record_anchor"],
            human_decision=decision.decision_anchor,template=lease["template_digest"],native_evidence=evidence_digest,
            adverse_stop=rs.ledger_head_anchor,authority=a["registry_anchor"])
        if (s["deployment_digest"]!=decision.adjudication.deployment_digest or s["profile_digest"]!=_digest(p,"sha256")
                or s["operation_digest"]!=digest_demand_operation(op,algorithm="sha256") or s["subject"]!=op["actor"] or s["zone"]!=p["zone"]
                or s["current_grant_epoch"]!=rs.current_grant_epoch or s["topology_epoch"]!=_parse_jcs_object(decision.adjudication.authenticated_state_bytes)["topology_epoch"]
                or s["ledger_head"]!={"anchor":rs.ledger_head_anchor,"sequence":rs.ledger_head_sequence}
                or a["id"]!=p["authority"] or a["id"]!=lease["issuer"] or a["nonce_namespace"]!=p["nonce_namespace"] or a["registered_at"]>lease["issued_at"]
                or n["lease_id"]!=lease["id"] or n["lease_digest"]!=rs.lease_digest or n["nonce"]!=lease["nonce"] or n["subject"]!=op["actor"]
                or n["grant_epoch"]!=rs.current_grant_epoch or n["registered_at"]>lease["issued_at"]
                or any(f["anchor"]!=expected_anchors[f["name"]] for f in s["fences"])):return result("RELATIONAL_COMMIT_BINDING")
        if a["withdrawn_at"] is not None or n["consumed_at"] is not None or n["revoked_at"] is not None:
            return result("RELATIONAL_COMMIT_NONCE_OR_AUTHORITY_INACTIVE")
        expiry=min(decision.expires_at,s["expires_at"],evaluated_at+p["max_contract_age_seconds"])
        if not_after is not None:expiry=min(expiry,not_after)
        if not _time(expiry):raise ValidationError("commit validity exceeds exact supported time range")
        body={k:s[k] for k in ("deployment_digest","profile_digest","operation_digest","subject","zone","current_grant_epoch","topology_epoch","ledger_head")}
        body.update(kind="conditional-relational-commit-v1",protocol=p["commit_protocol"],authority=p["authority"],nonce_namespace=p["nonce_namespace"],
            authority_state=a,nonce_state=n,nonce=n["nonce"],lease_digest=rs.lease_digest,template_digest=lease["template_digest"],
            human_decision_anchor=decision.decision_anchor,native_evidence_digest=evidence_digest,repair_ref=decision.repair_ref,
            fences=sorted(s["fences"],key=lambda f:f["name"]),checked_at=evaluated_at,expires_at=expiry)
        return result("RELATIONAL_COMMIT_CONDITIONAL",body,expiry)


__all__=("AuthenticatedRelationalCommitContext","RelationalCommitAssessment","RelationalCommitCheck","InstalledRelationalCommitVerifier","check_relational_commit")
