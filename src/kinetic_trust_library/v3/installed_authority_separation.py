"""Architectural audit and counted-measurer binding for a native decision.

Source establishes the actual audited access/capability inventory, accepted-key
registries and which authenticated environment attestations the decision used.
The Library validates their bindings and structural rules, not their physical
truth. This is explicitly audit-grade evidence, never cryptographic custody
proof, a signature verifier, a complete hand-back claim or execution permission.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .authority_separation import project_authority_separation,_names
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation


def _profile(p):
    if (set(p)!={"id","version","zone","formula","lease_authority","zone_class","quorum_members","quorum_k",
            "single_measurer_limit","maximum_audit_age_seconds","accepted_auditors"}
            or any(not _name(p[k]) for k in ("id","zone","lease_authority"))
            or not _time(p["version"]) or p["version"]==0 or p["formula"]!="audited-key-and-measurer-separation-v1"
            or not _time(p["maximum_audit_age_seconds"]) or p["maximum_audit_age_seconds"]==0
            or not _names(p["accepted_auditors"])):
        raise ValidationError("invalid selected authority-separation audit profile")
    members=_names(p["quorum_members"])
    if (not members or not _time(p["quorum_k"]) or not 1<=p["quorum_k"]<=len(members)
            or p["zone_class"] not in ("green","cyan","blue","deep_blue")
            or p["zone_class"] in ("blue","deep_blue") and p["quorum_k"]<2
            or p["single_measurer_limit"] is not None and (type(p["single_measurer_limit"]) is not str or not 0<len(p["single_measurer_limit"])<=4096)
            or p["quorum_k"]==1 and p["single_measurer_limit"] is None):
        raise ValidationError("invalid selected zone-specific measurer quorum")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedAuthoritySeparationContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class AuthoritySeparationAssessment:
    valid: bool
    reason: str
    action_permitted: bool
    projection: object
    decision_digest: str
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("authority separation requires installed actual audit/decision facts")


@dataclass(frozen=True,slots=True)
class InstalledAuthoritySeparationVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed authority-separation verifier")
        _parse_jcs_object(self.deployment_profile_bytes);_profile(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,decision_digest,actual_operation,evaluated_at,clock_healthy):
        if not is_digest(decision_digest) or not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("current trusted audit time and exact decision digest required")
        p=_profile(_parse_jcs_object(self.profile_bytes));op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            decision_digest=decision_digest,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedAuthoritySeparationContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("authority Source requires actual audit and decision attestation evidence")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","decision_digest","subject","zone","lease_authority",
                    "checked_at","expires_at","inventory","audit","attestations"}
                or s["deployment_digest"]!=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
                or s["profile_digest"]!=_digest(p,self.algorithm) or s["operation_digest"]!=digest_demand_operation(op,algorithm=self.algorithm)
                or s["decision_digest"]!=decision_digest or s["subject"]!=op["actor"] or s["zone"]!=p["zone"]
                or s["lease_authority"]!=p["lease_authority"] or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at):
            raise ValidationError("authority audit differs from current actual decision/deployment/issuer")
        projection=project_authority_separation(inventory=s["inventory"],quorum_members=p["quorum_members"],quorum_k=p["quorum_k"],
            zone_class=p["zone_class"],single_measurer_limit=p["single_measurer_limit"])
        audit=s["audit"];inventory_digest=_digest({k:v for k,v in s["inventory"].items() if k!="used_measurers"},self.algorithm)
        if (type(audit) is not dict or set(audit)!={"anchor","auditor","observed_at","profile_digest","inventory_digest"}
                or not _name(audit["anchor"]) or audit["auditor"] not in p["accepted_auditors"]
                or audit["profile_digest"]!=s["profile_digest"] or audit["inventory_digest"]!=inventory_digest
                or not _time(audit["observed_at"]) or not audit["observed_at"]<=evaluated_at<audit["observed_at"]+p["maximum_audit_age_seconds"]):
            raise ValidationError("actual current architectural audit does not cover this inventory/profile")
        attestations=s["attestations"];used=set(s["inventory"]["used_measurers"])
        if type(attestations) is not list or len(attestations)!=len(used):raise ValidationError("complete actually counted environment attestations required")
        seen=set();anchors={audit["anchor"]};roster={m["id"]:m for m in s["inventory"]["measurers"]}
        for a in attestations:
            if (type(a) is not dict or set(a)!={"anchor","measurer","key_id","decision_digest"}
                    or not _name(a["anchor"]) or a["anchor"] in anchors or not _name(a["measurer"])
                    or a["measurer"] not in used or a["measurer"] in seen
                    or a["key_id"] not in roster[a["measurer"]]["accepted_keys"] or a["decision_digest"]!=decision_digest):
                raise ValidationError("counted attestation substitutes actual measurer/key/decision")
            seen.add(a["measurer"]);anchors.add(a["anchor"])
        expiry=min(s["expires_at"],audit["observed_at"]+p["maximum_audit_age_seconds"])
        result=object.__new__(AuthoritySeparationAssessment)
        for k,v in dict(valid=projection.valid,reason=projection.reason,action_permitted=False,projection=projection,
            decision_digest=decision_digest,profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,
            authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,k,v)
        return result
