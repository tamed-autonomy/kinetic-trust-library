"""Installed person signed-act and institutional standing evidence boundary.

Source authenticates the complete corrected signed-act ledger, the declared
contribution assessment and current standing of the exact Root terminator.
This is a provisional zero-peer profile, not a human-capacity evaluation.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .assessed_root_selection import AssessedRootSelection
from .person_standing import calculate_person_standing
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .demand_supplier import _digest
from .root_lifecycle import _time
from .execution_observation import _name


@dataclass(frozen=True,slots=True)
class AuthenticatedPersonStandingContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class PersonStandingAssessment:
    standing: object
    roots: AssessedRootSelection
    operation_bytes: bytes
    profile_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    evaluated_at: int
    expires_at: int
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("installed person standing requires current authenticated evidence")


@dataclass(frozen=True,slots=True)
class InstalledPersonStandingVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed person standing verifier")
        dp=_parse_jcs_object(self.deployment_profile_bytes);p=_parse_jcs_object(self.profile_bytes)
        if (set(p)!={"id","version","zone","formula","contribution_policy","trajectory_ceiling_policy"}
                or any(not _name(p[k]) for k in ("id","zone","contribution_policy","trajectory_ceiling_policy"))
                or not _time(p["version"]) or p["version"]==0 or p["formula"]!="signed-act-single-root-person-standing-v1"
                or type(dp.get("peer_share")) is not int or dp["peer_share"]!=0
                or type(dp.get("external_root")) is not dict or type(dp["external_root"].get("hop_bound")) is not int
                or not 1<=dp["external_root"]["hop_bound"]<=12):
            raise ValidationError("person standing requires explicit zero-peer and provisional trajectory policies")

    def evaluate(self,*,roots,actual_operation,evaluated_at,clock_healthy):
        if type(roots) is not AssessedRootSelection or not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("person standing requires current root selection and healthy time")
        dp=_parse_jcs_object(self.deployment_profile_bytes);p=_parse_jcs_object(self.profile_bytes)
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        context=_parse_jcs_object(roots.context_bytes)
        if sum(_parse_jcs_object(c.projection_bytes)["kind"]!="none" for c in roots.candidates)>1:
            raise ValidationError("selected person profile does not support multiple current Root instruments")
        if (roots.evaluated_at!=evaluated_at or roots.algorithm!=self.algorithm
                or context.get("deployment_digest")!=_digest(dp,self.algorithm) or context.get("subject")!=op["actor"]
                or context.get("subject_profile")!="person" or context.get("receiving_zone")!=p["zone"]
                or context.get("hop_bound")!=dp["external_root"]["hop_bound"]
                or set(context)&{"generation","lineage","mass_ceiling","mitosis"}):
            raise ValidationError("person Root context differs from installed subject/zone/deployment")
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,root_selection=roots,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedPersonStandingContext or type(source.state_bytes) is not bytes
                or len(source.state_bytes)>262144 or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("person standing Source must authenticate bounded complete ledger and institution facts")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at",
                "signed_acts","por_contribution","zone_risk","ceilings","contribution_policy","trajectory_ceiling_policy",
                "ledger_head","root_digest","terminator"}
                or s["deployment_digest"]!=_digest(dp,self.algorithm) or s["profile_digest"]!=_digest(p,self.algorithm)
                or s["operation_digest"]!=digest_demand_operation(op,algorithm=self.algorithm) or s["subject"]!=op["actor"]
                or s["zone"]!=p["zone"] or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at or not _name(s["ledger_head"])
                or s["contribution_policy"]!=p["contribution_policy"] or s["trajectory_ceiling_policy"]!=p["trajectory_ceiling_policy"]
                or type(s["signed_acts"]) is not list or type(s["ceilings"]) is not dict or "trajectory" not in s["ceilings"]):
            raise ValidationError("person standing evidence differs from actual current request and declared policies")
        expiry=s["expires_at"];institutional_standing=0
        if roots.selected is None:
            if s["root_digest"] is not None or s["terminator"] is not None:
                raise ValidationError("missing current person Root cannot retain institutional credit")
        else:
            root=_parse_jcs_object(roots.selected.projection_bytes);institution=s["terminator"]
            if (root["kind"]!="external_attestation" or root["root_person"]!=op["actor"]
                    or root["attestation_digest"]!=s["root_digest"] or type(institution) is not dict
                    or set(institution)!={"identity","standing","anchor","as_of","expires_at"}
                    or institution["identity"]!=root["terminator"] or not _name(institution["anchor"])
                    or not _time(institution["as_of"]) or institution["as_of"]!=evaluated_at
                    or not _time(institution["expires_at"]) or institution["expires_at"]<=evaluated_at
                    or root["end_time"]<=evaluated_at):
                raise ValidationError("person institutional standing differs from actual current accountable Root")
            institutional_standing=institution["standing"]
            expiry=min(expiry,institution["expires_at"],root["end_time"])
        standing=calculate_person_standing(subject=op["actor"],zone=p["zone"],signed_acts=tuple(s["signed_acts"]),
            por_contribution=s["por_contribution"],terminator_standing=institutional_standing,ceilings=s["ceilings"],
            zone_risk=s["zone_risk"],evaluated_at=evaluated_at)
        result=object.__new__(PersonStandingAssessment)
        for k,v in dict(standing=standing,roots=roots,operation_bytes=op_bytes,profile_bytes=self.profile_bytes,
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
                evaluated_at=evaluated_at,expires_at=expiry,action_permitted=False).items():object.__setattr__(result,k,v)
        return result
