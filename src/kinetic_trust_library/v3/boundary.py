"""Installed zone-boundary checks over authenticated current external facts.

Identifiers and deployment-resolved patterns are compared as literal resource
sets. The authority source owns actual identity, resolution, jurisdiction and
authority-limit interpretation. An in-boundary result is never permission.
"""
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation


@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator
    schema=json.loads(files("kinetic_trust_library.v3").joinpath("schemas/deployment-profile-v3.json").read_text())
    return Draft202012Validator(schema["properties"]["boundary"])


def _boundary(raw):
    profile=_parse_jcs_object(raw)
    boundary=profile.get("boundary")
    if not _validator().is_valid(boundary):raise ValidationError("a valid declared boundary is required")
    if any(len(set(boundary[name]))!=len(boundary[name]) for name in ("resources","entitled_subjects","jurisdictions","authority_limits")):
        raise ValidationError("duplicate boundary declaration")
    classes=[value["class"] for value in boundary["affected_outside"]]
    if len(set(classes))!=len(classes):raise ValidationError("ambiguous boundary review route")
    return boundary


def _resolved(value,boundary):
    if (type(value) is not dict or set(value)!=set(boundary["resources"])
            or any(type(items) is not list or any(type(item) is not str or not item for item in items)
                   or len(set(items))!=len(items) for items in value.values())):
        raise ValidationError("boundary resources require complete literal installed resolution")
    return {item for items in value.values() for item in items}


@dataclass(frozen=True,slots=True)
class AuthenticatedBoundaryContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class BoundaryAssessment:
    allowed: bool
    reason: str
    deployment_digest: str
    operation_digest: str
    evaluated_at: int
    expires_at: int
    zone_id: str
    enclosure_zone: str | None
    topology_epoch: int
    enclosing_deployment_profile_bytes: bytes | None
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    review_routes: tuple[tuple[str,str], ...]

    def __init__(self,*args,**kwargs):raise TypeError("boundary assessments require installed verification")


@dataclass(frozen=True,slots=True)
class InstalledBoundaryVerifier:
    deployment_profile_bytes: bytes
    context_source: object
    algorithm: str
    enclosing_deployment_profile_bytes: bytes | None = None

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or self.algorithm not in ("sha256","sha384")
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed boundary policy")
        _boundary(self.deployment_profile_bytes)
        if self.enclosing_deployment_profile_bytes is not None:
            if type(self.enclosing_deployment_profile_bytes) is not bytes:raise ValidationError("invalid enclosing boundary")
            _boundary(self.enclosing_deployment_profile_bytes)

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("boundary requires a current healthy clock")
        operation_bytes=canonical_demand_operation_bytes(actual_operation)
        operation=_parse_jcs_object(operation_bytes)
        profile=_parse_jcs_object(self.deployment_profile_bytes);boundary=_boundary(self.deployment_profile_bytes)
        parent=self.enclosing_deployment_profile_bytes
        enclosing=None if parent is None else _boundary(parent)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,
            enclosing_deployment_profile_bytes=parent,operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedBoundaryContext or type(source.state_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("boundary source must authenticate current facts")
        state=_parse_jcs_object(source.state_bytes)
        deployment=_digest(profile,self.algorithm);invocation=digest_demand_operation(operation,algorithm=self.algorithm)
        if (set(state)!={"deployment_digest","operation_digest","enclosing_deployment_digest","checked_at","expires_at",
                "zone_id","enclosure_zone","topology_epoch","subject","subject_class","resource","affected_outside_classes",
                "authority_within_limits","resolved_resources","enclosing_resolved_resources"}
                or state["deployment_digest"]!=deployment or state["operation_digest"]!=invocation
                or state["enclosing_deployment_digest"]!=(None if parent is None else _digest(_parse_jcs_object(parent),self.algorithm))
                or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at
                or not _time(state["topology_epoch"]) or type(state["zone_id"]) is not str or not state["zone_id"]
                or state["subject"]!=operation["actor"] or state["resource"]!=operation["resource"]
                or type(state["subject_class"]) is not str or not state["subject_class"]
                or type(state["authority_within_limits"]) is not bool):
            raise ValidationError("boundary context differs from actual invocation/declaration/time")
        affected=state["affected_outside_classes"]
        routes={value["class"]:value["review_route"] for value in boundary["affected_outside"]}
        if (type(affected) is not list or any(type(value) is not str or value not in routes for value in affected)
                or len(set(affected))!=len(affected)):
            raise ValidationError("affected party lacks an unambiguous declared review route")
        resources=_resolved(state["resolved_resources"],boundary)
        reason="BOUNDARY_WITHIN"
        if enclosing is None:
            if state["enclosure_zone"] is not None or state["enclosing_resolved_resources"] is not None:
                raise ValidationError("undeclared enclosing boundary")
        else:
            if type(state["enclosure_zone"]) is not str or not state["enclosure_zone"] or state["enclosure_zone"]==state["zone_id"]:
                raise ValidationError("invalid enclosing boundary zone")
            if not resources<=_resolved(state["enclosing_resolved_resources"],enclosing):reason="BOUNDARY_ENCLOSURE"
        if reason=="BOUNDARY_WITHIN":
            reason=("BOUNDARY_RESOURCE" if operation["resource"] not in resources else
                    "BOUNDARY_SUBJECT" if state["subject_class"] not in boundary["entitled_subjects"] else
                    "BOUNDARY_AUTHORITY" if not state["authority_within_limits"] else "BOUNDARY_WITHIN")
        allowed=reason=="BOUNDARY_WITHIN"
        result=object.__new__(BoundaryAssessment)
        for name,value in dict(allowed=allowed,reason=reason,deployment_digest=deployment,operation_digest=invocation,
            evaluated_at=evaluated_at,expires_at=state["expires_at"],zone_id=state["zone_id"],enclosure_zone=state["enclosure_zone"],
            topology_epoch=state["topology_epoch"],enclosing_deployment_profile_bytes=parent,
            authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
            review_routes=() if allowed else tuple(sorted((value,routes[value]) for value in affected))).items():object.__setattr__(result,name,value)
        return result


__all__=("InstalledBoundaryVerifier","BoundaryAssessment","AuthenticatedBoundaryContext")
