"""Installed actual execution-boundary evidence, never a dispatch mechanism.

Source authenticates historical signed decisions and their complete semantics,
actual observations made by the declared execution boundary, route enforcement
truth and authoritative absence. A failed lookup is not authenticated absence.
Library binds whole operation/actor/zone/epoch, raw record digests and time.
These private semantic projections do not introduce an audit wire format.
"""
from dataclasses import dataclass
import hashlib
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .root_lifecycle import _time
from .execution_observation import (ExecutionScope,ExecutionDecision,ExecutionObservation,
                                    classify_execution_observation,_name)


def _profile(value):
    if (type(value) is not dict or set(value)!={"id","version","zone","enforcement_level","formula"}
            or any(not _name(value[key]) for key in ("id","zone","enforcement_level"))
            or not _time(value["version"]) or value["version"]==0
            or value["formula"]!="decision-bound-boundary-observation-v1"):
        raise ValidationError("invalid installed execution-observation profile")
    return value


@dataclass(frozen=True,slots=True)
class AuthenticatedExecutionObservationContext:
    state_bytes: bytes
    decision_record_bytes: bytes | None
    observation_record_bytes: bytes | None
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class ExecutionObservationAssessment:
    projection: object
    decision: ExecutionDecision | None
    observation: ExecutionObservation | None
    scope: ExecutionScope
    enforcement_level: str
    deployment_digest: str
    profile_bytes: bytes
    profile_digest: str
    operation_bytes: bytes
    checked_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    decision_record_bytes: bytes | None
    observation_record_bytes: bytes | None
    source_evidence_bytes: bytes
    frame_digest: str

    def __init__(self,*args,**kwargs):raise TypeError("execution observations require installed verification")


@dataclass(frozen=True,slots=True)
class InstalledExecutionObservationVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384")
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed execution-observation verifier")
        _parse_jcs_object(self.deployment_profile_bytes);_profile(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("execution observation requires healthy current clock")
        operation_bytes=canonical_demand_operation_bytes(actual_operation)
        operation=_parse_jcs_object(operation_bytes)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        profile=_profile(_parse_jcs_object(self.profile_bytes));policy=_digest(profile,self.algorithm)
        invocation=digest_demand_operation(operation,algorithm=self.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,
            profile_bytes=self.profile_bytes,operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedExecutionObservationContext
                or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("execution observation requires authenticated complete boundary state")
        state=_parse_jcs_object(source.state_bytes)
        if (set(state)!={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","scope",
                "enforcement_point_present","enforcement_level","decision","observation","observation_record_digest"}
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=policy
                or state["operation_digest"]!=invocation or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at
                or state["enforcement_level"]!=profile["enforcement_level"]
                or type(state["enforcement_point_present"]) is not bool):
            raise ValidationError("execution observation differs from actual invocation/profile/time")
        def scope_of(value):
            if type(value) is not dict or set(value)!={"actor","operation_digest","zone","topology_epoch"}:
                raise ValidationError("execution scope must be complete and closed")
            return ExecutionScope(**value)
        scope=scope_of(state["scope"])
        if (scope.actor!=operation["actor"] or scope.operation_digest!=invocation or scope.zone!=profile["zone"]):
            raise ValidationError("boundary scope differs from actual actor/whole operation/zone")
        def raw_digest(raw):
            if type(raw) is not bytes or not 0<len(raw)<=262144:
                raise ValidationError("execution evidence requires complete bounded immutable record")
            return self.algorithm+":"+hashlib.new(self.algorithm,raw).hexdigest()
        decision=None;observation=None
        body=state["decision"]
        if body is None:
            if source.decision_record_bytes is not None:raise ValidationError("absent decision has record bytes")
        else:
            if type(body) is not dict or set(body)!={"scope","decision_id","record_digest","decided_at","execution_permitted","supervision"}:
                raise ValidationError("invalid authenticated decision projection")
            decision=ExecutionDecision(scope_of(body["scope"]),**{k:v for k,v in body.items() if k!="scope"})
            if decision.record_digest!=raw_digest(source.decision_record_bytes) or decision.decided_at>evaluated_at:
                raise ValidationError("decision record digest/time differs from historical evidence")
        body=state["observation"]
        if body is None:
            if source.observation_record_bytes is not None or state["observation_record_digest"] is not None:
                raise ValidationError("absent observation has record bytes or digest")
        else:
            if type(body) is not dict or set(body)!={"scope","decision_id","decision_digest","boundary_id","kind","observed_at"}:
                raise ValidationError("invalid authenticated execution-boundary projection")
            observation=ExecutionObservation(scope_of(body["scope"]),**{k:v for k,v in body.items() if k!="scope"})
            if state["observation_record_digest"]!=raw_digest(source.observation_record_bytes) or observation.observed_at>evaluated_at:
                raise ValidationError("observation record digest/time differs from boundary evidence")
        projection=classify_execution_observation(scope=scope,decision=decision,observation=observation,
            enforcement_point_present=state["enforcement_point_present"])
        result=object.__new__(ExecutionObservationAssessment)
        frame={key:value for key,value in state.items() if key not in ("checked_at","expires_at")}
        for key,value in dict(projection=projection,decision=decision,observation=observation,scope=scope,
                enforcement_level=state["enforcement_level"],deployment_digest=deployment,profile_bytes=self.profile_bytes,
                profile_digest=policy,operation_bytes=operation_bytes,checked_at=evaluated_at,expires_at=state["expires_at"],
                authenticated_state_bytes=source.state_bytes,decision_record_bytes=source.decision_record_bytes,
                observation_record_bytes=source.observation_record_bytes,source_evidence_bytes=source.evidence_bytes,
                frame_digest=_digest(frame,self.algorithm)).items():object.__setattr__(result,key,value)
        return result
