"""Current software observations through an independently installed Source.

Source authenticates actual invocation/destination identity, original evidence,
source health/heads, current keys, complete protected history and calibrated
assessment truth. This module checks their deterministic bindings and preserves
unavailability/holds. Its results never authorize consumption or effects.
"""
from dataclasses import dataclass
import hashlib
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library._decimal import as_decimal
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .demand_supplier import _digest
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .software_restrictions import software_magnitudes
from .native_envelope import NativeEnvelopeThresholds


SOURCE_UNITS={"resource_pressure":"ratio","control_latency":"milliseconds","operation_assessment":"ratio-pair",
    "repair_path":"boolean","supervision_availability":"boolean","invalidation":"status"}


def software_binding(b):
    names={"request_id","actor_id","workload_id","authority_class","operation_id","resource_id","enforcement_destination"}
    digests={"parameters_digest","identity_session_digest","execution_profile_digest","policy_digest"}
    if (type(b) is not dict or set(b)!=names|digests
            or any(not _name(b[n]) or len(b[n])>512 or any(c in b[n] for c in "*?[]{}") for n in names)
            or any(not is_digest(b[n]) for n in digests)):
        raise ValidationError("actual software request requires exact literal invocation and complete digest bindings")
    return b


def software_thresholds(value):
    if value is None:return None
    if type(value) is not dict or set(value)!={"veto","assisted_floor","metacognitive_floor","allow"}:
        raise ValidationError("invalid installed software envelope thresholds")
    return NativeEnvelopeThresholds(**value)


@dataclass(frozen=True,slots=True)
class AuthenticatedSoftwareObservation:
    record_bytes: bytes
    original_evidence_bytes: bytes


@dataclass(frozen=True,slots=True)
class AuthenticatedSoftwarePrerequisite:
    kind: str
    representation: str
    artifact_bytes: bytes
    projection_bytes: bytes


@dataclass(frozen=True,slots=True)
class AuthenticatedSoftwareContext:
    state_bytes: bytes
    signing_keys_bytes: bytes
    observations: tuple[AuthenticatedSoftwareObservation,...]
    prerequisites: tuple[AuthenticatedSoftwarePrerequisite,...]
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class SoftwareEvidenceAssessment:
    verifier: object
    valid: bool
    reason: str
    checked_at: int
    expires_at: int
    inputs_expires_at: int
    operation_bytes: bytes
    profile_bytes: bytes
    request_binding_bytes: bytes
    observations_bytes: bytes
    source_state_bytes: bytes
    source_evidence_bytes: bytes
    signing_keys_bytes: bytes
    prerequisites: tuple
    assessment_bytes: bytes
    undefined_classes: tuple
    repair_path_verified: bool
    supervision_available: bool
    consumption_epoch: int
    state_revision: int
    frame_bytes: bytes
    frame_digest: str
    unresolved_restrictions: tuple
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("software evidence requires installed authenticated current sources")


def _history(events,authority,now):
    if type(events) is not list or len(events)>4096:raise ValidationError("complete bounded restriction history required")
    anchors=set();active={};sequence=-1;occurred=-1
    common={"kind","anchor","sequence","occurred_at","authority","cause_anchor"}
    for e in events:
        if (type(e) is not dict or e.get("kind") not in ("impose","resolve")
                or set(e)!=(common if e["kind"]=="impose" else common|{"restriction_anchor"})
                or any(not _name(e[k]) for k in ("anchor","authority","cause_anchor")) or e["anchor"] in anchors
                or e["authority"]!=authority or not _time(e["sequence"]) or e["sequence"]<=sequence
                or not _time(e["occurred_at"]) or not occurred<=e["occurred_at"]<=now):
            raise ValidationError("restriction history must preserve actual ordered original authority events")
        anchors.add(e["anchor"]);sequence=e["sequence"];occurred=e["occurred_at"]
        if e["kind"]=="impose":active[e["anchor"]]=e["cause_anchor"]
        elif not _name(e["restriction_anchor"]) or active.get(e["restriction_anchor"])!=e["cause_anchor"]:
            raise ValidationError("resolution does not address the actual active restriction and its original cause")
        else:del active[e["restriction_anchor"]]
    return tuple(active)


@dataclass(frozen=True,slots=True)
class InstalledSoftwareEvidenceVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed software evidence verifier")
        p=_parse_jcs_object(self.profile_bytes);dp=_parse_jcs_object(self.deployment_profile_bytes)
        if (set(p)!={"id","version","zone","formula","deployment_digest","execution_profile_digest","policy_digest","scale",
                "mapping_digest","assessment_profile_digest","authority_classes","sources","state_registry","key_registry","restriction_authority",
                "checkpoint_seconds","maximum_control_latency_ms","allow_conservative_capacity","envelope_thresholds"}
                or any(not _name(p[n]) for n in ("id","zone","state_registry","key_registry","restriction_authority"))
                or not _time(p["version"]) or p["version"]==0 or p["formula"]!="native-software-current-evidence-v1"
                or p["deployment_digest"]!=_digest(dp,self.algorithm) or p["scale"]!="urn:ktp:unit:action-risk-points"
                or any(not is_digest(p[n]) for n in ("execution_profile_digest","policy_digest","mapping_digest","assessment_profile_digest"))
                or not _time(p["checkpoint_seconds"]) or p["checkpoint_seconds"]==0 or not _time(p["maximum_control_latency_ms"])
                or type(p["allow_conservative_capacity"]) is not bool or type(p["authority_classes"]) is not dict or not p["authority_classes"]
                or any(not _name(k) or v not in ("Logistics","Coordination","Relational") for k,v in p["authority_classes"].items())
                or type(p["sources"]) is not list or len(p["sources"])!=6):
            raise ValidationError("software evidence requires exact installed declaration and native comparable scale")
        kinds=[]
        for d in p["sources"]:
            if (type(d) is not dict or set(d)!={"kind","source","unit","max_age_seconds"}
                    or type(d["kind"]) is not str or d["kind"] not in SOURCE_UNITS or not _name(d["source"])
                    or d["unit"]!=SOURCE_UNITS[d["kind"]] or not _time(d["max_age_seconds"]) or d["max_age_seconds"]==0):
                raise ValidationError("each software source requires its declared class/source/unit and positive bounded age")
            kinds.append(d["kind"])
        if len(set(kinds))!=6:raise ValidationError("software evidence requires every source class exactly once")
        software_thresholds(p["envelope_thresholds"])

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy,previous_assessment=None):
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("software evidence requires healthy current trusted time")
        import rfc8785
        p=_parse_jcs_object(self.profile_bytes);op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedSoftwareContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.signing_keys_bytes) is not bytes or len(source.signing_keys_bytes)>262144
                or type(source.observations) is not tuple or len(source.observations)!=6
                or type(source.prerequisites) is not tuple or len(source.prerequisites)>64
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("software Source must authenticate complete current facts and original artifacts")
        s=_parse_jcs_object(source.state_bytes);keys=_parse_jcs_object(source.signing_keys_bytes)
        expected={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at","request_binding",
            "target_revision","recovery_boundary","mapping_digest","requested_magnitudes","existing_ceilings","consumption_epoch","state_revision",
            "state_registry","key_registry","key_registry_anchor","signing_keys_digest","heads","restriction_history","assessment","continuity_checkpoint"}
        if (set(s)!=expected or s["deployment_digest"]!=p["deployment_digest"] or s["profile_digest"]!=_digest(p,self.algorithm)
                or s["operation_digest"]!=digest_demand_operation(op,algorithm=self.algorithm) or s["subject"]!=op["actor"] or s["zone"]!=p["zone"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or s["mapping_digest"]!=p["mapping_digest"] or not _name(s["target_revision"]) or not _name(s["recovery_boundary"])
                or not _time(s["consumption_epoch"]) or s["consumption_epoch"]==0 or not _time(s["state_revision"]) or s["state_revision"]==0
                or s["state_registry"]!=p["state_registry"] or s["key_registry"]!=p["key_registry"] or not _name(s["key_registry_anchor"])
                or s["signing_keys_digest"]!=_digest(keys,self.algorithm)):
            raise ValidationError("software Source differs from actual current deployment/profile/request/registry scope")
        b=software_binding(s["request_binding"])
        if (b["actor_id"]!=op["actor"] or b["request_id"]!=op["request_id"] or b["operation_id"]!=op["operation"] or b["resource_id"]!=op["resource"]
                or b["parameters_digest"]!=_digest(op["parameters"],self.algorithm) or b["execution_profile_digest"]!=p["execution_profile_digest"]
                or b["policy_digest"]!=p["policy_digest"] or b["authority_class"] not in p["authority_classes"]):
            raise ValidationError("software request binding differs from actual authenticated executing operation")
        software_magnitudes(s["requested_magnitudes"]);software_magnitudes(s["existing_ceilings"])
        active=_history(s["restriction_history"],p["restriction_authority"],evaluated_at)
        scope=dict(request_digest=_digest(b,self.algorithm),target_revision=s["target_revision"],recovery_boundary=s["recovery_boundary"])
        heads=s["heads"]
        if type(heads) is not dict or set(heads)!=set(SOURCE_UNITS):raise ValidationError("complete current software source heads required")
        records=[];undefined=[];values={};reason="SOFTWARE_EVIDENCE_CURRENT";valid=True
        input_expiry=s["expires_at"]
        counters={}
        for d,a in zip(p["sources"],source.observations):
            if (type(a) is not AuthenticatedSoftwareObservation or type(a.record_bytes) is not bytes or len(a.record_bytes)>65536
                    or type(a.original_evidence_bytes) is not bytes or not 0<len(a.original_evidence_bytes)<=1048576):
                raise ValidationError("actual original authenticated software observation/evidence bytes required")
            r=_parse_jcs_object(a.record_bytes);kind=d["kind"];h=heads[kind]
            if (set(r)!={"kind","source","scope","epoch","sequence","observed_at","max_age_seconds","value","unit","evidence_digest"}
                    or r["kind"]!=kind or r["source"]!=d["source"] or r["scope"]!=scope or r["unit"]!=d["unit"]
                    or not _time(r["epoch"]) or r["epoch"]==0 or not _time(r["sequence"]) or not _time(r["observed_at"])
                    or type(r["max_age_seconds"]) is not int or r["max_age_seconds"]!=d["max_age_seconds"]
                    or r["evidence_digest"]!=self.algorithm+":"+hashlib.new(self.algorithm,a.original_evidence_bytes).hexdigest()
                    or type(h) is not dict or set(h)!={"source","epoch","sequence","record_digest","health_anchor","checked_at","health_expires_at","status"}
                    or h["source"]!=d["source"] or type(h["epoch"]) is not int or h["epoch"]!=r["epoch"]
                    or type(h["sequence"]) is not int or h["sequence"]!=r["sequence"] or h["record_digest"]!=_digest(r,self.algorithm)
                    or not _name(h["health_anchor"]) or not _time(h["checked_at"]) or h["checked_at"]!=evaluated_at
                    or not _time(h["health_expires_at"]) or h["status"] not in ("healthy","unhealthy","unavailable")):
                raise ValidationError("software observation differs from installed source/scope/original evidence/current head")
            records.append(r);counters[kind]={n:h[n] for n in ("source","epoch","sequence","record_digest")}
            deadline=r["observed_at"]+d["max_age_seconds"]
            if not _time(deadline):raise ValidationError("software observation freshness deadline exceeds supported range")
            input_expiry=min(input_expiry,deadline,h["health_expires_at"])
            if h["status"]!="healthy" or h["health_expires_at"]<=evaluated_at:
                valid=False;reason="SOFTWARE_SOURCE_UNAVAILABLE";undefined.append(kind)
            if not r["observed_at"]<=evaluated_at<deadline:
                valid=False;reason="SOFTWARE_OBSERVATION_UNAVAILABLE";undefined.append(kind)
            value=r["value"];values[kind]=value
            if value is None:undefined.append(kind);continue
            if kind=="resource_pressure":as_decimal(value,name="software pressure",minimum=0,maximum=1)
            elif kind=="control_latency":
                if not _time(value):raise ValidationError("software control latency requires safe integer milliseconds")
                if value>p["maximum_control_latency_ms"]:valid=False;reason="SOFTWARE_CONTROL_LATENCY"
            elif kind=="operation_assessment":
                if type(value) is not dict or set(value)!={"irreversibility","novelty"}:raise ValidationError("complete current operation assessment required")
                for n in value:as_decimal(value[n],name="software "+n,minimum=0,maximum=1)
            elif kind in ("repair_path","supervision_availability"):
                if type(value) is not bool:raise ValidationError("software availability requires actual boolean observation")
            elif (type(value) is not dict or set(value)!={"status","consumption_epoch"} or value["status"] not in ("active","revoked","unavailable")
                    or type(value["consumption_epoch"]) is not int or value["consumption_epoch"]!=s["consumption_epoch"]):
                raise ValidationError("fresh actual invalidation status must name the current consumption epoch")
        checkpoint=s["continuity_checkpoint"]
        if (type(checkpoint) is not dict or set(checkpoint)!={"anchor","registry","epoch","revision","counter_heads_digest","restriction_history_digest"}
                or not _name(checkpoint["anchor"]) or checkpoint["registry"]!=p["state_registry"] or type(checkpoint["epoch"]) is not int
                or checkpoint["epoch"]!=s["consumption_epoch"] or type(checkpoint["revision"]) is not int or checkpoint["revision"]!=s["state_revision"]
                or checkpoint["counter_heads_digest"]!=_digest(counters,self.algorithm)
                or checkpoint["restriction_history_digest"]!=_digest(s["restriction_history"],self.algorithm)):
            raise ValidationError("software use requires the actual complete current protected continuity checkpoint")
        if previous_assessment is not None:
            if (type(previous_assessment) is not SoftwareEvidenceAssessment or previous_assessment.verifier is not self
                    or previous_assessment.operation_bytes!=op_bytes or previous_assessment.checked_at>evaluated_at):
                raise ValidationError("retained software assessment belongs to another installed scope or clock")
            old=_parse_jcs_object(previous_assessment.source_state_bytes);history=old["restriction_history"]
            if (s["consumption_epoch"]<old["consumption_epoch"] or s["state_revision"]<old["state_revision"]
                    or s["restriction_history"][:len(history)]!=history):
                raise ValidationError("software restore cannot roll back epoch/revision or erase/rewrite prior restrictions")
            if s["state_revision"]==old["state_revision"] and checkpoint!=old["continuity_checkpoint"]:
                raise ValidationError("software protected state changed under the same retained revision")
            for kind,h in heads.items():
                prior=old["heads"][kind]
                if (h["epoch"]>prior["epoch"]+1 or h["epoch"]==prior["epoch"] and h["sequence"]>prior["sequence"]+1):
                    raise ValidationError("software source continuity has an unaccounted sequence/epoch gap")
                if (h["epoch"]<prior["epoch"] or h["epoch"]==prior["epoch"] and (h["sequence"]<prior["sequence"]
                        or h["sequence"]==prior["sequence"] and h["record_digest"]!=prior["record_digest"])):
                    raise ValidationError("software source head rolled back or rewrote an original observation")
        assessment=s["assessment"]
        if (type(assessment) is not dict or set(assessment)!={"profile_digest","basis_anchor","evaluated_at","autonomyDemand","environmentalCapacity","capacityKnown"}
                or assessment["profile_digest"]!=p["assessment_profile_digest"] or not _name(assessment["basis_anchor"])
                or not _time(assessment["evaluated_at"]) or assessment["evaluated_at"]!=evaluated_at or type(assessment["capacityKnown"]) is not bool):
            raise ValidationError("actual calibrated software capacity/demand assessment required")
        for name in ("autonomyDemand","environmentalCapacity"):as_decimal(assessment[name],name="software "+name,minimum=0,maximum=100)
        unknown=tuple(dict.fromkeys(undefined))
        if unknown and (not p["allow_conservative_capacity"] or assessment["capacityKnown"]):valid=False;reason="SOFTWARE_ESTIMATE_UNAVAILABLE"
        if values["control_latency"] is None:
            valid=False;reason="SOFTWARE_CONTROL_LATENCY_UNAVAILABLE"
        if (values["invalidation"] is None or values["invalidation"]["status"]!="active"):
            valid=False;reason="SOFTWARE_INVALIDATED"
        if active:valid=False;reason="SOFTWARE_RESTRICTION_UNRESOLVED"
        for artifact in source.prerequisites:
            if (type(artifact) is not AuthenticatedSoftwarePrerequisite or not _name(artifact.kind)
                    or artifact.representation not in ("canonical-json","source-contract-original-bytes")
                    or type(artifact.artifact_bytes) is not bytes or not 0<len(artifact.artifact_bytes)<=262144
                    or type(artifact.projection_bytes) is not bytes or len(artifact.projection_bytes)>262144):
                raise ValidationError("complete original authenticated prerequisite artifacts required")
            _parse_jcs_object(artifact.projection_bytes)
            if artifact.representation=="canonical-json":_parse_jcs_object(artifact.artifact_bytes)
        frame=dict(deployment_digest=s["deployment_digest"],profile_digest=s["profile_digest"],registry=p["state_registry"],
            consumption_epoch=s["consumption_epoch"],state_revision=s["state_revision"],checkpoint=checkpoint,
            request_binding=b,target_revision=s["target_revision"],recovery_boundary=s["recovery_boundary"],mapping_digest=s["mapping_digest"],
            requested_magnitudes=s["requested_magnitudes"],existing_ceilings=s["existing_ceilings"],
            key_registry=s["key_registry"],key_registry_anchor=s["key_registry_anchor"],signing_keys_digest=s["signing_keys_digest"],
            source_health={kind:{n:h[n] for n in ("status","health_anchor","health_expires_at")} for kind,h in heads.items()},
            assessment={n:v for n,v in assessment.items() if n not in ("basis_anchor","evaluated_at")})
        result=object.__new__(SoftwareEvidenceAssessment)
        for k,v in dict(verifier=self,valid=valid,reason=reason,checked_at=evaluated_at,
                expires_at=min(input_expiry,evaluated_at+p["checkpoint_seconds"]),inputs_expires_at=input_expiry,operation_bytes=op_bytes,
                profile_bytes=self.profile_bytes,request_binding_bytes=rfc8785.dumps(b),observations_bytes=rfc8785.dumps(records),
                source_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,signing_keys_bytes=source.signing_keys_bytes,
                prerequisites=source.prerequisites,assessment_bytes=rfc8785.dumps(assessment),undefined_classes=unknown,
                repair_path_verified=values["repair_path"] is True,supervision_available=values["supervision_availability"] is True,
                consumption_epoch=s["consumption_epoch"],state_revision=s["state_revision"],frame_bytes=rfc8785.dumps(frame),frame_digest=_digest(frame,self.algorithm),
                unresolved_restrictions=active,action_permitted=False).items():object.__setattr__(result,k,v)
        return result
