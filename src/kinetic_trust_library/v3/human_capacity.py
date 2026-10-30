"""Current reviewed human measurements, never credentials or personal scores.

Source authenticates original measurement/review signatures, calibration,
comparability, actual human execution identity and complete current revocations.
This prerequisite cannot provide eligibility, standing, a proof or permission.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .demand_supplier import _digest
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest
from .person_standing import _person
from .installed_soul import NativeSoulAssessment
from .native_envelope import NativeEnvelopeThresholds,project_comparable_envelope
from kinetic_trust_library._decimal import as_decimal


def thresholds(p):
    t=p["envelope_thresholds"]
    if t is None:return None
    if type(t) is not dict or set(t)!={"veto","assisted_floor","metacognitive_floor","allow"}:
        raise ValidationError("invalid human envelope thresholds")
    return NativeEnvelopeThresholds(**t)


@dataclass(frozen=True,slots=True)
class AuthenticatedHumanCapacityContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class HumanCapacityAssessment:
    reason: str
    capacity_sufficient: bool
    supervision: str
    envelope: object
    soul: NativeSoulAssessment
    profile_bytes: bytes
    operation_bytes: bytes
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None
    evaluated_at: int
    expires_at: int | None
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("human capacity requires installed current reviewed measurements")


@dataclass(frozen=True,slots=True)
class InstalledHumanCapacityVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed human capacity verifier")
        dp=_parse_jcs_object(self.deployment_profile_bytes);p=_parse_jcs_object(self.profile_bytes)
        if (set(p)!={"id","version","zone","formula","measurement_profile_digest","unit","max_age_seconds","review_authorities","envelope_thresholds"}
                or any(not _name(p[k]) for k in ("id","zone")) or not _time(p["version"]) or p["version"]==0
                or p["formula"]!="reviewed-operation-human-capacity-v1" or not is_digest(p["measurement_profile_digest"])
                or not p["measurement_profile_digest"].startswith(self.algorithm+":")
                or p["unit"]!="urn:ktp:unit:action-risk-points" or not _time(p["max_age_seconds"]) or p["max_age_seconds"]==0
                or type(p["review_authorities"]) is not list or not p["review_authorities"]
                or any(not _name(a) for a in p["review_authorities"]) or len(set(p["review_authorities"]))!=len(p["review_authorities"])
                or dp.get("human_capacity_policy")!={"id":p["id"],"version":p["version"],"digest":_digest(p,self.algorithm)}):
            raise ValidationError("human capacity requires exact installed reviewed policy and comparable scale")
        thresholds(p)

    def evaluate(self,*,actual_operation,soul,evaluated_at,clock_healthy):
        if type(soul) is not NativeSoulAssessment or not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("human capacity requires current Soul assessment and healthy time")
        p=_parse_jcs_object(self.profile_bytes);dp=_parse_jcs_object(self.deployment_profile_bytes)
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        invocation=digest_demand_operation(op,algorithm=self.algorithm);deployment=_digest(dp,self.algorithm)
        if (not _person(op["actor"]) or soul.deployment_digest!=deployment or soul.operation_digest!=invocation or soul.evaluated_at!=evaluated_at
                or tuple(dp.get("soul_veto",{}).get("frameworks",()))!=soul.required_frameworks):
            raise ValidationError("human Soul and capacity request differ on actual scope")
        source=None;envelope=None;expiry=None
        def result(reason):
            sufficient=envelope is not None and envelope.supervision!="silent_veto"
            r=object.__new__(HumanCapacityAssessment)
            for k,v in dict(reason=reason,capacity_sufficient=sufficient,supervision="silent_veto" if envelope is None else envelope.supervision,
                    envelope=envelope,soul=soul,profile_bytes=self.profile_bytes,operation_bytes=op_bytes,
                    authenticated_state_bytes=None if source is None else source.state_bytes,
                    source_evidence_bytes=None if source is None else source.evidence_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                    action_permitted=False).items():object.__setattr__(r,k,v)
            return r
        if soul.gate.state.value!="clear":return result("HUMAN_CAPACITY_SOUL_"+soul.gate.state.value.upper())
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedHumanCapacityContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("human capacity Source must authenticate actual current reviewed measurements")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at","approval","measurement"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=_digest(p,self.algorithm) or s["operation_digest"]!=invocation
                or s["subject"]!=op["actor"] or s["zone"]!=p["zone"] or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at
                or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at):
            raise ValidationError("human measurement context differs from current actual request")
        a=s["approval"];m=s["measurement"]
        if (type(a) is not dict or set(a)!={"profile_digest","authority","anchor","approved_at","expires_at"}
                or a["profile_digest"]!=p["measurement_profile_digest"] or a["authority"] not in p["review_authorities"] or not _name(a["anchor"])
                or not _time(a["approved_at"]) or not _time(a["expires_at"]) or not a["approved_at"]<=evaluated_at<a["expires_at"]
                or type(m) is not dict or set(m)!={"profile_digest","operation_digest","actor","zone","observed_at","expires_at","unit","demand","capacity","source_anchor"}
                or m["profile_digest"]!=p["measurement_profile_digest"] or m["operation_digest"]!=invocation or m["actor"]!=op["actor"]
                or m["zone"]!=p["zone"] or m["unit"]!=p["unit"] or not _name(m["source_anchor"])
                or m["source_anchor"]==a["anchor"] or not _time(m["observed_at"]) or not _time(m["expires_at"])
                or not a["approved_at"]<=m["observed_at"]<=evaluated_at<m["expires_at"]
                or evaluated_at>=m["observed_at"]+p["max_age_seconds"]):
            raise ValidationError("human capacity lacks exact current approved comparable measurement evidence")
        expiry=min(s["expires_at"],a["expires_at"],m["expires_at"],m["observed_at"]+p["max_age_seconds"])
        for key in ("demand","capacity"):
            if m[key] is not None:as_decimal(m[key],name="human "+key,minimum=0,maximum=100)
        if m["demand"] is None or m["capacity"] is None:return result("HUMAN_CAPACITY_UNAVAILABLE")
        envelope=project_comparable_envelope(demand=m["demand"],decision_capacity=m["capacity"],capacity_known=True,thresholds=thresholds(p))
        return result("HUMAN_CAPACITY_EVIDENCE_VALID" if envelope.supervision!="silent_veto" else "HUMAN_CAPACITY_VETO")
