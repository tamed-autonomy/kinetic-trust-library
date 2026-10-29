"""Installed external demand-only judgments; never a capacity/risk rewrite.

Source authenticates current declared authorities, complete signed payloads,
whole-action demand calibration and actual grant/evidence/topology scope. The
private semantic projection is not a universal normative token wire. External
schemas supply content; Library validates carriage and restriction direction.
"""
from dataclasses import dataclass
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest


def profile_terms(p):
    if (type(p) is not dict or set(p)!={"id","version","zone","formula","external_schema_id","external_schema_digest","inputs"}
            or any(not _name(p[key]) for key in ("id","zone","external_schema_id"))
            or not is_digest(p["external_schema_digest"]) or not _time(p["version"]) or p["version"]==0
            or p["formula"]!="maximum-whole-action-demand-v1" or type(p["inputs"]) is not list
            or not 1<=len(p["inputs"])<=256):
        raise ValidationError("invalid demand-only normative profile")
    seen=set()
    for item in p["inputs"]:
        if (type(item) is not dict or set(item)!={"id","source","kind"}
                or not _name(item["id"]) or not _name(item["source"]) or item["id"] in seen
                or item["kind"] not in ("importance","supplied-input")):
            raise ValidationError("normative inputs require distinct declared authority and kind")
        seen.add(item["id"])
    return p


def _external_validator(raw):
    from jsonschema import Draft202012Validator
    from referencing import Registry,Resource
    from referencing.jsonschema import DRAFT202012
    from referencing.exceptions import NoSuchResource
    from .schema_formats import installed_format_checker
    schema=_parse_jcs_object(raw)
    def refuse_retrieval(uri):
        raise NoSuchResource(ref=uri)
    registry=Registry(retrieve=refuse_retrieval).with_resource(schema["$id"],
        Resource.from_contents(schema,default_specification=DRAFT202012))
    return Draft202012Validator(schema,registry=registry,format_checker=installed_format_checker())


@dataclass(frozen=True,slots=True)
class AuthenticatedNormativeDemandContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class NormativeDemandAssessment:
    demand: object
    baseline_demand: object
    required_demand: object
    deployment_digest: str
    operation_digest: str
    profile_bytes: bytes
    profile_digest: str
    external_schema_bytes: bytes
    evaluated_at: int
    expires_at: int
    zone: str
    topology_epoch: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    frame_bytes: bytes
    frame_digest: str

    def __init__(self,*args,**kwargs):raise TypeError("normative demand requires installed verification")

    def geometry_value(self):
        from .core_claims import _wire_number
        return dict(profile_digest=self.profile_digest,frame_digest=self.frame_digest,
                    required_demand=_wire_number(self.required_demand))


@dataclass(frozen=True,slots=True)
class InstalledNormativeDemandVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    external_schema_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        from jsonschema import Draft202012Validator
        if (any(type(raw) is not bytes for raw in (self.deployment_profile_bytes,self.profile_bytes,self.external_schema_bytes))
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed normative demand verifier")
        _parse_jcs_object(self.deployment_profile_bytes)
        p=profile_terms(_parse_jcs_object(self.profile_bytes));schema=_parse_jcs_object(self.external_schema_bytes)
        if schema.get("$id")!=p["external_schema_id"] or _digest(schema,self.algorithm)!=p["external_schema_digest"]:
            raise ValidationError("external normative schema differs from declaration")
        if schema.get("$schema","https://json-schema.org/draft/2020-12/schema")!="https://json-schema.org/draft/2020-12/schema":
            raise ValidationError("normative demand requires an installed Draft 2020-12 schema")
        Draft202012Validator.check_schema(schema)

    def evaluate(self,*,actual_operation,baseline_demand,evaluated_at,clock_healthy):
        from referencing.exceptions import Unresolvable
        if not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("normative inputs require healthy current clock")
        baseline=as_decimal(baseline_demand,name="pre-norm demand",minimum=0,maximum=100)
        p=profile_terms(_parse_jcs_object(self.profile_bytes));policy=_digest(p,self.algorithm)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        operation_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(operation_bytes)
        invocation=digest_demand_operation(op,algorithm=self.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            external_schema_bytes=self.external_schema_bytes,operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedNormativeDemandContext or type(source.state_bytes) is not bytes
                or len(source.state_bytes)>262144 or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("complete authenticated normative input inventory unavailable")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","actor","zone","topology_epoch",
                "grant_digest","evidence_digest","checked_at","expires_at","inputs"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=policy or s["operation_digest"]!=invocation
                or s["actor"]!=op["actor"] or s["zone"]!=p["zone"] or not _time(s["topology_epoch"])
                or not is_digest(s["grant_digest"]) or not is_digest(s["evidence_digest"])
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"])
                or s["expires_at"]<=evaluated_at or type(s["inputs"]) is not list or len(s["inputs"])!=len(p["inputs"])):
            raise ValidationError("normative inputs differ from current whole-action/profile scope")
        declarations={i["id"]:i for i in p["inputs"]};seen=set();demands=[];expiry=s["expires_at"]
        validator=_external_validator(self.external_schema_bytes)
        for item in s["inputs"]:
            if (type(item) is not dict or set(item)!={"id","source","kind","payload","demand","issued_at","expires_at"}
                    or type(item["id"]) is not str or item["id"] in seen or item["id"] not in declarations
                    or any(item[key]!=declarations[item["id"]][key] for key in ("source","kind"))
                    or not _time(item["issued_at"]) or not _time(item["expires_at"])
                    or not item["issued_at"]<=evaluated_at<item["expires_at"]):
                raise ValidationError("missing/invalid declared current normative input")
            try:valid=validator.is_valid(item["payload"])
            except Unresolvable as error:
                raise ValidationError("normative schema reference is not installed; external retrieval is disabled") from error
            if not valid:raise ValidationError("normative payload violates the declared external schema")
            seen.add(item["id"]);expiry=min(expiry,item["expires_at"])
            demands.append(as_decimal(item["demand"],name="whole-action normative demand",minimum=0,maximum=100))
        required=max(demands)
        import rfc8785
        frame={key:value for key,value in s.items() if key not in ("checked_at","expires_at")}
        result=object.__new__(NormativeDemandAssessment)
        for key,value in dict(demand=max(baseline,required),baseline_demand=baseline,required_demand=required,
                deployment_digest=deployment,operation_digest=invocation,profile_bytes=self.profile_bytes,profile_digest=policy,
                external_schema_bytes=self.external_schema_bytes,evaluated_at=evaluated_at,expires_at=expiry,zone=s["zone"],
                topology_epoch=s["topology_epoch"],authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
                frame_bytes=rfc8785.dumps(frame),frame_digest=_digest(frame,self.algorithm)).items():object.__setattr__(result,key,value)
        return result
