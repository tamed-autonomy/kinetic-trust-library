"""Evaluation-scoped rail increments and authenticated own-increment releases.

The pure projection is arithmetic over already authenticated facts. Installed
verification additionally requires complete current hold inventory and signed
changes under an explicitly selected external profile. No release is a grant.
"""
from dataclasses import dataclass
import re

from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object

LEVELS = ("stable", "metacognitive", "assisted", "regulated", "silent_veto")


def _identifier(value):
    if type(value) is not str or not value or any(char.isspace() for char in value):
        raise ValidationError("rail identifiers must be exact nonempty strings")


@dataclass(frozen=True, slots=True)
class RailScope:
    evaluation_id: str
    actor: str
    action_digest: str
    cnf_jkt: str
    grant_digest: str
    evidence_digest: str
    zone_id: str
    topology_epoch: int

    def __post_init__(self):
        for name in ("evaluation_id", "actor", "cnf_jkt", "zone_id"):
            _identifier(getattr(self,name))
        for name in ("action_digest", "grant_digest", "evidence_digest"):
            value=getattr(self,name)
            if type(value) is not str or re.fullmatch(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})",value) is None:
                raise ValidationError("rail scope digest is invalid")
        if not _time(self.topology_epoch):raise ValidationError("invalid rail topology epoch")


@dataclass(frozen=True, slots=True)
class RailIncrement:
    scope: RailScope
    increment_id: str
    rail_id: str
    issuer: str
    from_supervision: str
    to_supervision: str

    def __post_init__(self):
        if type(self.scope) is not RailScope:raise ValidationError("rail increment requires exact scope")
        for value in (self.increment_id,self.rail_id,self.issuer):_identifier(value)
        if (self.from_supervision not in LEVELS or self.to_supervision not in LEVELS
                or LEVELS.index(self.to_supervision)<LEVELS.index(self.from_supervision)):
            raise ValidationError("an increment cannot lower supervision")


@dataclass(frozen=True, slots=True)
class RailRelease:
    scope: RailScope
    release_id: str
    increment_id: str
    rail_id: str
    issuer: str
    to_supervision: str

    def __post_init__(self):
        if type(self.scope) is not RailScope or self.to_supervision not in LEVELS:
            raise ValidationError("invalid rail release scope/level")
        for value in (self.release_id,self.increment_id,self.rail_id,self.issuer):_identifier(value)


@dataclass(frozen=True, slots=True)
class RailReleaseOutcome:
    release_id: str
    applied: bool
    requested_level_permitted: bool
    reason: str


@dataclass(frozen=True, slots=True)
class RailSupervisionProjection:
    scope: RailScope
    environment_supervision: str
    supervision: str
    effective_increments: tuple[tuple[str,str], ...]
    release_outcomes: tuple[RailReleaseOutcome, ...]


def project_supervision_rails(scope, environment_supervision, increments, releases):
    """Never lower the environment or another rail; release only owned holds."""
    if (type(scope) is not RailScope or environment_supervision not in LEVELS
            or type(increments) is not tuple or type(releases) is not tuple
            or any(type(value) is not RailIncrement for value in increments)
            or any(type(value) is not RailRelease for value in releases)):
        raise ValidationError("invalid rail projection inputs")
    if len({value.increment_id for value in increments})!=len(increments) or len({value.release_id for value in releases})!=len(releases):
        raise ValidationError("duplicate rail increment/release identity")
    floor=LEVELS.index(environment_supervision)
    active={value.increment_id:value for value in increments if value.scope==scope}
    levels={key:LEVELS.index(value.to_supervision) for key,value in active.items()}
    outcomes=[]
    for change in releases:
        hold=active.get(change.increment_id)
        reason=("RAIL_SCOPE" if change.scope!=scope else "RAIL_INCREMENT" if hold is None else
                "RAIL_OWNER" if (change.rail_id,change.issuer)!=(hold.rail_id,hold.issuer) else None)
        if reason:
            outcomes.append(RailReleaseOutcome(change.release_id,False,False,reason));continue
        requested=LEVELS.index(change.to_supervision)
        if requested>LEVELS.index(hold.to_supervision):
            outcomes.append(RailReleaseOutcome(change.release_id,False,False,"RAIL_NOT_RELEASE"));continue
        minimum=max(floor,LEVELS.index(hold.from_supervision))
        levels[hold.increment_id]=min(levels[hold.increment_id],max(minimum,requested))
        outcomes.append(RailReleaseOutcome(change.release_id,True,requested>=minimum,"RAIL_RELEASED" if requested>=minimum else "RAIL_FLOOR"))
    result=max((floor,*levels.values()))
    return RailSupervisionProjection(scope,environment_supervision,LEVELS[result],
        tuple((key,LEVELS[value]) for key,value in sorted(levels.items())),tuple(outcomes))


@dataclass(frozen=True, slots=True)
class AuthenticatedRailContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedRailPayload:
    payload_bytes: bytes
    issuer: str
    key_id: str
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class SupervisionRailAssessment:
    core: object
    checked_at: int
    operation_bytes: bytes
    profile_bytes: bytes
    evaluation_profile_digest: str
    projection: RailSupervisionProjection
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    increment_tokens: tuple[bytes,...]
    release_tokens: tuple[bytes,...]
    authenticated_events: tuple[AuthenticatedRailPayload,...]
    rejected_release_digests: tuple[str,...]
    expires_at: int

    def __init__(self,*args,**kwargs):raise TypeError("rail assessments are derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledSupervisionRailVerifier:
    profile_bytes: bytes
    external_schema_bytes: bytes
    context_source: object
    change_adapter: object

    def __post_init__(self):
        from . import _readiness_crypto as c
        from jsonschema import Draft202012Validator
        if (type(self.profile_bytes) is not bytes or type(self.external_schema_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None)) or not callable(getattr(self.change_adapter,"verify",None))):
            raise ValidationError("invalid installed supervision-rail policy")
        profile=_parse_jcs_object(self.profile_bytes);schema=_parse_jcs_object(self.external_schema_bytes)
        if (set(profile)!={"id","version","external_schema_id","external_schema_digest","signature_profile_id","digest_algorithm","rail_authorities"}
                or not _time(profile["version"]) or profile["version"]==0 or profile["digest_algorithm"] not in ("sha256","sha384")
                or profile["external_schema_id"]!=schema.get("$id") or type(profile["rail_authorities"]) is not dict or not profile["rail_authorities"]):
            raise ValidationError("invalid supervision-rail declaration")
        for value in (profile["id"],profile["external_schema_id"],profile["signature_profile_id"],*profile["rail_authorities"].keys(),*profile["rail_authorities"].values()):_identifier(value)
        if profile["external_schema_digest"]!=c.digest(schema,3 if profile["digest_algorithm"]=="sha384" else 2):
            raise ValidationError("rail external schema binding differs")
        Draft202012Validator.check_schema(schema)

    def evaluate(self, claim_source, evaluation_profile_bytes, increment_tokens, release_tokens, *, evaluated_at, clock_healthy):
        from .core_claims import NativeCoreClaimsSource
        from .native_envelope import project_native_envelope,NativeEnvelopeThresholds
        from .demand_supplier import _digest
        from .demand_operation import digest_demand_operation
        from . import _readiness_crypto as c
        if (type(claim_source) is not NativeCoreClaimsSource or type(evaluation_profile_bytes) is not bytes
                or type(increment_tokens) is not tuple or type(release_tokens) is not tuple
                or any(type(raw) is not bytes or not 0<len(raw)<=262144 for raw in (*increment_tokens,*release_tokens))
                or len(increment_tokens)+len(release_tokens)>256 or not _time(evaluated_at) or clock_healthy is not True
                or claim_source.context.evaluated_at!=evaluated_at or claim_source.core.capacity is None):
            raise ValidationError("rail verification requires a completed current Core and bounded immutable events")
        context=claim_source.context;profile=_parse_jcs_object(self.profile_bytes)
        geometry=_parse_jcs_object(evaluation_profile_bytes)
        bands=geometry["thresholds"]
        baseline=project_native_envelope(claim_source.core.capacity,thresholds=None if bands is None else NativeEnvelopeThresholds(**bands)).supervision
        level=3 if profile["digest_algorithm"]=="sha384" else 2
        source=self.context_source.resolve(profile_bytes=self.profile_bytes,external_schema_bytes=self.external_schema_bytes,
            deployment_profile_bytes=context.deployment_profile_bytes,operation_bytes=context.operation_bytes,
            evaluation_profile_bytes=evaluation_profile_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedRailContext or type(source.state_bytes) is not bytes or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("rail source returned invalid authenticated inventory")
        state=_parse_jcs_object(source.state_bytes)
        operation=_parse_jcs_object(context.operation_bytes)
        if (set(state)!={"profile_digest","deployment_digest","operation_digest","evaluation_profile_digest","checked_at","scope","active_increment_digests","expires_at"}
                or state["profile_digest"]!=c.digest(profile,level)
                or state["deployment_digest"]!=_digest(_parse_jcs_object(context.deployment_profile_bytes),context.algorithm)
                or state["operation_digest"]!=digest_demand_operation(operation,algorithm=context.algorithm)
                or state["evaluation_profile_digest"]!=_digest(geometry,context.algorithm)
                or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at):
            raise ValidationError("rail inventory differs from current invocation/profile")
        scope=RailScope(**state["scope"])
        metadata=_parse_jcs_object(claim_source.assertion_metadata_bytes)
        if scope.actor!=operation["actor"] or scope.zone_id!=metadata["zone"]:
            raise ValidationError("rail inventory actor/zone differs from actual Core")
        enclosure=claim_source.core.enclosure_assessment
        if enclosure is not None and _parse_jcs_object(enclosure.authenticated_body_bytes)["topology_epoch"]!=scope.topology_epoch:
            raise ValidationError("rail inventory topology differs from current enclosure")
        active=state["active_increment_digests"]
        if type(active) is not dict:raise ValidationError("complete active rail inventory required")
        def authenticate(raw,kind):
            checked=self.change_adapter.verify(raw,profile_bytes=self.profile_bytes,external_schema_bytes=self.external_schema_bytes,
                authenticated_context_bytes=source.state_bytes,evaluated_at=evaluated_at)
            if (type(checked) is not AuthenticatedRailPayload or type(checked.payload_bytes) is not bytes
                    or len(checked.payload_bytes)>65536 or type(checked.evidence_bytes) is not bytes or not checked.evidence_bytes
                    or type(checked.key_id) is not str or not checked.key_id):
                raise ValidationError("unverified rail act")
            body=_parse_jcs_object(checked.payload_bytes)
            fields={"kind","scope","increment_id","rail_id","issuer","to_supervision","iat","exp"}|({"from_supervision"} if kind=="increment" else {"release_id"})
            if (set(body)!=fields or body["kind"]!=kind or checked.issuer!=body["issuer"]
                    or profile["rail_authorities"].get(body["rail_id"])!=checked.issuer
                    or not _time(body["iat"]) or not _time(body["exp"]) or not body["iat"]<=evaluated_at<body["exp"]):
                raise ValidationError("rail act role/time/shape differs")
            act_scope=RailScope(**body["scope"])
            values={key:value for key,value in body.items() if key not in ("kind","scope","iat","exp")}
            act=(RailIncrement if kind=="increment" else RailRelease)(scope=act_scope,**values)
            return act,checked,body["exp"]
        increments=[];releases=[];verified=[];rejected=[]
        expiry=min(state["expires_at"],_parse_jcs_object(claim_source.assertion_metadata_bytes)["exp"])
        for raw in increment_tokens:
            act,checked,until=authenticate(raw,"increment")
            if act.scope!=scope or active.get(act.increment_id)!=c.digest_bytes(raw,level):
                raise ValidationError("active rail hold differs from independent current inventory")
            increments.append(act);verified.append(checked);expiry=min(expiry,until)
        if len(increments)!=len(active) or len({act.increment_id for act in increments})!=len(increments):
            raise ValidationError("active rail hold omitted or duplicated")
        for raw in release_tokens:
            try:act,checked,until=authenticate(raw,"release")
            except (ValueError,TypeError,KeyError,UnicodeError,ValidationError):
                rejected.append(c.digest_bytes(raw,level));continue
            releases.append(act);verified.append(checked);expiry=min(expiry,until)
        projection=project_supervision_rails(scope,baseline,tuple(increments),tuple(releases))
        if expiry<=evaluated_at:raise ValidationError("rail assessment supporting evidence has expired")
        result=object.__new__(SupervisionRailAssessment)
        for name,value in dict(core=claim_source.core,checked_at=evaluated_at,operation_bytes=context.operation_bytes,profile_bytes=self.profile_bytes,
            evaluation_profile_digest=state["evaluation_profile_digest"],projection=projection,authenticated_state_bytes=source.state_bytes,
            source_evidence_bytes=source.evidence_bytes,increment_tokens=increment_tokens,release_tokens=release_tokens,authenticated_events=tuple(verified),
            rejected_release_digests=tuple(rejected),expires_at=expiry).items():object.__setattr__(result,name,value)
        return result


__all__=("RailScope","RailIncrement","RailRelease","RailSupervisionProjection","RailReleaseOutcome","project_supervision_rails",
         "InstalledSupervisionRailVerifier","SupervisionRailAssessment","AuthenticatedRailContext","AuthenticatedRailPayload")
