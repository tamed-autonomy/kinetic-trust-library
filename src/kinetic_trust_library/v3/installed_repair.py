"""Current complete lineage-breach inventory from an installed authority source.

The source verifies current anchors (including lawful disposal), actual lineage
and descendants, terminators, verifier independence at the record date, harm
declarations and voluntary attendance. Its record is a semantic adapter
projection, not a new Flight Recorder or RFC wire format.
"""
from dataclasses import dataclass,fields
from decimal import Decimal
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .repair import ReconciliationFacts,ReentryProjection,project_reentry
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .earned_repair import EarnedRepairAct,project_earned_ceiling


HARD_ENTRIES=frozenset(("act-outside-decision","withdrawal-for-cause","misattestation","seeking-without-attendance"))


def _profile(raw):
    profile=_parse_jcs_object(raw)
    if (not {"id","version","formula","route","entry_classes"}<=set(profile)
            or set(profile)-{"id","version","formula","route","entry_classes","ceiling_lift"}
            or type(profile["id"]) is not str or not profile["id"] or not _time(profile["version"]) or profile["version"]==0
            or profile["formula"]!="fractional-reentry-with-additive-unrepaired-raise-v1"
            or type(profile["route"]) is not str or not profile["route"] or type(profile["entry_classes"]) is not dict
            or not HARD_ENTRIES<=profile["entry_classes"].keys()):
        raise ValidationError("invalid declared re-entry policy")
    for name,value in profile["entry_classes"].items():
        if (not name or type(value) is not dict or set(value)!={"hard","delta","unrepaired_raise"}
                or type(value["hard"]) is not bool or name in HARD_ENTRIES and not value["hard"]):
            raise ValidationError("repair entry classes must apply without actor-specific exceptions")
        delta=as_decimal(value["delta"],name="declared delta",minimum=0,maximum=1)
        increase=as_decimal(value["unrepaired_raise"],name="declared unrepaired raise",minimum=0,maximum=1)
        if value["hard"] and delta<Decimal(".1") or increase==0:
            raise ValidationError("repair policy cannot waive the floor or harm declaration")
    return profile


@dataclass(frozen=True,slots=True)
class AuthenticatedRepairContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class RepairAssessment:
    reentry_eligible: bool
    reason: str
    standing_ceiling: Decimal | None
    readiness_after: int | None
    deployment_digest: str
    operation_digest: str
    profile_bytes: bytes
    evaluated_at: int
    expires_at: int
    actor: str
    lineage: str
    zone_id: str
    breaches: tuple[tuple[str,ReentryProjection | None], ...]
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    ceiling_lift_profile_bytes: bytes | None
    lifted_ceilings: tuple[tuple[str,Decimal], ...]

    def __init__(self,*args,**kwargs):raise TypeError("repair assessments require installed verification")


@dataclass(frozen=True,slots=True)
class InstalledRepairVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str
    ceiling_lift_profile_bytes: bytes | None = None
    ceiling_lift_adapter: object | None = None

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed repair verifier")
        _parse_jcs_object(self.deployment_profile_bytes);profile=_profile(self.profile_bytes)
        if "ceiling_lift" in profile:
            if type(self.ceiling_lift_profile_bytes) is not bytes or not callable(getattr(self.ceiling_lift_adapter,"project",None)):
                raise ValidationError("declared ceiling lift requires an installed ordinary policy")
            policy=_parse_jcs_object(self.ceiling_lift_profile_bytes);binding=profile["ceiling_lift"]
            if (type(binding) is not dict or set(binding)!={"id","version","digest"}
                    or binding["id"]!=policy.get("id") or binding["version"]!=policy.get("version")
                    or not _time(policy.get("version")) or policy["version"]==0
                    or type(policy.get("id")) is not str or not policy["id"] or policy.get("unit")!="ktp-standing-points"
                    or type(policy.get("formula")) is not str or not policy["formula"]
                    or binding["digest"]!=_digest(policy,self.algorithm)):
                raise ValidationError("earned ceiling policy binding differs")
        elif self.ceiling_lift_profile_bytes is not None or self.ceiling_lift_adapter is not None:
            raise ValidationError("earned ceiling policy requires explicit declaration")

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("repair requires a healthy current clock")
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        profile=_profile(self.profile_bytes)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedRepairContext or type(source.state_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("repair source must authenticate the complete current inventory")
        state=_parse_jcs_object(source.state_bytes)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        invocation=digest_demand_operation(op,algorithm=self.algorithm)
        if (set(state)!={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","actor","lineage","zone_id","breaches"}
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=_digest(profile,self.algorithm)
                or state["operation_digest"]!=invocation or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at or state["actor"]!=op["actor"]
                or any(type(state[name]) is not str or not state[name] for name in ("lineage","zone_id"))
                or type(state["breaches"]) is not list or len(state["breaches"])>4096):
            raise ValidationError("repair state differs from current actor/invocation/profile/time")
        projections=[];anchors=set();ceiling=None;after=None;lifted=[]
        for entry in state["breaches"]:
            expected={"breach_anchor","entry_class","standing_at_breach","previous_delta",
                    "breached_at","breaching_terminator","required_parties","record_facts"}
            if "ceiling_lift" in profile:expected.add("post_record_acts")
            if (type(entry) is not dict or set(entry)!=expected
                    or type(entry["breach_anchor"]) is not str or entry["breach_anchor"] in anchors
                    or entry["entry_class"] not in profile["entry_classes"]):
                raise ValidationError("invalid or duplicate applicable breach")
            anchors.add(entry["breach_anchor"])
            record=entry["record_facts"]
            if record is None:
                projections.append((entry["breach_anchor"],None));continue
            if type(record) is not dict or set(record)!={field.name for field in fields(ReconciliationFacts)}:
                raise ValidationError("incomplete reconciliation semantic record")
            declared=profile["entry_classes"][entry["entry_class"]]
            if (any(record[name]!=entry[name] for name in ("breach_anchor","standing_at_breach","previous_delta","breached_at",
                    "breaching_terminator","required_parties")) or record["hard_entry"] is not declared["hard"]
                    or as_decimal(record["declared_delta"],name="record delta")!=as_decimal(declared["delta"],name="declared delta")
                    or as_decimal(record["declared_unrepaired_raise"],name="record raise")!=as_decimal(declared["unrepaired_raise"],name="declared raise")
                    or record["route_published"] is not True):
                raise ValidationError("reconciliation record substitutes its breach or declared cost")
            converted=dict(record)
            for name in ("required_parties","record_parties","independent_of","declined_parties","open_to"):
                if type(record[name]) is not list:raise ValidationError("repair parties require exact immutable projection")
                converted[name]=tuple(record[name])
            projection=project_reentry(ReconciliationFacts(**converted))
            if projection.record_valid:
                if projection.anchored_at>evaluated_at:raise ValidationError("future reconciliation anchor")
                current=projection.ceiling
                if "ceiling_lift" in profile:
                    import rfc8785
                    raw_acts=entry["post_record_acts"]
                    if type(raw_acts) is not list or len(raw_acts)>4096:raise ValidationError("bounded ordinary repair acts required")
                    acts=[]
                    for act in raw_acts:
                        if type(act) is not dict or set(act)!={"anchor","recorded_at","lineage","ordinary_profile_digest","record","current_anchor_verified","ordinary_admissible"}:
                            raise ValidationError("invalid authenticated ordinary repair act")
                        acts.append(EarnedRepairAct(**{name:value for name,value in act.items() if name!="record"},record_bytes=rfc8785.dumps(act["record"])))
                    current=project_earned_ceiling(projection,tuple(acts),lineage=state["lineage"],evaluated_at=evaluated_at,
                        profile_bytes=self.ceiling_lift_profile_bytes,adapter=self.ceiling_lift_adapter)
                    lifted.append((entry["breach_anchor"],current))
                ceiling=current if ceiling is None else min(ceiling,current)
                after=projection.anchored_at if after is None else max(after,projection.anchored_at)
            projections.append((entry["breach_anchor"],projection))
        eligible=all(value is not None and value.record_valid for _,value in projections)
        result=object.__new__(RepairAssessment)
        for name,value in dict(reentry_eligible=eligible,reason="REPAIR_ELIGIBLE" if eligible else "REPAIR_UNRECONCILED",
            standing_ceiling=ceiling if eligible else None,readiness_after=after if eligible else None,deployment_digest=deployment,
            operation_digest=invocation,profile_bytes=self.profile_bytes,evaluated_at=evaluated_at,expires_at=state["expires_at"],
            actor=state["actor"],lineage=state["lineage"],zone_id=state["zone_id"],breaches=tuple(projections),
            authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
            ceiling_lift_profile_bytes=self.ceiling_lift_profile_bytes,lifted_ceilings=tuple(lifted)).items():object.__setattr__(result,name,value)
        return result


__all__=("InstalledRepairVerifier","RepairAssessment","AuthenticatedRepairContext")
