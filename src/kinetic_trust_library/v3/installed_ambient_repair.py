"""Current zone-wide ambient repair inputs and a pinned pressure normalizer.

The source authenticates complete audit windows, actual breach classes/lineages,
backlog, current anchors and repairer order/history, prior stock/bank, accountable
roots, inward ancestry, reproduction and consequential-operation classification.
The internal projection is not a new RFC wire or a consensus implementation.
"""
from dataclasses import dataclass,replace
from decimal import Decimal
from fractions import Fraction
import re
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .ambient_repair import project_ambient_window,reference_criticality_valid,ratio
from .repair_capacity import RepairCapacityRecord,RepairCapacityWindow,project_repair_capacity,project_capacity_by_class
from .installed_repair import HARD_ENTRIES
from .installed_repair_recovery import validate_recovery_declaration,project_installed_recovery,project_installed_rule_repair
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .root_lifecycle import _time
from .risk import _FACTORS


def _rational(value):
    if type(value) is dict:
        if (set(value)!={"n","d"} or any(type(value[name]) is not str or len(value[name])>4096 for name in ("n","d"))
                or re.fullmatch(r"0|[1-9][0-9]*",value["n"]) is None or re.fullmatch(r"[1-9][0-9]*",value["d"]) is None):
            raise ValidationError("invalid exact ambient ratio")
        value=Fraction(int(value["n"]),int(value["d"]))
    return ratio(value,name="ambient metric")


def _profile(raw):
    profile=_parse_jcs_object(raw)
    if (set(profile)-{"recovery"}!={"id","version","zone_id","formula","criticality_model","window_seconds","recovery_windows","declared_capacity",
            "criticality","single_lineage_share","repairer_interval","retirement_credit_per_weight","source_signals","entry_classes","normalizer"}
            or any(type(profile[name]) is not str or not profile[name] for name in ("id","zone_id"))
            or not _time(profile["version"]) or profile["version"]==0
            or profile["formula"]!="pooled-and-class-pressure-with-anchored-retirement-v1"
            or profile["criticality_model"]!="idle-reproduction-reference-v1"
            or not _time(profile["window_seconds"]) or profile["window_seconds"]==0
            or not _time(profile["recovery_windows"]) or not 1<=profile["recovery_windows"]<=4096
            or type(profile["source_signals"]) is not list or not profile["source_signals"]
            or any(type(name) is not str or not name for name in profile["source_signals"])
            or len(set(profile["source_signals"]))!=len(profile["source_signals"])
            or type(profile["entry_classes"]) is not dict or not HARD_ENTRIES<=profile["entry_classes"].keys()):
        raise ValidationError("invalid declared ambient repair reference profile")
    if profile["declared_capacity"] is not None:_rational(profile["declared_capacity"])
    if _rational(profile["criticality"])<1 or not 0<_rational(profile["single_lineage_share"])<=1 or _rational(profile["retirement_credit_per_weight"])==0:
        raise ValidationError("invalid ambient criticality/share/retirement declaration")
    _rational(profile["repairer_interval"])
    for name,entry in profile["entry_classes"].items():
        if (not name or type(entry) is not dict or set(entry)!={"hard","weight","declared_capacity"} or type(entry["hard"]) is not bool
                or name in HARD_ENTRIES and not entry["hard"] or not 0<_rational(entry["weight"])<=1
                or entry["hard"] and _rational(entry["weight"])!=1):
            raise ValidationError("ambient entry weights must preserve hard breaches")
        if entry["declared_capacity"] is not None:_rational(entry["declared_capacity"])
    class_limits=[entry["declared_capacity"] for entry in profile["entry_classes"].values()]
    if profile["declared_capacity"] is not None and all(value is not None for value in class_limits):
        if _rational(profile["declared_capacity"])>sum((_rational(value) for value in class_limits),Fraction(0)):
            raise ValidationError("pooled capacity exceeds all declared class capacities combined")
    if "recovery" in profile:
        validate_recovery_declaration(profile["recovery"],criticality=profile["criticality"],recovery_windows=profile["recovery_windows"],parse=_rational)
    return profile


@dataclass(frozen=True,slots=True)
class AuthenticatedAmbientContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class AmbientRepairAssessment:
    deployment_digest: str
    operation_digest: str
    profile_bytes: bytes
    normalizer_profile_bytes: bytes
    evaluated_at: int
    expires_at: int
    zone_id: str
    parent_zone: str | None
    topology_epoch: int
    capacity: object
    metrics: object
    class_capacities: tuple
    class_metrics: tuple
    maximum_utilization: Fraction | None
    maximum_banked_excess: Fraction | None
    recovery: object
    available_contingency: tuple
    rule_repair: object
    criticality_valid: bool | None
    pressure_floor: Decimal | None
    supervision_floor: str
    consequential_hosting_forbidden: bool
    profile_digest: str
    frame_digest: str
    frame_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("ambient assessments require installed current verification")

    def geometry_value(self):
        value=None if self.pressure_floor is None else Fraction(self.pressure_floor)
        result=dict(profile_digest=self.profile_digest,frame_digest=self.frame_digest,
            pressure_floor=None if value is None else dict(n=str(value.numerator),d=str(value.denominator)),
            criticality_valid=self.criticality_valid,supervision_floor=self.supervision_floor,
            consequential_hosting_forbidden=self.consequential_hosting_forbidden)
        if self.recovery is not None:
            result["recovery"]=dict(tier=self.recovery.tier,recovered=self.recovery.recovered,
                measurement_complete=self.recovery.measurement_complete,rule_repair_required=self.recovery.rule_repair_required,
                emergency_authorized=False,available_contingency=list(self.available_contingency))
        if self.rule_repair is not None:
            result["rule_repair"]=dict(records_complete=self.rule_repair.records_complete,
                open_patterns=list(self.rule_repair.open_patterns),closed_patterns=list(self.rule_repair.closed_patterns))
        return result


@dataclass(frozen=True,slots=True)
class InstalledAmbientRepairVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    normalizer_profile_bytes: bytes
    context_source: object
    normalizer: object
    algorithm: str

    def __post_init__(self):
        if (any(type(raw) is not bytes for raw in (self.deployment_profile_bytes,self.profile_bytes,self.normalizer_profile_bytes))
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))
                or not callable(getattr(self.normalizer,"normalize",None))):
            raise ValidationError("invalid installed ambient repair policy")
        deployment=_parse_jcs_object(self.deployment_profile_bytes)
        factors=deployment.get("risk_factors")
        if type(factors) is not dict or set(factors)!=set(_FACTORS):raise ValidationError("ambient composition requires the five declared Risk Factors")
        weights=tuple(_rational(factors[name]["weight"]) for name in _FACTORS)
        if any(value==0 for value in weights) or sum(weights)!=1:raise ValidationError("ambient Risk Factor weights must be positive and sum exactly to one")
        profile=_profile(self.profile_bytes);normalizer=_parse_jcs_object(self.normalizer_profile_bytes);binding=profile["normalizer"]
        if (type(binding) is not dict or set(binding)!={"id","version","digest"}
                or not _time(binding["version"]) or binding["version"]==0
                or binding["id"]!=normalizer.get("id") or binding["version"]!=normalizer.get("version")
                or type(normalizer.get("id")) is not str or not normalizer["id"]
                or not _time(normalizer.get("version")) or normalizer["version"]==0
                or normalizer.get("unit")!="normalized-adversarial-pressure"
                or type(normalizer.get("formula")) is not str or not normalizer["formula"]
                or binding["digest"]!=_digest(normalizer,self.algorithm)):
            raise ValidationError("ambient normalizer differs from the declared binding")

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("ambient verification requires a healthy current clock")
        operation_bytes=canonical_demand_operation_bytes(actual_operation);operation=_parse_jcs_object(operation_bytes)
        profile=_profile(self.profile_bytes);policy=_digest(profile,self.algorithm)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        invocation=digest_demand_operation(operation,algorithm=self.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            normalizer_profile_bytes=self.normalizer_profile_bytes,operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedAmbientContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("ambient source must authenticate complete current zone-wide evidence")
        state=_parse_jcs_object(source.state_bytes)
        if (set(state)!={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","zone_id","topology_epoch",
                "parent","ledger_head","window_ledger_head","accountable_roots","consequential","reproduction_at_idle","prior_hard_times","capacity_windows","current"}|({"recovery"} if "recovery" in profile else set())
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=policy or state["operation_digest"]!=invocation
                or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at
                or state["zone_id"]!=profile["zone_id"] or not _time(state["topology_epoch"]) or not _time(state["accountable_roots"])
                or type(state["consequential"]) is not bool or type(state["ledger_head"]) is not str
                or re.fullmatch(self.algorithm+r":[0-9a-f]{"+str(64 if self.algorithm=="sha256" else 96)+"}",state["ledger_head"]) is None
                or state["window_ledger_head"]!=state["ledger_head"]
                or type(state["capacity_windows"]) is not list or len(state["capacity_windows"])!=profile["recovery_windows"]
                or type(state["prior_hard_times"]) is not list):
            raise ValidationError("ambient state differs from actual invocation/profile/current ledger scope")
        prior=[]
        for item in state["prior_hard_times"]:
            if type(item) is not dict or set(item)!={"repairer","at"}:raise ValidationError("invalid ambient repairer history")
            prior.append((item["repairer"],_rational(item["at"])))
        windows=[];last_closure=Fraction(0);classes_by_window=[];backlog_by_window=[];last_class_closure={}
        for raw_window in state["capacity_windows"]:
            if (type(raw_window) is not dict or set(raw_window)!={"starts_at","ends_at","backlog_positive","backlog_by_class","records"}
                    or type(raw_window["records"]) is not list or type(raw_window["backlog_by_class"]) is not dict
                    or raw_window["backlog_by_class"].keys()!=profile["entry_classes"].keys()
                    or any(type(value) is not bool for value in raw_window["backlog_by_class"].values())
                    or raw_window["backlog_positive"] is not any(raw_window["backlog_by_class"].values())):
                raise ValidationError("invalid complete ambient capacity window")
            records=[];last_closure=Fraction(0);mapping={};last_class_closure=dict.fromkeys(profile["entry_classes"],0)
            for item in raw_window["records"]:
                if (type(item) is not dict or set(item)!={"anchor","repairer","anchored_at","entry_class","current_anchor_verified","anchor_order"}
                        or item["entry_class"] not in profile["entry_classes"]):raise ValidationError("invalid ambient anchored repair record")
                entry=profile["entry_classes"][item["entry_class"]]
                records.append(RepairCapacityRecord(item["anchor"],item["repairer"],_rational(item["anchored_at"]),entry["hard"],item["current_anchor_verified"],item["anchor_order"]))
                mapping[item["anchor"]]=item["entry_class"]
                if item["current_anchor_verified"] is True:
                    last_closure+=_rational(entry["weight"]);last_class_closure[item["entry_class"]]+=1
            start,end=_rational(raw_window["starts_at"]),_rational(raw_window["ends_at"])
            if end-start!=profile["window_seconds"]:raise ValidationError("ambient window changes the declared aggregation period")
            windows.append(RepairCapacityWindow(start,end,raw_window["backlog_positive"],tuple(records)))
            classes_by_window.append(mapping);backlog_by_window.append(raw_window["backlog_by_class"])
        if not windows[-1].ends_at<=evaluated_at<windows[-1].ends_at+profile["window_seconds"]:
            raise ValidationError("ambient windows are stale or future-dated")
        capacity=project_repair_capacity(declared_capacity=None if profile["declared_capacity"] is None else _rational(profile["declared_capacity"]),
            windows=tuple(windows),repairer_interval=_rational(profile["repairer_interval"]),prior_hard_times=tuple(prior),accountable_roots=state["accountable_roots"])
        class_capacities=project_capacity_by_class(capacity,
            declared_by_class={name:None if entry["declared_capacity"] is None else _rational(entry["declared_capacity"]) for name,entry in profile["entry_classes"].items()},
            classes_by_window=tuple(classes_by_window),backlog_by_window=tuple(backlog_by_window),accountable_roots=state["accountable_roots"])
        current=state["current"]
        if (type(current) is not dict or set(current)!={"prior_stock","prior_banked_excess","retired_excess","arrivals",
                "prior_stock_by_class","prior_bank_by_class","retired_excess_by_class"} or type(current["arrivals"]) is not list):
            raise ValidationError("ambient stock and bank need an authenticated carried state")
        for name in ("prior_stock_by_class","prior_bank_by_class","retired_excess_by_class"):
            if type(current[name]) is not dict or current[name].keys()!=profile["entry_classes"].keys():
                raise ValidationError("complete class stock and debt declarations required")
        if any(not _time(value) for value in current["prior_stock_by_class"].values()):raise ValidationError("class stock must be an exact breach count")
        if sum((count*_rational(profile["entry_classes"][name]["weight"]) for name,count in current["prior_stock_by_class"].items()),Fraction(0))!=_rational(current["prior_stock"]):
            raise ValidationError("class stocks differ from the carried zone stock")
        arrivals=[];arrivals_by_class={name:[] for name in profile["entry_classes"]}
        for item in current["arrivals"]:
            if (type(item) is not dict or set(item)!={"lineage","counts"} or type(item["counts"]) is not dict
                    or not item["counts"].keys()<=profile["entry_classes"].keys() or any(not _time(count) for count in item["counts"].values())):
                raise ValidationError("invalid actual lineage breach aggregate")
            arrivals.append((item["lineage"],sum((count*_rational(profile["entry_classes"][name]["weight"]) for name,count in item["counts"].items()),Fraction(0))))
            for name in arrivals_by_class:arrivals_by_class[name].append((item["lineage"],item["counts"].get(name,0)))
        parent=state["parent"];indices=();parent_unknown=False
        if parent is not None:
            if (type(parent) is not dict or set(parent)!={"zone_id","heard_index"} or type(parent["zone_id"]) is not str
                    or not parent["zone_id"] or parent["zone_id"]==state["zone_id"]):raise ValidationError("invalid authenticated enclosing index")
            parent_unknown=parent["heard_index"] is None
            if not parent_unknown:indices=(_rational(parent["heard_index"]),)
        metrics=project_ambient_window(prior_stock=_rational(current["prior_stock"]),arrivals=tuple(arrivals),anchored_weight=last_closure,
            effective_capacity=capacity.effective_capacity,criticality=_rational(profile["criticality"]),single_lineage_share=_rational(profile["single_lineage_share"]),
            prior_banked_excess=_rational(current["prior_banked_excess"]),retired_excess=_rational(current["retired_excess"]),
            retirement_credit_per_weight=_rational(profile["retirement_credit_per_weight"]),enclosing_indices=indices,accountable_roots=state["accountable_roots"])
        if parent_unknown:metrics=replace(metrics,heard_index=None)
        class_metrics=[];active_views=[]
        for name,cap in class_capacities:
            weight=_rational(profile["entry_classes"][name]["weight"])
            view=project_ambient_window(prior_stock=current["prior_stock_by_class"][name]*weight,
                arrivals=tuple((lineage,count*weight) for lineage,count in arrivals_by_class[name]),anchored_weight=last_class_closure[name]*weight,
                effective_capacity=None if cap.effective_capacity is None else cap.effective_capacity*weight,
                criticality=_rational(profile["criticality"]),single_lineage_share=_rational(profile["single_lineage_share"]),
                prior_banked_excess=_rational(current["prior_bank_by_class"][name]),retired_excess=_rational(current["retired_excess_by_class"][name]),
                retirement_credit_per_weight=_rational(profile["retirement_credit_per_weight"]),accountable_roots=state["accountable_roots"])
            class_metrics.append((name,view))
            if view.open_stock>0 or view.uncapped_arrival>0 or _rational(current["prior_bank_by_class"][name])>0:active_views.append(view)
        criticality=None if state["reproduction_at_idle"] is None else reference_criticality_valid(_rational(profile["criticality"]),_rational(state["reproduction_at_idle"]))
        def normalized(view,enclosing=()):
            heard,bank=view.heard_index,view.banked_excess
            if view.effective_capacity==0 and view.open_stock==0 and view.uncapped_arrival==0:
                heard=max((Fraction(0),*enclosing));bank=view.banked_excess_floor
            if heard is None or bank is None:return None
            def normalize(index,bank):return as_decimal(self.normalizer.normalize(index=index,banked_excess=bank,profile_bytes=self.normalizer_profile_bytes),name="ambient pressure floor",minimum=0,maximum=1)
            base=normalize(Fraction(0),Fraction(0));by_index=normalize(heard,Fraction(0));by_bank=normalize(Fraction(0),bank)
            pressure=normalize(heard,bank)
            if (base!=0 or pressure<max(by_index,by_bank) or (by_index>0)!=(heard>1)
                    or (by_bank>0)!=(bank>0)):
                raise ValidationError("ambient normalizer violates the declared restrictive reference policy")
            return pressure
        views=(metrics,*active_views)
        pressure=None
        if not parent_unknown and criticality is not None and all(entry["declared_capacity"] is not None for entry in profile["entry_classes"].values()):
            pressures=(normalized(metrics,indices),*(normalized(view) for view in active_views))
            if all(value is not None for value in pressures):pressure=max(pressures)
        utilizations=tuple(view.utilization for view in views)
        banks=tuple(view.banked_excess for view in views)
        maximum_utilization=None if any(value is None for value in utilizations) else max(utilizations)
        maximum_bank=None if any(value is None for value in banks) else max(banks)
        recovery=None;available_contingency=();rule_repair=None
        if "recovery" in profile:
            recovery=project_installed_recovery(profile["recovery"],state["recovery"],capacity_windows=tuple(windows),
                criticality=profile["criticality"],recovery_windows=profile["recovery_windows"],
                utilization=None if any(entry["declared_capacity"] is None for entry in profile["entry_classes"].values()) else maximum_utilization,
                stock=metrics.open_stock,bank=maximum_bank,parse=_rational)
            rule_repair=project_installed_rule_repair(profile["recovery"],state["recovery"],recovery=recovery,
                profile_digest=policy,evaluated_at=evaluated_at,algorithm=self.algorithm)
            contingency=profile["recovery"]["contingency"]
            if recovery.tier in ("debt-growth","crisis") and contingency is not None:
                available_contingency=tuple(name for name in ("triage_order","verifier_mutual_aid","admission_tightening") if contingency[name])
        result=object.__new__(AmbientRepairAssessment)
        import rfc8785
        frame={name:value for name,value in state.items() if name not in ("checked_at","expires_at")}
        for name,value in dict(deployment_digest=deployment,operation_digest=invocation,profile_bytes=self.profile_bytes,normalizer_profile_bytes=self.normalizer_profile_bytes,
            evaluated_at=evaluated_at,expires_at=state["expires_at"],zone_id=state["zone_id"],parent_zone=None if parent is None else parent["zone_id"],
            topology_epoch=state["topology_epoch"],capacity=capacity,metrics=metrics,criticality_valid=criticality,pressure_floor=pressure,
            class_capacities=class_capacities,class_metrics=tuple(class_metrics),
            maximum_utilization=maximum_utilization,maximum_banked_excess=maximum_bank,recovery=recovery,available_contingency=available_contingency,rule_repair=rule_repair,
            supervision_floor="assisted" if pressure is None else metrics.supervision_floor,
            consequential_hosting_forbidden=(any(view.consequential_hosting_forbidden for view in views)
                or recovery is not None and recovery.consequential_hosting_forbidden) and state["consequential"],profile_digest=policy,
            frame_digest=_digest(frame,self.algorithm),frame_bytes=rfc8785.dumps(frame),
            authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,name,value)
        return result


__all__=("InstalledAmbientRepairVerifier","AmbientRepairAssessment","AuthenticatedAmbientContext")
