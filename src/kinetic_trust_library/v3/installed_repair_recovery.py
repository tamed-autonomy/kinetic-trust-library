"""Closed reference declarations and authenticated ambient recovery composition.

The ambient source owns complete historical windows and durable prior tier.
Latest stock, bank and utilization are supplied only by Library projections.
"""
from kinetic_trust_library.errors import ValidationError
from .repair_recovery import RecoveryWindow, project_recovery
from .rule_repair import project_rule_repairs


def validate_recovery_declaration(value,*,criticality,recovery_windows,parse):
    if (type(value) is not dict or set(value)-{"rule_repair"}!={"margin","stock_target","amendment_rate_limit",
            "nonattendance_rate_limit","crisis_invariants_preserved","contingency"}
            or type(value["crisis_invariants_preserved"]) is not bool):
        raise ValidationError("invalid published recovery declaration")
    if "rule_repair" in value:
        policy=value["rule_repair"]
        if (type(policy) is not dict or set(policy)!={"recurrence_limit"}
                or type(policy["recurrence_limit"]) is not int or not 1<=policy["recurrence_limit"]<=4096):
            raise ValidationError("rule repair requires a bounded published recurrence")
    contingency=value["contingency"]
    if contingency is not None:
        if (type(contingency) is not dict or set(contingency)!={"triage_order","verifier_mutual_aid","admission_tightening"}
                or contingency["triage_order"] not in (None,"residual_harm,criticality","criticality,residual_harm")
                or type(contingency["verifier_mutual_aid"]) is not bool or type(contingency["admission_tightening"]) is not bool):
            raise ValidationError("recovery contingency must contain only declared permitted measures")
    # Validate exact policy bounds even before current evidence is requested.
    project_recovery(previous_tier="normal",windows=(RecoveryWindow(None,0,None,0,0),),
        **_parameters(value,criticality,recovery_windows,parse))


def _parameters(value,criticality,recovery_windows,parse):
    return dict(criticality=parse(criticality),recovery_windows=recovery_windows,
        recovery_margin=parse(value["margin"]),stock_target=parse(value["stock_target"]),
        amendment_rate_limit=parse(value["amendment_rate_limit"]),
        nonattendance_rate_limit=parse(value["nonattendance_rate_limit"]),
        crisis_invariants_preserved=value["crisis_invariants_preserved"])


def project_installed_recovery(declaration,state,*,capacity_windows,criticality,
                               recovery_windows,utilization,stock,bank,parse):
    if (type(state) is not dict or set(state)!={"previous_tier","history","amendment_rate","nonattendance_rate"}|({"rule_repair"} if "rule_repair" in declaration else set())
            or type(state["history"]) is not list or len(state["history"])!=recovery_windows-1):
        raise ValidationError("recovery requires complete authenticated trailing history")
    windows=[]
    for item,period in zip(state["history"],capacity_windows[:-1]):
        if (type(item) is not dict or set(item)!={"starts_at","ends_at","utilization","open_stock","banked_excess","amendment_rate","nonattendance_rate"}
                or parse(item["starts_at"])!=period.starts_at or parse(item["ends_at"])!=period.ends_at):
            raise ValidationError("recovery history differs from the declared consecutive periods")
        windows.append(RecoveryWindow(*(None if item[name] is None else parse(item[name]) for name in
            ("utilization","open_stock","banked_excess","amendment_rate","nonattendance_rate"))))
    windows.append(RecoveryWindow(utilization,stock,bank,
        None if state["amendment_rate"] is None else parse(state["amendment_rate"]),
        None if state["nonattendance_rate"] is None else parse(state["nonattendance_rate"])))
    return project_recovery(previous_tier=state["previous_tier"],windows=tuple(windows),
        **_parameters(declaration,criticality,recovery_windows,parse))


def project_installed_rule_repair(declaration,state,*,recovery,profile_digest,evaluated_at,algorithm):
    if "rule_repair" not in declaration:return None
    inventory=state["rule_repair"]
    result=project_rule_repairs(inventory,recurrence_limit=declaration["rule_repair"]["recurrence_limit"],
        tier_record_required=recovery.rule_repair_required,evaluated_at=evaluated_at,algorithm=algorithm)
    tiers=("normal","reserve-gone","debt-growth","crisis")
    for item in inventory["patterns"]:
        if item["pattern_id"]==inventory["tier_pattern_id"]:
            if (item["kind"]!="profile" or tiers.index(recovery.tier)>tiers.index(state["previous_tier"])
                    and item["profile_digest"]!=profile_digest):
                raise ValidationError("tier rule repair substitutes its responsible published profile")
    return result
