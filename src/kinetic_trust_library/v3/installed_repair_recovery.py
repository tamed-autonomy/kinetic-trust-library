"""Closed reference declarations and authenticated ambient recovery composition.

The ambient source owns complete historical windows and durable prior tier.
Latest stock, bank and utilization are supplied only by Library projections.
"""
from kinetic_trust_library.errors import ValidationError
from .repair_recovery import RecoveryWindow, project_recovery


def validate_recovery_declaration(value,*,criticality,recovery_windows,parse):
    if (type(value) is not dict or set(value)!={"margin","stock_target","amendment_rate_limit",
            "nonattendance_rate_limit","crisis_invariants_preserved","contingency"}
            or type(value["crisis_invariants_preserved"]) is not bool):
        raise ValidationError("invalid published recovery declaration")
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
    if (type(state) is not dict or set(state)!={"previous_tier","history","amendment_rate","nonattendance_rate"}
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
