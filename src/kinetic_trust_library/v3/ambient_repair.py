"""Exact reference accounting for ambient breach, not measurement authority.

Lineage caps affect arrival heat, never open breach stock. A quiet window alone
does not clear stock or banked excess. The selected carry/anchored-retirement
reference policy requires explicit retirement credit backed by anchored closure.
Other reviewed policies may implement the RFC's behaviours differently.
"""
from dataclasses import dataclass
from fractions import Fraction
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time


def ratio(value,*,name,minimum=0,maximum=None):
    result=value if type(value) is Fraction else Fraction(as_decimal(value,name=name))
    if (max(result.numerator.bit_length(),result.denominator.bit_length())>65536 or result<minimum
            or maximum is not None and result>maximum):
        raise ValidationError(name+" is outside the supported exact range")
    return result


@dataclass(frozen=True,slots=True)
class AmbientWindowProjection:
    capacity_known: bool
    effective_capacity: Fraction | None
    uncapped_arrival: Fraction
    arrival: Fraction | None
    open_stock: Fraction
    stock_change: Fraction
    utilization: Fraction | None
    local_index: Fraction | None
    heard_index: Fraction | None
    banked_excess: Fraction | None
    banked_excess_floor: Fraction
    saturated: bool
    consequential_hosting_forbidden: bool
    supervision_floor: str
    durable_capacity_exceeded: bool | None


def project_ambient_window(*,prior_stock,arrivals,anchored_weight,effective_capacity,criticality,single_lineage_share,
                           prior_banked_excess=0,retired_excess=0,retirement_credit_per_weight=1,window_duration=1,
                           enclosing_indices=(),accountable_roots=1):
    stock=ratio(prior_stock,name="prior open breach stock")
    closed=ratio(anchored_weight,name="anchored reconciliation weight")
    k=ratio(criticality,name="declared criticality",minimum=1)
    share=ratio(single_lineage_share,name="single-lineage arrival share",maximum=1)
    duration=ratio(window_duration,name="aggregation window duration")
    prior=ratio(prior_banked_excess,name="prior banked excess")
    retired=ratio(retired_excess,name="anchored bank retirement")
    credit=ratio(retirement_credit_per_weight,name="declared bank retirement credit")
    if share==0 or duration==0 or credit==0 or not _time(accountable_roots):
        raise ValidationError("ambient policy requires positive share/window/credit and an exact root count")
    if (type(arrivals) is not tuple or type(enclosing_indices) is not tuple or len(arrivals)>65536
            or any(type(item) is not tuple or len(item)!=2 or type(item[0]) is not str or not item[0] for item in arrivals)):
        raise ValidationError("ambient arrival requires an exact complete lineage aggregate")
    if len({item[0] for item in arrivals})!=len(arrivals):
        raise ValidationError("a lineage cannot evade its share through duplicate aggregates")
    weights=tuple(ratio(value,name="lineage breach weight") for _,value in arrivals)
    uncapped=sum(weights,Fraction(0))
    if closed>stock+uncapped:raise ValidationError("anchored closure cannot exceed open breach stock")
    if retired>prior or retired>closed*credit:
        raise ValidationError("banked excess cannot clear without sufficient anchored closure credit")
    capacity=None if effective_capacity is None else ratio(effective_capacity,name="effective repair capacity")
    if accountable_roots==0:capacity=Fraction(0)
    arrival=None if capacity is None else sum((min(value,capacity*share) for value in weights),Fraction(0))
    utilization=None if capacity is None or capacity==0 else arrival/capacity
    local=None if utilization is None else k*utilization
    parents=tuple(ratio(value,name="authenticated enclosing breach index") for value in enclosing_indices)
    heard=None if local is None else max((local,*parents))
    bank_floor=prior-retired
    bank=None if local is None else bank_floor+max(Fraction(0),local-1)*duration
    current_stock=stock+uncapped-closed
    unknown_floor=capacity is None or capacity==0 and current_stock>0
    saturated=unknown_floor or utilization is not None and utilization>=1
    forbidden=capacity==0 and current_stock>0
    return AmbientWindowProjection(capacity is not None,capacity,uncapped,arrival,current_stock,uncapped-closed,
        utilization,local,heard,bank,bank_floor,saturated,forbidden,"assisted" if unknown_floor else "stable",
        None if utilization is None else utilization>1)


def reference_criticality_valid(criticality,reproduction_at_idle):
    """Exact reference test K > 1/(1-sqrt(g)), without rounded square roots."""
    k=ratio(criticality,name="declared criticality",minimum=1)
    g=ratio(reproduction_at_idle,name="measured idle reproduction")
    return k>1 and g<(1-1/k)**2


__all__=("AmbientWindowProjection","project_ambient_window","reference_criticality_valid")
