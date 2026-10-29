"""Pure tier projection, not emergency authority or an anchored audit writer.

The Service authenticates complete consecutive windows and persists the prior
tier. Unknown evidence cannot prove recovery or a measured crisis.
"""
from dataclasses import dataclass
from fractions import Fraction
from kinetic_trust_library.errors import ValidationError
from .ambient_repair import ratio

_TIERS=("normal","reserve-gone","debt-growth","crisis")


@dataclass(frozen=True,slots=True)
class RecoveryWindow:
    conservative_utilization: object
    open_stock: object
    banked_excess: object
    amendment_rate: object
    nonattendance_rate: object


@dataclass(frozen=True,slots=True)
class RecoveryProjection:
    tier: str
    recovered: bool
    measurement_complete: bool
    rule_repair_required: bool
    consequential_hosting_forbidden: bool
    emergency_authorized: bool = False


def project_recovery(*,previous_tier,windows,criticality,recovery_windows,
                     recovery_margin,stock_target,amendment_rate_limit,
                     nonattendance_rate_limit,crisis_invariants_preserved=True):
    """Return exact tier and obligations, without executing contingency measures.

    ``normal`` denotes the reserve-held state outside the three recovery tiers.
    The caller owns continuity, conservative estimates and prior-tier authority.
    The prior tier is the persisted state immediately before the latest window;
    earlier windows supply trailing evidence, not an alternate replay history.
    No per-person values are accepted or produced.
    """
    if (type(previous_tier) is not str or previous_tier not in _TIERS
            or type(windows) is not tuple or not windows or len(windows)>65536
            or type(recovery_windows) is not int or not 1<=recovery_windows<=65536
            or type(crisis_invariants_preserved) is not bool):
        raise ValidationError("repair recovery requires a tier and bounded complete windows")
    k=ratio(criticality,name="recovery criticality",minimum=1)
    margin=ratio(recovery_margin,name="recovery margin")
    target=ratio(stock_target,name="recovery stock target")
    amend=ratio(amendment_rate_limit,name="amendment rate limit")
    absent=ratio(nonattendance_rate_limit,name="nonattendance rate limit")
    if k<=1 or margin<=0:
        raise ValidationError("recovery requires criticality above one and a positive margin")
    parsed=[]
    for item in windows:
        if type(item) is not RecoveryWindow:
            raise ValidationError("recovery windows require exact aggregate records")
        parsed.append(tuple(None if value is None else ratio(value,name="recovery measure")
            for value in (item.conservative_utilization,item.open_stock,item.banked_excess,
                          item.amendment_rate,item.nonattendance_rate)))
    tail=parsed[-recovery_windows:]
    full=len(tail)==recovery_windows
    current=parsed[-1][0]
    crisis=full and all(row[0] is not None and row[0]>=2 for row in tail)
    measured=("crisis" if crisis else "debt-growth" if current is not None and current>1
              else "reserve-gone" if current is not None and current>1/k else "normal")
    threshold={"reserve-gone":1/k,"debt-growth":Fraction(1),"crisis":Fraction(2)}
    recovered=previous_tier!="normal" and full and all(
        all(value is not None for value in row) and row[0]<threshold[previous_tier]-margin
        and row[1]<=target and row[2]==0 and row[3]<amend and row[4]<absent for row in tail)
    tier=measured if recovered else _TIERS[max(_TIERS.index(previous_tier),_TIERS.index(measured))]
    return RecoveryProjection(tier,recovered,all(all(v is not None for v in row) for row in tail),
        tier!="normal" or previous_tier!="normal",not crisis_invariants_preserved)


__all__=("RecoveryWindow","RecoveryProjection","project_recovery")
