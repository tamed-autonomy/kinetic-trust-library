"""Pure home-zone sponsorship capital, including permanent residuals.

The installed source must authenticate the complete current owned inventory,
actual intrinsic standing, prior closure, current adjudication and transfer
provenance. These facts do not establish a bond, current External Root credit,
genesis, a reservation or permission. The taper is accounting only.
"""
from dataclasses import dataclass
from fractions import Fraction
from kinetic_trust_library.errors import ValidationError
from .ambient_repair import ratio
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True)
class BondCapital:
    bond_id: str
    stake_amount: object
    intrinsic_base: object
    depth: int
    opened_at: int
    expires_at: int
    without_cause_terminated: bool = False
    for_cause_state: str = "none"
    transferred_residual: object | None = None
    previously_closed: bool = False


@dataclass(frozen=True,slots=True)
class BondCapitalProjection:
    effective_reserve: Fraction
    retained_liability: Fraction
    phase: str
    nonrenewable: bool
    unresolved_lapse: bool


def project_bond_capital(facts,*,now):
    """Return exact reserve; expiry/closure retains the ancestral floor.

    A transferred residual keeps its authenticated current value rather than
    being recalculated at its receiving ancestor's depth. Only a sustained
    for-cause finding discharges it. Resource bounds are not protocol depth caps.
    """
    if (type(facts) is not BondCapital or type(facts.bond_id) is not str or not facts.bond_id
            or type(facts.depth) is not int or not 1<=facts.depth<=4096
            or any(not _time(value) for value in (facts.opened_at,facts.expires_at,now))
            or not facts.opened_at<facts.expires_at or now<facts.opened_at
            or type(facts.without_cause_terminated) is not bool or type(facts.previously_closed) is not bool
            or type(facts.for_cause_state) is not str or facts.for_cause_state not in ("none","pending","sustained","rejected","misattestation")):
        raise ValidationError("invalid current sponsorship capital facts")
    stake=ratio(facts.stake_amount,name="original sponsorship stake",maximum=100)
    intrinsic=ratio(facts.intrinsic_base,name="intrinsic standing",maximum=100)
    if stake==0:raise ValidationError("an established bond must have positive original stake")
    transferred=None if facts.transferred_residual is None else ratio(facts.transferred_residual,name="transferred current residual",maximum=stake)
    if transferred==0 and facts.for_cause_state!="sustained":
        raise ValidationError("an unreleased transferred residual cannot disappear")
    liability=stake/Fraction(10)**facts.depth if transferred is None else transferred
    if facts.for_cause_state=="sustained":
        reserve=liability=Fraction(0);phase="released"
    elif facts.previously_closed or transferred is not None or now>=facts.expires_at or intrinsic>=80:
        reserve=liability;phase="residual"
    else:
        reserve=max(liability,stake*(1-intrinsic/80));phase="active"
    return BondCapitalProjection(reserve,liability,phase,facts.without_cause_terminated,
        facts.for_cause_state=="pending" and now>=facts.expires_at)


@dataclass(frozen=True,slots=True)
class SponsorCapitalProjection:
    sponsor_base: Fraction
    total_reserved: Fraction
    available_base: Fraction
    overcommitted: bool
    bonds: tuple[tuple[str,BondCapitalProjection],...]


def project_sponsor_capital(*,sponsor_base,bonds,now):
    """Subtract every owned active/residual liability from unencumbered base.

    The caller authenticates completeness across all zones, including inherited
    residuals. A visible overcommitment cannot become negative staking capacity.
    """
    base=ratio(sponsor_base,name="unencumbered sponsor base standing",maximum=100)
    if (type(bonds) is not tuple or len(bonds)>65536 or not _time(now)
            or any(type(item) is not BondCapital for item in bonds)):
        raise ValidationError("complete bounded sponsorship capital inventory required")
    seen=set();projected=[]
    for item in bonds:
        result=project_bond_capital(item,now=now)
        if item.bond_id in seen:raise ValidationError("duplicate owned sponsorship liability")
        seen.add(item.bond_id);projected.append((item.bond_id,result))
    reserved=sum((item.effective_reserve for _,item in projected),Fraction(0))
    return SponsorCapitalProjection(base,reserved,max(Fraction(0),base-reserved),reserved>base,tuple(projected))


__all__=("BondCapital","BondCapitalProjection","SponsorCapitalProjection","project_bond_capital","project_sponsor_capital")
