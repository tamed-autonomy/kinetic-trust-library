"""Zone-scoped person standing from authenticated signed-act contributions.

No act-count scoring model, software ceilings, eligibility, human operational
capacity or execution permission is supplied. Inputs need source authentication.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from kinetic_trust_library.errors import ValidationError
from .ambient_repair import ratio
from ._exact import finite_decimal
from .root_lifecycle import _time
from .execution_observation import _name


ACT_KINDS=frozenset(("bond_posted","attestation_issued","approval","veto_clear","decision_contested"))
PERSON_CEILINGS=frozenset(("ial","trajectory","adversity","external_root_missing","repair_reentry"))


@dataclass(frozen=True,slots=True,init=False)
class PersonStanding:
    subject: str
    zone: str
    por_contribution: Fraction
    root_term: Fraction
    raw_base: Fraction
    base_trust: Decimal
    effective_trust: Decimal
    ceilings: tuple
    signed_act_anchors: tuple
    evaluated_at: int
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("person standing requires signed-act composition")


def _person(subject):
    return type(subject) is str and subject.startswith("person:") and len(subject)>7 and not any(c.isspace() for c in subject)


def calculate_person_standing(*,subject,zone,signed_acts,por_contribution,terminator_standing,ceilings,zone_risk,evaluated_at):
    """Compose the zero-peer-share person profile without default ceilings.

    The complete authenticated historical ledger supplies signed stress acts
    and the contribution derived under its declared assessment policy. Merely
    participating in an incident earns no contribution. Corrections and retained
    historical credit are provider facts; elapsed time does not decay them.
    """
    if (not _person(subject) or not _name(zone) or not _time(evaluated_at)
            or type(signed_acts) is not tuple or len(signed_acts)>4096
            or type(ceilings) is not dict or not set(ceilings)<=PERSON_CEILINGS):
        raise ValidationError("explicit person/zone, bounded signed ledger and person ceilings required")
    ids=set();anchors=set();stress=False
    for act in signed_acts:
        if (type(act) is not dict or set(act)!={"id","subject","zone","kind","under_stress","anchor","occurred_at"}
                or not _name(act["id"]) or not _name(act["anchor"])
                or act["subject"]!=subject or act["zone"]!=zone or act["kind"] not in ACT_KINDS
                or type(act["under_stress"]) is not bool or not _time(act["occurred_at"])
                or act["occurred_at"]>evaluated_at or act["id"] in ids or act["anchor"] in anchors):
            raise ValidationError("person ledger contains unbound, duplicated or unsigned act facts")
        ids.add(act["id"]);anchors.add(act["anchor"]);stress=stress or act["under_stress"]
    por=ratio(por_contribution,name="signed stress-act contribution",maximum=70)
    root=ratio(terminator_standing,name="institutional terminator standing",maximum=100)
    risk=ratio(zone_risk,name="person zone risk",maximum=1)
    if por and not stress:raise ValidationError("resilience requires an authenticated signed act under stress")
    bounded={k:ratio(v,name="person "+k+" ceiling",maximum=100) for k,v in ceilings.items()}
    if "ial" in bounded and bounded["ial"] not in (40,80,95):raise ValidationError("person identity assurance ceiling is invalid")
    raw=por+root*Fraction(3,10)
    base=min((raw,*bounded.values()))
    try:base_decimal=finite_decimal(base);effective=finite_decimal(base*(1-risk))
    except ValueError as exc:raise ValidationError("nonterminating person standing needs a declared wire precision profile") from exc
    result=object.__new__(PersonStanding)
    for k,v in dict(subject=subject,zone=zone,por_contribution=por,root_term=root*Fraction(3,10),raw_base=raw,
            base_trust=base_decimal,effective_trust=effective,ceilings=tuple(sorted(bounded.items())),
            signed_act_anchors=tuple(a["anchor"] for a in signed_acts),evaluated_at=evaluated_at,action_permitted=False).items():
        object.__setattr__(result,k,v)
    return result


@dataclass(frozen=True,slots=True,init=False)
class ImportedPersonStanding:
    subject: str
    source_zone: str
    receiving_zone: str
    transferred: bool
    raw_base: Fraction
    base_trust: Decimal
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("person import requires a directional agreement")


def calculate_imported_person_standing(*,subject,source_zone,receiving_zone,exportable_base,
        agreement_exists,receiver_signed,person_factor,zone_ceiling):
    """Apply one authenticated receiver-signed factor and receiver zone bound.

    Zero-factor admission differs from absence of a directional agreement.
    No local/imported accumulation formula or software mass ceiling is invented.
    """
    if (not _person(subject) or not _name(source_zone) or not _name(receiving_zone) or source_zone==receiving_zone
            or type(agreement_exists) is not bool or type(receiver_signed) is not bool):
        raise ValidationError("person import requires explicit directional agreement facts")
    base=ratio(exportable_base,name="person exportable standing",maximum=100)
    cap=ratio(zone_ceiling,name="receiver person standing ceiling",maximum=100)
    factor=None if person_factor is None else ratio(person_factor,name="person directional factor",maximum=1)
    transferred=agreement_exists and receiver_signed and factor is not None
    raw=base*factor if transferred else Fraction(0)
    try:effective=finite_decimal(min(raw,cap))
    except ValueError as exc:raise ValidationError("nonterminating person import needs a declared wire precision profile") from exc
    result=object.__new__(ImportedPersonStanding)
    for k,v in dict(subject=subject,source_zone=source_zone,receiving_zone=receiving_zone,transferred=transferred,
            raw_base=raw,base_trust=effective,action_permitted=False).items():object.__setattr__(result,k,v)
    return result
