"""Reconciliation preconditions and exact declared fractional re-entry ceilings.

Pure projections consume already authenticated facts; they cannot establish
anchors, independence, attendance, affected-party declarations or readiness.
The additive residual-harm raise is an explicitly selected reference policy,
not a universal formula supplied by the RFC.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
import re
from kinetic_trust_library._decimal import DecimalLike,as_decimal
from kinetic_trust_library.errors import ValidationError
from ._exact import finite_decimal
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True)
class ReconciliationFacts:
    breach_anchor: str
    record_breach_anchor: str
    breaching_terminator: str
    required_parties: tuple[str,...]
    record_parties: tuple[str,...]
    acknowledged_by: str | None
    residual_harm: str | None
    verifier: str
    oracle: str
    independent_of: tuple[str,...]
    current_anchor_verified: bool
    anchored_at: int
    breached_at: int
    declined_parties: tuple[str,...]
    open_to: tuple[str,...]
    route_followed: bool
    route_published: bool
    standing_at_breach: DecimalLike
    declared_delta: DecimalLike
    previous_delta: DecimalLike
    hard_entry: bool
    unrepaired_declared: bool
    declared_unrepaired_raise: DecimalLike


@dataclass(frozen=True,slots=True)
class ReentryProjection:
    record_valid: bool
    reason: str
    delta: Decimal | None
    ceiling: Decimal | None
    anchored_at: int | None


def project_reentry(facts):
    """Validate record prerequisites; a valid ceiling restores no readiness."""
    if type(facts) is not ReconciliationFacts:raise ValidationError("typed reconciliation facts required")
    for field in ("current_anchor_verified","route_followed","route_published","hard_entry","unrepaired_declared"):
        if type(getattr(facts,field)) is not bool:raise ValidationError("repair truth values must be explicit booleans")
    for field in ("required_parties","record_parties","independent_of","declined_parties","open_to"):
        values=getattr(facts,field)
        if (type(values) is not tuple or any(type(value) is not str or not value for value in values)
                or len(set(values))!=len(values)):
            raise ValidationError("repair parties must be exact distinct identifiers")
    for field in ("breach_anchor","record_breach_anchor"):
        value=getattr(facts,field)
        if type(value) is not str or re.fullmatch(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})",value) is None:
            raise ValidationError("invalid repair anchor digest")
    for value in (facts.breaching_terminator,facts.verifier,facts.oracle):
        if type(value) is not str or not value:raise ValidationError("repair authority identifier required")
    if not _time(facts.breached_at) or not _time(facts.anchored_at):raise ValidationError("repair record times are invalid")
    standing=as_decimal(facts.standing_at_breach,name="standing at breach",minimum=0,maximum=100)
    declared=as_decimal(facts.declared_delta,name="re-entry delta",minimum=0,maximum=1)
    previous=as_decimal(facts.previous_delta,name="previous re-entry delta",minimum=0,maximum=1)
    increase=as_decimal(facts.declared_unrepaired_raise,name="declared unrepaired raise",minimum=0,maximum=1)
    if (facts.hard_entry and declared<Decimal(".1")) or increase==0:
        raise ValidationError("repair policy lacks the hard floor or a positive residual-harm raise")
    parties=set(facts.record_parties);required=set(facts.required_parties)
    reason=("REPAIR_ANCHOR" if not facts.current_anchor_verified or facts.record_breach_anchor!=facts.breach_anchor
                or facts.anchored_at<facts.breached_at else
            "REPAIR_PARTIES" if not required or facts.breaching_terminator not in required or not required<=parties else
            "REPAIR_ACKNOWLEDGMENT" if facts.acknowledged_by!=facts.breaching_terminator else
            "REPAIR_RESIDUAL_HARM" if type(facts.residual_harm) is not str or not facts.residual_harm else
            "REPAIR_INDEPENDENCE" if facts.verifier==facts.oracle or facts.verifier in parties
                or not parties<=set(facts.independent_of) else
            "REPAIR_ROUTE" if facts.declined_parties and (not facts.route_published or not facts.route_followed
                or not set(facts.declined_parties)<=required or not set(facts.declined_parties)<=set(facts.open_to)) else
            "REPAIR_RECONCILED")
    if reason!="REPAIR_RECONCILED":return ReentryProjection(False,reason,None,None,None)
    delta=min(Fraction(1),max(Fraction(declared),Fraction(previous))+(Fraction(increase) if facts.unrepaired_declared else 0))
    return ReentryProjection(True,reason,finite_decimal(delta),finite_decimal(Fraction(standing)*(1-delta)),facts.anchored_at)


__all__=("ReconciliationFacts","ReentryProjection","project_reentry")
