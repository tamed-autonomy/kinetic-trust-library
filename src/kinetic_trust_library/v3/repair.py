"""Reconciliation preconditions and exact declared fractional re-entry ceilings.

Pure projections consume already authenticated facts; they cannot establish
anchors, independence, attendance, affected-party declarations or readiness.
The additive residual-harm raise is an explicitly selected reference policy,
not a universal formula supplied by the RFC.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from kinetic_trust_library._decimal import DecimalLike,as_decimal
from kinetic_trust_library.errors import ValidationError
from ._exact import finite_decimal
from .reconciliation_record import ReconciliationRecordFacts,project_reconciliation_record


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
    for field in ("hard_entry","unrepaired_declared"):
        if type(getattr(facts,field)) is not bool:raise ValidationError("repair truth values must be explicit booleans")
    record=project_reconciliation_record(ReconciliationRecordFacts(
        cause_anchor=facts.breach_anchor,record_cause_anchor=facts.record_breach_anchor,
        accountable_terminator=facts.breaching_terminator,
        **{field:getattr(facts,field) for field in ReconciliationRecordFacts.__dataclass_fields__
           if field not in ("cause_anchor","record_cause_anchor","accountable_terminator","cause_at")},
        cause_at=facts.breached_at))
    standing=as_decimal(facts.standing_at_breach,name="standing at breach",minimum=0,maximum=100)
    declared=as_decimal(facts.declared_delta,name="re-entry delta",minimum=0,maximum=1)
    previous=as_decimal(facts.previous_delta,name="previous re-entry delta",minimum=0,maximum=1)
    increase=as_decimal(facts.declared_unrepaired_raise,name="declared unrepaired raise",minimum=0,maximum=1)
    if (facts.hard_entry and declared<Decimal(".1")) or increase==0:
        raise ValidationError("repair policy lacks the hard floor or a positive residual-harm raise")
    reason=record.reason
    if not record.record_valid:return ReentryProjection(False,reason,None,None,None)
    delta=min(Fraction(1),max(Fraction(declared),Fraction(previous))+(Fraction(increase) if facts.unrepaired_declared else 0))
    return ReentryProjection(True,reason,finite_decimal(delta),finite_decimal(Fraction(standing)*(1-delta)),facts.anchored_at)


__all__=("ReconciliationFacts","ReentryProjection","project_reentry")
