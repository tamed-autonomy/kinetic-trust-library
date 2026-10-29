"""Shared anchored reconciliation prerequisites, without standing penalties.

Inputs are authenticated facts. A lawful relational stop is a cause for a
relationship record; it does not become a breach through this projection.
"""
from dataclasses import dataclass
import re
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True)
class ReconciliationRecordFacts:
    cause_anchor: str
    record_cause_anchor: str
    accountable_terminator: str
    required_parties: tuple[str,...]
    record_parties: tuple[str,...]
    acknowledged_by: str | None
    residual_harm: str | None
    verifier: str
    oracle: str
    independent_of: tuple[str,...]
    current_anchor_verified: bool
    anchored_at: int
    cause_at: int
    declined_parties: tuple[str,...]
    open_to: tuple[str,...]
    route_followed: bool
    route_published: bool


@dataclass(frozen=True,slots=True)
class ReconciliationRecordProjection:
    record_valid: bool
    reason: str
    anchored_at: int | None


def project_reconciliation_record(facts):
    if type(facts) is not ReconciliationRecordFacts:
        raise ValidationError("typed reconciliation record facts required")
    for field in ("current_anchor_verified","route_followed","route_published"):
        if type(getattr(facts,field)) is not bool:raise ValidationError("repair truth values must be explicit booleans")
    for field in ("required_parties","record_parties","independent_of","declined_parties","open_to"):
        values=getattr(facts,field)
        if (type(values) is not tuple or any(type(value) is not str or not value for value in values)
                or len(set(values))!=len(values)):
            raise ValidationError("repair parties must be exact distinct identifiers")
    for field in ("cause_anchor","record_cause_anchor"):
        value=getattr(facts,field)
        if type(value) is not str or re.fullmatch(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})",value) is None:
            raise ValidationError("invalid repair anchor digest")
    for value in (facts.accountable_terminator,facts.verifier,facts.oracle):
        if type(value) is not str or not value:raise ValidationError("repair authority identifier required")
    if not _time(facts.cause_at) or not _time(facts.anchored_at):raise ValidationError("repair record times are invalid")
    parties=set(facts.record_parties);required=set(facts.required_parties)
    reason=("REPAIR_ANCHOR" if not facts.current_anchor_verified or facts.record_cause_anchor!=facts.cause_anchor
                or facts.anchored_at<facts.cause_at else
            "REPAIR_PARTIES" if not required or facts.accountable_terminator not in required or not required<=parties else
            "REPAIR_ACKNOWLEDGMENT" if facts.acknowledged_by!=facts.accountable_terminator else
            "REPAIR_RESIDUAL_HARM" if type(facts.residual_harm) is not str or not facts.residual_harm else
            "REPAIR_INDEPENDENCE" if facts.verifier==facts.oracle or facts.verifier in parties
                or not parties<=set(facts.independent_of) else
            "REPAIR_ROUTE" if facts.declined_parties and (not facts.route_published or not facts.route_followed
                or not set(facts.declined_parties)<=required or not set(facts.declined_parties)<=set(facts.open_to)) else
            "REPAIR_RECONCILED")
    if reason!="REPAIR_RECONCILED":return ReconciliationRecordProjection(False,reason,None)
    return ReconciliationRecordProjection(True,reason,facts.anchored_at)


__all__=("ReconciliationRecordFacts","ReconciliationRecordProjection","project_reconciliation_record")
