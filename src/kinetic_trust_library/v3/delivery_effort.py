"""Pure declared delivery-work projection; no sending, storage or authority.

Actual attempts/receipts, capacity snapshots and escrow must be authenticated
independently. Missing effort creates obligations and never vetoes a stop or
permits an action. The relative-retry/anchored-escalation clock is a selected
reference policy, not an RFC-prescribed numeric schedule.
"""
from dataclasses import dataclass,field
from kinetic_trust_library.errors import ValidationError
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .hand_back_hysteresis import _at


@dataclass(frozen=True,slots=True)
class DeliveryEffortProjection:
    delivery_state: str
    effort_current: bool
    escrow_required: bool
    escrow_needed: bool
    attempt_due: bool
    next_attempt_at: object
    escalation_due: tuple
    late_attempt_record_required: tuple
    late_escalation_record_required: tuple
    schedule_defect_record_required: tuple
    capacity_exhaustion_anchors: tuple
    delivered_at: object
    delivery_confirmed_at: object
    missed_attempt_record_required: bool
    missed_escalation_record_required: tuple
    receipt_anchor: str | None
    acknowledgment_due: bool
    acknowledgment_overdue: bool
    next_change_at: int | None
    action_permitted: bool = field(default=False,init=False)


def project_delivery_effort(terms,attempts,escalations,*,issued_at,evaluated_at,ledger_head_sequence,escrow_present,
                            capacity_freshness_seconds,ack_sla_seconds,hand_back_digest,capacity_binding,acknowledged_at=None):
    if (type(terms) is not dict or set(terms)!={"retry_seconds","tolerance_seconds","escalation_seconds","escalation_cap"}
            or any(not _time(v) for v in terms.values()) or terms["retry_seconds"]==0 or terms["escalation_seconds"]==0 or terms["escalation_cap"]>4096
            or not is_digest(hand_back_digest) or not _name(capacity_binding)
            or not _time(evaluated_at) or not _time(ledger_head_sequence) or type(escrow_present) is not bool
            or not _time(capacity_freshness_seconds) or capacity_freshness_seconds==0 or not _time(ack_sla_seconds) or ack_sla_seconds==0
            or type(attempts) is not list or len(attempts)>4096 or type(escalations) is not list or len(escalations)>4096):
        raise ValidationError("complete declared delivery terms and authenticated history required")
    issued=_at(issued_at)
    if issued>evaluated_at:raise ValidationError("delivery cannot precede the actual hand-back")
    anchors=set();positions=set();ids=set();capacity_records={};late=[];late_escalations=[];defects=[];exhausted=[]
    due=issued;delivered=None;receipt_anchor=None;confirmed=None;receipt_sequence=None;timeline=[];receipts=[];previous_at=issued;previous_sequence=0
    def position(record):
        if (not is_digest(record["anchor"]) or record["anchor"] in anchors or not _time(record["sequence"])
                or not 0<record["sequence"]<=ledger_head_sequence or record["sequence"] in positions):
            raise ValidationError("actual delivery records require distinct audit anchors and positions")
        anchors.add(record["anchor"]);positions.add(record["sequence"])
    for attempt in attempts:
        if (type(attempt) is not dict or set(attempt)!={"id","anchor","sequence","attempted_at","route_ref","channel_reachable","message_digest","capacity_binding",
                "capacity","capacity_observed_at","capacity_anchor","receipt"}
                or not _name(attempt["id"]) or attempt["id"] in ids or not _name(attempt["route_ref"])
                or type(attempt["channel_reachable"]) is not bool or attempt["capacity"] not in ("available","exhausted","unknown")
                or attempt["message_digest"]!=hand_back_digest or attempt["capacity_binding"]!=capacity_binding
                or not is_digest(attempt["capacity_anchor"])):raise ValidationError("actual bound capacity-aware attempt record required")
        position(attempt);at=_at(attempt["attempted_at"]);observed=_at(attempt["capacity_observed_at"])
        if not previous_at<=at<=evaluated_at or attempt["sequence"]<=previous_sequence or not issued<=at or observed>at:
            raise ValidationError("delivery attempt/capacity/audit chronology differs")
        previous_at=at;previous_sequence=attempt["sequence"];ids.add(attempt["id"])
        observation=(attempt["capacity"],observed)
        if capacity_records.get(attempt["capacity_anchor"],observation)!=observation:raise ValidationError("capacity record was reused with different facts")
        capacity_records[attempt["capacity_anchor"]]=observation
        if attempt["capacity"]!="unknown" and at-observed>capacity_freshness_seconds:defects.append(attempt["capacity_anchor"])
        elif attempt["capacity"]=="exhausted":exhausted.append(attempt["anchor"])
        receipt=attempt["receipt"]
        if receipt is not None:
            if type(receipt) is not dict or set(receipt)!={"anchor","sequence","accepted_at","recorded_at"}:raise ValidationError("actual recipient receipt record required")
            position(receipt);accepted=_at(receipt["accepted_at"]);recorded=_at(receipt["recorded_at"])
            if (not at<=accepted<=recorded<=evaluated_at or receipt["sequence"]<=attempt["sequence"] or not attempt["channel_reachable"]
                    or attempt["capacity"]!="available" or at-observed>capacity_freshness_seconds):
                raise ValidationError("delivery receipt lacks fresh available capacity/reachable-channel evidence")
            receipts.append((accepted,recorded,receipt["sequence"],receipt["anchor"]))
        timeline.append((attempt,at))
    if receipts:
        delivered,_,_,receipt_anchor=min(receipts)
        _,confirmed,receipt_sequence,_=min(receipts,key=lambda r:(r[1],r[2]))
    for attempt,at in timeline:
        known=confirmed is not None and at>=confirmed and attempt["sequence"]>receipt_sequence
        if known:defects.append(attempt["anchor"])
        else:
            if at>due+terms["tolerance_seconds"]:late.append(attempt["anchor"])
            elif at<due:defects.append(attempt["anchor"])
            due=at+terms["retry_seconds"]
    levels=set()
    for escalation in escalations:
        if (type(escalation) is not dict or set(escalation)!={"anchor","sequence","level","occurred_at","route_ref","message_digest"}
                or not _time(escalation["level"]) or not 1<=escalation["level"]<=terms["escalation_cap"]
                or escalation["level"] in levels or escalation["message_digest"]!=hand_back_digest or not _name(escalation["route_ref"])):raise ValidationError("actual bound capped escalation record required")
        position(escalation);at=_at(escalation["occurred_at"]);scheduled=issued+escalation["level"]*terms["escalation_seconds"]
        if not issued<=at<=evaluated_at:raise ValidationError("escalation occurrence differs from actual hand-back")
        levels.add(escalation["level"])
        if at<scheduled or confirmed is not None and at>confirmed and escalation["sequence"]>receipt_sequence:defects.append(escalation["anchor"])
        elif at>scheduled+terms["tolerance_seconds"]:late_escalations.append(escalation["anchor"])
    horizon=confirmed if confirmed is not None else evaluated_at
    required_levels=range(1,min(terms["escalation_cap"],int((horizon-issued)//terms["escalation_seconds"]))+1)
    missing_levels=tuple(level for level in required_levels if level not in levels)
    escalation_due=missing_levels if delivered is None else ()
    missed_escalation=tuple(level for level in missing_levels if horizon>issued+level*terms["escalation_seconds"]+terms["tolerance_seconds"])
    attempt_due=delivered is None and evaluated_at>=due
    attempt_late=horizon>due+terms["tolerance_seconds"]
    if acknowledged_at is not None:
        ack=_at(acknowledged_at)
        if delivered is None or not delivered<=ack<=evaluated_at:raise ValidationError("acknowledgment requires actual preceding delivery")
    else:ack=None
    ack_due=delivered is not None and ack is None
    ack_overdue=delivered is not None and (evaluated_at>=delivered+ack_sla_seconds if ack is None else ack>delivered+ack_sla_seconds)
    ticks=[]
    def tick(at,*,strict=False):
        value=int(at)+1 if strict else (at.numerator+at.denominator-1)//at.denominator
        if value>evaluated_at:ticks.append(value)
    if delivered is None:
        tick(due);tick(due+terms["tolerance_seconds"],strict=True)
        for level in range(1,terms["escalation_cap"]+1):
            if level not in levels:
                at=issued+level*terms["escalation_seconds"];tick(at);tick(at+terms["tolerance_seconds"],strict=True)
    if ack_due:tick(delivered+ack_sla_seconds)
    needs_escrow=delivered is None or any(a["receipt"] is None and (confirmed is None or at<confirmed) for a,at in timeline)
    escrow_required=needs_escrow and not escrow_present
    current=not (escrow_required or late or late_escalations or defects or attempt_late or missed_escalation or ack_overdue)
    return DeliveryEffortProjection("delivered" if delivered is not None else "parked",current,escrow_required,needs_escrow,attempt_due,due if delivered is None else None,
        escalation_due,tuple(late),tuple(late_escalations),tuple(defects),tuple(exhausted),delivered,confirmed,attempt_late,missed_escalation,receipt_anchor,ack_due,ack_overdue,min(ticks) if ticks else None)


__all__=("DeliveryEffortProjection","project_delivery_effort")
