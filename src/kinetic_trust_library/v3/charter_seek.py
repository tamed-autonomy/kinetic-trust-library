"""Procedural charter seek/attendance over authenticated governance facts.

Sources authenticate bound lineages, complete current breach records and actual
publication/answer adequacy. These private projections neither bypass the zone
gate nor establish a filing, publication, breach append or governance mutation.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .charter_amendment import _inventory
from .execution_observation import _name
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True,init=False)
class CharterSeekAssessment:
    is_seek: bool
    route_open: bool
    eligible_count: int
    required_count: int
    council_route_remains: bool
    council_threshold_applied: bool
    breach_by_lineage: bool
    filing_anchor: str
    filed_at: int
    records_cited: tuple
    authority: str
    published_route: str
    dispute_route: str
    attend_deadline: int | None
    deadline_inclusive: bool
    gate_evaluation_required: bool
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("seek assessment requires authenticated rule/filing/record facts")


def assess_charter_seek(*,filing,rule_id,rule_version,bound_rules,records,required_records,window_seconds,attend_seconds,
        published_route,dispute_route,authority,window_start_inclusive,deadline_inclusive):
    bound=_inventory(bound_rules)
    if (not _name(rule_id) or not _time(rule_version) or rule_version==0
            or any(not _name(v) for v in (published_route,dispute_route,authority))
            or any(not _time(v) or v==0 for v in (required_records,window_seconds,attend_seconds))
            or type(window_start_inclusive) is not bool or type(deadline_inclusive) is not bool
            or type(records) is not tuple or len(records)>4096 or type(filing) is not dict
            or set(filing)!={"id","anchor","lineage","rule_id","rule_version","filed_at","records_cited"}
            or any(not _name(filing[k]) for k in ("id","anchor","lineage")) or not _time(filing["filed_at"])
            or filing["rule_id"]!=rule_id or type(filing["rule_version"]) is not int or filing["rule_version"]!=rule_version
            or not _time(filing["filed_at"]+attend_seconds)):
        raise ValidationError("explicit current rule, original filing and declared recurrence/route/time policy required")
    cited=_inventory(filing["records_cited"]);ids=set();anchors=set();eligible=set()
    start=filing["filed_at"]-window_seconds
    for r in records:
        if (type(r) is not dict or set(r)!={"id","anchor","rule_id","rule_version","occurred_at","status"}
                or any(not _name(r[k]) for k in ("id","anchor","rule_id")) or not _time(r["rule_version"]) or r["rule_version"]==0
                or not _time(r["occurred_at"]) or r["status"] not in ("current","withdrawn") or r["id"] in ids or r["anchor"] in anchors):
            raise ValidationError("complete distinct original breach record metadata required")
        ids.add(r["id"]);anchors.add(r["anchor"])
        inside=(r["occurred_at"]>=start if window_start_inclusive else r["occurred_at"]>start) and r["occurred_at"]<=filing["filed_at"]
        if (r["id"] in cited and r["rule_id"]==rule_id and r["rule_version"]==rule_version and r["status"]=="current" and inside):
            eligible.add(r["id"])
    is_seek=rule_id in bound and bool(cited)
    opened=is_seek and len(eligible)>=required_records
    result=object.__new__(CharterSeekAssessment)
    for k,v in dict(is_seek=is_seek,route_open=opened,eligible_count=len(eligible),required_count=required_records,
            council_route_remains=True,council_threshold_applied=False,breach_by_lineage=False,filing_anchor=filing["anchor"],
            filed_at=filing["filed_at"],records_cited=filing["records_cited"],authority=authority,published_route=published_route,
            dispute_route=dispute_route,attend_deadline=filing["filed_at"]+attend_seconds if opened else None,
            deadline_inclusive=deadline_inclusive,gate_evaluation_required=True,action_permitted=False).items():object.__setattr__(result,k,v)
    return result


@dataclass(frozen=True,slots=True,init=False)
class CharterAttendanceAssessment:
    attended: bool
    attended_late: bool
    authority_breach_required: bool
    notice_period_opened: bool
    refusal_contestable: bool
    contest_route: str | None
    response_anchor: str | None
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("attendance assessment requires actual published authority responses")


def assess_authority_attendance(seek,*,responses,evaluated_at):
    if (type(seek) is not CharterSeekAssessment or type(responses) is not tuple or len(responses)>4096
            or not _time(evaluated_at) or evaluated_at<seek.filed_at):
        raise ValidationError("original seek, complete authority responses and current time required")
    qualified=[];ids=set();anchors=set()
    for r in responses:
        if (type(r) is not dict or set(r)!={"id","authority","filing_anchor","kind","published_at","publication_anchor","record_answers"}
                or any(not _name(r[k]) for k in ("id","authority","filing_anchor","publication_anchor"))
                or r["id"] in ids or r["publication_anchor"] in anchors or r["authority"]!=seek.authority
                or r["filing_anchor"]!=seek.filing_anchor or r["kind"] not in ("open-notice","refusal")
                or not _time(r["published_at"]) or not seek.filed_at<=r["published_at"]<=evaluated_at
                or type(r["record_answers"]) is not tuple or len(r["record_answers"])>4096):
            raise ValidationError("authority response differs from actual filing/publication scope")
        ids.add(r["id"]);anchors.add(r["publication_anchor"]);answered=set()
        for answer in r["record_answers"]:
            if (type(answer) is not dict or set(answer)!={"record_id","answer_ref"} or any(not _name(v) for v in answer.values())
                    or answer["record_id"] in answered or answer["record_id"] not in seek.records_cited):
                raise ValidationError("refusal must refer to distinct actual filed records")
            answered.add(answer["record_id"])
        if r["kind"]=="open-notice" or answered==set(seek.records_cited):qualified.append(r)
    attended=late=breach=False;anchor=None
    # An inadequate refusal can fail the attendance duty and still be
    # contestable. A later notice does not erase an earlier refusal's record.
    contest=any(r["kind"]=="refusal" for r in responses)
    notice=any(r["kind"]=="open-notice" for r in responses)
    if seek.route_open:
        deadline=seek.attend_deadline
        timely=[r for r in qualified if r["published_at"]<deadline or seek.deadline_inclusive and r["published_at"]==deadline]
        attended=bool(timely);late=not attended and bool(qualified)
        overdue=evaluated_at>deadline if seek.deadline_inclusive else evaluated_at>=deadline
        breach=overdue and not attended
        selected=min(timely or qualified,key=lambda r:(r["published_at"],r["id"])) if timely or qualified else None
        if selected is not None:
            anchor=selected["publication_anchor"]
    result=object.__new__(CharterAttendanceAssessment)
    for k,v in dict(attended=attended,attended_late=late,authority_breach_required=breach,notice_period_opened=notice,
            refusal_contestable=contest,contest_route=seek.dispute_route if contest else None,response_anchor=anchor,action_permitted=False).items():
        object.__setattr__(result,k,v)
    return result
