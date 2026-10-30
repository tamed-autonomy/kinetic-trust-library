"""Forward amendment checks over authenticated historical governance facts.

This private semantic record is not RFC wire or an adoption authority. Providers
authenticate cited evidence, full council membership and signatures, semantic
effect classifications, publication/deliberation and the original governor
decision. No previous evaluation or signed record is modified here.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest
from .native_envelope import project_comparable_envelope


PROTECTED_EFFECTS=frozenset(("change-recursive-constraint","change-minimum-governor-base","remove-amendment-process",
    "remove-dispute-process","remove-amendment-route","unpublish-amendment-route","change-declared-recurrence",
    "disable-declared-recurrence","override-veto","change-repair-invariants","remove-class-amendment-standing",
    "remove-class-refusal-contest-standing","remove-class-objection-standing"))


def _inventory(values):
    if (type(values) is not tuple or len(values)>4096 or any(not _name(v) for v in values)
            or len(set(values))!=len(values)):
        raise ValidationError("complete distinct immutable governance reference inventory required")
    return set(values)


@dataclass(frozen=True,slots=True,init=False)
class ForwardAmendmentAssessment:
    valid: bool
    void: bool
    reason: str
    rule_id: str
    version_for_evaluation: int | None
    ratification_closed_at: int
    reevaluate_inflight: bool
    retroactive_breach: bool
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("forward amendment selection requires authenticated historical evidence")


def assess_forward_amendment(record,*,evaluation_started_at,council_members,measurement_sources,
        expected_rule_id,expected_from_version,notice_minimum_seconds,ratification_minimum_seconds,
        approval_numerator,approval_denominator):
    """Check record floors and select a version without retrospective rewriting.

    Equal coarse timestamps supply no causal order: the result has no selected
    version until the caller establishes whether evaluation began before or
    after ratification. A recorded vote or governor permit label alone cannot
    override an immutable rule or a measured capacity veto.
    """
    members=_inventory(council_members);sources=_inventory(measurement_sources)
    if (not members or not _time(evaluation_started_at) or not _name(expected_rule_id)
            or not _time(notice_minimum_seconds) or notice_minimum_seconds<30*86400
            or not _time(ratification_minimum_seconds) or ratification_minimum_seconds<14*86400
            or not _time(approval_numerator) or not _time(approval_denominator) or approval_denominator==0
            or not 0<approval_numerator<=approval_denominator or approval_numerator*5<approval_denominator*4
            or not _time(expected_from_version) or expected_from_version==0 or type(record) is not dict
            or set(record)!={"id","rule_id","from_version","to_version","proposal_digest","records_cited","changes_constant",
                "measurements_cited","effects","notice_opened_at","notice_closed_at","voted_at","ratification_closed_at",
                "approvers","vote_anchor","governor_anchor","governor_decision","governor_demand","governor_capacity"}
            or any(not _name(record[k]) for k in ("id","rule_id","vote_anchor","governor_anchor"))
            or record["vote_anchor"]==record["governor_anchor"] or not is_digest(record["proposal_digest"])
            or record["rule_id"]!=expected_rule_id or record["from_version"]!=expected_from_version
            or not _time(record["from_version"]) or not _time(record["to_version"]) or record["to_version"]<=record["from_version"]
            or type(record["changes_constant"]) is not bool or type(record["measurements_cited"]) is not tuple
            or len(record["measurements_cited"])>4096 or record["governor_decision"] not in ("permit","deny")
            or any(not _time(record[k]) for k in ("notice_opened_at","notice_closed_at","voted_at","ratification_closed_at"))):
        raise ValidationError("complete original amendment and independently bound predecessor are required")
    cited=_inventory(record["records_cited"]);approvers=_inventory(record["approvers"]);effects=_inventory(record["effects"])
    if not effects or not effects<=PROTECTED_EFFECTS|{"ordinary-change"} or not approvers<=members:
        raise ValidationError("unknown classified effect or voter outside established council")
    measurement_ids=set();anchors=set();measurement_sources_valid=True
    for m in record["measurements_cited"]:
        if (type(m) is not dict or set(m)!={"id","source","anchor"} or any(not _name(v) for v in m.values())
                or m["id"] in measurement_ids or m["anchor"] in anchors):
            raise ValidationError("distinct original measurement references required")
        measurement_ids.add(m["id"]);anchors.add(m["anchor"])
        measurement_sources_valid=measurement_sources_valid and m["source"] in sources
    envelope=project_comparable_envelope(demand=record["governor_demand"],decision_capacity=record["governor_capacity"],capacity_known=True)
    void=bool(effects&PROTECTED_EFFECTS)
    clocks=(record["notice_closed_at"]-record["notice_opened_at"]>=notice_minimum_seconds
        and record["notice_closed_at"]<=record["voted_at"]
        and record["ratification_closed_at"]-record["voted_at"]>=ratification_minimum_seconds)
    valid=(not void and bool(cited) and measurement_sources_valid and (not record["changes_constant"] or bool(measurement_ids))
        and len(approvers)*approval_denominator>=len(members)*approval_numerator and clocks and record["governor_decision"]=="permit"
        and envelope.supervision!="silent_veto")
    version=record["from_version"]
    reason="AMENDMENT_VOID" if void else "AMENDMENT_INVALID"
    if valid:
        reason="AMENDMENT_FORWARD_VALID"
        if evaluation_started_at>record["ratification_closed_at"]:version=record["to_version"]
        elif evaluation_started_at==record["ratification_closed_at"]:version=None;reason="AMENDMENT_ORDER_UNRESOLVED"
    result=object.__new__(ForwardAmendmentAssessment)
    for k,v in dict(valid=valid,void=void,reason=reason,rule_id=record["rule_id"],version_for_evaluation=version,
            ratification_closed_at=record["ratification_closed_at"],reevaluate_inflight=False,retroactive_breach=False,action_permitted=False).items():
        object.__setattr__(result,k,v)
    return result
