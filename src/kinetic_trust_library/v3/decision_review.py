"""Selected exogenous decision-review projection over authenticated history.

The reference draw is uniform over the declared denominator; Source authenticates
the real sampler/first draw and complete zone-wide decider history, outcomes and
review records, including older outstanding obligations. This projection cannot
establish stochastic provenance, review quality or actual record persistence.
It does not supply a Full claim, a standing sanction or permission to execute.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .hand_back_hysteresis import _at


def profile_terms(p):
    if (type(p) is not dict or set(p)!={"id","version","zone","formula","ledger_owner","append_protocol","sampler_id","review_authority",
            "sampling_rate","outcome_triggers","window_seconds","review_sla_seconds","uniform_approval_threshold"}
            or any(not _name(p[k]) for k in ("id","zone","ledger_owner","append_protocol","sampler_id","review_authority"))
            or not _time(p["version"]) or p["version"]==0 or p["formula"]!="uniform-draw-and-outcome-review-v1"
            or any(not _time(p[k]) or p[k]==0 for k in ("window_seconds","review_sla_seconds","uniform_approval_threshold"))
            or p["uniform_approval_threshold"]<2 or type(p["outcome_triggers"]) is not list or not p["outcome_triggers"]
            or any(not _name(x) for x in p["outcome_triggers"]) or len(set(p["outcome_triggers"]))!=len(p["outcome_triggers"])):
        raise ValidationError("complete declared production review policy required")
    rate=p["sampling_rate"]
    if (type(rate) is not dict or set(rate)!={"numerator","denominator"} or not _time(rate["numerator"])
            or not _time(rate["denominator"]) or not 0<rate["numerator"]<=rate["denominator"]):
        raise ValidationError("production sampling requires an exact positive declared probability")
    return p


@dataclass(frozen=True,slots=True)
class DecisionReviewProjection:
    review_current: bool
    sampled_decisions: tuple
    required_reviews: tuple
    overdue_reviews: tuple
    pending_reviews: tuple
    late_review_record_required: tuple
    rubber_stamp_finding: bool
    finding_decisions: tuple
    next_change_at: int | None


def project_decision_review(profile,events,*,decided_by,evaluated_at,ledger_head_sequence,event_profiles=None):
    """Apply exact draws, independent reviews, trigger clocks and HB-10-003.

    The threshold counts all sampled decisions of this decider in the rolling
    window, across actors, not staged certification cases. Uniform approval with
    exact indistinguishable acknowledgment/review times at threshold is a finding.
    Event profiles preserve historically governing draws/triggers/reviewer/SLA.
    The current profile governs only the current rolling finding population.
    Missing review and late completion remain separate recording obligations.
    """
    p=profile_terms(profile)
    if (not _name(decided_by) or decided_by==p["review_authority"] or type(events) is not list or len(events)>4096
            or not _time(evaluated_at) or not _time(ledger_head_sequence)
            or event_profiles is not None and type(event_profiles) is not dict):
        raise ValidationError("complete current decider review history required")
    anchors=set();positions=set();ids=set();decision_anchors=set();sampled=[];required=[];overdue=[];pending=[];late=[];ticks=[]
    def position(anchor,sequence):
        if (not is_digest(anchor) or anchor in anchors or not _time(sequence) or not 0<sequence<=ledger_head_sequence or sequence in positions):
            raise ValidationError("production review records require distinct actual anchors and audit positions")
        anchors.add(anchor);positions.add(sequence)
    def instant(value):
        at=_at(value)
        if at>evaluated_at:raise ValidationError("production review history cannot contain future events")
        return at
    window_start=max(0,evaluated_at-p["window_seconds"])
    for event in events:
        if (type(event) is not dict or set(event)!={"id","anchor","sequence","decided_by","actor","decided_at","choice",
                "acknowledged_at","reviewed_at","review_kind","sample","outcomes","reviews"}
                or not _name(event["id"]) or event["id"] in ids or event["decided_by"]!=decided_by or not _name(event["actor"])
                or event["choice"] not in ("approve","refuse") or event["review_kind"] not in ("review","acknowledgment")
                or type(event["outcomes"]) is not list or len(event["outcomes"])>4096 or type(event["reviews"]) is not list or len(event["reviews"])>4096):
            raise ValidationError("actual complete production decision/outcome/review records required")
        ids.add(event["id"]);position(event["anchor"],event["sequence"])
        decision_anchors.add(event["anchor"])
        q=p if event_profiles is None else profile_terms(event_profiles.get(event["anchor"]))
        if (any(q[k]!=p[k] for k in ("zone","ledger_owner","append_protocol")) or q["review_authority"]==decided_by):
            raise ValidationError("historical review policy differs from actual zone/ledger or independent review role")
        decided=instant(event["decided_at"]);ack=instant(event["acknowledged_at"])
        reviewed=None if event["reviewed_at"] is None else instant(event["reviewed_at"])
        if ack>decided or reviewed is not None and not ack<=reviewed<=decided:
            raise ValidationError("production decision acknowledgment/review chronology differs")
        sample=event["sample"]
        if (type(sample) is not dict or set(sample)!={"anchor","sequence","sampler_id","draw","space","drawn_at"}
                or sample["sampler_id"]!=q["sampler_id"] or not _time(sample["draw"]) or not _time(sample["space"])
                or sample["space"]!=q["sampling_rate"]["denominator"] or not 0<=sample["draw"]<sample["space"]):
            raise ValidationError("actual first uniform draw in the declared sampling space required")
        position(sample["anchor"],sample["sequence"]);drawn=instant(sample["drawn_at"])
        if sample["sequence"]<=event["sequence"] or drawn<decided:raise ValidationError("sampling must bind the actual production decision")
        needs=[]
        if sample["draw"]<q["sampling_rate"]["numerator"]:
            needs.append((sample["anchor"],sample["sequence"],drawn))
            if decided>=window_start:
                sampled.append((event["anchor"],event["choice"]=="approve" and reviewed is not None and reviewed==ack))
                ticks.append(int(decided+p["window_seconds"])+1)
        outcome_refs={}
        for outcome in event["outcomes"]:
            if type(outcome) is not dict or set(outcome)!={"anchor","sequence","kind","observed_at"} or not _name(outcome["kind"]):
                raise ValidationError("actual observed outcome record required")
            position(outcome["anchor"],outcome["sequence"]);observed=instant(outcome["observed_at"])
            if outcome["sequence"]<=event["sequence"] or observed<decided:raise ValidationError("outcome precedes its actual decision")
            outcome_refs[outcome["anchor"]]=(outcome["sequence"],observed)
            if outcome["kind"] in q["outcome_triggers"]:needs.append((outcome["anchor"],outcome["sequence"],observed))
        reviews=[]
        for review in event["reviews"]:
            if (type(review) is not dict or set(review)!={"anchor","sequence","decision_anchor","reviewer","kind","completed_at","outcome_refs"}
                    or review["decision_anchor"]!=event["anchor"] or not _name(review["reviewer"])
                    or review["kind"] not in ("review","acknowledgment") or type(review["outcome_refs"]) is not list
                    or any(not is_digest(x) for x in review["outcome_refs"]) or len(set(review["outcome_refs"]))!=len(review["outcome_refs"])):
                raise ValidationError("actual independent exogenous review record required")
            position(review["anchor"],review["sequence"]);completed=instant(review["completed_at"])
            if (review["sequence"]<=event["sequence"] or completed<decided or not set(review["outcome_refs"])<=set(outcome_refs)
                    or any(outcome_refs[a][0]>=review["sequence"] or outcome_refs[a][1]>completed for a in review["outcome_refs"])):
                raise ValidationError("review cannot cover missing or future outcomes")
            if review["kind"]=="review" and review["reviewer"]==q["review_authority"] and review["reviewer"]!=event["actor"]:
                reviews.append((review,completed))
        for cause,sequence,occurred in needs:
            deadline=occurred+q["review_sla_seconds"];item=(event["anchor"],cause,deadline)
            required.append(item)
            matches=[(review,completed) for review,completed in reviews if completed>=occurred and review["sequence"]>sequence
                     and (cause==sample["anchor"] or cause in review["outcome_refs"])]
            if matches:
                if min(completed for _,completed in matches)>deadline:late.append(item)
            elif evaluated_at>=deadline:overdue.append(item)
            else:
                pending.append(item);ticks.append((deadline.numerator+deadline.denominator-1)//deadline.denominator)
    if event_profiles is not None and set(event_profiles)!=decision_anchors:
        raise ValidationError("complete exact historical policy mapping required")
    finding=len(sampled)>=p["uniform_approval_threshold"] and all(stamp for _,stamp in sampled)
    return DecisionReviewProjection(not overdue and not finding,tuple(sorted(a for a,_ in sampled)),tuple(sorted(required)),tuple(sorted(overdue)),
        tuple(sorted(pending)),tuple(sorted(late)),finding,tuple(sorted(a for a,_ in sampled)) if finding else (),min(ticks) if ticks else None)


__all__=("DecisionReviewProjection","profile_terms","project_decision_review")
