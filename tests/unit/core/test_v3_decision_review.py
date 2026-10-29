import unittest
from kinetic_trust_library.errors import ValidationError


def profile():
    return dict(id="production-review:1",version=1,zone="zone-a",formula="uniform-draw-and-outcome-review-v1",
        ledger_owner="authority:review-ledger",append_protocol="append:review",sampler_id="sampler:external",
        review_authority="person:reviewer",sampling_rate=dict(numerator=1,denominator=2),outcome_triggers=["harm"],
        window_seconds=100,review_sla_seconds=10,uniform_approval_threshold=2)


def event(index=1,*,draw=0,choice="approve",same_time=False,actor="agent:a"):
    anchor="sha256:"+format(index,"064x")
    return dict(id="production:"+str(index),anchor=anchor,sequence=index*10,decided_by="person:decider",actor=actor,
        decided_at=952+index,choice=choice,acknowledged_at=950+index,reviewed_at=950+index+(not same_time),review_kind="review",
        sample=dict(anchor="sha256:"+format(100+index,"064x"),sequence=index*10+1,sampler_id="sampler:external",draw=draw,space=2,drawn_at=953+index),
        outcomes=[],reviews=[dict(anchor="sha256:"+format(200+index,"064x"),sequence=index*10+2,decision_anchor=anchor,
            reviewer="person:reviewer",kind="review",completed_at=958+index,outcome_refs=[])])


class DecisionReviewTests(unittest.TestCase):
    def project(self,events,**changes):
        from kinetic_trust_library.v3.decision_review import project_decision_review
        return project_decision_review(profile(),events,decided_by="person:decider",evaluated_at=1000,ledger_head_sequence=100,**changes)

    def test_declared_sampling_rate_is_applied_to_actual_draws(self):
        a=event();b=event(2,draw=1);b["reviews"]=[]
        r=self.project([a,b]);self.assertEqual(r.sampled_decisions,(a["anchor"],));self.assertTrue(r.review_current)

    def test_uniform_approval_and_indistinguishable_review_at_threshold_is_finding(self):
        a=event(same_time=True);b=event(2,same_time=True,actor="agent:another-subject")
        r=self.project([a,b]);self.assertTrue(r.rubber_stamp_finding);self.assertFalse(r.review_current)
        b["choice"]="refuse";self.assertFalse(self.project([a,b]).rubber_stamp_finding)
        b["choice"]="approve";b["reviewed_at"]+=1;self.assertFalse(self.project([a,b]).rubber_stamp_finding)

    def test_staged_endogenous_refusal_is_not_production_review(self):
        a=event();a["reviews"]=[]
        r=self.project([a]);self.assertFalse(r.review_current);self.assertTrue(r.overdue_reviews)

    def test_outcome_trigger_requires_review_even_when_not_sampled(self):
        a=event(draw=1);a["reviews"]=[]
        a["outcomes"]=[dict(anchor="sha256:"+"a"*64,sequence=15,kind="harm",observed_at=980)]
        r=self.project([a]);self.assertEqual(r.sampled_decisions,());self.assertTrue(r.overdue_reviews)
        a["reviews"]=[dict(anchor="sha256:"+"b"*64,sequence=16,decision_anchor=a["anchor"],reviewer="person:reviewer",
            kind="review",completed_at=985,outcome_refs=[a["outcomes"][0]["anchor"]])]
        self.assertTrue(self.project([a]).review_current)

    def test_review_before_outcome_or_without_its_reference_does_not_discharge_it(self):
        a=event(draw=1);a["outcomes"]=[dict(anchor="sha256:"+"a"*64,sequence=15,kind="harm",observed_at=980)]
        self.assertTrue(self.project([a]).overdue_reviews)

    def test_acknowledgment_is_not_exogenous_review(self):
        a=event();a["reviews"][0]["kind"]="acknowledgment"
        self.assertFalse(self.project([a]).review_current)

    def test_pending_deadline_bounds_validity_and_late_completion_retains_failure_obligation(self):
        a=event();a["sample"]["drawn_at"]=995;a["reviews"]=[]
        r=self.project([a]);self.assertTrue(r.review_current);self.assertEqual(r.next_change_at,1005)
        a["sample"]["drawn_at"]=954
        a["reviews"]=[dict(anchor="sha256:"+"b"*64,sequence=18,decision_anchor=a["anchor"],reviewer="person:reviewer",
            kind="review",completed_at=980,outcome_refs=[])]
        r=self.project([a]);self.assertTrue(r.review_current);self.assertTrue(r.late_review_record_required)

    def test_decider_cannot_supply_own_exogenous_review(self):
        a=event();a["reviews"][0]["reviewer"]="person:decider"
        self.assertFalse(self.project([a]).review_current)

    def test_duplicate_decision_or_draw_anchor_and_out_of_range_draw_rejected(self):
        for events in ([event(),event()], [event(),dict(event(2),sample=event()["sample"])]):
            with self.assertRaises(ValidationError):self.project(events)
        a=event();a["sample"]["draw"]=2
        with self.assertRaises(ValidationError):self.project([a])

    def test_unknown_outcomes_do_not_invent_triggers_and_old_decisions_can_have_current_outcomes(self):
        a=event(draw=1);a["decided_at"]=802;a["acknowledged_at"]=800;a["reviewed_at"]=801
        a["sample"]["drawn_at"]=802;a["outcomes"]=[dict(anchor="sha256:"+"a"*64,sequence=15,kind="informational",observed_at=990)]
        self.assertTrue(self.project([a]).review_current)
        a["outcomes"][0]["kind"]="harm"
        self.assertFalse(self.project([a]).review_current)

    def test_fractional_review_deadlines_are_not_rounded_into_permission(self):
        a=event();a["sample"]["drawn_at"]="1970-01-01T00:16:35.5Z";a["reviews"]=[]
        self.assertEqual(self.project([a]).next_change_at,1006)

    def test_exact_probability_is_not_a_float_or_boolean_shortcut(self):
        from kinetic_trust_library.v3.decision_review import project_decision_review
        p=profile();p["sampling_rate"]=dict(numerator=1,denominator=10)
        a=event(draw=1);a["sample"]["space"]=10;a["reviews"]=[]
        self.assertEqual(project_decision_review(p,[a],decided_by="person:decider",evaluated_at=1000,ledger_head_sequence=100).sampled_decisions,())
        a["sample"]["draw"]=True
        with self.assertRaises(ValidationError):project_decision_review(p,[a],decided_by="person:decider",evaluated_at=1000,ledger_head_sequence=100)

    def test_historical_rate_trigger_and_deadline_are_not_replaced_by_current_policy(self):
        from copy import deepcopy
        from kinetic_trust_library.v3.decision_review import project_decision_review
        current=profile();old=deepcopy(current);old.update(version=2,review_sla_seconds=30,outcome_triggers=["harm","legacy-harm"])
        old["sampling_rate"]=dict(numerator=2,denominator=2)
        a=event(draw=1);a["reviews"]=[];a["sample"]["drawn_at"]=980
        kw=dict(decided_by="person:decider",evaluated_at=1000,ledger_head_sequence=100)
        r=project_decision_review(current,[a],event_profiles={a["anchor"]:old},**kw)
        self.assertEqual(r.sampled_decisions,(a["anchor"],));self.assertEqual(r.next_change_at,1010)
        self.assertTrue(r.review_current)
        old["sampling_rate"]["numerator"]=1
        a["outcomes"]=[dict(anchor="sha256:"+"a"*64,sequence=15,kind="legacy-harm",observed_at=960)]
        r=project_decision_review(current,[a],event_profiles={a["anchor"]:old},**kw)
        self.assertFalse(r.review_current);self.assertEqual(r.overdue_reviews[0][2],990)

    def test_sampling_policy_change_does_not_split_decider_population(self):
        from kinetic_trust_library.v3.decision_review import project_decision_review
        current=profile();old=dict(current,version=2)
        a=event(same_time=True);b=event(2,same_time=True)
        r=project_decision_review(current,[a,b],event_profiles={a["anchor"]:old,b["anchor"]:current},
            decided_by="person:decider",evaluated_at=1000,ledger_head_sequence=100)
        self.assertTrue(r.rubber_stamp_finding)
