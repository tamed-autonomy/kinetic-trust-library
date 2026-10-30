import unittest
from kinetic_trust_library.errors import ValidationError


def terms():
    return dict(retry_seconds=5,tolerance_seconds=1,escalation_seconds=10,escalation_cap=2)


def attempt(index,at,*,reachable=False,capacity="available",accepted=False):
    return dict(id="attempt:"+str(index),anchor="sha256:"+format(index,"064x"),sequence=index*10,attempted_at=at,
        message_digest="sha256:"+"f"*64,capacity_binding="capacity:declared",
        route_ref="route:primary",channel_reachable=reachable,capacity=capacity,capacity_observed_at=at,
        capacity_anchor="sha256:"+format(100+index,"064x"),
        receipt=None if not accepted else dict(anchor="sha256:"+format(200+index,"064x"),sequence=index*10+1,accepted_at=at,recorded_at=at))


class DeliveryEffortTests(unittest.TestCase):
    def project(self,attempts,*,now=1000,escalations=(),escrow=True,issued=1000,ack=None):
        from kinetic_trust_library.v3.delivery_effort import project_delivery_effort
        return project_delivery_effort(terms(),attempts,list(escalations),issued_at=issued,evaluated_at=now,
            ledger_head_sequence=100,escrow_present=escrow,capacity_freshness_seconds=2,ack_sla_seconds=30,
            hand_back_digest="sha256:"+"f"*64,capacity_binding="capacity:declared",acknowledged_at=ack)

    def test_unreachable_stop_parks_without_waiting_for_delivery(self):
        r=self.project([])
        self.assertEqual(r.delivery_state,"parked");self.assertTrue(r.attempt_due);self.assertFalse(r.action_permitted)
        self.assertTrue(r.effort_current)

    def test_missing_escrow_and_late_initial_attempt_are_obligations_not_construction_vetoes(self):
        r=self.project([],now=1003,escrow=False)
        self.assertTrue(r.escrow_required);self.assertFalse(r.effort_current);self.assertTrue(r.attempt_due)

    def test_capacity_exhaustion_and_unknown_capacity_never_count_as_delivery(self):
        for capacity in ("exhausted","unknown"):
            r=self.project([attempt(1,1000,reachable=True,capacity=capacity)])
            self.assertEqual(r.delivery_state,"parked");self.assertFalse(r.action_permitted)
        self.assertEqual(self.project([attempt(1,1000,reachable=True,capacity="exhausted")]).capacity_exhaustion_anchors,("sha256:"+format(1,"064x"),))

    def test_retries_and_escalation_are_declared_and_capped_not_authority(self):
        r=self.project([attempt(1,1000)],now=1025)
        self.assertTrue(r.attempt_due);self.assertEqual(r.escalation_due,(1,2));self.assertFalse(r.effort_current)
        self.assertFalse(r.action_permitted)

    def test_recorded_recovery_receipt_finishes_delivery_but_never_clears(self):
        r=self.project([attempt(1,1000),attempt(2,1005,reachable=True,accepted=True)],now=1005)
        self.assertEqual(r.delivery_state,"delivered");self.assertFalse(r.attempt_due);self.assertFalse(r.action_permitted)
        self.assertEqual(r.delivered_at,1005)

    def test_receipt_with_exhausted_or_stale_capacity_is_rejected(self):
        for capacity in ("exhausted","unknown"):
            with self.assertRaises(ValidationError):self.project([attempt(1,1000,reachable=True,capacity=capacity,accepted=True)])
        a=attempt(1,1000,reachable=True,accepted=True);a["capacity_observed_at"]=990
        with self.assertRaises(ValidationError):self.project([a])

    def test_late_attempt_does_not_erase_recording_debt(self):
        r=self.project([attempt(1,1000),attempt(2,1008)],now=1008)
        self.assertTrue(r.late_attempt_record_required);self.assertFalse(r.effort_current)

    def test_duplicate_attempt_or_unrecorded_escalation_cannot_fake_effort(self):
        with self.assertRaises(ValidationError):self.project([attempt(1,1000),attempt(1,1000)])

    def test_delayed_receipt_does_not_make_unaware_retry_a_duplicate(self):
        a=attempt(1,1000,reachable=True,accepted=True)
        a["receipt"].update(sequence=25,recorded_at=1006)
        r=self.project([a,attempt(2,1005)],now=1006)
        self.assertEqual(r.delivery_state,"delivered");self.assertFalse(r.schedule_defect_record_required)
        self.assertEqual(r.delivery_confirmed_at,1006)

    def test_work_missed_before_late_confirmation_is_not_erased(self):
        a=attempt(1,1000,reachable=True,accepted=True);a["receipt"].update(sequence=25,recorded_at=1013)
        r=self.project([a,attempt(2,1005)],now=1013)
        self.assertTrue(r.missed_attempt_record_required);self.assertEqual(r.missed_escalation_record_required,(1,))
        self.assertFalse(r.escalation_due);self.assertFalse(r.attempt_due)

    def test_foreign_message_or_capacity_binding_cannot_supply_delivery_effort(self):
        for change in (dict(message_digest="sha256:"+"e"*64),dict(capacity_binding="capacity:other")):
            a=attempt(1,1000);a.update(change)
            with self.subTest(change=change),self.assertRaises(ValidationError):self.project([a])

    def test_live_immediate_delivery_needs_no_parked_escrow_and_ack_has_its_declared_clock(self):
        a=attempt(1,1000,reachable=True,accepted=True)
        r=self.project([a],escrow=False);self.assertTrue(r.effort_current);self.assertFalse(r.escrow_required)
        self.assertEqual(r.next_change_at,1030)
        self.assertTrue(self.project([a],now=1030).acknowledgment_overdue)
        self.assertFalse(self.project([a],now=1005,ack=1004).acknowledgment_overdue)

    def test_recorded_escalation_satisfies_level_and_extra_levels_cannot_exceed_cap(self):
        records=[dict(anchor="sha256:"+"a"*64,sequence=40,level=1,occurred_at=1010,route_ref="route:backup",message_digest="sha256:"+"f"*64)]
        r=self.project([attempt(1,1000),attempt(2,1005),attempt(3,1010)],now=1010,escalations=records)
        self.assertFalse(r.escalation_due);self.assertTrue(r.effort_current)
        records[0]["level"]=3
        with self.assertRaises(ValidationError):self.project([attempt(1,1000)],now=1010,escalations=records)
