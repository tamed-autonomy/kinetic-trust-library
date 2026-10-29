import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.hand_back_hysteresis import project_hysteresis


def profile():
    return dict(id="hysteresis:a",version=1,zone="zone-a",formula="capped-linear-adjudicated-hysteresis-v1",
        ledger_owner="authority:ledger",append_protocol="protocol:append",window_seconds=100,retention_seconds=200,
        revoker_repeat_threshold=2,classes={kind:dict(minimum_seconds=10,increment_seconds=10,cap_seconds=40)
            for kind in ("Logistics","Coordination","Relational")})


def event(index,subject="agent:a",variant="Exceeded",outcome="confirmed",occurred=950):
    return dict(id="event:"+str(index),stop_anchor="sha256:"+format(index,"064x"),sequence=index*10,subject=subject,
        consequence_class="Coordination",variant=variant,occurred_at=occurred,revoker="person:revoker" if variant=="Revoked" else None,
        causing_attestation_digest=None,
        adjudications=[] if outcome is None else [dict(record_id="adjudication:"+str(index),stop_anchor="sha256:"+format(index,"064x"),sequence=index*10+1,
                                                     decided_at=occurred+1,outcome=outcome)],
        false_attestation_finding=None,expungement=None)


class HysteresisTests(unittest.TestCase):
    def price(self,history,**kw):
        args=dict(subject="agent:a",consequence_class="Coordination",issued_at=1000,current_sequence=100,
                  as_of=1000,ledger_head_sequence=100)
        args.update(kw)
        return project_hysteresis(profile(),history,**args)

    def test_only_confirmed_prior_adversity_counts_and_cap_holds(self):
        history=[event(1),event(2,outcome=None),event(3,outcome="overturned"),event(4,variant="Expired",outcome=None)]
        result=self.price(history)
        self.assertEqual(result.prior_adverse_count,1)
        self.assertEqual(result.reissue_not_before,1020)
        self.assertEqual(result.expungement_required,("event:3",))
        self.assertEqual(self.price([event(i) for i in range(1,9)]).delay_seconds,40)

    def test_false_causing_attestation_is_excluded_and_requires_expungement(self):
        e=event(1);e["causing_attestation_digest"]="sha256:"+"a"*64
        e["false_attestation_finding"]=dict(record_id="finding:1",sequence=12,found_at=980,attestation_digest=e["causing_attestation_digest"])
        result=self.price([e])
        self.assertEqual(result.prior_adverse_count,0);self.assertEqual(result.expungement_required,(e["id"],))
        e["expungement"]=dict(record_id="expungement:1",stop_anchor=e["stop_anchor"],sequence=13,recorded_at=981,basis_record_id="finding:1")
        self.assertEqual(self.price([e]).expungement_required,())
        e["false_attestation_finding"]["attestation_digest"]="sha256:"+"b"*64
        with self.assertRaises(ValidationError):self.price([e])

    def test_revoker_history_is_zone_wide_and_never_subject_adversity(self):
        history=[event(1,"other:a","Revoked","overturned"),event(2,"other:b","Revoked","overturned")]
        result=self.price(history)
        self.assertEqual(result.prior_adverse_count,0)
        self.assertEqual(result.revoker_overturn_counts,(("person:revoker","Coordination",2),))
        self.assertEqual(result.revoker_accountability_required,(("person:revoker","Coordination"),))

    def test_same_tick_uses_audit_order_and_later_confirmation_cannot_reprice_history(self):
        e=event(1,occurred=1000);e["adjudications"][0]["decided_at"]=1000
        self.assertEqual(self.price([e]).prior_adverse_count,1)
        e["adjudications"][0]["sequence"]=101
        self.assertEqual(self.price([e],ledger_head_sequence=101).prior_adverse_count,0)

    def test_window_subject_expiry_and_bad_duplicate_inventory(self):
        self.assertEqual(self.price([event(1,occurred=899),event(2,"other"),event(3,variant="Expired",outcome="confirmed")]).prior_adverse_count,0)
        with self.assertRaises(ValidationError):self.price([event(1),event(1)])
        e=event(1);e["expungement"]=dict(record_id="exp:fake",stop_anchor=e["stop_anchor"],sequence=12,recorded_at=980,basis_record_id="unrelated")
        with self.assertRaises(ValidationError):self.price([e])

    def test_later_overturn_corrects_reissue_without_falsifying_original_price(self):
        e=event(1)
        e["adjudications"].append(dict(record_id="upheld:1",stop_anchor=e["stop_anchor"],sequence=105,decided_at=1005,outcome="overturned"))
        r=self.price([e],as_of=1010,ledger_head_sequence=110)
        self.assertEqual(r.original_reissue_not_before,1020)
        self.assertEqual(r.reissue_not_before,1010)
        self.assertEqual(r.expungement_required,(e["id"],))
