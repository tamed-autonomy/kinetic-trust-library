from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785,json
    from tests.unit.core.test_v3_hand_back import fixture as hand_back_fixture
    from tests.unit.core.test_v3_hand_back_hysteresis import profile,event
    from kinetic_trust_library.v3.installed_hysteresis import InstalledHandBackHysteresisVerifier,AuthenticatedHysteresisContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    hb,hs,w,op,_,now,stamp=hand_back_fixture();p=profile()
    e=event(1,op["actor"],occurred=now-50);e["adjudications"][0]["decided_at"]=now-49
    current=event(10,op["actor"],outcome=None,occurred=now);current.update(id="stop:current",stop_anchor="sha256:"+"e"*64)
    state=dict(deployment_digest=_digest(json.loads(hb.deployment_profile_bytes),"sha256"),profile_digest=_digest(p,"sha256"),
        operation_digest=digest_demand_operation(op,algorithm="sha256"),checked_at=now,expires_at=now+7,zone=p["zone"],
        subject=op["actor"],ledger_owner=p["ledger_owner"],append_protocol=p["append_protocol"],retained_since=now-200,
        ledger_head=dict(anchor="sha256:"+"f"*64,sequence=100),
        pricing_stop=dict(id="stop:current",stop_anchor="sha256:"+"e"*64,subject=op["actor"],operation_digest=digest_demand_operation(op,algorithm="sha256"),
            consequence_class="Coordination",issued_at=w["issued_at"],sequence=100,hysteresis_profile_digest=_digest(p,"sha256")),history=[e,current])
    class Source:
        def resolve(self,**kw):return AuthenticatedHysteresisContext(rfc8785.dumps(state),b"modeled complete actual audit/head/order/adjudication/finding/expungement inventory")
    verifier=InstalledHandBackHysteresisVerifier(hb.deployment_profile_bytes,rfc8785.dumps(p),Source(),"sha256")
    return verifier,state,hb,hs,w,op,now,stamp


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class InstalledHysteresisTests(unittest.TestCase):
    def evaluate(self,v,op,now):return v.evaluate(actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_complete_current_scope_and_derived_price(self):
        v,s,hb,hs,w,op,now,_=fixture();r=self.evaluate(v,op,now)
        self.assertEqual(r.projection.reissue_not_before,now+20)
        self.assertEqual(r.projection.prior_adverse_count,1)
        self.assertEqual(r.stop_anchor,s["pricing_stop"]["stop_anchor"])
        self.assertTrue(r.source_evidence_bytes)
        with self.assertRaises(TypeError):type(r)()

    def test_head_owner_retention_and_actual_priced_stop_scope(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s.update(ledger_owner="other"),lambda s:s.update(retained_since=s["checked_at"]-10),
                       lambda s:s["pricing_stop"].update(subject="other"),lambda s:s["pricing_stop"].update(operation_digest="sha256:"+"0"*64),
                       lambda s:s["ledger_head"].update(sequence=50),lambda s:s["history"].pop()):
            v,s,hb,hs,w,op,now,_=fixture();change(s)
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(v,op,now)

    def test_selected_hand_back_bound_must_equal_declared_adjudicated_price(self):
        import rfc8785,json
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,hb,hs,w,op,now,stamp=fixture();p=json.loads(hb.profile_bytes)
        p["hysteresis_profile_digest"]=_digest(json.loads(v.profile_bytes),"sha256")
        hb=replace(hb,profile_bytes=rfc8785.dumps(p),hysteresis_verifier=v)
        hs["profile_digest"]=_digest(p,"sha256");hs["stop_anchor"]=s["pricing_stop"]["stop_anchor"]
        self.assertFalse(hb.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True).valid)
        w["reissue_not_before"]=hs["reissue_not_before"]=stamp(now+20)
        r=hb.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True)
        self.assertTrue(r.valid);self.assertEqual(r.hysteresis.projection.prior_adverse_count,1)
        hs["stop_anchor"]="sha256:"+"0"*64
        self.assertFalse(hb.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True).valid)

    def test_historical_hand_back_survives_its_later_expungement_as_evidence_only(self):
        import rfc8785,json
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,hb,hs,w,op,now,stamp=fixture();p=json.loads(hb.profile_bytes)
        p["hysteresis_profile_digest"]=_digest(json.loads(v.profile_bytes),"sha256")
        hb=replace(hb,profile_bytes=rfc8785.dumps(p),hysteresis_verifier=v)
        hs.update(profile_digest=_digest(p,"sha256"),stop_anchor=s["pricing_stop"]["stop_anchor"],checked_at=now+3)
        w["reissue_not_before"]=hs["reissue_not_before"]=stamp(now+20)
        current=s["history"][-1]
        current["adjudications"]=[dict(record_id="confirm:current",stop_anchor=current["stop_anchor"],sequence=101,decided_at=now+1,outcome="confirmed"),
                                   dict(record_id="upheld:current",stop_anchor=current["stop_anchor"],sequence=102,decided_at=now+2,outcome="overturned")]
        s["ledger_head"]["sequence"]=102;s["checked_at"]=now+3
        r=hb.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now+3,clock_healthy=True)
        self.assertTrue(r.valid);self.assertFalse(r.action_permitted)
        self.assertTrue(r.hysteresis.projection.priced_stop_expunged)
