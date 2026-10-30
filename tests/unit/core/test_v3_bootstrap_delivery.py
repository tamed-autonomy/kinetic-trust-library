from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture():
    import json,rfc8785
    from tests.unit.core.test_v3_installed_delivery import fixture as delivery_fixture
    from tests.unit.core.test_v3_bootstrap_hand_back import fixture as bootstrap_fixture
    from kinetic_trust_library.v3.demand_supplier import _digest
    dv,s,_,_,_,now=delivery_fixture();b=bootstrap_fixture();p=json.loads(dv.profile_bytes)
    p.update(formula="anchored-retry-and-escalation-v2",hand_back_profile_digest=_digest(b["p"],"sha256"))
    s["profile_digest"]=s["declaration"]["profile_digest"]=_digest(p,"sha256")
    s["hand_back_digest"]=s["escrow"]["hand_back_digest"]=_digest(b["w"],"sha256")
    s["escrow"]["ciphertext_digest"]=b["w"]["context"]["ciphertext_digest"]
    s["declaration"].update(origin_kind="mint-request",template_digest=None,lease_id=None,request_id="mint:1",request_anchor="audit:mint-request")
    v=replace(dv,hand_back_verifier=b["v"],profile_bytes=rfc8785.dumps(p))
    return v,s,b,p


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class BootstrapDeliveryTests(unittest.TestCase):
    def evaluate(self,args):
        import rfc8785
        v,_,b,_=args
        return v.evaluate(rfc8785.dumps(b["w"]),request_id="mint:1",request_anchor="audit:mint-request",
            actual_operation=b["op"],evaluated_at=b["now"],clock_healthy=True)

    def test_missing_template_refusal_retries_without_inventing_a_lease(self):
        args=fixture();r=self.evaluate(args)
        self.assertTrue(r.hand_back.valid);self.assertTrue(r.projection.attempt_due)
        self.assertFalse(r.action_permitted);self.assertFalse(r.hand_back.clearance_capable)

    def test_current_receipt_advances_without_rewriting_original_bootstrap(self):
        from tests.unit.core.test_v3_installed_delivery import add_attempt
        args=fixture();v,s,b,_=args
        add_attempt((v,s,b["s"],b["w"],b["op"],b["now"]),accepted=True)
        r=self.evaluate(args)
        self.assertEqual(r.hand_back.delivery_state,"parked");self.assertEqual(r.projection.delivery_state,"delivered")
        self.assertFalse(r.action_permitted)

    def test_wrong_request_origin_or_stop_time_route_is_rejected(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["declaration"].update(request_id="another:mint"),
                       lambda s:s["declaration"].update(lease_id="fabricated:lease"),
                       lambda s:s["declaration"].update(declared_at=s["checked_at"]),
                       lambda s:s["declaration"]["routes"][0].update(principal="person:other")):
            args=fixture();change(args[1])
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(args)

    def test_registered_refusal_without_lease_binds_delivery_to_original_template(self):
        import json,rfc8785
        from tests.unit.core.test_v3_installed_delivery import fixture as delivery_fixture
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.errors import ValidationError
        dv,s,hs,w,op,now=delivery_fixture();hs["lease"]=None;w["reason"]=hs["reason"]="mint_refused"
        with self.assertRaisesRegex(ValidationError,"v2"):
            dv.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True)
        p=json.loads(dv.profile_bytes);p["formula"]="anchored-retry-and-escalation-v2"
        s["profile_digest"]=s["declaration"]["profile_digest"]=_digest(p,"sha256")
        s["hand_back_digest"]=s["escrow"]["hand_back_digest"]=_digest(w,"sha256")
        s["declaration"].update(origin_kind="template-registration",lease_id=None,request_id=None,request_anchor=None,declared_at=now-110)
        s["capacity_binding"]["declared_at"]=now-100
        for route in s["declaration"]["routes"]:route["registered_at"]=now-100
        dv=replace(dv,profile_bytes=rfc8785.dumps(p))
        r=dv.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True)
        self.assertTrue(r.hand_back.valid);self.assertTrue(r.projection.attempt_due);self.assertFalse(r.action_permitted)
        s["declaration"]["origin_kind"]="lease-grant"
        with self.assertRaises(ValidationError):dv.evaluate(rfc8785.dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_bootstrap_cannot_be_silently_accepted_by_grant_only_delivery_profile(self):
        import rfc8785
        from kinetic_trust_library.errors import ValidationError
        v,_,_,p=fixture();p["formula"]="anchored-retry-and-escalation-v1"
        with self.assertRaisesRegex(ValidationError,"v2"):
            replace(v,profile_bytes=rfc8785.dumps(p))
