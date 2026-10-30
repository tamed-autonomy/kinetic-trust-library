from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785,json
    from tests.unit.core.test_v3_hand_back import fixture as hb_fixture
    from kinetic_trust_library.v3.mint_stop import InstalledMintStopVerifier,AuthenticatedMintStopContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    hb,hs,wire,op,_,now,stamp=hb_fixture()
    hs["lease"]=None;hs["reason"]=wire["reason"]="mint_refused"
    profile=dict(id="mint-monitor:a",version=1,zone="zone-a",formula="mint-refusal-and-silence-v1",
        hand_back_profile_digest=_digest(json.loads(hb.profile_bytes),"sha256"),
        authority="authority:a",response_sla_seconds=10,default_hand_back_endpoint="channel:default")
    state=dict(deployment_digest=_digest(json.loads(hb.deployment_profile_bytes),"sha256"),
        profile_digest=_digest(profile,"sha256"),operation_digest=hs["operation_digest"],
        subject=op["actor"],zone="zone-a",checked_at=now,expires_at=now+7,
        authority_declaration=dict(anchor="audit:authority-policy",profile_digest=_digest(profile,"sha256"),declared_at=now-100),
        request=dict(id="mint:1",anchor="audit:request",requested_at=now-5,
            principal=hs["delegator"],principal_channel="channel:requester",consequence_class="Coordination"),
        response=None,silence_record=None)
    records=dict(hand_back=None)
    class Source:
        def resolve(self,**kw):return AuthenticatedMintStopContext(rfc8785.dumps(state),records["hand_back"],b"modeled complete authority request/response history")
    v=InstalledMintStopVerifier(hb,rfc8785.dumps(profile),Source())
    return dict(v=v,s=state,hs=hs,w=wire,op=op,now=now,records=records)


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class MintStopTests(unittest.TestCase):
    def evaluate(self,f):
        return f["v"].evaluate(actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)

    def refuse(self,f):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        f["s"]["response"]=dict(kind="Refused",authority="authority:a",request_id="mint:1",
            anchor="audit:reply",responded_at=f["now"],hand_back_digest=_digest(f["w"],"sha256"))
        f["records"]["hand_back"]=rfc8785.dumps(f["w"])

    def test_pending_before_deadline_grants_nothing_and_expires_at_deadline(self):
        f=fixture();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertEqual(r.status,"pending")
        self.assertFalse(r.action_permitted);self.assertFalse(r.silence_record_required)
        self.assertEqual(r.expires_at,f["now"]+5)

    def test_silence_is_attributed_to_authority_and_routed_at_deadline(self):
        f=fixture();f["s"]["request"]["requested_at"]=f["now"]-10
        r=self.evaluate(f)
        self.assertTrue(r.silence_record_required);self.assertTrue(r.routing_required)
        self.assertEqual(r.attributed_to,"authority:a");self.assertEqual(r.route,"channel:requester")
        f["s"]["request"]["principal_channel"]=None
        self.assertEqual(self.evaluate(f).route,"channel:default")

    def test_late_refusal_retains_silence_debt_and_validated_hand_back(self):
        f=fixture();f["s"]["request"]["requested_at"]=f["now"]-11;self.refuse(f)
        r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertEqual(r.status,"Refused");self.assertTrue(r.hand_back.valid)
        self.assertTrue(r.silence_record_required);self.assertFalse(r.action_permitted)

    def test_recorded_silence_requires_exact_authority_request_time_and_route(self):
        f=fixture();f["s"]["request"]["requested_at"]=f["now"]-11
        record=dict(anchor="audit:silence",authority="authority:a",request_id="mint:1",
            occurred_at=f["now"],route="channel:requester",route_receipt=None)
        f["s"]["silence_record"]=record
        self.assertFalse(self.evaluate(f).silence_record_required)
        self.assertTrue(self.evaluate(f).routing_required)
        record["route_receipt"]=dict(anchor="audit:routed",accepted_at=f["now"],endpoint="channel:requester",
            record_anchor="audit:silence",request_id="mint:1")
        self.assertFalse(self.evaluate(f).routing_required)
        for key,value in (("authority","agent:a"),("request_id","another"),("occurred_at",f["now"]-2),("route","other")):
            f["s"]["silence_record"]=dict(record,**{key:value})
            with self.subTest(key=key):self.assertFalse(self.evaluate(f).valid)

    def test_route_receipt_cannot_replace_record_or_name_a_different_endpoint(self):
        f=fixture();f["s"]["request"]["requested_at"]=f["now"]-11
        f["s"]["silence_record"]=dict(anchor="audit:silence",authority="authority:a",request_id="mint:1",
            occurred_at=f["now"],route="channel:requester",route_receipt=dict(anchor="audit:routed",
                accepted_at=f["now"],endpoint="channel:another",record_anchor="audit:silence",request_id="mint:1"))
        self.assertFalse(self.evaluate(f).valid)

    def test_authority_cannot_install_a_new_sla_after_receiving_the_request(self):
        f=fixture();f["s"]["authority_declaration"]["declared_at"]=f["now"]
        self.assertFalse(self.evaluate(f).valid)

    def test_routing_receipt_is_bound_to_this_event_and_request(self):
        f=fixture();f["s"]["request"]["requested_at"]=f["now"]-11
        receipt=dict(anchor="audit:routed",accepted_at=f["now"],endpoint="channel:requester",
            record_anchor="audit:another-silence",request_id="mint:1")
        f["s"]["silence_record"]=dict(anchor="audit:silence",authority="authority:a",request_id="mint:1",
            occurred_at=f["now"],route="channel:requester",route_receipt=receipt)
        self.assertFalse(self.evaluate(f).valid)

    def test_child_source_errors_are_not_relabelled_as_wire_failure(self):
        from kinetic_trust_library.errors import ValidationError
        f=fixture();self.refuse(f)
        class Broken:
            def resolve(self,**kw):raise ValidationError("hand-back Source failed")
        f["v"]=replace(f["v"],hand_back_verifier=replace(f["v"].hand_back_verifier,context_source=Broken()))
        with self.assertRaisesRegex(ValidationError,"hand-back Source failed"):self.evaluate(f)

    def test_refusal_cannot_omit_or_rebind_hand_back(self):
        for change in (lambda f:f["records"].update(hand_back=None),
                       lambda f:f["s"]["response"].update(authority="agent:a"),
                       lambda f:f["s"]["response"].update(responded_at=f["now"]-1),
                       lambda f:f["hs"].update(delegator="person:other")):
            f=fixture();self.refuse(f);change(f)
            with self.subTest(change=change):self.assertFalse(self.evaluate(f).valid)

    def test_source_errors_propagate_and_minted_is_explicitly_unsupported(self):
        from kinetic_trust_library.errors import ValidationError
        f=fixture();f["s"]["response"]=dict(kind="Minted")
        self.assertEqual(self.evaluate(f).reason,"MINT_SUCCESS_REQUIRES_CLEARANCE")
        class Broken:
            def resolve(self,**kw):raise ValidationError("authority Source failed")
        f["v"]=replace(f["v"],context_source=Broken())
        with self.assertRaisesRegex(ValidationError,"Source failed"):self.evaluate(f)
