from importlib.util import find_spec
from dataclasses import replace
import unittest


def fixture(hand_back_fixture=None):
    import json,rfc8785
    from tests.unit.core.test_v3_hand_back import fixture as hb_fixture
    from kinetic_trust_library.v3.installed_management import InstalledManagementVerifier,AuthenticatedManagementContext,HistoricalDemotionHandBack
    from kinetic_trust_library.v3.demand_supplier import _digest
    hb,hs,wire,op,_,now,_=(hand_back_fixture or hb_fixture)()
    hs["reason"]=wire["reason"]="demotion"
    profile=dict(id="membership:a",version=1,zone="zone-a",formula="attested-management-history-v1",
        hand_back_profile_digest=_digest(json.loads(hb.profile_bytes),"sha256"),registry="registry:membership",
        append_protocol="audit:append",hostile_facing=False,wire_silence=False,admission_endpoint="channel:admission",
        surface="surface:a",timing_uniformity_limit="Service scheduler; no constant-time guarantee")
    state=dict(deployment_digest=_digest(json.loads(hb.deployment_profile_bytes),"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=hs["operation_digest"],subject=op["actor"],zone="zone-a",checked_at=now,expires_at=now+7,
        registry=profile["registry"],append_protocol=profile["append_protocol"],credential_digest=None,surface="surface:a",
        request_kind="action",regime="unmanaged",history=[],event_count=0,ledger_head=dict(anchor="audit:head",sequence=5))
    records=[]
    class Source:
        def resolve(self,**kw):return AuthenticatedManagementContext(rfc8785.dumps(state),tuple(records),b"modeled complete attested classification history")
    verifier=InstalledManagementVerifier(hb,rfc8785.dumps(profile),Source())
    def demote():
        state["history"]=[dict(kind="admitted",anchor="audit:admit",sequence=1,occurred_at=now-100,authority="authority:a",hand_back_digest=None),
            dict(kind="demoted",anchor="audit:demote",sequence=2,occurred_at=now,authority="authority:a",hand_back_digest=_digest(wire,"sha256"))]
        state["event_count"]=2
        records.append(HistoricalDemotionHandBack(rfc8785.dumps(op),rfc8785.dumps(wire)))
    return dict(v=verifier,s=state,hs=hs,w=wire,op=op,now=now,records=records,profile=profile,demote=demote)


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class InstalledManagementTests(unittest.TestCase):
    def evaluate(self,f,**kw):
        return f["v"].evaluate(actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True,**kw)

    def test_unknown_receives_uniform_denial_and_no_action_permission(self):
        f=fixture();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertEqual(r.management.regime,"unmanaged")
        self.assertEqual(r.public_response.body_bytes,b'{"admission_endpoint":"channel:admission"}')
        self.assertFalse(r.action_permitted)

    def test_demotion_is_immediate_and_preserves_validated_final_hand_back(self):
        f=fixture();f["demote"]();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertEqual(r.management.regime,"unmanaged")
        self.assertTrue(r.management.ever_managed);self.assertTrue(r.hand_backs[0].valid)
        self.assertTrue(r.delivery_validation_required)
        self.assertEqual(r.public_response.body_bytes,b'{"admission_endpoint":"channel:admission"}')

    def test_checkpoint_prevents_retroactive_reclassification_or_history_rewrite(self):
        f=fixture();f["demote"]();prior=self.evaluate(f)
        f["s"].update(history=[],event_count=0);f["records"].clear()
        from kinetic_trust_library.errors import ValidationError
        with self.assertRaisesRegex(ValidationError,"history"):
            self.evaluate(f,previous_assessment=prior)

    def test_missing_final_hand_back_cannot_hide_demoted_membership(self):
        f=fixture();f["demote"]();f["records"].clear();r=self.evaluate(f)
        self.assertFalse(r.valid);self.assertEqual(r.management.regime,"unmanaged")
        self.assertTrue(r.hand_back_required);self.assertFalse(r.action_permitted)

    def test_silent_surface_cannot_hide_pending_demotion_delivery(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture();f["profile"].update(hostile_facing=True,wire_silence=True)
        f["s"]["profile_digest"]=_digest(f["profile"],"sha256")
        f["v"]=replace(f["v"],profile_bytes=rfc8785.dumps(f["profile"]))
        self.assertIsNone(self.evaluate(f).public_response.body_bytes)
        f["demote"]()
        self.assertEqual(self.evaluate(f).public_response.status,401)
        f["s"]["request_kind"]="admission"
        self.assertEqual(self.evaluate(f).public_response.body_bytes,b'{"admission_endpoint":"channel:admission"}')

    def test_final_hand_back_time_and_original_action_are_not_interchangeable(self):
        f=fixture();f["demote"]();f["s"]["history"][1]["occurred_at"]-=1
        self.assertFalse(self.evaluate(f).valid)

    def test_malformed_final_hand_back_is_debt_not_a_bare_parser_error(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.installed_management import HistoricalDemotionHandBack
        f=fixture();f["demote"]();del f["w"]["issued_at"]
        f["s"]["history"][1]["hand_back_digest"]=_digest(f["w"],"sha256")
        f["records"][:]=[HistoricalDemotionHandBack(rfc8785.dumps(f["op"]),rfc8785.dumps(f["w"]))]
        r=self.evaluate(f)
        self.assertFalse(r.valid);self.assertTrue(r.hand_back_required)

    def test_source_failure_propagates_without_inventing_empty_history(self):
        from kinetic_trust_library.errors import ValidationError
        f=fixture()
        class Broken:
            def resolve(self,**kw):raise ValidationError("management Source failed")
        f["v"]=replace(f["v"],context_source=Broken())
        with self.assertRaisesRegex(ValidationError,"Source failed"):self.evaluate(f)

    def test_silence_after_demotion_requires_actual_current_delivery_completion(self):
        import json,rfc8785
        from tests.unit.core.test_v3_installed_delivery import fixture as delivery_fixture,add_attempt
        from kinetic_trust_library.v3.demand_supplier import _digest
        args=delivery_fixture();dv,ds,hs,wire,op,now=args
        f=fixture(lambda:(dv.hand_back_verifier,hs,wire,op,[],now,None))
        digest=_digest(wire,"sha256");ds["hand_back_digest"]=ds["escrow"]["hand_back_digest"]=digest
        f["profile"].update(hostile_facing=True,wire_silence=True,delivery_profile_digest=_digest(json.loads(dv.profile_bytes),"sha256"))
        f["s"]["profile_digest"]=_digest(f["profile"],"sha256")
        f["v"]=replace(f["v"],profile_bytes=rfc8785.dumps(f["profile"]),delivery_verifier=dv)
        f["demote"]()
        self.assertEqual(self.evaluate(f).public_response.status,401)
        add_attempt(args,accepted=True)
        # This selected completion policy waits for the accountable recipient's
        # acknowledgment too; an old delivered wire annotation never suffices.
        ds["acknowledgment"]=dict(anchor="sha256:"+"9"*64,hand_back_digest=digest,
            principal=hs["delegator"],acknowledged_at=now)
        r=self.evaluate(f)
        self.assertFalse(r.delivery_validation_required);self.assertIsNone(r.public_response.status)
        self.assertFalse(r.action_permitted)
