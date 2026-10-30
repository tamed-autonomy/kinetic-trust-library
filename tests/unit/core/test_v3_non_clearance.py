from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785,json
    from tests.unit.core.test_v3_hand_back import fixture as hand_back_fixture
    from kinetic_trust_library.v3.non_clearance import InstalledNonClearanceVerifier,AuthenticatedNonClearanceContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    hb,hs,w,op,_,now,stamp=hand_back_fixture()
    profile=dict(id="non-clearance:a",version=1,zone="zone-a",formula="authoritative-non-clearance-v1",
        hand_back_profile_digest=_digest(json.loads(hb.profile_bytes),"sha256"),lease_authority="authority:a",
        principal_token_max_age_seconds=100,reissue_path="admission:reissue")
    intent=dict(actor=op["actor"],operation_digest=digest_demand_operation(op,algorithm="sha256"),consequence_class="Coordination",
        principal="person:delegator",issued_at=now-60,expires_at=now,record_digest="sha256:"+"a"*64)
    lease=dict(id=hs["lease"]["id"],issuer="authority:a",subject=op["actor"],operation_digest=intent["operation_digest"],
        consequence_class="Coordination",issued_at=now-50,expires_at=now+100,kind="duration",nonce=None,consumed=False,revoked=False,
        template_digest=hs["lease"]["template_digest"],principal_token_digest=intent["record_digest"],grant_epoch=5)
    state=dict(deployment_digest=_digest(json.loads(hb.deployment_profile_bytes),"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=intent["operation_digest"],subject=op["actor"],zone="zone-a",managed_relation_id="managed:relation:1",checked_at=now,expires_at=now+7,
        principal="person:delegator",consequence_class="Coordination",mutates_relation=False,current_grant_epoch=5,
        template_digest=lease["template_digest"],lease=lease,intent=intent,
        adverse_stop=dict(id="stop:1",kind="Exceeded",reason=w["reason"],issued_at=w["issued_at"],hand_back_digest=_digest(w,"sha256")))
    class Source:
        def resolve(self,**kw):return AuthenticatedNonClearanceContext(rfc8785.dumps(state),b"modeled actual current signed grant/intent/stop registry")
    verifier=InstalledNonClearanceVerifier(hb,rfc8785.dumps(profile),Source())
    return verifier,state,hs,w,op,now,stamp


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class NonClearanceTests(unittest.TestCase):
    def evaluate(self,v,message,op,now):
        import rfc8785
        return v.evaluate(rfc8785.dumps(message),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_exceeded_requires_real_resolved_or_parked_hand_back(self):
        v,s,hs,w,op,now,_=fixture();r=self.evaluate(v,dict(kind="Exceeded",hand_back=w),op,now)
        self.assertTrue(r.valid);self.assertEqual(r.kind,"Exceeded");self.assertFalse(r.action_permitted)
        self.assertTrue(r.hand_back.valid);self.assertEqual(r.hand_back.delivery_state,"parked")
        self.assertTrue(r.human_handoff_required);self.assertFalse(r.hysteresis_countable)
        self.assertTrue(r.adjudication_required_for_counting)
        with self.assertRaises(TypeError):type(r)()

    def test_expired_has_only_reissue_no_contest_interrupt_or_hysteresis(self):
        v,s,hs,w,op,now,_=fixture();s["adverse_stop"]=None;s["lease"]["expires_at"]=now
        message=dict(kind="Expired",reissue_path="admission:reissue")
        r=self.evaluate(v,message,op,now)
        self.assertTrue(r.valid);self.assertEqual(r.kind,"Expired");self.assertIsNone(r.hand_back)
        self.assertFalse(r.human_handoff_required);self.assertFalse(r.hysteresis_countable);self.assertFalse(r.adjudication_required_for_counting)
        self.assertEqual(r.reissue_path,"admission:reissue")
        for extra in (dict(contest="review:any"),dict(hand_back=w),dict(hysteresis=1)):
            self.assertFalse(self.evaluate(v,dict(message,**extra),op,now).valid)

    def test_expired_assertion_cannot_hide_active_adverse_stop(self):
        v,s,hs,w,op,now,_=fixture();s["lease"]["expires_at"]=now
        self.assertFalse(self.evaluate(v,dict(kind="Expired",reissue_path="admission:reissue"),op,now).valid)

    def test_forged_clear_or_orphan_revocation_is_not_coerced_into_another_variant(self):
        v,s,hs,w,op,now,_=fixture()
        for message in (dict(kind="Clear",supervision="stable",lease="lease:1"),dict(kind="Revoked"),dict(kind="Exceeded")):
            r=self.evaluate(v,message,op,now)
            self.assertFalse(r.valid);self.assertIsNone(r.kind);self.assertTrue(r.defect_route_required)

    def test_stop_and_original_lease_digest_subject_time_and_variant_are_bound(self):
        for change in (lambda s:s["adverse_stop"].update(kind="Revoked"),
                       lambda s:s["adverse_stop"].update(hand_back_digest="sha256:"+"0"*64),
                       lambda s:s["lease"].update(id="different-lease"),
                       lambda s:s.update(subject="other"),lambda s:s.update(checked_at=s["checked_at"]-1)):
            v,s,hs,w,op,now,_=fixture();change(s)
            with self.subTest(change=change):self.assertFalse(self.evaluate(v,dict(kind="Exceeded",hand_back=w),op,now).valid)

    def test_live_revocation_is_not_reclassified_as_routine_expiry(self):
        v,s,hs,w,op,now,_=fixture();s["adverse_stop"]=None;s["lease"].update(expires_at=now,revoked=True)
        self.assertFalse(self.evaluate(v,dict(kind="Expired",reissue_path="admission:reissue"),op,now).valid)

    def test_valid_revocation_retains_hand_back_and_original_denial(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,hs,w,op,now,_=fixture()
        w["reason"]=hs["reason"]="revoked_by_principal";hs["stop_origin"]="principal"
        s["lease"]["revoked"]=True
        s["adverse_stop"].update(kind="Revoked",reason=w["reason"],hand_back_digest=_digest(w,"sha256"))
        s["adverse_stop"]["authority"]=dict(claimant=s["principal"],formation=None)
        r=self.evaluate(v,dict(kind="Revoked",hand_back=w),op,now)
        self.assertTrue(r.valid);self.assertEqual(r.kind,"Revoked");self.assertFalse(r.action_permitted)
        self.assertEqual(r.lease.reason,"LEASE_REVOKED")

    def test_unwitnessed_counterparty_revocation_is_contest_not_direct_revoked(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,hs,w,op,now,_=fixture()
        w["reason"]=hs["reason"]="revoked_by_counterparty"
        s["adverse_stop"].update(kind="Revoked",reason=w["reason"],hand_back_digest=_digest(w,"sha256"),
            authority=dict(claimant="person:counterparty",formation=None))
        r=self.evaluate(v,dict(kind="Revoked",hand_back=w),op,now)
        self.assertFalse(r.valid);self.assertIsNone(r.kind)
        self.assertEqual(r.reason,"CLEARANCE_FORMATION_CONTEST_REQUIRED")
        self.assertTrue(r.formation_contest_required);self.assertTrue(r.identity_assurance_required)
        self.assertTrue(r.human_handoff_required)
        self.assertFalse(r.action_permitted)

    def test_revocation_without_actual_claimant_authority_is_rejected(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,hs,w,op,now,_=fixture()
        w["reason"]=hs["reason"]="revoked_by_principal"
        s["adverse_stop"].update(kind="Revoked",reason=w["reason"],hand_back_digest=_digest(w,"sha256"))
        self.assertFalse(self.evaluate(v,dict(kind="Revoked",hand_back=w),op,now).valid)

    def test_witnessed_relational_counterparty_can_revoke_with_original_hand_back(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,hs,w,op,now,_=fixture()
        s.update(consequence_class="Relational",mutates_relation=True)
        s["intent"]["consequence_class"]="Relational"
        hs["consequence_class"]=hs["template"]["consequence_class"]=hs["lease"]["consequence_class"]="Relational"
        td=_digest(hs["template"],"sha256")
        hs["lease"]["template_digest"]=s["template_digest"]=td
        s["lease"].update(consequence_class="Relational",kind="single-use",nonce="nonce:a",
            expires_at=None,revoked=True,template_digest=td)
        w["reason"]=hs["reason"]="revoked_by_counterparty";hs["stop_origin"]="principal"
        formation=dict(subject=s["subject"],relation_id=s["managed_relation_id"],consequence_class="Relational",
            template_digest=td,counterparty="person:counterparty",registered_at=now-100,formed_at=now-70,
            countersigned_at=now-70,witness_anchor="audit:formation",countersignature_anchor="audit:signature",objection_at=None)
        s["adverse_stop"].update(kind="Revoked",reason=w["reason"],hand_back_digest=_digest(w,"sha256"),
            authority=dict(claimant="person:counterparty",formation=formation))
        r=self.evaluate(v,dict(kind="Revoked",hand_back=w),op,now)
        self.assertTrue(r.valid);self.assertEqual(r.kind,"Revoked");self.assertTrue(r.hand_back.valid)
        self.assertFalse(r.formation_contest_required);self.assertFalse(r.action_permitted)
        formation["relation_id"]="another:relation"
        self.assertFalse(self.evaluate(v,dict(kind="Revoked",hand_back=w),op,now).valid)

    def test_expiry_does_not_need_human_delivery_or_a_fresh_principal_token(self):
        v,s,hs,w,op,now,_=fixture();s["adverse_stop"]=None;s["lease"]["expires_at"]=now
        # The principal token was valid at mint; it is no longer current. Its
        # expiry does not renew or retroactively invalidate the duration lease.
        s["intent"]["expires_at"]=now-1
        hs["delivery"]["capacity"]="exhausted"
        self.assertTrue(self.evaluate(v,dict(kind="Expired",reissue_path="admission:reissue"),op,now).valid)

    def test_child_source_contract_failure_is_not_relabelled_as_hostile_wire(self):
        from kinetic_trust_library.errors import ValidationError
        v,s,hs,w,op,now,_=fixture()
        class BadSource:
            def resolve(self,**kw):raise ValidationError("hand-back Source contract failed")
        hb=replace(v.hand_back_verifier,context_source=BadSource())
        v=replace(v,hand_back_verifier=hb)
        with self.assertRaisesRegex(ValidationError,"Source contract"):
            self.evaluate(v,dict(kind="Exceeded",hand_back=w),op,now)
