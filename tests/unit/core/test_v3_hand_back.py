"""Authenticated registered-template facts; no actual delivery/custody claim."""
from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785,hashlib
    from datetime import datetime,timezone
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from kinetic_trust_library.v3.hand_back import InstalledHandBackVerifier,AuthenticatedHandBackContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    now=1800000000
    stamp=lambda value:datetime.fromtimestamp(value,timezone.utc).isoformat().replace("+00:00","Z")
    op=dict(subject="subject:a",actor="agent:a",audience="service:a",operation="action:write",resource="resource:a",
        parameters={},request_id="request:1",replay_domain="domain:a")
    dp=dict(id="deployment:a")
    profile=dict(id="hand-back:a",version=1,zone="zone-a",defect_endpoint="channel:human-defects",
        formula="registered-template-and-sealed-context-v1",
        classes={kind:dict(ack_sla_seconds=60,minimum_reissue_seconds=10) for kind in ("Logistics","Coordination","Relational")})
    key=AESGCM.generate_key(bit_length=256);nonce=b"fixtureNonce"
    sections=["action","lease_history","environment_attestations","work_product"]
    plaintext=rfc8785.dumps({name:dict(actual="private "+name) for name in sections})
    cipher=nonce+AESGCM(key).encrypt(nonce,plaintext,b"registered template context")
    h=lambda raw:"sha256:"+hashlib.sha256(raw).hexdigest()
    template=dict(id="template:1",version=1,subject=op["actor"],consequence_class="Coordination",registered_at=now-100,
        recipient=dict(endpoint="channel:delegator",principal="person:delegator",key_id="key:delegator",channel="protected:inbox",
                       ack_sla_seconds=30,liability_ref="accountability:delegator"),
        recourse=dict(kind="contest",ref="review:independent",owner="person:reviewer",
                      independent_of=[op["actor"],"measurer:1","operator:a","affiliate:a"]),
        repair=dict(subject=op["actor"],ref="repair:relation"),redaction_policy_digest=h(b"registered full-tier policy"))
    wire=dict(action=op["operation"],reason="exceeded_zeroth_law",recipient=dict(endpoint="channel:delegator",ack_sla_seconds=30),
        recourse=dict(kind="contest",ref="review:independent"),repair="repair:relation",reissue_not_before=stamp(now+10),
        context=dict(sealed_to="key:delegator",ciphertext_digest=h(cipher)),issued_at=stamp(now),delivery=dict(state="parked",attempts=0))
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=digest_demand_operation(op,algorithm="sha256"),checked_at=now,expires_at=now+7,
        subject=op["actor"],subject_profile="software",zone="zone-a",consequence_class="Coordination",action_id=op["operation"],
        reason=wire["reason"],stop_origin="system",delegator="person:delegator",operator="operator:a",operator_affiliates=["affiliate:a"],
        measurers=["measurer:1"],lease=dict(id="lease:1",subject=op["actor"],consequence_class="Coordination",issued_at=now-50,
            template_digest=_digest(template,"sha256")),issued_at=wire["issued_at"],reissue_not_before=wire["reissue_not_before"],template=template,
        bundle=dict(sealed_to="key:delegator",ciphertext_digest=h(cipher),recipient_endpoint="channel:delegator",sections=sections,
            tier="full",redaction_policy_digest=template["redaction_policy_digest"],agent_can_read=False),
        delivery=dict(channel_reachable=False,capacity="available",accepted_at=None,receipt_ref=None,attempts=0))
    calls=[]
    class Source:
        def resolve(self,**kw):
            calls.append(kw)
            # Test-only actual cryptographic content verification, never a
            # production claim about process/key custody or human authority.
            AESGCM(key).decrypt(cipher[:12],cipher[12:],b"registered template context")
            return AuthenticatedHandBackContext(rfc8785.dumps(state),cipher,b"modeled registry/template/authority/recourse/custody/delivery evidence")
    v=InstalledHandBackVerifier(rfc8785.dumps(dp),rfc8785.dumps(profile),Source(),"sha256")
    return v,state,wire,op,calls,now,stamp


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class HandBackTests(unittest.TestCase):
    def evaluate(self,v,wire,op,now):
        import rfc8785
        return v.evaluate(rfc8785.dumps(wire),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_registered_sealed_hand_back_is_parked_and_never_restores_clearance(self):
        v,s,w,op,calls,now,_=fixture();r=self.evaluate(v,w,op,now)
        self.assertTrue(r.valid)
        self.assertEqual(r.delivery_state,"parked")
        self.assertFalse(r.action_permitted)
        self.assertTrue(r.delivery_effort_required)
        self.assertEqual(r.expires_at,now+7)
        self.assertEqual(r.defect_endpoint,"channel:human-defects")
        self.assertTrue(r.source_evidence_bytes)
        self.assertNotIn(b"private work_product",r.authenticated_state_bytes)
        with self.assertRaises(TypeError):type(r)()

    def test_every_required_wire_field_and_extra_are_protocol_errors(self):
        v,s,w,op,_,now,_=fixture()
        for key in w:
            if key=="delivery":continue
            malformed={k:v for k,v in w.items() if k!=key}
            r=self.evaluate(v,malformed,op,now)
            with self.subTest(key=key):
                self.assertFalse(r.valid);self.assertTrue(r.protocol_error_record_required);self.assertTrue(r.defect_route_required)
        self.assertFalse(self.evaluate(v,dict(w,override=True),op,now).valid)

    def test_template_and_actual_scope_cannot_be_substituted(self):
        for change in (lambda s:s.update(subject="other"),lambda s:s.update(profile_digest="sha256:"+"0"*64),
                       lambda s:s["template"].update(subject="other"),
                       lambda s:s["template"]["repair"].update(subject="other"),
                       lambda s:s["template"]["recipient"].update(principal="community:declined"),
                       lambda s:s["template"].update(registered_at=s["lease"]["issued_at"]+1)):
            v,s,w,op,_,now,_=fixture();change(s)
            from kinetic_trust_library.v3.demand_supplier import _digest
            s["lease"]["template_digest"]=_digest(s["template"],"sha256")
            with self.subTest(change=change):self.assertFalse(self.evaluate(v,w,op,now).valid)

    def test_bundle_contents_key_custody_and_redaction_are_not_just_schema_checks(self):
        for change in (lambda s:s["bundle"].update(sections=[]),lambda s:s["bundle"].update(agent_can_read=True),
                       lambda s:s["bundle"].update(tier="counterparty"),lambda s:s["bundle"].update(sealed_to="key:other"),
                       lambda s:s["bundle"].update(redaction_policy_digest="sha256:"+"0"*64)):
            v,s,w,op,_,now,_=fixture();change(s)
            with self.subTest(change=change):self.assertFalse(self.evaluate(v,w,op,now).valid)

    def test_saturated_or_unreachable_recipient_cannot_be_claimed_delivered(self):
        v,s,w,op,_,now,_=fixture();w["delivery"]["state"]="delivered"
        self.assertFalse(self.evaluate(v,w,op,now).valid)
        s["delivery"].update(channel_reachable=True,capacity="exhausted",accepted_at=now,receipt_ref="receipt:1")
        self.assertFalse(self.evaluate(v,w,op,now).valid)
        w["delivery"]["state"]="parked"
        self.assertTrue(self.evaluate(v,w,op,now).valid)
        w["delivery"]["state"]="delivered";s["delivery"]["capacity"]="available"
        r=self.evaluate(v,w,op,now)
        self.assertTrue(r.valid);self.assertFalse(r.action_permitted);self.assertFalse(r.delivery_effort_required)

    def test_recourse_independence_and_sovereign_refusal_route(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,w,op,_,now,_=fixture();s["template"]["recourse"]["owner"]="affiliate:a"
        s["lease"]["template_digest"]=_digest(s["template"],"sha256")
        self.assertFalse(self.evaluate(v,w,op,now).valid)
        v,s,w,op,_,now,_=fixture();s.update(reason="exceeded_soul",stop_origin="sovereign");w["reason"]="exceeded_soul"
        self.assertFalse(self.evaluate(v,w,op,now).valid)
        s["template"]["recourse"]=dict(kind="closed_by_authority",ref="sovereign:protocol",authority="community:a",protocol="protocol:refusal")
        s["lease"]["template_digest"]=_digest(s["template"],"sha256")
        w["recourse"]=dict(kind="closed_by_authority",ref="sovereign:protocol")
        self.assertTrue(self.evaluate(v,w,op,now).valid)
        self.assertEqual(w["recipient"]["endpoint"],"channel:delegator")

    def test_reissue_floor_fractional_instants_and_person_own_recipient(self):
        v,s,w,op,_,now,stamp=fixture();w["reissue_not_before"]=stamp(now+9)
        self.assertFalse(self.evaluate(v,w,op,now).valid)

        s["reissue_not_before"]=w["reissue_not_before"]
        self.assertFalse(self.evaluate(v,w,op,now).valid)
        s["reissue_not_before"]=stamp(now+10)
        w["reissue_not_before"]=stamp(now+10);w["issued_at"]=stamp(now).replace("Z",".000000001Z")
        self.assertFalse(self.evaluate(v,w,op,now).valid)
        w["issued_at"]=stamp(now);s["subject_profile"]="person"
        self.assertFalse(self.evaluate(v,w,op,now).valid)

    def test_original_grant_template_is_not_replaced_by_a_new_template(self):
        v,s,w,op,_,now,_=fixture();s["template"]["version"]=2
        self.assertFalse(self.evaluate(v,w,op,now).valid)

    def test_person_receives_own_hand_back_and_undetermined_fabricates_no_authority(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,w,op,_,now,_=fixture();s["subject_profile"]="person"
        s["template"]["recipient"]["principal"]=op["actor"]
        s["lease"]["template_digest"]=_digest(s["template"],"sha256")
        self.assertTrue(self.evaluate(v,w,op,now).valid)
        s["stop_origin"]="undetermined"
        s["template"]["recourse"]=dict(kind="undetermined",ref="registry:consulted",registry="registry:authorities")
        s["lease"]["template_digest"]=_digest(s["template"],"sha256")
        w["recourse"]=dict(kind="undetermined",ref="registry:consulted")
        self.assertTrue(self.evaluate(v,w,op,now).valid)

    def test_operational_source_failure_is_not_fabricated_recipient_or_clearance(self):
        v,s,w,op,_,now,_=fixture()
        class Unavailable:
            def resolve(self,**kw):raise RuntimeError("registry unavailable")
        with self.assertRaisesRegex(RuntimeError,"unavailable"):
            self.evaluate(replace(v,context_source=Unavailable()),w,op,now)
