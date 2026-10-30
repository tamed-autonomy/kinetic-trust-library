from importlib.util import find_spec
from dataclasses import replace
import unittest


def fixture():
    import rfc8785,json
    from tests.unit.core.test_v3_hand_back import fixture as base
    from kinetic_trust_library.v3.bootstrap_hand_back import InstalledBootstrapHandBackVerifier,AuthenticatedBootstrapHandBackContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    hb,hs,wire,op,_,now,_=base()
    encrypted=hb.context_source.resolve().ciphertext_bytes
    t=hs["template"];wire["reason"]="mint_refused"
    profile=dict(id="bootstrap:a",version=1,zone="zone-a",formula="mint-request-sealed-bootstrap-v1",
        lease_authority="authority:a",template_registry="registry:templates",defect_endpoint=json.loads(hb.profile_bytes)["defect_endpoint"],default_endpoint="channel:default",
        classes={kind:dict(ack_sla_seconds=60,minimum_reissue_seconds=10,recourse_ref=t["recourse"]["ref"],
            repair_ref=t["repair"]["ref"],redaction_policy_digest=t["redaction_policy_digest"]) for kind in ("Logistics","Coordination","Relational")})
    q=dict(id="mint:1",anchor="audit:mint-request",requested_at=now-1,principal=hs["delegator"],
        principal_channel=t["recipient"]["endpoint"],consequence_class="Coordination",template_digest=None)
    state={k:hs[k] for k in ("deployment_digest","operation_digest","checked_at","expires_at","subject","subject_profile","zone",
        "consequence_class","action_id","delegator","operator","operator_affiliates","measurers","issued_at","reissue_not_before","bundle","delivery")}
    state.update(profile_digest=_digest(profile,"sha256"),lease_authority="authority:a",reason="mint_refused",stop_origin="system",lease=None,
        mint_request=q,mutates_relation=False,
        policy_declaration=dict(anchor="audit:bootstrap-policy",profile_digest=_digest(profile,"sha256"),declared_at=now-100),
        template_lookup=dict(anchor="audit:template-absence",registry="registry:templates",as_of=q["requested_at"],request_anchor=q["anchor"],template_digest=None),
        fallback={k:t[k] for k in ("recipient","recourse","repair","redaction_policy_digest")})
    class Source:
        def resolve(self,**kw):return AuthenticatedBootstrapHandBackContext(rfc8785.dumps(state),encrypted,
            b"modeled authenticated mint request, actual historical template absence and predeclared sealed return policy; fixture AES-GCM ciphertext")
    v=InstalledBootstrapHandBackVerifier(hb.deployment_profile_bytes,rfc8785.dumps(profile),Source(),"sha256")
    return dict(v=v,s=state,w=wire,op=op,now=now,p=profile)


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class BootstrapHandBackTests(unittest.TestCase):
    def evaluate(self,f):
        import rfc8785
        return f["v"].evaluate(rfc8785.dumps(f["w"]),request_id="mint:1",request_anchor="audit:mint-request",
            actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)

    def test_request_principal_route_gets_sealed_refusal_without_becoming_template(self):
        f=fixture();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertEqual(r.delivery_state,"parked")
        self.assertEqual(r.construction_origin,"mint-request-fallback")
        self.assertFalse(r.action_permitted);self.assertFalse(r.clearance_capable)
        self.assertNotIn(b'"template":',r.authenticated_state_bytes)

    def test_default_endpoint_only_when_request_channel_is_absent(self):
        f=fixture();s=f["s"];s["mint_request"]["principal_channel"]=None
        s["fallback"]["recipient"]["endpoint"]=s["bundle"]["recipient_endpoint"]=f["w"]["recipient"]["endpoint"]="channel:default"
        self.assertTrue(self.evaluate(f).valid)
        s["mint_request"]["principal_channel"]="channel:declared-requester"
        self.assertFalse(self.evaluate(f).valid)

    def test_an_existing_template_or_issued_lease_cannot_select_bootstrap(self):
        for change in (lambda s:s["mint_request"].update(template_digest="sha256:"+"a"*64),
                       lambda s:s["template_lookup"].update(template_digest="sha256:"+"a"*64),
                       lambda s:s.update(lease={"id":"lease:already-minted"})):
            f=fixture();change(f["s"])
            with self.subTest(change=change):self.assertFalse(self.evaluate(f).valid)

    def test_request_scope_and_predeclared_defaults_cannot_be_replaced_at_stop(self):
        for change in (lambda s:s["mint_request"].update(id="another:request"),
                       lambda s:s["policy_declaration"].update(declared_at=s["checked_at"]),
                       lambda s:s["template_lookup"].update(registry="registry:unrelated"),
                       lambda s:s["fallback"]["repair"].update(ref="repair:new-at-stop"),
                       lambda s:s["fallback"]["recourse"].update(owner=s["operator"]),
                       lambda s:s.update(mutates_relation=True)):
            f=fixture();change(f["s"])
            with self.subTest(change=change):self.assertFalse(self.evaluate(f).valid)

    def test_wrong_key_recipient_plaintext_or_fake_delivery_is_rejected(self):
        for change in (lambda f:f["s"]["bundle"].update(agent_can_read=True),
                       lambda f:f["s"]["fallback"]["recipient"].update(principal="person:other"),
                       lambda f:f["w"]["context"].update(sealed_to="key:other"),
                       lambda f:f["w"]["delivery"].update(state="delivered")):
            f=fixture();change(f)
            with self.subTest(change=change):self.assertFalse(self.evaluate(f).valid)

    def test_only_mint_refusal_can_use_this_non_clearance_path(self):
        f=fixture();f["w"]["reason"]="revoked_by_principal"
        self.assertFalse(self.evaluate(f).valid)

    def test_source_failures_propagate(self):
        from kinetic_trust_library.errors import ValidationError
        f=fixture()
        class Broken:
            def resolve(self,**kw):raise ValidationError("bootstrap Source failed")
        f["v"]=replace(f["v"],context_source=Broken())
        with self.assertRaisesRegex(ValidationError,"Source failed"):self.evaluate(f)

    def test_selected_hysteresis_preserves_the_actual_adjudicated_price(self):
        import rfc8785,json
        from tests.unit.core.test_v3_installed_hysteresis import fixture as hysteresis_fixture
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture();hv,history,_,_,_,_,now,stamp=hysteresis_fixture()
        f["p"]["hysteresis_profile_digest"]=_digest(json.loads(hv.profile_bytes),"sha256")
        f["s"]["profile_digest"]=f["s"]["policy_declaration"]["profile_digest"]=_digest(f["p"],"sha256")
        f["s"]["stop_anchor"]=history["pricing_stop"]["stop_anchor"]
        f["v"]=replace(f["v"],profile_bytes=rfc8785.dumps(f["p"]),hysteresis_verifier=hv)
        self.assertFalse(self.evaluate(f).valid)
        f["s"]["reissue_not_before"]=f["w"]["reissue_not_before"]=stamp(now+20)
        r=self.evaluate(f);self.assertTrue(r.valid);self.assertEqual(r.hysteresis.projection.prior_adverse_count,1)
        f["s"]["stop_anchor"]="sha256:"+"0"*64
        self.assertFalse(self.evaluate(f).valid)

    def test_selected_hysteresis_source_failure_is_not_malformed_wire(self):
        import rfc8785,json
        from tests.unit.core.test_v3_installed_hysteresis import fixture as hysteresis_fixture
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.errors import ValidationError
        f=fixture();hv,history,_,_,_,_,_,_=hysteresis_fixture()
        class Broken:
            def resolve(self,**kw):raise ValidationError("hysteresis Source unavailable")
        hv=replace(hv,context_source=Broken())
        f["p"]["hysteresis_profile_digest"]=_digest(json.loads(hv.profile_bytes),"sha256")
        f["s"]["profile_digest"]=f["s"]["policy_declaration"]["profile_digest"]=_digest(f["p"],"sha256")
        f["s"]["stop_anchor"]=history["pricing_stop"]["stop_anchor"]
        f["v"]=replace(f["v"],profile_bytes=rfc8785.dumps(f["p"]),hysteresis_verifier=hv)
        with self.assertRaisesRegex(ValidationError,"hysteresis Source unavailable"):self.evaluate(f)
