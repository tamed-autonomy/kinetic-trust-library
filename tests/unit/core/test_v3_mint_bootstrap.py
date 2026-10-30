from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture():
    import json,rfc8785
    from tests.unit.core.test_v3_mint_stop import fixture as mint_fixture
    from tests.unit.core.test_v3_bootstrap_hand_back import fixture as bootstrap_fixture
    from kinetic_trust_library.v3.demand_supplier import _digest
    m=mint_fixture();b=bootstrap_fixture();p=json.loads(m["v"].profile_bytes)
    p["bootstrap_profile_digest"]=_digest(json.loads(b["v"].profile_bytes),"sha256")
    m["s"]["profile_digest"]=m["s"]["authority_declaration"]["profile_digest"]=_digest(p,"sha256")
    m["s"]["request"]=dict(b["s"]["mint_request"])
    m["records"]["hand_back"]=rfc8785.dumps(b["w"])
    m["s"]["response"]=dict(kind="Refused",authority="authority:a",request_id="mint:1",anchor="audit:reply",
        responded_at=m["now"],hand_back_digest=_digest(b["w"],"sha256"))
    m["v"]=replace(m["v"],profile_bytes=rfc8785.dumps(p),bootstrap_verifier=b["v"])
    return m,b,p


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class MintBootstrapTests(unittest.TestCase):
    def evaluate(self,m):
        return m["v"].evaluate(actual_operation=m["op"],evaluated_at=m["now"],clock_healthy=True)

    def test_missing_template_refusal_composes_actual_sealed_bootstrap(self):
        m,b,_=fixture();r=self.evaluate(m)
        self.assertTrue(r.valid);self.assertEqual(r.status,"Refused")
        self.assertEqual(r.hand_back.construction_origin,"mint-request-fallback")
        self.assertFalse(r.action_permitted);self.assertFalse(r.hand_back.clearance_capable)

    def test_a_missing_selection_fact_or_disagreeing_request_cannot_downgrade(self):
        m,_,_=fixture();del m["s"]["request"]["template_digest"]
        self.assertFalse(self.evaluate(m).valid)
        m,_,_=fixture();m["s"]["request"]["principal_channel"]="channel:another"
        self.assertFalse(self.evaluate(m).valid)

    def test_registered_template_uses_the_original_validator_with_bootstrap_installed(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        m,_,_=fixture();m["s"]["request"]["template_digest"]=_digest(m["hs"]["template"],"sha256")
        m["records"]["hand_back"]=rfc8785.dumps(m["w"])
        m["s"]["response"]["hand_back_digest"]=_digest(m["w"],"sha256")
        r=self.evaluate(m)
        self.assertTrue(r.valid);self.assertEqual(r.hand_back.reason,"HAND_BACK_VALID")
        self.assertFalse(r.action_permitted)

    def test_bootstrap_source_failure_retains_its_provenance(self):
        from kinetic_trust_library.errors import ValidationError
        m,b,_=fixture()
        class Broken:
            def resolve(self,**kw):raise ValidationError("bootstrap registry unavailable")
        m["v"]=replace(m["v"],bootstrap_verifier=replace(b["v"],context_source=Broken()))
        with self.assertRaisesRegex(ValidationError,"bootstrap registry unavailable"):self.evaluate(m)

    def test_composed_bootstrap_cannot_drop_the_normal_adjudicated_price(self):
        import json,rfc8785
        from tests.unit.core.test_v3_installed_hysteresis import fixture as hysteresis_fixture
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.errors import ValidationError
        m,b,p=fixture();hv,history,_,_,_,_,now,stamp=hysteresis_fixture()
        digest=_digest(json.loads(hv.profile_bytes),"sha256")
        hp=json.loads(m["v"].hand_back_verifier.profile_bytes);hp["hysteresis_profile_digest"]=digest
        hb=replace(m["v"].hand_back_verifier,profile_bytes=rfc8785.dumps(hp),hysteresis_verifier=hv)
        b["p"]["hysteresis_profile_digest"]=digest
        b["s"]["profile_digest"]=b["s"]["policy_declaration"]["profile_digest"]=_digest(b["p"],"sha256")
        b["s"]["stop_anchor"]=history["pricing_stop"]["stop_anchor"]
        b["s"]["reissue_not_before"]=b["w"]["reissue_not_before"]=stamp(now+20)
        bv=replace(b["v"],profile_bytes=rfc8785.dumps(b["p"]),hysteresis_verifier=hv)
        p.update(hand_back_profile_digest=_digest(hp,"sha256"),bootstrap_profile_digest=_digest(b["p"],"sha256"))
        m["s"]["profile_digest"]=m["s"]["authority_declaration"]["profile_digest"]=_digest(p,"sha256")
        m["records"]["hand_back"]=rfc8785.dumps(b["w"]);m["s"]["response"]["hand_back_digest"]=_digest(b["w"],"sha256")
        m["v"]=replace(m["v"],hand_back_verifier=hb,profile_bytes=rfc8785.dumps(p),bootstrap_verifier=bv)
        r=self.evaluate(m);self.assertTrue(r.valid);self.assertEqual(r.hand_back.hysteresis.projection.prior_adverse_count,1)
        with self.assertRaisesRegex(ValidationError,"exact installed"):
            replace(m["v"],bootstrap_verifier=replace(bv,hysteresis_verifier=replace(hv)))
