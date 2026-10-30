from dataclasses import replace
from importlib.util import find_spec
from fractions import Fraction
import unittest
from kinetic_trust_library.errors import ValidationError


def fixture():
    import rfc8785
    from kinetic_trust_library.v3.person_federation import InstalledPersonFederationVerifier
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core.test_v3_federation import fixture as software_fixture
    op=dict(subject="subject:a",actor="person:acct:z1:0417",audience="service:partner",operation="action:review",resource="resource:a",
        parameters={},request_id="request:1",replay_domain="domain:partner")
    old,s,_,p,_=software_fixture(operation=op)
    p.update(subject_profiles=["person"],formula="minimum-person-directional-terms-v1",zone_ceiling=40)
    s["profile_digest"]=_digest(p,"sha256");s.update(subject_profile="person",substrate_profile="person-signed-acts")
    a=s["agreement"];a["data_handling"].update(persons={"standing":True,"terms":"signed-acts-only"},attestation_types=["person-signed-acts"])
    a["directions"][0]["factor"]="0.5"
    s["attestation"].update(subject_profile="person",kind="person-signed-acts",signed_act=True,exportable_base=66)
    v=InstalledPersonFederationVerifier(old.deployment_profile_bytes,rfc8785.dumps(p),old.context_source,"sha256")
    return v,s,op,p


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class PersonFederationTests(unittest.TestCase):
    def evaluate(self,v,op):return v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    def test_receiver_signed_person_factor_and_ceiling(self):
        v,s,op,p=fixture();r=self.evaluate(v,op)
        self.assertTrue(r.admitted);self.assertEqual(r.standing.base_trust,33)
        self.assertFalse(r.action_permitted);self.assertEqual(r.expires_at,1007)
        s["agreement"]["directions"][0]["factor"]=1
        r=self.evaluate(v,op)
        self.assertEqual(r.factor.applied_factor,Fraction(7,10));self.assertEqual(r.standing.base_trust,40)
        s["agreement"]["directions"][0]["factor"]=0
        r=self.evaluate(v,op);self.assertTrue(r.admitted);self.assertEqual(r.standing.base_trust,0)

    def test_no_agreement_or_person_terms_cannot_transfer(self):
        changes=(lambda s:s.update(agreement=None),lambda s:s["agreement"]["data_handling"].update(persons=None),
            lambda s:s["agreement"]["data_handling"]["persons"].update(standing=False),
            lambda s:s["attestation"].update(signed_act=False),lambda s:s["attestation"].update(kind="behavior"),
            lambda s:s.update(receiver_accepting=False),lambda s:s["agreement"]["directions"][0].update(signed_by="zone-a"),
            lambda s:s["attestation"].update(link_count=2))
        for change in changes:
            v,s,op,_=fixture();change(s)
            with self.subTest(change=change):
                r=self.evaluate(v,op);self.assertFalse(r.admitted);self.assertIsNone(r.standing)

    def test_actual_person_scope_and_current_time_required(self):
        v,s,op,_=fixture();s["subject_profile"]="software"
        self.assertFalse(self.evaluate(v,op).admitted)
        v,s,op,_=fixture();s["subject"]="person:other"
        with self.assertRaises(ValidationError):self.evaluate(v,op)
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=False)

    def test_source_outage_propagates(self):
        v,s,op,_=fixture()
        class Offline:
            def resolve(self,**kwargs):raise OSError("registry unavailable")
        with self.assertRaises(OSError):self.evaluate(replace(v,context_source=Offline()),op)

    def test_currentness_earliest_expiry_and_no_relay(self):
        v,s,op,_=fixture();s["expires_at"]=1200
        self.assertEqual(self.evaluate(v,op).expires_at,1050)
        s["agreement"]["expires_at"]=1020
        self.assertEqual(self.evaluate(v,op).expires_at,1020)
        s["agreement"].update(version=2,starts_at=950)
        self.assertFalse(self.evaluate(v,op).admitted)
        v,s,op,_=fixture();s["attestation"]["signatures"][0]["witnessed"]=False
        self.assertFalse(self.evaluate(v,op).admitted)
        v,s,op,_=fixture();s["attestation"]["earned_in_zone"]="zone:third"
        self.assertFalse(self.evaluate(v,op).admitted)
        v,s,op,_=fixture();s["agreement"]["directions"][0]["factor"]="1.1"
        self.assertFalse(self.evaluate(v,op).admitted)

    def test_nonwidening_class_lowering_sovereignty_and_void_terms(self):
        v,s,op,_=fixture()
        s["lowered_factors"]=[{"policy":"decay","factor":"0.25"}]
        self.assertEqual(self.evaluate(v,op).standing.base_trust,Fraction(33,2))
        s["agreement"]["clauses"]=[{"id":"clause:bad","effect":"standing-delta"}]
        # Invalid effect vocabulary is rejected, never interpreted as a grant.
        self.assertFalse(self.evaluate(v,op).admitted)
        v,s,op,_=fixture();s["required_sovereignty"]=["missing-constraint"]
        self.assertFalse(self.evaluate(v,op).admitted)
