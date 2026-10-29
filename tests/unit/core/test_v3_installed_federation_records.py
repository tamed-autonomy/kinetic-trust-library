"""Modeled complete authority inventory for federation record delivery."""
from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785
    from tests.unit.core.test_v3_federation import fixture as federation_fixture
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.installed_federation_records import (
        InstalledFederationRecordVerifier,AuthenticatedFederationRecordContext)
    parent,current,_,_,_=federation_fixture()
    profile=dict(id="record-policy",version=1,origin_zone="zone-a",formula="reached-subject-exposure-and-anchor-notification-v1")
    raw=rfc8785.dumps(dict(id="actual-record",content="source-owned breach evidence"))
    state=dict(deployment_digest=_digest(__import__('json').loads(parent.deployment_profile_bytes),"sha256"),
        profile_digest=_digest(profile,"sha256"),record_digest=_digest(__import__('json').loads(raw),"sha256"),
        checked_at=1000,expires_at=1007,origin_zone="zone-a",subject="person-7",subject_profile="person",
        kind="breach",breach_anchor="breach-1",reconciliation_anchor=None,recorded_at=900,current_valid=True,
        signatures=[dict(zone_id="zone-a",registry_verified=True,witnessed=True)],
        required_sovereignty=["consent"],destinations=[dict(zone="zone-b",agreement=current["agreement"],
            receiver_accepting=True,standing_admitted=False,bond_ever_opened=True,
            attestation_admitted=False,prior_breach_delivery=None)])
    calls=[]
    class Source:
        def resolve(self,**kw):
            calls.append(kw)
            return AuthenticatedFederationRecordContext(rfc8785.dumps(state),b"modeled record/signatures/current agreements/complete subject coverage/delivery history")
    verifier=InstalledFederationRecordVerifier(parent.deployment_profile_bytes,rfc8785.dumps(profile),Source(),"sha256")
    return verifier,state,raw,calls


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class InstalledFederationRecordTests(unittest.TestCase):
    def evaluate(self,v,raw):return v.evaluate(record_bytes=raw,evaluated_at=1000,clock_healthy=True)

    def test_complete_record_scope_current_exposure_and_raw_evidence(self):
        v,s,raw,calls=fixture();result=self.evaluate(v,raw)
        self.assertEqual(result.plan.required_destinations,("zone-b",))
        self.assertFalse(result.plan.closes_receiver_exposure)
        self.assertEqual(result.record_bytes,raw)
        self.assertEqual(calls[0]["record_bytes"],raw)
        self.assertEqual(result.expires_at,1007)
        self.assertTrue(result.source_evidence_bytes)
        with self.assertRaises(TypeError):type(result)()

    def test_notification_has_two_anchors_and_no_person_repair_body(self):
        v,s,raw,_=fixture();s.update(kind="reconciliation-anchored",reconciliation_anchor="repair-1")
        from kinetic_trust_library.v3.demand_supplier import _digest
        d=s["destinations"][0]
        d["prior_breach_delivery"]=dict(subject=s["subject"],breach_anchor=s["breach_anchor"],
            origin_zone=s["origin_zone"],agreement_digest=_digest(d["agreement"],"sha256"),delivered_at=899)
        r=self.evaluate(v,raw)
        self.assertEqual(dict(r.plan.notification_payload),dict(breach_anchor="breach-1",reconciliation_anchor="repair-1"))
        self.assertEqual(r.plan.permitted_destinations,("zone-b",))
        for key,value in (("subject","other-person"),("breach_anchor","another-breach"),
                          ("agreement_digest","sha256:"+"0"*64),("delivered_at",1001)):
            saved=d["prior_breach_delivery"][key];d["prior_breach_delivery"][key]=value
            from kinetic_trust_library.errors import ValidationError
            with self.subTest(key=key),self.assertRaises(ValidationError):self.evaluate(v,raw)
            d["prior_breach_delivery"][key]=saved
        # Delayed delivery can reach a zone after the local repair was anchored.
        d["prior_breach_delivery"]["delivered_at"]=950
        self.assertEqual(self.evaluate(v,raw).plan.required_destinations,("zone-b",))
        s["destinations"][0]["prior_breach_delivery"]=None
        self.assertEqual(self.evaluate(v,raw).plan.required_destinations,())

    def test_source_cannot_substitute_scope_or_bad_registry_witness(self):
        from kinetic_trust_library.errors import ValidationError
        for key,value in (("record_digest","sha256:"+"0"*64),("origin_zone","other"),
                          ("profile_digest","sha256:"+"0"*64),("checked_at",999),
                          ("expires_at",1000),("recorded_at",1001),("current_valid",False)):
            v,s,raw,_=fixture();s[key]=value
            with self.subTest(key=key),self.assertRaises(ValidationError):self.evaluate(v,raw)
        for field in ("registry_verified","witnessed"):
            v,s,raw,_=fixture();s["signatures"][0][field]=False
            with self.subTest(field=field),self.assertRaises(ValidationError):self.evaluate(v,raw)

    def test_actual_agreement_scope_expiry_and_sovereignty(self):
        v,s,raw,_=fixture();d=s["destinations"][0]
        d["agreement"]["expires_at"]=1002
        self.assertEqual(self.evaluate(v,raw).expires_at,1002)
        d["agreement"]["sovereignty_enforced"]["zone-b"]=[]
        r=self.evaluate(v,raw)
        self.assertEqual(r.plan.required_destinations,("zone-b",))
        self.assertEqual(r.plan.blocked_destinations,("zone-b",))
        d["receiver_accepting"]=False
        self.assertEqual(self.evaluate(v,raw).plan.required_destinations,())

    def test_clock_only_refresh_keeps_frame_but_history_changes_it(self):
        v,s,raw,_=fixture();before=self.evaluate(v,raw)
        s["expires_at"]=1008
        self.assertEqual(self.evaluate(v,raw).frame_digest,before.frame_digest)
        s["destinations"][0]["bond_ever_opened"]=False
        self.assertNotEqual(self.evaluate(v,raw).frame_digest,before.frame_digest)

    def test_derived_frame_changes_at_agreement_expiry(self):
        v,s,raw,_=fixture();s["destinations"][0]["agreement"]["expires_at"]=1001
        before=self.evaluate(v,raw)
        s["checked_at"]=1001
        after=v.evaluate(record_bytes=raw,evaluated_at=1001,clock_healthy=True)
        self.assertEqual(after.plan.required_destinations,())
        self.assertNotEqual(before.frame_digest,after.frame_digest)

    def test_no_local_repair_or_delta_becomes_foreign_closure(self):
        v,s,raw,_=fixture()
        for kind in ("reconciliation-record","delta","silent-veto","soul-veto"):
            s["kind"]=kind
            result=self.evaluate(v,raw)
            self.assertEqual(result.plan.permitted_destinations,())
            self.assertFalse(result.plan.closes_receiver_exposure)
