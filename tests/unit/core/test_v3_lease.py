import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.lease import project_lease


def fixture():
    intent=dict(actor="agent:a",operation_digest="sha256:"+"a"*64,consequence_class="Coordination",principal="person:a",
                issued_at=900,expires_at=1000,record_digest="sha256:"+"b"*64)
    lease=dict(id="lease:1",issuer="authority:a",subject="agent:a",operation_digest=intent["operation_digest"],
        consequence_class="Coordination",issued_at=950,expires_at=1100,kind="duration",nonce=None,consumed=False,revoked=False,
        template_digest="sha256:"+"c"*64,principal_token_digest=intent["record_digest"],grant_epoch=5)
    kwargs=dict(actual_actor="agent:a",actual_operation_digest=intent["operation_digest"],actual_consequence_class="Coordination",
        mutates_relation=False,principal="person:a",lease_authority="authority:a",template_digest=lease["template_digest"],
        current_grant_epoch=5,principal_token_max_age_seconds=100,evaluated_at=1000)
    return lease,intent,kwargs


class LeaseTests(unittest.TestCase):
    def test_duration_is_bounded_and_does_not_renew_with_new_environment_proof(self):
        lease,intent,kw=fixture();r=project_lease(lease,intent,**kw)
        self.assertTrue(r.active);self.assertEqual(r.expires_at,1100)
        kw["evaluated_at"]=1100
        self.assertEqual(project_lease(lease,intent,**kw).reason,"LEASE_EXPIRED")

    def test_class_specific_duration_ceilings(self):
        for kind,limit in (("Logistics",259200),("Coordination",1800)):
            lease,intent,kw=fixture();lease["consequence_class"]=intent["consequence_class"]=kw["actual_consequence_class"]=kind
            lease["expires_at"]=lease["issued_at"]+limit
            self.assertTrue(project_lease(lease,intent,**kw).active)
            lease["expires_at"]+=1
            with self.subTest(kind=kind),self.assertRaises(ValidationError):project_lease(lease,intent,**kw)

    def test_relational_is_nonce_never_zero_length_duration(self):
        lease,intent,kw=fixture();lease["consequence_class"]=intent["consequence_class"]=kw["actual_consequence_class"]="Relational"
        kw["mutates_relation"]=True
        lease.update(kind="single-use",nonce="nonce:one-step",expires_at=None)
        r=project_lease(lease,intent,**kw)
        self.assertTrue(r.active);self.assertTrue(r.single_use_required);self.assertIsNone(r.expires_at)
        lease["consumed"]=True
        self.assertEqual(project_lease(lease,intent,**kw).reason,"LEASE_CONSUMED")
        lease.update(consumed=False,kind="duration",expires_at=lease["issued_at"])
        with self.assertRaises(ValidationError):project_lease(lease,intent,**kw)

    def test_signed_intent_class_actor_whole_action_and_principal_must_match(self):
        for key,value in (("actor","other"),("operation_digest","sha256:"+"0"*64),
                          ("consequence_class","Logistics"),("principal","agent:a"),("expires_at",950)):
            lease,intent,kw=fixture();intent[key]=value
            with self.subTest(key=key),self.assertRaises(ValidationError):project_lease(lease,intent,**kw)

    def test_epoch_revocation_classification_and_fresh_principal_token(self):
        lease,intent,kw=fixture();kw["current_grant_epoch"]=6
        self.assertEqual(project_lease(lease,intent,**kw).reason,"LEASE_EPOCH_CHANGED")
        kw["current_grant_epoch"]=5;lease["revoked"]=True
        self.assertEqual(project_lease(lease,intent,**kw).reason,"LEASE_REVOKED")
        lease["revoked"]=False;kw["mutates_relation"]=True
        with self.assertRaises(ValidationError):project_lease(lease,intent,**kw)
        kw["mutates_relation"]=False;kw["principal_token_max_age_seconds"]=10
        with self.assertRaises(ValidationError):project_lease(lease,intent,**kw)

    def test_template_and_declared_authority_are_not_requester_choices(self):
        for key,value in (("template_digest",None),("lease_authority","agent:a"),("actual_actor","other")):
            lease,intent,kw=fixture();kw[key]=value
            with self.subTest(key=key),self.assertRaises(ValidationError):project_lease(lease,intent,**kw)
