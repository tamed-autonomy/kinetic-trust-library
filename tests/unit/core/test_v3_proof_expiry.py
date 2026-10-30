from importlib.util import find_spec
from dataclasses import replace
from pathlib import Path
import unittest


def fixture():
    import json,rfc8785
    from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
    from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle
    from kinetic_trust_library.v3.proof_expiry import InstalledProofExpiryVerifier
    vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/trust-proof-v3.json").read_text());context=vectors["context"]
    proof=next(c["jws"] for c in vectors["cases"] if c["id"]=="clear")
    def no_root_query(*args):raise AssertionError("expiry must never revalidate or revive Root authority at a historical time")
    pv=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({k["kid"]:k for k in vectors["keys"]}),
        rfc8785.dumps(context),("ES256","EdDSA"),no_root_query)
    profile=dict(id="proof-expiry:a",version=1,zone=context["zone"],formula="signed-ordinary-expiry-refresh-v1",refresh_path="proof:refresh")
    op=dict(subject="subject:a",actor=context["subject"],audience=context["audience"],operation="action:write",resource="resource:a",
        parameters={},request_id="request:1",replay_domain="domain:a")
    return InstalledProofExpiryVerifier(pv,rfc8785.dumps(profile)),proof,op,context["now"],vectors


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class ProofExpiryTests(unittest.TestCase):
    def test_signed_expired_proof_is_only_refresh_metadata_not_authority(self):
        v,proof,op,now,_=fixture()
        r=v.evaluate(proof,actual_operation=op,evaluated_at=now+10,clock_healthy=True)
        self.assertTrue(r.expired);self.assertFalse(r.action_permitted)
        self.assertEqual(r.refresh_path,"proof:refresh");self.assertEqual(r.proof_expires_at,now+10)
        self.assertEqual(r.ordinary_verification.reason,"TP_TIME")
        self.assertIsNone(r.ordinary_verification.authenticated_payload_bytes)

    def test_current_proof_does_not_enter_expiry_or_query_root(self):
        v,proof,op,now,_=fixture();r=v.evaluate(proof,actual_operation=op,evaluated_at=now,clock_healthy=True)
        self.assertFalse(r.expired);self.assertIsNone(r.refresh_path);self.assertFalse(r.action_permitted)

    def test_invalid_signature_or_wrong_subject_cannot_claim_routine_expiry(self):
        v,proof,op,now,_=fixture()
        proof=proof[:-4]+("AAAA" if proof[-4:]!="AAAA" else "BBBB")
        self.assertFalse(v.evaluate(proof,actual_operation=op,evaluated_at=now+10,clock_healthy=True).expired)
        v,proof,op,now,_=fixture();op["actor"]="agent:guarantor:7gen:other:1234"
        self.assertFalse(v.evaluate(proof,actual_operation=op,evaluated_at=now+10,clock_healthy=True).expired)

    def test_bad_lifetime_future_or_clock_failure_is_not_expiry(self):
        v,proof,op,now,vectors=fixture()
        self.assertFalse(v.evaluate(proof,actual_operation=op,evaluated_at=now+10,clock_healthy=False).expired)
        observed=0
        for case in vectors["cases"]:
            if case["expected"]["reason"]=="TP_TIME" and "context" not in case:
                r=v.evaluate(case["jws"],actual_operation=op,evaluated_at=now,clock_healthy=True)
                self.assertFalse(r.expired);observed+=1
        self.assertGreater(observed,0)
