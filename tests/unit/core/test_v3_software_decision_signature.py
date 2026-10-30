import json
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
import unittest


def fixture(algorithm="EdDSA"):
    import rfc8785
    from cryptography.hazmat.primitives.asymmetric import ec,ed25519,utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from kinetic_trust_library.v3.software_decision_signature import InstalledSoftwareDecisionSignatureVerifier
    from kinetic_trust_library.v3.native_issuance import _segment
    body=json.loads((Path(__file__).parents[3]/"spec/proposals/software-substrate-execution.json").read_text())["schemaFixture"]
    key=dict(kid="software:key",subject=body["issuer_id"],zone_id="zone:software",purpose="ktp-software-substrate-decision",
        alg=algorithm,not_before=90,not_after=150,revoked=False)
    if algorithm=="EdDSA":
        private=ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        key.update(kty="OKP",crv="Ed25519",x=_segment(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)))
    else:
        private=ec.derive_private_key(3,ec.SECP256R1());numbers=private.public_key().public_numbers()
        key.update(kty="EC",crv="P-256",x=_segment(numbers.x.to_bytes(32,"big")),y=_segment(numbers.y.to_bytes(32,"big")))
    profile=dict(id="software-signature:a",version=1,zone="zone:software",formula="software-decision-es256-ed25519-v1",
        execution_profile_digest=body["request_binding"]["execution_profile_digest"],policy_digest=body["request_binding"]["policy_digest"],
        issuer_ids=[body["issuer_id"]],algorithms=["ES256","EdDSA"])
    def sign(typ="ktp-software-substrate-decision",high_s=False):
        raw=rfc8785.dumps({k:v for k,v in body.items() if k!="signature"})
        head=_segment(rfc8785.dumps(dict(alg=algorithm,kid=key["kid"],typ=typ)))
        message=(head+"."+_segment(raw)).encode("ascii")
        if algorithm=="EdDSA":signature=private.sign(message)
        else:
            from kinetic_trust_library.v3._readiness_crypto import ORDERS
            r,s=utils.decode_dss_signature(private.sign(message,ec.ECDSA(hashes.SHA256())))
            s=min(s,ORDERS["ES256"]-s)
            if high_s:s=ORDERS["ES256"]-s
            signature=r.to_bytes(32,"big")+s.to_bytes(32,"big")
        body["signature"]=message.decode()+"."+_segment(signature)
        return rfc8785.dumps(body)
    verifier=InstalledSoftwareDecisionSignatureVerifier(rfc8785.dumps({key["kid"]:key}),rfc8785.dumps(profile))
    return verifier,key,profile,body,sign


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class SoftwareDecisionSignatureTests(unittest.TestCase):
    def test_real_supported_classical_signatures_are_only_a_prerequisite(self):
        for algorithm in ("ES256","EdDSA"):
            v,_,_,_,sign=fixture(algorithm);raw=sign();r=v.verify(raw,now=100,clock_healthy=True)
            self.assertTrue(r.verified);self.assertEqual(r.decision_bytes,raw);self.assertFalse(r.action_permitted)
            self.assertFalse(r.complete_consumption_verified)

    def test_changed_object_wrong_purpose_or_expired_artifact_cannot_verify(self):
        import rfc8785
        v,_,_,body,sign=fixture();raw=sign()
        self.assertFalse(v.verify(raw,now=101,clock_healthy=True).verified)
        self.assertFalse(v.verify(raw,now=100,clock_healthy=False).verified)
        body["result"]["autonomyDemand"]=0.3
        self.assertFalse(v.verify(rfc8785.dumps(body),now=100,clock_healthy=True).verified)
        self.assertFalse(v.verify(sign("ktp-trust-proof+jwt"),now=100,clock_healthy=True).verified)

    def test_current_key_role_revocation_zone_and_lifetime_are_bound(self):
        import rfc8785
        for patch in (dict(revoked=True),dict(purpose="ktp-trust-proof+jwt"),dict(zone_id="zone:other"),
                dict(not_after=100),dict(subject="issuer:other")):
            v,key,_,_,sign=fixture();raw=sign()
            v=replace(v,trusted_keys_bytes=rfc8785.dumps({key["kid"]:dict(key,**patch)}))
            with self.subTest(patch=patch):self.assertFalse(v.verify(raw,now=100,clock_healthy=True).verified)

    def test_high_s_and_signed_wrong_installed_profile_are_rejected(self):
        v,_,_,_,sign=fixture("ES256")
        self.assertFalse(v.verify(sign(high_s=True),now=100,clock_healthy=True).verified)
        v,_,_,body,sign=fixture();body["request_binding"]["policy_digest"]="sha256:"+"b"*64
        self.assertFalse(v.verify(sign(),now=100,clock_healthy=True).verified)
