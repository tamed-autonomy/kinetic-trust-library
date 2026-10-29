"""Real test-profile signatures; schema/issuer/session authority is modeled."""
from importlib.util import find_spec
import unittest

from kinetic_trust_library.v3.adjudication import (
    InstalledAdjudicationVerifier,AuthenticatedAdjudicationContext,AuthenticatedAdjudicationPayload,
    AdjudicationUnavailable,AdjudicationInvalid,
)

HAS_EXTRAS=all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography"))


def fixture(operation=None,deployment=None,now=1000,gate_id="gate-1"):
    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
    from kinetic_trust_library.v3 import _readiness_crypto as c
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    operation=operation or dict(subject="urn:person:1",actor="urn:agent:1",audience="urn:service:1",operation="urn:operation:recover",
        resource="urn:resource:1",parameters={"limit":3},request_id="request-1",replay_domain="urn:replay:1")
    deployment=deployment or {"profile_id":"test-deployment"}
    external={"$id":"urn:test:norm-schema","type":"object","description":"Modeled approved gate criteria; no adequacy claim"}
    profile=dict(id="urn:test:adjudication:"+gate_id,version=1,gate_id=gate_id,gate_required=True,issuer="https://adjudicator.example.com",
        zone_id="zone:alpha",external_schema_id=external["$id"],external_schema_digest=c.digest(external,2),token_profile_id="urn:unsafe-test:adjudication-ed25519")
    state=dict(deployment_digest=c.digest(deployment,2),operation_digest=digest_demand_operation(operation,algorithm="sha256"),
        profile_digest=c.digest(profile,2),checked_at=now,actor=operation["actor"],action_digest=c.digest(operation,2),cnf_jkt="test-possession",
        grant_digest=c.digest({"grant":"current"},2),evidence_digest=c.digest({"evidence":"current"},2),zone_id="zone:alpha",topology_epoch=5,expires_at=now+8)
    payload={name:state[name] for name in ("actor","action_digest","cnf_jkt","grant_digest","evidence_digest","zone_id","topology_epoch")}
    payload.update(iss=profile["issuer"],favorable=True,iat=now-1,exp=now+6,jti="token-1")
    private=Ed25519PrivateKey.from_private_bytes(bytes([47])*32)
    calls=[]
    class Source:
        unavailable=False
        def resolve(self,**kwargs):
            calls.append(("context",kwargs))
            if self.unavailable:raise AdjudicationUnavailable()
            return AuthenticatedAdjudicationContext(rfc8785.dumps(state),b"modeled-approved-schema/issuer/actual-possession/grant/evidence")
    class Adapter:
        invalid=False
        def verify(self,raw,**kwargs):
            calls.append(("token",kwargs))
            if self.invalid:raise AdjudicationInvalid()
            try:
                header,body,signature=raw.decode().split(".")
                if c.unb64(header)!=c.canonical(dict(alg="EdDSA",kid="test-key",typ="ktp-adjudication-test-v1",profile_digest=c.digest(profile,2))):
                    raise AdjudicationInvalid()
                private.public_key().verify(c.unb64(signature),(header+"."+body).encode())
                return AuthenticatedAdjudicationPayload(c.unb64(body),b"real-test-signature/modeled-current-key-role","test-key",profile["issuer"],c.digest(profile,2))
            except (ValueError,InvalidSignature) as error:raise AdjudicationInvalid() from error
    def sign():
        message=(c.b64(c.canonical(dict(alg="EdDSA",kid="test-key",typ="ktp-adjudication-test-v1",profile_digest=c.digest(profile,2))))+"."+c.b64(c.canonical(payload))).encode()
        return message+b"."+c.b64(private.sign(message)).encode()
    source=Source();adapter=Adapter()
    verifier=InstalledAdjudicationVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),rfc8785.dumps(external),source,adapter)
    return dict(verifier=verifier,operation=operation,payload=payload,state=state,source=source,adapter=adapter,profile=profile,external=external,sign=sign,calls=calls,now=now)


def evaluate(f,token=True):
    return f["verifier"].evaluate(f["sign"]() if token else None,actual_operation=f["operation"],evaluated_at=f["now"],clock_healthy=True)


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class AdjudicationTests(unittest.TestCase):
    def test_favorable_unfavorable_and_absence_are_not_measurements(self):
        f=fixture();result=evaluate(f)
        self.assertEqual(result.reason,"ADJ_FAVORABLE")
        self.assertTrue(result.gate_satisfied)
        self.assertEqual(result.expires_at,1006)
        self.assertIsNotNone(result.authenticated_payload_bytes)
        self.assertEqual(result.token_bytes,f["sign"]())
        self.assertEqual(result.verified_key_id,"test-key")
        self.assertNotIn("token",f["calls"][0][1])
        f["payload"]["favorable"]=False
        self.assertEqual(evaluate(f).reason,"ADJ_UNFAVORABLE")
        self.assertFalse(evaluate(f).gate_satisfied)
        absent=evaluate(f,False)
        self.assertEqual(absent.reason,"ADJ_ABSENT")
        self.assertFalse(absent.gate_satisfied)
        self.assertFalse(hasattr(result,"capacity"))

    def test_complete_signed_binding_changes_void_token(self):
        for name in ("actor","action_digest","cnf_jkt","grant_digest","evidence_digest","zone_id","topology_epoch","iss","exp","iat"):
            f=fixture()
            if name=="topology_epoch":f["payload"][name]=4
            elif name=="exp":f["payload"][name]=1000
            elif name=="iat":f["payload"][name]=1001
            elif name.endswith("digest"):f["payload"][name]="sha256:"+"0"*64
            else:f["payload"][name]="urn:other"
            with self.subTest(name=name):
                result=evaluate(f)
                self.assertEqual(result.reason,"ADJ_ABSENT")
                self.assertFalse(result.gate_satisfied)

    def test_correction_and_whole_operation_scope_require_new_token(self):
        f=fixture();old=f["sign"]()
        f["state"]["evidence_digest"]="sha256:"+"0"*64
        self.assertEqual(f["verifier"].evaluate(old,actual_operation=f["operation"],evaluated_at=1000,clock_healthy=True).reason,"ADJ_ABSENT")
        f=fixture();f["operation"]={**f["operation"],"parameters":{"limit":4}}
        self.assertEqual(evaluate(f).reason,"ADJ_UNAVAILABLE")

    def test_invalid_signature_shape_clock_and_source_remain_absent(self):
        f=fixture();f["adapter"].invalid=True
        self.assertEqual(evaluate(f).reason,"ADJ_ABSENT")
        f=fixture();f["payload"]["capacity_multiplier"]=2
        self.assertEqual(evaluate(f).reason,"ADJ_ABSENT")
        f=fixture();f["payload"]["topology_epoch"]=True
        self.assertEqual(evaluate(f).reason,"ADJ_ABSENT")
        f=fixture();f["payload"]["kid"]="other-key"
        self.assertEqual(evaluate(f).reason,"ADJ_ABSENT")
        f=fixture();f["source"].unavailable=True
        self.assertEqual(evaluate(f).reason,"ADJ_UNAVAILABLE")
        f=fixture();result=f["verifier"].evaluate(f["sign"](),actual_operation=f["operation"],evaluated_at=1000,clock_healthy=False)
        self.assertEqual(result.reason,"ADJ_UNAVAILABLE");self.assertEqual(f["calls"],[])
