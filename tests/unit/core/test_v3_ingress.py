"""Real fixture receipt signatures; modeled topology/session/key authority."""
from importlib.util import find_spec
from dataclasses import replace
import copy
import unittest

from kinetic_trust_library.v3.ingress import (
    AuthenticatedIngressContext, AuthenticatedIngressReceipt, InstalledIngressVerifier,
    IngressUnavailable, IngressReceiptInvalid,
)

HAS_EXTRAS=all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography"))
NOW=1800000000


def fixture(depth=2, *, evaluated_at=NOW):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from kinetic_trust_library.v3 import _trajectory_reference as t
    profile=dict(id="urn:unsafe-test:ingress-jcs-ed25519",version=1,signature="embedded-JWS-over-JCS-body",link="sha256-of-complete-JCS-receipt",link_digest_algorithm="sha256")
    subject="agent:guarantor:7gen:optimized:a1b2c3d4"
    context=dict(subject=subject,issuing_zone="zone-"+str(depth),receiving_zone="zone-"+str(depth),receipt_profile_id=profile["id"],receipt_profile_digest=t.digest(profile,2),conformance_level=2)
    rings=[dict(zone_id="zone-"+str(i),enforcement_class=("green","cyan","blue","deep_blue")[min(i,3)],
                enclosure_reach="0" if i==0 else "0.5",registry_enclosure_reach="0" if i==0 else "0.5",oracle_kids=["key-"+str(i)]) for i in range(depth+1)]
    session=dict(sub=subject,cnf_jkt="test-possession-key",admission_id="admission-1",expires_at=evaluated_at+8)
    state=dict(context=context,checked_at=evaluated_at,topology=dict(epoch=5,rings=rings),session=session)
    private={"key-"+str(i):Ed25519PrivateKey.from_private_bytes(bytes([i+1])*32) for i in range(depth)}
    receipts=[dict(zone_id=rings[i]["zone_id"],oracle_kid="key-"+str(i),sub=subject,cnf_jkt=session["cnf_jkt"],aud=rings[i+1]["zone_id"],
                   prev=None,topology_epoch=5,iat=evaluated_at-1,exp=evaluated_at+9,admission_id=session["admission_id"],sig="pending") for i in range(depth)]
    def sign_path(link=True):
        previous=None
        for receipt in receipts:
            if link:receipt["prev"]=previous
            body={k:v for k,v in receipt.items() if k!="sig"}
            message=(t.b64(t.canonical(dict(alg="EdDSA",kid=receipt["oracle_kid"],typ="ktp-ingress-test-v1")))+"."+t.b64(t.canonical(body))).encode()
            receipt["sig"]=message.decode()+"."+t.b64(private[receipt["oracle_kid"]].sign(message))
            previous=t.digest(receipt,2)
    sign_path()
    calls=[]
    class Topology:
        unavailable=False
        def resolve(self,**kwargs):
            calls.append(("state",kwargs))
            if self.unavailable:raise IngressUnavailable()
            return AuthenticatedIngressContext(t.canonical(state),b"modeled-governance/current-topology/actual-possession-session")
    class ReceiptVerifier:
        invalid=False
        def verify(self,raw,**kwargs):
            calls.append(("receipt",kwargs))
            receipt=t.strict_loads(raw)
            body={k:v for k,v in receipt.items() if k!="sig"}
            key=private.get(receipt["oracle_kid"])
            if self.invalid or key is None:raise IngressReceiptInvalid()
            from cryptography.exceptions import InvalidSignature
            try:
                header,payload,signature=receipt["sig"].split(".")
                expected=dict(alg="EdDSA",kid=receipt["oracle_kid"],typ="ktp-ingress-test-v1")
                if t.unb64(header)!=t.canonical(expected) or t.unb64(payload)!=t.canonical(body):
                    raise IngressReceiptInvalid()
                key.public_key().verify(t.unb64(signature),(header+"."+payload).encode())
            except (t.InvalidRecord,ValueError,InvalidSignature) as error:raise IngressReceiptInvalid() from error
            return AuthenticatedIngressReceipt(raw,t.digest(receipt,2),b"unsafe-test-profile-real-signature/current-role")
    source=Topology();adapter=ReceiptVerifier()
    verifier=InstalledIngressVerifier(t.canonical(context),t.canonical(profile),source,adapter)
    payload=dict(sub=subject,exp=evaluated_at+10,ktp=dict(zone=context["receiving_zone"]))
    if depth:payload["ktp"]["ingress_path"]=receipts
    return dict(t=t,profile=profile,context=context,rings=rings,state=state,session=session,receipts=receipts,payload=payload,
                source=source,adapter=adapter,verifier=verifier,calls=calls,sign=sign_path)


def check(f):
    return f["verifier"].verify(f["t"].canonical(f["payload"]),now=NOW,clock_healthy=True)


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class IngressTests(unittest.TestCase):
    def test_issuing_zone_can_differ_from_authenticated_receiving_ring(self):
        f=fixture()
        f["context"]["issuing_zone"]="zone-1"
        f["payload"]["ktp"]["zone"]="zone-1"
        f["verifier"]=replace(f["verifier"],context_bytes=f["t"].canonical(f["context"]))
        self.assertEqual(check(f).reason,"INGRESS_VERIFIED")
        f["payload"]["ktp"]["zone"]="zone-0"
        self.assertEqual(check(f).reason,"INGRESS_INVALID")

    def test_ordinary_proof_retains_fresh_ingress_and_rejects_boolean_shortcut(self):
        import json,base64
        from pathlib import Path
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
        from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        f=fixture()
        f["context"]["issuing_zone"]="zone-1"
        f["verifier"]=replace(f["verifier"],context_bytes=f["t"].canonical(f["context"]))
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/trust-proof-v3.json").read_text())
        case=next(c for c in vectors["cases"] if c["id"]=="clear")
        payload=json.loads(base64.urlsafe_b64decode(case["jws"].split(".")[1]+"=="))
        context={**vectors["context"],"subject_kind":"software_agent","ring_depth":2}
        context.update(subject=f["context"]["subject"],zone=f["context"]["issuing_zone"],receiving_zone=f["context"]["receiving_zone"])
        context["now"]=NOW
        payload.update(sub=context["subject"],iat=NOW,exp=NOW+10)
        payload["ktp"].update(zone=context["zone"],subject_kind="software_agent",ingress_path=f["receipts"],
            root_instrument=dict(kind="none",status="none",reason="missing"))
        keys={k["kid"]:dict(k,zone=context["zone"],not_before=NOW-10,not_after=NOW+100) for k in vectors["keys"]}
        verifier=InstalledProofVerifier(native_schema_bundle(),f["t"].canonical(keys),f["t"].canonical(context),("ES256","EdDSA"),
            lambda raw,now:True,ingress_policy=f["verifier"])
        class Source:
            def produce(self,**kwargs):return f["t"].canonical(payload)
        class Signer:
            def sign(self,message,**kwargs):return Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(message)
        issued=InstalledProofIssuer(Source(),Signer(),verifier,"EdDSA","TEST-ed25519").issue(now=NOW,clock_healthy=True)
        evidence=issued.verification.ingress_verification
        self.assertEqual(evidence.reason,"INGRESS_VERIFIED")
        self.assertEqual(evidence.payload_bytes,issued.payload_bytes)
        shortcut=replace(verifier,ingress_policy=None,ingress_verifier=lambda path:True)
        self.assertEqual(shortcut.verify(issued.compact,now=NOW,clock_healthy=True).reason,"TP_INGRESS")
        f["state"]["topology"]["epoch"]+=1
        self.assertEqual(verifier.verify(issued.compact,now=NOW,clock_healthy=True).reason,"TP_INGRESS")

    def test_complete_paths_depth_zero_through_five(self):
        for depth in range(6):
            f=fixture(depth)
            result=check(f)
            self.assertEqual((result.reason,result.depth),("INGRESS_VERIFIED",depth))
            self.assertEqual(result.expires_at,NOW+8)
            self.assertEqual(result.payload_bytes,f["t"].canonical(f["payload"]))
            self.assertEqual(len(result.receipts),depth)
            self.assertNotIn("payload_bytes",f["calls"][0][1])
            self.assertIsNotNone(result.source_evidence_bytes)

    def test_missing_wrong_session_epoch_audience_subject_and_links(self):
        for mode in ("missing","empty","session","possession","epoch","audience","subject","link","expired","future"):
            f=fixture()
            receipt=f["receipts"][-1]
            if mode=="missing":f["payload"]["ktp"].pop("ingress_path")
            elif mode=="empty":f["receipts"].clear()
            elif mode=="session":receipt["admission_id"]="other-admission"
            elif mode=="possession":receipt["cnf_jkt"]="other-possession-key"
            elif mode=="epoch":receipt["topology_epoch"]=4
            elif mode=="audience":receipt["aud"]="other-zone"
            elif mode=="subject":receipt["sub"]="agent:7gen:optimized:other"
            elif mode=="link":receipt["prev"]=f["t"].digest({},2)
            elif mode=="expired":receipt["exp"]=NOW
            else:receipt["iat"]=NOW+1
            f["sign"](link=False)
            with self.subTest(mode=mode):self.assertEqual(check(f).reason,"INGRESS_INVALID")

    def test_topology_class_depth_reach_and_epoch_are_independently_current(self):
        for mode in ("seven","cycle","zero-reach","zero-registry-reach","duplicate","quarantine","receiver","session-expired","stale"):
            f=fixture()
            if mode=="seven":f["rings"].extend(copy.deepcopy(f["rings"])*2)
            elif mode=="cycle":f["rings"][-1]["enforcement_class"]="green"
            elif mode=="zero-reach":f["rings"][-1]["enclosure_reach"]="0"
            elif mode=="zero-registry-reach":f["rings"][-1]["registry_enclosure_reach"]="0"
            elif mode=="duplicate":f["rings"][1]["zone_id"]=f["rings"][0]["zone_id"]
            elif mode=="quarantine":f["rings"][1]["enforcement_class"]="quarantine"
            elif mode=="receiver":f["rings"][-1]["zone_id"]="wrong-receiver"
            elif mode=="session-expired":f["session"]["expires_at"]=NOW
            else:f["state"]["checked_at"]=NOW-1
            with self.subTest(mode=mode):self.assertEqual(check(f).reason,"INGRESS_UNAVAILABLE" if mode=="stale" else "INGRESS_INVALID")

    def test_unavailable_oracle_never_shortens_path_and_real_signature_required(self):
        f=fixture();f["source"].unavailable=True
        self.assertEqual(check(f).reason,"INGRESS_UNAVAILABLE")
        self.assertEqual([kind for kind,_ in f["calls"]],["state"])
        f=fixture();f["adapter"].invalid=True
        self.assertEqual(check(f).reason,"INGRESS_INVALID")
        f=fixture();f["receipts"][0]["sig"]+="x"
        self.assertEqual(check(f).reason,"INGRESS_INVALID")
        f=fixture();f["rings"][0]["oracle_kids"]=[]
        result=check(f)
        self.assertNotEqual(result.reason,"INGRESS_VERIFIED")
        self.assertEqual(len(f["rings"]),3)

    def test_zero_depth_path_is_absent_and_unhealthy_clock_stops_sources(self):
        f=fixture(0);f["payload"]["ktp"]["ingress_path"]=[]
        self.assertEqual(check(f).reason,"INGRESS_INVALID")
        f=fixture()
        result=f["verifier"].verify(f["t"].canonical(f["payload"]),now=NOW,clock_healthy=False)
        self.assertEqual(result.reason,"INGRESS_UNAVAILABLE")
        self.assertEqual(f["calls"],[])
