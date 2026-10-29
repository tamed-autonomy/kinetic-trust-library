"""Real encryption/signatures with modeled ingest policy and key custody."""
from importlib.util import find_spec
import unittest

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.privacy_issuance import (
    AuthenticatedPrivacyIngest, AuthenticatedPrivacyKeyStorage,
    InstalledPrivacyEvidenceIssuer, IssuedPrivacyEvidence,
)

HAS_EXTRAS = all(find_spec(name) for name in ("rfc8785", "cryptography", "jsonschema"))


def fixture(level=2, kind="Ed25519"):
    from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, ec, utils
    from cryptography.hazmat.primitives import hashes, serialization
    from kinetic_trust_library.v3 import _trajectory_reference as t
    from kinetic_trust_library.v3.privacy_evidence import AuthenticatedPrivacyArchive, AuthenticatedPrivacyAccess
    plaintext = b'{ "original" : "caf\xc3\xa9" }\n'
    context = dict(envelope_id="entry-1", zone_id="zone-1", chain_id="archive-1", purpose_id="review",
                   privacy_policy_digest=t.digest({"approved": "bounded-policy"},level),
                   issuer_id="archive-issuer", conformance_level=level)
    operation = dict(request_id="request-1", subject="urn:person:1", actor="urn:archive:writer",
                     audience="urn:archive:1", operation="urn:operation:archive-evidence",
                     resource="urn:entry:1", parameters={}, replay_domain="urn:replay:archive")
    if kind in ("ES256", "ES384"):
        size = 32 if kind == "ES256" else 48
        private = ec.derive_private_key(31, ec.SECP256R1() if size == 32 else ec.SECP384R1())
        numbers = private.public_key().public_numbers()
        jwk = dict(kty="EC",crv="P-256" if size == 32 else "P-384",
                   x=t.b64(numbers.x.to_bytes(size,"big")),y=t.b64(numbers.y.to_bytes(size,"big")))
        algorithm = kind
    else:
        private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([31])*32) if kind == "Ed25519" else ed448.Ed448PrivateKey.from_private_bytes(bytes([31])*57)
        jwk = dict(kty="OKP", crv=kind, x=t.b64(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)))
        algorithm = "EdDSA"
    keys = {"archive-key":dict(jwk,kid="archive-key",subject="archive-issuer",zone_id="zone-1",purpose=t.PRIVACY_EVIDENCE_TYPE,
                              alg=algorithm,revoked=False,not_before=50,not_after=150)}
    metadata = dict(envelope_id="entry-1",zone_id="zone-1",chain_id="archive-1",purpose_id="review",privacy_policy_digest=context["privacy_policy_digest"],
                    issuer_id="archive-issuer",sequence=1,previous_hash=None,created_at=110,delete_after=200)
    state = dict(context=context,operation=operation,checked_at=110,plaintext_digest=t.digest_bytes(plaintext,level),
                 metadata=metadata,kid="archive-key",algorithm=algorithm)
    calls=[]
    class Ingest:
        def resolve(self, **kwargs):
            calls.append(("ingest",kwargs))
            return AuthenticatedPrivacyIngest(t.canonical(state),t.canonical(keys),b"modeled-current-ingest-policy")
    class Signer:
        bad=False
        def sign(self, message, *, algorithm, kid):
            calls.append(("sign",message))
            if self.bad:return bytes(64)
            if algorithm in ("ES256","ES384"):
                r,s=utils.decode_dss_signature(private.sign(message,ec.ECDSA(hashes.SHA256() if size==32 else hashes.SHA384())))
                return r.to_bytes(size,"big")+min(s,t.ORDERS[algorithm]-s).to_bytes(size,"big")
            return private.sign(message)
    class Storage:
        bad=False
        def __init__(self):self.keys={};self.contexts={}
        def store(self,data_key,*,context_bytes):
            context_body=t.strict_loads(context_bytes)
            calls.append(("store",context_body))
            self.keys[context_body["key_ref"]]=data_key
            self.contexts[context_body["key_ref"]]=context_body
            if self.bad:context_body["key_digest"]=t.digest_bytes(bytes(32),level)
            return AuthenticatedPrivacyKeyStorage(t.canonical(context_body),b"modeled-durable-key-custody")
    storage=Storage();signer=Signer()
    issuer=InstalledPrivacyEvidenceIssuer(t.canonical(context),Ingest(),signer,storage)
    class Archive:
        envelope=None
        def resolve(self,**kwargs):
            e=self.envelope
            archive_state=dict(context=context,checked_at=kwargs["checked_at"],anchor=dict(sequence=e["sequence"],previous_hash=e["previous_hash"],record_hash=e["record_hash"]))
            return AuthenticatedPrivacyArchive(t.canonical(archive_state),t.canonical(keys),b"modeled-committed-anchor")
    class Access:
        def authorize_and_resolve_key(self,**kwargs):
            envelope=t.strict_loads(kwargs["envelope_bytes"])
            access=dict(context=context,operation=operation,record_hash=envelope["record_hash"],key_ref=envelope["encryption"]["key_ref"],checked_at=kwargs["checked_at"],expires_at=200)
            return AuthenticatedPrivacyAccess(t.canonical(access),storage.keys[access["key_ref"]],b"modeled-read-access")
    return dict(t=t,issuer=issuer,plaintext=plaintext,context=context,operation=operation,metadata=metadata,state=state,keys=keys,
                signer=signer,storage=storage,calls=calls,archive=Archive(),access=Access())


def issue(f):
    return f["issuer"].issue(f["plaintext"],actual_operation=f["operation"],now=110,clock_healthy=True)


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class PrivacyIssuanceTests(unittest.TestCase):
    def test_declared_maximum_plaintext_fits_verifier_and_recovers_exact_bytes(self):
        from kinetic_trust_library.v3.privacy_evidence import InstalledPrivacyEvidenceVerifier,InstalledPrivacyEvidenceReader
        f=fixture()
        f["plaintext"]=bytes(range(256))*256
        f["state"]["plaintext_digest"]=f["t"].digest_bytes(f["plaintext"],2)
        issued=issue(f)
        self.assertLessEqual(len(issued.envelope_bytes),262144)
        f["archive"].envelope=f["t"].strict_loads(issued.envelope_bytes)
        verifier=InstalledPrivacyEvidenceVerifier(f["t"].canonical(f["context"]),f["archive"])
        recovered=InstalledPrivacyEvidenceReader(verifier,f["access"]).open(issued.envelope_bytes,actual_operation=f["operation"],now=110,clock_healthy=True)
        self.assertEqual(recovered.plaintext_bytes,f["plaintext"])

    def test_new_keys_nonces_and_refs_with_no_key_or_plaintext_in_result(self):
        f=fixture()
        first,second=issue(f),issue(f)
        self.assertEqual(first.reason,"PRIVACY_ENVELOPE_SIGNED_UNANCHORED")
        a,b=(f["t"].strict_loads(item.envelope_bytes) for item in (first,second))
        for field in ("key_ref","nonce","ciphertext"):
            self.assertNotEqual(a["encryption"][field],b["encryption"][field])
        self.assertNotEqual(f["storage"].keys[a["encryption"]["key_ref"]],f["storage"].keys[b["encryption"]["key_ref"]])
        self.assertNotIn("data_key",repr(first))
        self.assertNotIn("original",first.envelope_bytes.decode())
        self.assertNotIn("plaintext",f["calls"][0][1])
        self.assertEqual([kind for kind,_ in f["calls"]],["ingest","sign","store"]*2)
        with self.assertRaises(TypeError):IssuedPrivacyEvidence()

    def test_issued_envelope_full_verify_and_exact_read_all_classical_profiles(self):
        from kinetic_trust_library.v3.privacy_evidence import InstalledPrivacyEvidenceVerifier,InstalledPrivacyEvidenceReader
        for level,kind in ((1,"ES256"),(2,"Ed25519"),(2,"ES384"),(3,"ES384"),(3,"Ed448")):
            with self.subTest(level=level,kind=kind):
                f=fixture(level,kind)
                issued=issue(f)
                f["archive"].envelope=f["t"].strict_loads(issued.envelope_bytes)
                verifier=InstalledPrivacyEvidenceVerifier(f["t"].canonical(f["context"]),f["archive"])
                self.assertEqual(verifier.verify(issued.envelope_bytes,now=110,clock_healthy=True).reason,"PRIVACY_OUTER_INTEGRITY_ONLY")
                result=InstalledPrivacyEvidenceReader(verifier,f["access"]).open(issued.envelope_bytes,actual_operation=f["operation"],now=110,clock_healthy=True)
                self.assertEqual(result.plaintext_bytes,f["plaintext"])

    def test_invalid_ingest_cannot_reach_signing_or_storage(self):
        for mode in ("plaintext","operation","context","time","created","deadline","position","kid","role","revoked","key-time","extra"):
            f=fixture()
            if mode=="plaintext":f["state"]["plaintext_digest"]=f["t"].digest_bytes(b"other",2)
            elif mode=="operation":f["state"]["operation"]=dict(f["operation"],subject="urn:person:other")
            elif mode=="context":f["state"]["context"]=dict(f["context"],purpose_id="other-purpose")
            elif mode=="time":f["state"]["checked_at"]=109
            elif mode=="created":f["metadata"]["created_at"]=109
            elif mode=="deadline":f["metadata"]["delete_after"]=110
            elif mode=="position":f["metadata"]["sequence"]=2
            elif mode=="kid":f["state"]["kid"]="unknown"
            elif mode=="role":f["keys"]["archive-key"]["purpose"]=f["t"].AGENT_TYPE
            elif mode=="revoked":f["keys"]["archive-key"]["revoked"]=True
            elif mode=="key-time":f["keys"]["archive-key"]["not_after"]=110
            else:f["metadata"]["names"]=["private-name"]
            with self.subTest(mode=mode),self.assertRaises(ValidationError):issue(f)
            self.assertEqual([kind for kind,_ in f["calls"]],["ingest"])

    def test_bad_signature_and_storage_ack_are_not_emitted(self):
        f=fixture();f["signer"].bad=True
        with self.assertRaises(ValidationError):issue(f)
        self.assertEqual([kind for kind,_ in f["calls"]],["ingest","sign"])
        f=fixture();f["storage"].bad=True
        with self.assertRaises(ValidationError):issue(f)
        self.assertEqual([kind for kind,_ in f["calls"]],["ingest","sign","store"])

    def test_unhealthy_clock_oversize_empty_and_level3_downgrade(self):
        f=fixture()
        for plaintext,clock in ((f["plaintext"],False),(b"",True),(bytes(65537),True)):
            with self.assertRaises(ValidationError):f["issuer"].issue(plaintext,actual_operation=f["operation"],now=110,clock_healthy=clock)
        self.assertEqual(f["calls"],[])
        for kind in ("ES256","Ed25519"):
            f=fixture(3,kind)
            with self.assertRaises(ValidationError):issue(f)
            self.assertEqual([kind for kind,_ in f["calls"]],["ingest"])
