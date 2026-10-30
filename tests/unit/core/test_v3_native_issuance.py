import base64
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle, RootProofBinding
from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class NativeIssuanceTests(unittest.TestCase):
    def test_native_proof_issue_verify_and_bad_signer_rejection(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/trust-proof-v3.json").read_text())
        clear=next(c for c in vectors["cases"] if c["id"]=="clear")
        segment=clear["jws"].split(".")[1]
        payload=json.loads(base64.urlsafe_b64decode(segment+"="*(-len(segment)%4)))
        payload["ktp"].update(subject_kind="software_agent",root_instrument={"kind":"none","status":"none","reason":"missing"})
        context={**vectors["context"],"subject_kind":"software_agent"}
        roots=select_assessed_roots((),context_bytes=rfc8785.dumps({"subject":context["subject"],"subject_profile":"software"}),evaluated_at=context["now"],algorithm="sha256")
        verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({k["kid"]:k for k in vectors["keys"]}),
            rfc8785.dumps(context),("ES256","EdDSA"),RootProofBinding(roots,context["zone"]))
        class Source:
            def produce(self,*,evaluated_at): return rfc8785.dumps(payload)
        class Signer:
            calls=0
            def sign(self,signing_input,*,algorithm,kid):
                self.calls+=1
                return Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(signing_input)
        signer=Signer()
        issuer=InstalledProofIssuer(Source(),signer,verifier,"EdDSA","TEST-ed25519")
        result=issuer.issue(now=context["now"],clock_healthy=True)
        self.assertEqual(result.verification.reason,"TP_CLEAR")
        self.assertEqual(result.payload_bytes,rfc8785.dumps(payload))
        self.assertEqual(signer.calls,1)
        with self.assertRaises(ValidationError): issuer.issue(now=context["now"],clock_healthy=False)
        self.assertEqual(signer.calls,1)
        class BadSigner:
            def sign(self, signing_input, *, algorithm, kid): return bytes(64)
        with self.assertRaisesRegex(ValidationError, "TP_SIGNATURE"):
            InstalledProofIssuer(Source(),BadSigner(),verifier,"EdDSA","TEST-ed25519").issue(
                now=context["now"],clock_healthy=True)
        with self.assertRaisesRegex(ValidationError, "TP_TIME"):
            issuer.issue(now=payload["exp"],clock_healthy=True)
        self.assertEqual(signer.calls,1)
        with self.assertRaisesRegex(ValidationError, "TP_KEY_UNTRUSTED"):
            InstalledProofIssuer(Source(),signer,verifier,"EdDSA","missing").issue(
                now=context["now"],clock_healthy=True)
        self.assertEqual(signer.calls,1)
        payload["ktp"]["extra"]=True
        with self.assertRaises(ValidationError): issuer.issue(now=context["now"],clock_healthy=True)
        self.assertEqual(signer.calls,1)


if __name__ == "__main__": unittest.main()
