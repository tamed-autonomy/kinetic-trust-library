import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.geometry_issuance import InstalledGeometryCarrierIssuer


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class GeometryIssuanceTests(unittest.TestCase):
    def test_new_signed_carrier_and_pre_sign_rejection(self):
        import base64
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from kinetic_trust_library.v3.geometry_carrier import InstalledGeometryCarrierVerifier
        from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier, AuthenticatedGeometryReproduction
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier, InstalledSchemaBundle
        root=Path(__file__).parents[3]
        vectors=json.loads((root/"spec/proposals/decision-geometry-v1.json").read_text())
        proofs=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        context=vectors["contexts"]["complete"]
        body=vectors["bodies"]["complete"]
        schemas=[json.loads((root/"src/kinetic_trust_library/v3/schemas"/n).read_text()) for n in
                 ("trust-proof-v3.json","risk-factors-composed-v3.json","soul-constraint-v2.json")]
        bundle=InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas),schemas[0]["$id"])
        pv=InstalledProofVerifier(bundle,rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}),
            rfc8785.dumps(proofs["context"]),("ES256",),lambda p,n:True,fixture_software_default=True)
        class Reproduction:
            def reproduce(self,*,evaluated_at):
                return AuthenticatedGeometryReproduction(rfc8785.dumps(body),rfc8785.dumps(context["request"]),context["proof"],True)
        gv=InstalledGeometryVerifier(Reproduction(),pv,"sha256")
        private=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        key={**vectors["keys"][0],"kid":"native-geometry-test","alg":"EdDSA","curve":"Ed25519",
            "x":base64.urlsafe_b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).rstrip(b"=").decode()}
        key.pop("y")
        verifier=InstalledGeometryCarrierVerifier(rfc8785.dumps({key["kid"]:key}),rfc8785.dumps(context),gv,("EdDSA",))
        class Source:
            raw=rfc8785.dumps(body)
            def produce(self,*,evaluated_at): return self.raw
        source=Source()
        class Signer:
            calls=0
            def sign(self,signing_input,**kwargs):
                self.calls+=1
                return private.sign(signing_input)
        signer=Signer()
        issuer=InstalledGeometryCarrierIssuer(source,signer,verifier,"EdDSA",key["kid"])
        issued=issuer.issue(now=context["now"],clock_healthy=True)
        self.assertEqual(issued.verification.reason,"DG_CARRIER_VALID")
        payload=json.loads(issued.payload_bytes)
        proof_exp=json.loads(base64.urlsafe_b64decode(context["proof"].split(".")[1]+"=="))["exp"]
        self.assertEqual(payload["expires_at"],min(proof_exp,key["not_after"],context["profile_expires_at"],*context.get("supporting_expiries",[])))
        self.assertEqual(payload["geometry"],body)
        self.assertEqual(signer.calls,1)
        for now,healthy in ((context["now"],False),(payload["expires_at"],True)):
            with self.assertRaises(ValidationError): issuer.issue(now=now,clock_healthy=healthy)
        source.raw=rfc8785.dumps({**body,"capacity":{**body["capacity"],"E":46}})
        with self.assertRaisesRegex(ValidationError,"DG_ORDER"):
            issuer.issue(now=context["now"],clock_healthy=True)
        self.assertEqual(signer.calls,1)
        source.raw=rfc8785.dumps(body)
        class BadSigner:
            def sign(self,*args,**kwargs): return bytes(64)
        with self.assertRaisesRegex(ValidationError,"DG_CARRIER_SIGNATURE"):
            InstalledGeometryCarrierIssuer(source,BadSigner(),verifier,"EdDSA",key["kid"]).issue(now=context["now"],clock_healthy=True)


if __name__ == "__main__": unittest.main()
