import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from dataclasses import replace
from kinetic_trust_library.v3.carrier_association import AssociationGeometryCarrier
from kinetic_trust_library.v3.geometry_carrier import InstalledGeometryCarrierVerifier
from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier, AuthenticatedGeometryReproduction
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier, InstalledSchemaBundle
from kinetic_trust_library.v3.request_association import InstalledRequestAssociationVerifier


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class CarrierAssociationTests(unittest.TestCase):
    def test_exact_carrier_binding_precedes_replay_and_retains_restrictions(self):
        import rfc8785
        root=Path(__file__).parents[3]
        vectors=json.loads((root/"spec/proposals/decision-geometry-v1.json").read_text())
        proofs=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        context=vectors["contexts"]["complete"]
        schemas=[json.loads((root/"src/kinetic_trust_library/v3/schemas"/n).read_text()) for n in
                 ("trust-proof-v3.json","risk-factors-native-v3.json","soul-constraint-v2.json","root-instrument-v3.json")]
        pv=InstalledProofVerifier(InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas),schemas[0]["$id"]),
            rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}),rfc8785.dumps(proofs["context"]),
            ("ES256",),lambda p,n:True,fixture_software_default=True)
        class Source:
            def reproduce(self, *, evaluated_at):
                return AuthenticatedGeometryReproduction(rfc8785.dumps(vectors["bodies"]["complete"]),rfc8785.dumps(context["request"]),context["proof"],True)
        carrier=InstalledGeometryCarrierVerifier(rfc8785.dumps({k["kid"]:k for k in vectors["keys"]}),
            rfc8785.dumps(context),InstalledGeometryVerifier(Source(),pv,"sha256"))
        compact=next(c["jws"] for c in vectors["carrier_cases"] if c["id"]=="valid-carrier")
        bridge=AssociationGeometryCarrier(compact,carrier)
        class Invocation:
            def reconstruct(self,*args,**kwargs): return rfc8785.dumps(context["request"])
        class Replay:
            calls=0
            def reserve(self,**kwargs): self.calls+=1; return "RB_BOUND"
        replay=Replay()
        verifier=InstalledRequestAssociationVerifier(Invocation(),pv,replay,"sha256",True,bridge)
        body=vectors["bodies"]["complete"]
        def associate(now):
            return verifier.verify(rfc8785.dumps(context["request"]),rfc8785.dumps(body["association"]),context["proof"],
                invocation_evidence=b"authenticated invocation",now=now,clock_healthy=True)
        expired=associate(context["now"]+5)
        self.assertEqual(expired.reason,"RB_CARRIER")
        self.assertEqual(replay.calls,0)
        accepted=associate(context["now"])
        self.assertEqual(accepted.reason,"RB_BOUND")
        self.assertEqual(replay.calls,1)
        self.assertEqual(accepted.carrier_binding.compact_carrier,compact)
        geometry=json.loads(accepted.carrier_binding.canonical_geometry_bytes)
        self.assertEqual(geometry["result"],body["result"])
        class ClaimedFlag:
            def verify(self,**kwargs): return True
        flagged=replace(verifier,carrier_verifier=ClaimedFlag()).verify(
            rfc8785.dumps(context["request"]),rfc8785.dumps(body["association"]),context["proof"],
            invocation_evidence=b"authenticated invocation",now=context["now"],clock_healthy=True)
        self.assertEqual(flagged.reason,"RB_CARRIER")
        self.assertEqual(replay.calls,1)
        proof=pv.verify(context["proof"],now=context["now"],clock_healthy=True)
        changed={**context["request"],"resource":"urn:changed"}
        self.assertIsNone(bridge.verify(canonical_request_bytes=rfc8785.dumps(changed),
            canonical_association_bytes=rfc8785.dumps(body["association"]),proof=proof,now=context["now"],clock_healthy=True))


if __name__ == "__main__": unittest.main()
