import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.geometry_carrier import InstalledGeometryCarrierVerifier
from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier, AuthenticatedGeometryReproduction
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier, InstalledSchemaBundle


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class GeometryCarrierTests(unittest.TestCase):
    def test_all_published_signed_carriers(self):
        import rfc8785
        root=Path(__file__).parents[3]
        vectors=json.loads((root/"spec/proposals/decision-geometry-v1.json").read_text())
        proofs=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        schemas=[json.loads((root/"src/kinetic_trust_library/v3/schemas"/n).read_text()) for n in
                 ("trust-proof-v3.json","risk-factors-composed-v3.json","soul-constraint-v2.json")]
        bundle=InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas),schemas[0]["$id"])
        for case in vectors["carrier_cases"]:
            with self.subTest(case=case["id"]):
                context={**vectors["contexts"][case["context"]],**case.get("context_overrides",{})}
                expected=vectors["bodies"][case["context"]]
                class Source:
                    def reproduce(self, *, evaluated_at):
                        return AuthenticatedGeometryReproduction(rfc8785.dumps(expected),rfc8785.dumps(context["request"]),context["proof"],True)
                pv=InstalledProofVerifier(bundle,rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}),
                    rfc8785.dumps(proofs["context"]),("ES256",),lambda p,n:True,fixture_software_default=True)
                body_verifier=InstalledGeometryVerifier(Source(),pv,context["digest_algorithm"])
                carrier=InstalledGeometryCarrierVerifier(rfc8785.dumps({k["kid"]:k for k in vectors["keys"]}),
                    rfc8785.dumps(context),body_verifier,(context["signature_algorithm"],))
                result=carrier.verify(case["jws"],now=context["now"],clock_healthy=context["clock_healthy"])
                self.assertEqual(result.reason,case["expected"])
                self.assertEqual(result.compact,case["jws"])


if __name__ == "__main__": unittest.main()
