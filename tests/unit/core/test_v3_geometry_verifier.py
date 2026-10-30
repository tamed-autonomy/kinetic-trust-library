import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier, AuthenticatedGeometryReproduction
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier, InstalledSchemaBundle


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class GeometryVerifierTests(unittest.TestCase):
    def test_published_bodies_and_explicitly_recorded_source_preimage_defects(self):
        import rfc8785
        root=Path(__file__).parents[3]
        vectors=json.loads((root/"spec/proposals/decision-geometry-v1.json").read_text())
        proofs=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        schemas=[json.loads((root/"src/kinetic_trust_library/v3/schemas"/n).read_text()) for n in
                 ("trust-proof-v3.json","risk-factors-native-v3.json","soul-constraint-v2.json","root-instrument-v3.json")]
        bundle=InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas),schemas[0]["$id"])
        for case in vectors["body_cases"]:
            with self.subTest(case=case["id"]):
                context={**vectors["contexts"][case["context"]],**case.get("context_overrides",{})}
                expected=json.loads(json.dumps(vectors["bodies"][case["context"]]))
                for key,field in (("gates","expected_gates"),("inputs","expected_inputs"),("result","expected_result"),("reason_codes","expected_reasons")):
                    expected[key]=context[field]
                if expected["gates"]["consumer"]=="passed" and "consumer_result" not in expected:
                    expected["consumer_result"]=json.loads(json.dumps(expected["result"]))
                class Source:
                    def reproduce(self, *, evaluated_at):
                        return AuthenticatedGeometryReproduction(rfc8785.dumps(expected),rfc8785.dumps(context["request"]),context["proof"],context["clock_healthy"])
                pv=InstalledProofVerifier(bundle,rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}),
                    rfc8785.dumps(proofs["context"]),("ES256",),lambda p,n:True,fixture_software_default=True)
                verifier=InstalledGeometryVerifier(Source(),pv,context["digest_algorithm"])
                body=json.loads(json.dumps(vectors["bodies"][case["base"]]))
                for mutation in case.get("mutations",[]):
                    target=body
                    for key in mutation["path"][:-1]: target=target[int(key) if type(target) is list else key]
                    key=mutation["path"][-1]
                    if type(target) is list: key=int(key)
                    if mutation.get("remove"): target.pop(key,None)
                    else: target[key]=mutation["value"]
                raw=case.get("raw_json",json.dumps(body)).encode()
                result=verifier.verify(raw,evaluated_at=context["identity"]["evaluated_at"])
                if case["id"] in ("over-capacity","equality"):
                    # These exact upstream records still bind the old unit's
                    # request preimage. Never weaken verification to pass them.
                    import hashlib
                    from kinetic_trust_library.v3.request_binding import digest_canonical_request
                    old_request=json.loads(json.dumps(context["request"]))
                    old_request["demand"]["unit"]="ktp-action-risk-points"
                    old_digest="sha256:"+hashlib.sha256(b"KTP/request-binding-v1\0"+rfc8785.dumps(old_request)).hexdigest()
                    self.assertEqual(body["association"]["request_digest"],old_digest)
                    self.assertEqual(result.reason,"DG_BINDING")
                    # Separately exercise a locally corrected unsigned body;
                    # retained source bytes and manifest hashes stay untouched.
                    corrected=digest_canonical_request(context["request"],algorithm=context["digest_algorithm"])
                    body["association"]["request_digest"]=expected["association"]["request_digest"]=corrected
                    self.assertEqual(verifier.verify(rfc8785.dumps(body),evaluated_at=context["identity"]["evaluated_at"]).reason,"DG_VALID")
                    continue
                self.assertEqual(result.reason,case["expected"])


if __name__ == "__main__": unittest.main()
