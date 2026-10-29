"""All published association sequences through installed adapter boundaries."""
import base64
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from threading import Lock
from kinetic_trust_library.v3.request_association import InstalledRequestAssociationVerifier, RequestContextFailure
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier, InstalledSchemaBundle


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class RequestAssociationTests(unittest.TestCase):
    def test_all_published_sequences_with_fixture_atomic_replay(self):
        import rfc8785
        root = Path(__file__).parents[3]
        vectors = json.loads((root / "spec/proposals/request-binding-v1.json").read_text())
        proofs = json.loads((root / "spec/proposals/trust-proof-v3.json").read_text())
        from kinetic_trust_library.v3.request_binding import digest_canonical_request
        for label, supplied, actual, expected in (
            ("nested-bool-number", {"flags":[1,{"x":0}]}, {"flags":[True,{"x":False}]}, "RB_CONTEXT"),
            ("numeric-jcs-equivalence", {"number":1}, {"number":1.0}, "RB_BOUND"),
        ):
            step=json.loads(json.dumps(vectors["cases"][0]["steps"][0]))
            request=json.loads(step["request_json"])
            request["parameters"]=supplied
            actual_request={**request,"parameters":actual}
            association=json.loads(step["association_json"])
            association["request_digest"]=digest_canonical_request(request,algorithm="sha256")
            step.update(request_json=json.dumps(request), association_json=json.dumps(association),
                        context={"actual_request":actual_request}, expected={"reason":expected})
            vectors["cases"].append({"id":label,"steps":[step]})
        schemas = [json.loads((root / "src/kinetic_trust_library/v3/schemas" / name).read_text())
                   for name in ("trust-proof-v3.json","risk-factors-composed-v3.json","soul-constraint-v2.json")]
        bundle = InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas), schemas[0]["$id"])
        class Replay:
            def __init__(self): self.requests,self.proofs,self.lock = {},{},Lock()
            def reserve(self, *, replay_domain, request_id, request_digest, proof_digest, issuer, proof_jti):
                with self.lock:
                    key=(replay_domain,request_id); pair=(request_digest,proof_digest)
                    if key in self.requests:
                        return "RB_REPLAY" if self.requests[key] == pair else "RB_COLLISION"
                    known=self.proofs.get((issuer,proof_jti))
                    if known is not None and known != proof_digest: return "RB_JTI_COLLISION"
                    self.requests[key]=pair; self.proofs[(issuer,proof_jti)]=proof_digest
                    return "RB_BOUND"
        for case in vectors["cases"]:
            replay = Replay()
            for step in case["steps"]:
                with self.subTest(case=case["id"]):
                    context = {**vectors["context"], **step.get("context",{})}
                    proof_context = {**proofs["context"], **context.get("proof_context",{})}
                    proof_verifier = InstalledProofVerifier(bundle,
                        rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}), rfc8785.dumps(proof_context),
                        ("ES256",), lambda payload,now:True, fixture_software_default=True)
                    class Invocation:
                        def reconstruct(self, evidence, *, evaluated_at):
                            actual=context["actual_request"]
                            if actual["subject"] != actual["actor"] and not context["delegation_verified"]:
                                raise RequestContextFailure("RB_CONTEXT")
                            return rfc8785.dumps(actual)
                    class ReplayAdapter:
                        def reserve(self, **kwargs):
                            return replay.reserve(**kwargs) if context["replay_state_ready"] else "RB_REPLAY_STATE"
                    verifier=InstalledRequestAssociationVerifier(Invocation(), proof_verifier, ReplayAdapter(),
                        context["digest_algorithm"], context["crosses_trust_boundary"])
                    request = (base64.urlsafe_b64decode(step["request_base64"]+"="*(-len(step["request_base64"])%4)) if "request_base64" in step
                               else step["request_json"].encode())
                    result=verifier.verify(request, step["association_json"].encode(), step["proof"],
                        invocation_evidence=b"authenticated fixture invocation", now=proof_context["now"], clock_healthy=proof_context["clock_healthy"])
                    self.assertEqual(result.reason,step["expected"]["reason"])
                    self.assertEqual(result.proof_reason,step["expected"].get("proof_reason"))


if __name__ == "__main__": unittest.main()
