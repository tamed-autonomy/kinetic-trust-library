"""Current-use checks must not reaccept an ordinary replay."""
import json,unittest
from pathlib import Path
from importlib.util import find_spec


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class ExistingAssociationTests(unittest.TestCase):
    def test_current_reserved_invocation_is_separate_from_ordinary_reacceptance(self):
        import rfc8785
        from kinetic_trust_library.v3.request_association import InstalledRequestAssociationVerifier
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier,InstalledSchemaBundle
        from kinetic_trust_library.v3.existing_association import InstalledExistingAssociationVerifier,AuthenticatedExistingAssociation
        from kinetic_trust_library.v3.demand_supplier import _digest
        root=Path(__file__).parents[3]
        v=json.loads((root/"spec/proposals/request-binding-v1.json").read_text());proofs=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        step=v["cases"][0]["steps"][0];ctx=v["context"];pc=proofs["context"];now=pc["now"]
        schemas=[json.loads((root/"src/kinetic_trust_library/v3/schemas"/n).read_text()) for n in
            ("trust-proof-v3.json","risk-factors-native-v3.json","soul-constraint-v2.json","root-instrument-v3.json")]
        pv=InstalledProofVerifier(InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas),schemas[0]["$id"]),
            rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}),rfc8785.dumps(pc),("ES256",),lambda p,n:True,fixture_software_default=True)
        class Invocation:
            def reconstruct(self,*args,**kwargs):return rfc8785.dumps(ctx["actual_request"])
        class Replay:
            def __init__(self):self.calls=0
            def reserve(self,**kwargs):self.calls+=1;return "RB_BOUND" if self.calls==1 else "RB_REPLAY"
        replay=Replay();av=InstalledRequestAssociationVerifier(Invocation(),pv,replay,"sha256")
        def accept():return av.verify(step["request_json"].encode(),step["association_json"].encode(),step["proof"],
            invocation_evidence=b"actual invocation",now=now,clock_healthy=True)
        accepted=accept();self.assertEqual(accepted.reason,"RB_BOUND");self.assertEqual(accept().reason,"RB_REPLAY")
        p=dict(id="existing:a",version=1,zone=pc["zone"],formula="reserved-invocation-current-use-v1",registry="registry:replay",maximum_recheck_seconds=2)
        association=json.loads(accepted.canonical_association_bytes)
        state=dict(profile_digest=_digest(p,"sha256"),registry=p["registry"],registry_epoch=1,state_revision=1,
            replay_domain=ctx["actual_request"]["replay_domain"],request_id=ctx["actual_request"]["request_id"],
            request_digest=association["request_digest"],proof_digest=association["proof_digest"],
            issuer=pc["issuer"],proof_jti=association["proof_jti"],reservation_anchor="audit:accepted-invocation",
            accepted_at=now,checked_at=now,expires_at=now+2,status="active")
        class Source:
            def resolve(self,**kwargs):return AuthenticatedExistingAssociation(rfc8785.dumps(state),b"modeled current complete protected reservation")
        current=InstalledExistingAssociationVerifier(av,rfc8785.dumps(p),Source())
        use=current.verify(accepted,invocation_evidence=b"actual invocation",now=now,clock_healthy=True)
        self.assertEqual(use.reason,"RB_CURRENT");self.assertEqual(replay.calls,2)
        self.assertIsNotNone(use.reservation_state_bytes)
        state["status"]="retired"
        self.assertEqual(current.verify(use,invocation_evidence=b"actual invocation",now=now,clock_healthy=True).reason,"RB_RESERVATION_UNAVAILABLE")
        state["status"]="active";state["registry_epoch"]=0
        from kinetic_trust_library.errors import ValidationError
        with self.assertRaises(ValidationError):current.verify(use,invocation_evidence=b"actual invocation",now=now,clock_healthy=True)
