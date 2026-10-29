import base64
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from dataclasses import replace
from kinetic_trust_library.v3.live_root import InstalledLiveRootVerifier, AuthenticatedRootInventory, RootInventoryUnavailable


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class LiveRootTests(unittest.TestCase):
    def test_unaccepted_stronger_foreign_bond_cannot_displace_local_candidate(self):
        import rfc8785
        from copy import deepcopy
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        from tests.unit.core.test_v3_federated_sponsorship import fixture
        _,_,foreign,foreign_raw,raw_context=fixture()
        context=json.loads(raw_context);context.pop("receiving_zone");context.pop("federated_sponsorship_profile_digest")
        local=deepcopy(foreign);local.update(id="local:bond",issuer="urn:local:sponsor");local["inputs"]["sponsor_e_base"]=50
        class Adapter:
            def verify(self,evidence,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(local if evidence==b"local" else foreign),(),
                issuer_zone="zone-b" if evidence==b"local" else "zone-a")
        root=InstalledRootVerifier(Adapter(),"sha256")
        selected=root.evaluate(b"local",context_bytes=rfc8785.dumps({**context,"receiving_zone":"zone-b"}),evaluated_at=1000)
        payload=rfc8785.dumps(dict(sub=local["subject"],exp=1007,ktp=dict(zone="zone-b",subject_kind="software_agent",generation=0,
            lineage="sponsored",sponsor=local["issuer"],root_instrument=json.loads(selected.projection_bytes),applicable_ceilings=[])))
        class Inventory:
            def resolve(self,*,context_bytes,evaluated_at):return AuthenticatedRootInventory((foreign_raw,b"local"),b"modeled-complete-inventory",context_bytes,evaluated_at)
        live=InstalledLiveRootVerifier(root,Inventory(),rfc8785.dumps(context),"zone-b")
        result=live.evaluate(payload,evaluated_at=1000)
        self.assertTrue(result.valid)
        self.assertEqual(json.loads(result.selection.selected.projection_bytes)["bond_id"],"local:bond")

    def test_refresh_within_proof_lifetime_and_current_withdrawal(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
        from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier
        from tests.unit.core._v3_root_fixture import RootFixtureAdapter
        root=Path(__file__).parents[3]
        proofs=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        root_vectors=json.loads((root/"spec/proposals/external-root-v1.json").read_text())
        instrument=root_vectors["instruments"]["attestation"]
        original=next(c["jws"] for c in proofs["cases"] if c["id"]=="clear")
        payload=json.loads(base64.urlsafe_b64decode(original.split(".")[1]+"=="))
        payload["ktp"]["subject_kind"]="software_agent"
        context={**proofs["context"],"subject_kind":"software_agent"}
        now=context["now"]
        raw=base64.urlsafe_b64decode(instrument["complete_bytes_base64url"]+"==")
        root_context=rfc8785.dumps(dict(subject=context["subject"],subject_profile="software",generation=7,lineage="guarantor",hop_bound=4))
        instrument_adapter=RootFixtureAdapter(root_vectors)
        iv=InstalledRootVerifier(instrument_adapter,"sha256")
        assessed=iv.evaluate(raw,context_bytes=root_context,evaluated_at=now)
        payload["ktp"]["root_instrument"]=json.loads(assessed.projection_bytes)
        class Inventory:
            calls=[]
            stale=False
            unavailable=False
            def resolve(self,*,context_bytes,evaluated_at):
                self.calls.append(evaluated_at)
                if self.unavailable:raise RootInventoryUnavailable()
                return AuthenticatedRootInventory((raw,),b"fixture-authenticated-complete-inventory",context_bytes,
                    now if self.stale else evaluated_at,"missing")
        inventory=Inventory()
        live=InstalledLiveRootVerifier(iv,inventory,root_context,context["zone"])
        self.assertEqual(json.loads(live.context_bytes)["receiving_zone"],context["zone"])
        verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({k["kid"]:k for k in proofs["keys"]}),rfc8785.dumps(context),
            ("ES256","EdDSA"),live)
        def signed():
            enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b"=")
            message=enc(rfc8785.dumps(dict(alg="EdDSA",kid="TEST-ed25519",typ="ktp-trust-proof+jwt")))+b"."+enc(rfc8785.dumps(payload))
            return (message+b"."+enc(Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(message))).decode()
        compact=signed()
        for current in (now,now+1):
            result=verifier.verify(compact,now=current,clock_healthy=True)
            if current==now:cached=result.root_verification
            self.assertEqual(result.reason,"TP_CLEAR")
            self.assertEqual(result.root_verification.checked_at,current)
            self.assertEqual(result.root_verification.inventory_evidence_bytes,b"fixture-authenticated-complete-inventory")
        self.assertEqual(inventory.calls,[now,now+1])
        original_base,original_trust=payload["ktp"]["e_base"],payload["ktp"]["e_trust"]
        payload["ktp"].update(e_base=55,e_trust=40)
        cached_verifier=replace(verifier,root_verifier=lambda p,n:cached)
        self.assertEqual(cached_verifier.verify(signed(),now=now,clock_healthy=True).reason,"TP_INVARIANT")
        payload["ktp"].update(e_base=original_base,e_trust=original_trust)
        inventory.stale=True
        self.assertEqual(verifier.verify(compact,now=now+1,clock_healthy=True).reason,"TP_INVARIANT")
        inventory.stale=False;inventory.unavailable=True
        unavailable=verifier.verify(compact,now=now+1,clock_healthy=True)
        self.assertEqual(unavailable.reason,"TP_INVARIANT")
        self.assertEqual(unavailable.root_verification.reason,"ROOT_UNAVAILABLE")
        inventory.unavailable=False
        instrument_adapter.event_jws=(root_vectors["events"]["attestation-for-cause"]["jws"],)
        withdrawn=verifier.verify(compact,now=now+2,clock_healthy=True)
        self.assertEqual(withdrawn.reason,"TP_INVARIANT")
        self.assertIsNone(withdrawn.root_verification.selection.selected)
        count=len(inventory.calls)
        self.assertEqual(verifier.verify(compact,now=payload["exp"],clock_healthy=True).reason,"TP_TIME")
        self.assertEqual(len(inventory.calls),count)
        signature=compact.split(".")[2]
        broken=".".join(compact.split(".")[:2])+"."+("B" if signature[0]=="A" else "A")+signature[1:]
        self.assertEqual(verifier.verify(broken,now=now,clock_healthy=True).reason,"TP_SIGNATURE")
        self.assertEqual(len(inventory.calls),count)


if __name__ == "__main__":unittest.main()
