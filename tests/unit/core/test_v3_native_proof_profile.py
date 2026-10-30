import base64
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from dataclasses import replace
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle, RootProofBinding
from kinetic_trust_library.v3.installed_root import InstalledRootVerifier, AuthenticatedRootInstrument


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class NativeProofProfileTests(unittest.TestCase):
    def test_signed_foreign_bond_proof_refreshes_current_support(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from kinetic_trust_library.v3.live_root import InstalledLiveRootVerifier,AuthenticatedRootInventory
        from tests.unit.core.test_v3_federated_sponsorship import fixture
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/trust-proof-v3.json").read_text())
        ctx={**vectors["context"],"subject_kind":"software_agent","required_ceilings":{"generation":25,"zone_mass":90}}
        now=ctx["now"]
        cross,state,body,instrument,root_context=fixture(subject="agent:sponsored:acme:aria:1234",receiving_zone=ctx["zone"],now=now)
        class Adapter:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone=state["home_zone"])
        policy=InstalledRootVerifier(Adapter(),"sha256",federated_sponsorship_verifier=cross)
        assessed=policy.evaluate(instrument,context_bytes=root_context,evaluated_at=now)
        payload=json.loads(base64.urlsafe_b64decode(next(c["jws"] for c in vectors["cases"] if c["id"]=="clear").split(".")[1]+"=="))
        payload.update(sub=body["subject"],iat=now,exp=now+5)
        payload["ktp"].update(subject_kind="software_agent",generation=0,lineage="sponsored",sponsor=body["issuer"],
            e_base=20,e_trust=15,root_instrument=json.loads(assessed.projection_bytes),applicable_ceilings=[dict(ceiling="generation",value=25),
            dict(ceiling="zone_mass",value=90),dict(ceiling="federated_sponsor",value=72),dict(ceiling=assessed.federated_sponsorship.credit_ceiling_name,value=72)])
        ctx["subject"]=body["subject"]
        class Inventory:
            def resolve(self,*,context_bytes,evaluated_at):return AuthenticatedRootInventory((instrument,),b"modeled-complete-current-inventory",context_bytes,evaluated_at)
        live=InstalledLiveRootVerifier(policy,Inventory(),root_context,ctx["zone"])
        verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({k["kid"]:k for k in vectors["keys"]}),rfc8785.dumps(ctx),("EdDSA",),live)
        enc=lambda value:base64.urlsafe_b64encode(value).rstrip(b"=")
        message=enc(rfc8785.dumps(dict(alg="EdDSA",kid="TEST-ed25519",typ="ktp-trust-proof+jwt")))+b"."+enc(rfc8785.dumps(payload))
        compact=(message+b"."+enc(Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(message))).decode()
        verified=verifier.verify(compact,now=now,clock_healthy=True)
        self.assertEqual(verified.reason,"TP_CLEAR",str((json.loads(assessed.projection_bytes),verified.root_verification)))
        state["current"]["lent_withdrawn"]=True
        self.assertEqual(verifier.verify(compact,now=now,clock_healthy=True).reason,"TP_INVARIANT")

    def test_fresh_native_signed_proof_closed_root_and_no_credit_cap(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json").read_text())
        clear = next(c for c in vectors["cases"] if c["id"] == "clear")
        segment = clear["jws"].split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(segment+"="*(-len(segment)%4)))
        payload["ktp"]["subject_kind"] = "software_agent"
        payload["ktp"]["root_instrument"] = {"kind":"none","status":"none","reason":"missing"}
        context = {**vectors["context"], "subject_kind":"software_agent"}
        roots = select_assessed_roots((), context_bytes=rfc8785.dumps({"subject":context["subject"], "subject_profile":"software"}),
            evaluated_at=context["now"], algorithm="sha256")
        verifier = InstalledProofVerifier(native_schema_bundle(),
            rfc8785.dumps({k["kid"]: k for k in vectors["keys"]}), rfc8785.dumps(context),
            ("ES256","EdDSA"), RootProofBinding(roots, context["zone"]))
        with self.assertRaises(ValidationError):
            replace(verifier, expected_context_bytes=rfc8785.dumps({k:v for k,v in vectors["context"].items() if k!="subject_kind"}))
        def signed():
            enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
            header = {"alg":"EdDSA","kid":"TEST-ed25519","typ":"ktp-trust-proof+jwt"}
            raw = enc(rfc8785.dumps(header))+b"."+enc(rfc8785.dumps(payload))
            return (raw+b"."+enc(Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(raw))).decode()
        compact = signed()
        self.assertEqual(verifier.verify(compact, now=context["now"], clock_healthy=True).reason, "TP_CLEAR")
        payload["ktp"]["root_instrument"]["diagnostic_ref"] = "urn:root:missing-evidence"
        self.assertEqual(verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_CLEAR")
        payload["ktp"]["applicable_ceilings"].pop()
        self.assertEqual(verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_INVARIANT")
        payload["ktp"]["root_instrument"] = {"status":"none"}
        self.assertEqual(verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_SCHEMA")
        root_vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        instrument = root_vectors["instruments"]["attestation"]
        class Adapter:
            def verify(self, *args, **kwargs):
                return AuthenticatedRootInstrument(rfc8785.dumps(instrument["body"]), (), issuer_zone=context["zone"])
        root_context = rfc8785.dumps(dict(subject=context["subject"], subject_profile="software", lineage="guarantor", generation=7, hop_bound=4))
        raw = instrument["complete_bytes_base64url"]
        assessed = InstalledRootVerifier(Adapter(), "sha256").evaluate(
            base64.urlsafe_b64decode(raw+"="*(-len(raw)%4)), context_bytes=root_context, evaluated_at=context["now"])
        selected = select_assessed_roots((assessed,), context_bytes=root_context, evaluated_at=context["now"], algorithm="sha256")
        active_context=dict(context,required_ceilings={k:v for k,v in context["required_ceilings"].items() if k!="external_root_missing"})
        active_verifier = replace(verifier, root_verifier=RootProofBinding(selected, context["zone"]),expected_context_bytes=rfc8785.dumps(active_context))
        payload["ktp"]["root_instrument"] = json.loads(assessed.projection_bytes)
        self.assertEqual(active_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_CLEAR")
        payload["ktp"]["root_instrument"]["declared_exposure"] += 1
        self.assertEqual(active_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_INVARIANT")
        instrument = root_vectors["instruments"]["bond"]
        subject = instrument["body"]["subject"]
        root_context = rfc8785.dumps(dict(subject=subject, subject_profile="software", lineage="sponsored", generation=2, hop_bound=4))
        raw = instrument["complete_bytes_base64url"]
        assessed = InstalledRootVerifier(Adapter(), "sha256").evaluate(
            base64.urlsafe_b64decode(raw+"="*(-len(raw)%4)), context_bytes=root_context, evaluated_at=context["now"])
        selected = select_assessed_roots((assessed,), context_bytes=root_context, evaluated_at=context["now"], algorithm="sha256")
        expected_context = {**context, "subject":subject, "required_ceilings":{"generation":45,"zone_mass":90}}
        bond_verifier = replace(verifier, root_verifier=RootProofBinding(selected, context["zone"]), expected_context_bytes=rfc8785.dumps(expected_context))
        payload["sub"] = subject
        payload["ktp"].update(generation=2, lineage="sponsored", sponsor=instrument["body"]["issuer"], e_base=40, e_trust=30,
            root_instrument=json.loads(assessed.projection_bytes), applicable_ceilings=[{"ceiling":"generation","value":45},{"ceiling":"zone_mass","value":90}])
        self.assertEqual(bond_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_CLEAR")
        payload["ktp"]["sponsor"] = "agent:guarantor:7gen:other:other"
        self.assertEqual(bond_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_INVARIANT")
        person = "person:acct:zone:1234"
        instrument = json.loads(json.dumps(root_vectors["instruments"]["attestation"]))
        instrument["body"].update(subject=person, root_person=person)
        root_context = rfc8785.dumps(dict(subject=person, subject_profile="person", hop_bound=4))
        assessed = InstalledRootVerifier(Adapter(), "sha256").evaluate(
            b"authenticated person instrument fixture", context_bytes=root_context, evaluated_at=context["now"])
        selected = select_assessed_roots((assessed,), context_bytes=root_context, evaluated_at=context["now"], algorithm="sha256")
        person_context = {**context, "subject":person, "subject_kind":"person", "required_ceilings":{"receiving_zone":85}}
        person_verifier = replace(verifier, root_verifier=RootProofBinding(selected, context["zone"]), expected_context_bytes=rfc8785.dumps(person_context))
        payload["sub"] = person
        for field in ("generation","lineage","advancement_floor","sponsor"):
            payload["ktp"].pop(field, None)
        payload["ktp"].update(subject_kind="person", root_instrument=json.loads(assessed.projection_bytes),
            applicable_ceilings=[{"ceiling":"receiving_zone","value":85}])
        self.assertEqual(person_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_CLEAR")
        payload["ktp"]["generation"] = 7
        self.assertEqual(person_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_SCHEMA")
        payload["ktp"].pop("generation")
        cross_kind = replace(person_verifier, expected_context_bytes=rfc8785.dumps({**person_context, "subject_kind":"software_agent"}))
        self.assertEqual(cross_kind.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_INVARIANT")
        payload["ktp"]["root_instrument"]["root_person"] = "person:acct:zone:other"
        self.assertEqual(person_verifier.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_INVARIANT")
        empty = select_assessed_roots((), context_bytes=root_context, evaluated_at=context["now"], algorithm="sha256")
        no_credit_person = replace(person_verifier, root_verifier=RootProofBinding(empty, context["zone"]))
        payload["ktp"]["root_instrument"] = {"kind":"none","status":"none","reason":"missing"}
        self.assertEqual(no_credit_person.verify(signed(), now=context["now"], clock_healthy=True).reason, "TP_CLEAR")


if __name__ == "__main__": unittest.main()
