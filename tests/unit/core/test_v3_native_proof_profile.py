import base64
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from dataclasses import replace
from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle, RootProofBinding
from kinetic_trust_library.v3.installed_root import InstalledRootVerifier, AuthenticatedRootInstrument


@unittest.skipUnless(all(find_spec(m) for m in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class NativeProofProfileTests(unittest.TestCase):
    def test_fresh_native_signed_proof_closed_root_and_no_credit_cap(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json").read_text())
        clear = next(c for c in vectors["cases"] if c["id"] == "clear")
        segment = clear["jws"].split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(segment+"="*(-len(segment)%4)))
        payload["ktp"]["subject_kind"] = "software_agent"
        payload["ktp"]["root_instrument"] = {"kind":"none","status":"none","reason":"missing"}
        payload["ktp"]["applicable_ceilings"].append({"ceiling":"external_root_missing","value":70})
        context = vectors["context"]
        roots = select_assessed_roots((), context_bytes=rfc8785.dumps({"subject":context["subject"]}),
            evaluated_at=context["now"], algorithm="sha256")
        verifier = InstalledProofVerifier(native_schema_bundle(),
            rfc8785.dumps({k["kid"]: k for k in vectors["keys"]}), rfc8785.dumps(context),
            ("ES256","EdDSA"), RootProofBinding(roots, context["zone"]))
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
                return AuthenticatedRootInstrument(rfc8785.dumps(instrument["body"]), ())
        root_context = rfc8785.dumps(dict(subject=context["subject"], subject_profile="software", lineage="guarantor", generation=7, hop_bound=4))
        raw = instrument["complete_bytes_base64url"]
        assessed = InstalledRootVerifier(Adapter(), "sha256").evaluate(
            base64.urlsafe_b64decode(raw+"="*(-len(raw)%4)), context_bytes=root_context, evaluated_at=context["now"])
        selected = select_assessed_roots((assessed,), context_bytes=root_context, evaluated_at=context["now"], algorithm="sha256")
        active_verifier = replace(verifier, root_verifier=RootProofBinding(selected, context["zone"]))
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


if __name__ == "__main__": unittest.main()
