"""Installed root boundary with authenticated fixture-body adapter."""
import base64
import hashlib
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.installed_root import AuthenticatedRootInstrument, InstalledRootVerifier
from kinetic_trust_library.v3.root_lifecycle import RootLifecycleEvent


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"), "install v3-proofs")
class InstalledRootTests(unittest.TestCase):
    def test_adapter_operational_errors_are_not_lifecycle_findings(self):
        import rfc8785
        class Broken:
            def verify(self, *args, **kwargs):
                raise ValueError("source unavailable")
        with self.assertRaisesRegex(ValueError, "source unavailable"):
            InstalledRootVerifier(Broken(), "sha256").evaluate(
                b"evidence", context_bytes=rfc8785.dumps({"hop_bound": 4}), evaluated_at=10)

    def test_generation_binding_and_repeating_score_handoff(self):
        import rfc8785
        from kinetic_trust_library.v3.base_trust import calculate_native_base_trust
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        body = vectors["instruments"]["attestation"]["body"]
        body["inputs"]["declared_exposure"] = 1
        body["inputs"]["anchored_capacity"] = 3
        class Adapter:
            def verify(self, evidence, **kwargs):
                return AuthenticatedRootInstrument(rfc8785.dumps(body), ())
        verifier = InstalledRootVerifier(Adapter(), "sha256")
        context = dict(hop_bound=4, subject_profile="software", lineage="guarantor", generation=7, subject=body["subject"])
        result = verifier.evaluate(b"authenticated fixture", context_bytes=rfc8785.dumps(context), evaluated_at=1800000004)
        standing = calculate_native_base_trust(por_contribution=70, root_score=result.score,
            peer_share=0, peer_score=0, ceilings=dict(generation=100, ial=95, trajectory=100, adversity=100))
        self.assertGreater(standing.base_trust, 70)
        self.assertEqual((result.score_numerator, result.score_denominator), (100, 3))
        for generation in (0, None, True):
            invalid = {**context, "lineage": "independent", "generation": generation}
            assessed = verifier.evaluate(b"authenticated fixture", context_bytes=rfc8785.dumps(invalid), evaluated_at=1800000004)
            self.assertEqual(assessed.score, 0)

    def test_published_deterministic_projection_cases(self):
        import rfc8785
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        cases = [c for c in vectors["projection_cases"] if set(c["given"]) <= {
            "instrument", "now", "hop_bound", "subject_profile", "lineage", "generation", "subject", "events", "proof_exp", "proof_sponsor", "candidate_projection"}]
        for case in cases:
            with self.subTest(case=case["id"]):
                given = case["given"]
                instrument = vectors["instruments"][given["instrument"]]
                events = []
                for name in given["events"]:
                    event = vectors["events"][name]
                    body = event["body"]
                    events.append(RootLifecycleEvent(
                        "sha256:" + hashlib.sha256(event["jws"].encode()).hexdigest(),
                        body["instrument_digest"], body["subject"], body["event_time"],
                        body["action"], body.get("claim_digest"), body.get("finding")))
                class Adapter:
                    def verify(self, evidence, *, context_bytes, evaluated_at):
                        return AuthenticatedRootInstrument(rfc8785.dumps(instrument["body"]), tuple(events))
                verifier = InstalledRootVerifier(Adapter(), "sha256")
                raw = instrument["complete_bytes_base64url"]
                evidence = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
                context = {k: v for k, v in given.items() if k not in ("instrument", "events", "now")}
                result = verifier.evaluate(evidence, context_bytes=rfc8785.dumps(context), evaluated_at=given["now"])
                self.assertEqual(json.loads(result.projection_bytes), case["expected"]["projection"])
                self.assertEqual(result.score > 0, case["expected"]["rootCreditEligible"])
                self.assertEqual(result.complete_instrument_bytes, evidence)


if __name__ == "__main__": unittest.main()
