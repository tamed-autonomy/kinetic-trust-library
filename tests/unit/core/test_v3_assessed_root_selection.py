import json
import unittest
from importlib.util import find_spec
from pathlib import Path
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.installed_root import AuthenticatedRootInstrument, InstalledRootVerifier
from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"), "install v3-proofs")
class AssessedRootSelectionTests(unittest.TestCase):
    def test_zero_strength_current_bond_is_retained_but_cannot_win(self):
        import rfc8785
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        body = vectors["instruments"]["bond"]["body"]
        body["inputs"]["sponsor_e_base"] = 0
        context = rfc8785.dumps(dict(hop_bound=4, subject_profile="software", lineage="sponsored", generation=2, subject=body["subject"]))
        class Adapter:
            def verify(self, *args, **kwargs):
                return AuthenticatedRootInstrument(rfc8785.dumps(body), ())
        root = InstalledRootVerifier(Adapter(), "sha256").evaluate(b"zero bond", context_bytes=context, evaluated_at=1800000004)
        self.assertEqual(json.loads(root.projection_bytes)["kind"], "sponsorship_bond")
        result = select_assessed_roots((root,), context_bytes=context, evaluated_at=1800000004, algorithm="sha256")
        self.assertIsNone(result.selected)
        self.assertEqual(result.candidates, (root,))

    def test_exact_ratios_select_stronger_root_and_reject_mixed_contexts(self):
        import rfc8785
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        body = vectors["instruments"]["attestation"]["body"]
        context = rfc8785.dumps(dict(hop_bound=4, subject_profile="software", lineage="guarantor", generation=7, subject=body["subject"]))
        def assess(n, label, now=1800000004):
            candidate = json.loads(json.dumps(body))
            candidate["id"] = label
            candidate["inputs"]["declared_exposure"] = n
            candidate["inputs"]["anchored_capacity"] = 3*n+1
            class Adapter:
                def verify(self, *args, **kwargs):
                    return AuthenticatedRootInstrument(rfc8785.dumps(candidate), ())
            return InstalledRootVerifier(Adapter(), "sha256").evaluate(label.encode(), context_bytes=context, evaluated_at=now)
        weaker, stronger = assess(10**14, "weaker"), assess(10**14+1, "stronger")
        for ordered in ((weaker, stronger), (stronger, weaker)):
            result = select_assessed_roots(ordered, context_bytes=context, evaluated_at=1800000004, algorithm="sha256")
            self.assertIs(result.selected, stronger)
            self.assertEqual(result.candidates, ordered)
        with self.assertRaises(ValidationError):
            select_assessed_roots((weaker, assess(1, "old", 1800000003)), context_bytes=context,
                                  evaluated_at=1800000004, algorithm="sha256")
        tied = (assess(1, "tie-a"), assess(1, "tie-b"))
        import hashlib
        expected = min(tied, key=lambda root: hashlib.sha256(root.complete_instrument_bytes).hexdigest())
        self.assertIs(select_assessed_roots(tied, context_bytes=context, evaluated_at=1800000004, algorithm="sha256").selected, expected)
        self.assertIsNone(select_assessed_roots((), context_bytes=context, evaluated_at=1800000004, algorithm="sha256").selected)
        with self.assertRaises(ValidationError):
            select_assessed_roots((weaker, weaker), context_bytes=context, evaluated_at=1800000004, algorithm="sha256")


if __name__ == "__main__": unittest.main()
