import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
from kinetic_trust_library.v3.demand_supplier import _digest
from kinetic_trust_library.v3.installed_standing import AuthenticatedStandingEvidence, InstalledStandingVerifier


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"), "install v3-proofs")
class InstalledStandingTests(unittest.TestCase):
    def test_derived_ceilings_no_root_cap_and_context_binding(self):
        import rfc8785
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/demand-supplier-v1.json").read_text())
        profile, operation = vectors["deployment_profile"], vectors["operation"]
        for generation, expected in ((0, 25), (7, 70)):
            lineage = "sponsored" if generation < 3 else "guarantor"
            body = dict(subject=operation["subject"], generation=generation, identity_assurance_level=3,
                        trajectory_length=20000, por_contribution=70, peer_score=0,
                        maximum_adversity_friction=.8, crisis_exposure=False, additional_ceilings={})
            class Adapter:
                def verify(self, *args, **kwargs):
                    if "root_selection" not in kwargs:
                        raise AssertionError("provider cannot check the supplied candidate inventory")
                    self_selection = kwargs["root_selection"]
                    if self_selection is not roots:
                        raise AssertionError("standing provider received another candidate set")
                    return AuthenticatedStandingEvidence(rfc8785.dumps(body))
            root_context = rfc8785.dumps(dict(subject=operation["subject"], subject_profile="software",
                generation=generation, lineage=lineage, hop_bound=3, deployment_digest=_digest(profile,"sha256")))
            roots = select_assessed_roots((), context_bytes=root_context, evaluated_at=1030, algorithm="sha256")
            installed = InstalledStandingVerifier(rfc8785.dumps(profile), Adapter(), "sha256")
            result = installed.evaluate(b"standing evidence", roots=roots, actual_operation=operation, evaluated_at=1030)
            self.assertEqual(result.base.base_trust, expected)
            self.assertEqual(dict(result.base.ceilings)["ial"], 95)
            self.assertIs(result.roots, roots)
            self.assertEqual(result.original_evidence, b"standing evidence")
            for friction, crisis, ceiling in ((.5, False, 60), (.7, False, 80), (.9, True, 100)):
                body["maximum_adversity_friction"] = friction
                body["crisis_exposure"] = crisis
                boundary = installed.evaluate(b"standing evidence", roots=roots, actual_operation=operation, evaluated_at=1030)
                self.assertEqual(dict(boundary.base.ceilings)["adversity"], ceiling)
            with self.assertRaises(ValidationError):
                installed.evaluate(b"standing evidence", roots=roots, actual_operation=operation, evaluated_at=1031)


if __name__ == "__main__": unittest.main()
