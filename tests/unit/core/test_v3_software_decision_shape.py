from copy import deepcopy
from importlib.util import find_spec
from pathlib import Path
import json
import unittest
from kinetic_trust_library.errors import ValidationError,ProofFormatError


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class SoftwareDecisionShapeTests(unittest.TestCase):
    def test_all_26_exact_published_shape_vectors(self):
        import rfc8785
        from kinetic_trust_library.v3.software_decision_shape import parse_software_decision,software_decision_validator
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/software-substrate-execution.json").read_text())
        for case in vectors["schemaVectors"]:
            candidate=deepcopy(vectors["schemaFixture"])
            mutation=case.get("mutation")
            if mutation:
                parent=candidate
                for part in mutation["path"][:-1]:parent=parent[part]
                if mutation["operation"]=="remove":del parent[mutation["path"][-1]]
                else:parent[mutation["path"][-1]]=mutation["value"]
            with self.subTest(case=case["id"]):
                self.assertEqual(software_decision_validator().is_valid(candidate),case["expect"]["schemaValid"])
                if case["expect"]["schemaValid"]:self.assertEqual(parse_software_decision(rfc8785.dumps(candidate)),candidate)
                else:
                    raw=json.dumps(candidate,sort_keys=True,separators=(",",":")).encode("utf-8")
                    with self.assertRaises((ValidationError,ProofFormatError)):parse_software_decision(raw)

    def test_representation_checks_exceed_schema_only_integer_semantics(self):
        import rfc8785
        from kinetic_trust_library.v3.software_decision_shape import parse_software_decision
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/software-substrate-execution.json").read_text())
        raw=rfc8785.dumps(vectors["schemaFixture"])
        for malformed in (raw.replace(b'"consumption_epoch":1',b'"consumption_epoch":1.0'),
                raw.replace(b'"evaluated_at":100',b'"evaluated_at":100.0'),raw.replace(b'"max":1024',b'"max":1024.0'),
                raw.replace(b'"consumption_epoch":1',b'"consumption_epoch":1,"consumption_epoch":1'),raw+b'\n'):
            with self.subTest(malformed=malformed[:30]),self.assertRaises((ValidationError,ProofFormatError)):parse_software_decision(malformed)

    def test_false_availability_remains_shape_valid_and_never_proves_permission(self):
        import rfc8785
        from kinetic_trust_library.v3.software_decision_shape import parse_software_decision
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/software-substrate-execution.json").read_text())
        candidate=vectors["schemaFixture"];candidate["result"].update(repairPathVerified=False,supervisionAvailable=False)
        self.assertFalse(parse_software_decision(rfc8785.dumps(candidate))["result"]["repairPathVerified"])
