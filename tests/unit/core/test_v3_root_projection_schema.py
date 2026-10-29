import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.root_projection import validate_root_projection


@unittest.skipUnless(find_spec("jsonschema"), "install v3-proofs for root schema tests")
class RootProjectionSchemaTests(unittest.TestCase):
    def test_all_closed_union_cases(self):
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        for case in vectors["schema_cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate_root_projection(case["value"]), case["schemaAccepted"])


if __name__ == "__main__": unittest.main()
