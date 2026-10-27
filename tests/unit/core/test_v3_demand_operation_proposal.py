"""Native v3 preclassification operation binding from RFC PR #202."""

import base64
import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.demand_operation import (
    canonical_demand_operation_bytes,
    digest_demand_operation,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/demand-supplier-v1.json"
PREFIX = b"KTP/demand-operation-v1\x00"


@unittest.skipUnless(
    find_spec("rfc8785") and find_spec("jsonschema"),
    "install the v3-proofs extra for JCS demand tests",
)
class ProposedDemandOperation(unittest.TestCase):
    def test_published_sha256_and_sha384_known_answers(self):
        vector = json.loads(VECTORS.read_text())
        operation = vector["operation"]
        canonical = canonical_demand_operation_bytes(operation)
        for algorithm, answer in vector["known_answers"].items():
            with self.subTest(algorithm=algorithm):
                self.assertEqual(
                    base64.urlsafe_b64encode(canonical).rstrip(b"=").decode(),
                    answer["canonical_operation_base64url"],
                )
                self.assertEqual(
                    base64.urlsafe_b64encode(PREFIX + canonical).rstrip(b"=").decode(),
                    answer["preimage_base64url"],
                )
                self.assertEqual(
                    digest_demand_operation(operation, algorithm=algorithm),
                    answer["operation_digest"],
                )

    def test_parameters_bound_and_final_demand_excluded(self):
        operation = json.loads(VECTORS.read_text())["operation"]
        changed = {**operation, "parameters": {**operation["parameters"], "overwrite": True}}
        self.assertNotEqual(
            digest_demand_operation(operation, algorithm="sha256"),
            digest_demand_operation(changed, algorithm="sha256"),
        )
        with self.assertRaises(ValidationError):
            canonical_demand_operation_bytes({**operation, "moment_criticality": 0})
        with self.assertRaises(ValidationError):
            canonical_demand_operation_bytes({**operation, "demand": 1})


if __name__ == "__main__":
    unittest.main()
