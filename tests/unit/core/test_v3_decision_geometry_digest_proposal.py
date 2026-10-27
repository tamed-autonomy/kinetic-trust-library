"""Provisional Decision Geometry body digest from RFC PR #197."""

import base64
import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.decision_geometry import (
    canonical_geometry_bytes,
    digest_geometry_body,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/decision-geometry-v1.json"
PREFIX = b"KTP/decision-geometry-v1\x00"


@unittest.skipUnless(
    find_spec("rfc8785") and find_spec("jsonschema"),
    "install the v3-proofs extra for JCS geometry tests",
)
class ProposedDecisionGeometryDigest(unittest.TestCase):
    def test_published_known_answers(self):
        answers = json.loads(VECTORS.read_text())["known_answers"]
        self.assertEqual(len(answers), 2)
        for index, answer in enumerate(answers):
            with self.subTest(answer=index):
                canonical = canonical_geometry_bytes(answer["body"])
                self.assertEqual(
                    base64.urlsafe_b64encode(canonical).rstrip(b"=").decode(),
                    answer["canonical_base64url"],
                )
                self.assertEqual(
                    base64.urlsafe_b64encode(PREFIX + canonical).rstrip(b"=").decode(),
                    answer["preimage_base64url"],
                )
                for algorithm in ("sha256", "sha384"):
                    self.assertEqual(
                        digest_geometry_body(answer["body"], algorithm=algorithm),
                        answer[algorithm],
                    )

    def test_object_order_is_canonical_and_result_changes_digest(self):
        body = json.loads(VECTORS.read_text())["known_answers"][0]["body"]
        reordered = dict(reversed(list(body.items())))
        self.assertEqual(
            digest_geometry_body(body, algorithm="sha256"),
            digest_geometry_body(reordered, algorithm="sha256"),
        )
        with self.assertRaises(ValidationError):
            canonical_geometry_bytes({**body, "executed": True})


if __name__ == "__main__":
    unittest.main()
