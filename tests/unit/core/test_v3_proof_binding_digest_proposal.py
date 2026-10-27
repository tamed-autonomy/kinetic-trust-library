"""Provisional exact-proof digest checks from RFC PR #196."""

import json
import unittest
from importlib.util import find_spec
import base64
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.request_binding import (
    canonical_request_bytes,
    digest_canonical_request,
    digest_complete_proof,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/request-binding-v1.json"


class ProposedProofBindingDigest(unittest.TestCase):
    @unittest.skipUnless(
        find_spec("rfc8785") and find_spec("jsonschema"),
        "install the v3-proofs extra for JCS request tests",
    )
    def test_published_request_canonical_bytes_and_digests(self):
        vectors = json.loads(VECTORS.read_text())
        self.assertEqual(len(vectors["known_answers"]), 2)
        for index, answer in enumerate(vectors["known_answers"]):
            with self.subTest(answer=index):
                canonical = canonical_request_bytes(answer["request"])
                encoded = base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii")
                self.assertEqual(encoded, answer["canonical_utf8_base64url"])
                for algorithm in ("sha256", "sha384"):
                    self.assertEqual(
                        digest_canonical_request(answer["request"], algorithm=algorithm),
                        answer[algorithm]["request_digest"],
                    )

    def test_published_known_answers_for_complete_proof(self):
        vectors = json.loads(VECTORS.read_text())
        self.assertGreaterEqual(len(vectors["known_answers"]), 1)
        for index, answer in enumerate(vectors["known_answers"]):
            for algorithm in ("sha256", "sha384"):
                with self.subTest(answer=index, algorithm=algorithm):
                    self.assertEqual(
                        digest_complete_proof(answer["proof"], algorithm=algorithm),
                        answer[algorithm]["proof_digest"],
                    )

    def test_exact_signature_bytes_are_bound(self):
        proof = json.loads(VECTORS.read_text())["known_answers"][0]["proof"]
        altered = proof[:-1] + ("A" if proof[-1] != "A" else "B")
        self.assertNotEqual(
            digest_complete_proof(proof, algorithm="sha256"),
            digest_complete_proof(altered, algorithm="sha256"),
        )

    @unittest.skipUnless(
        find_spec("rfc8785") and find_spec("jsonschema"),
        "install the v3-proofs extra for JCS request tests",
    )
    def test_request_order_is_canonical_but_content_is_bound(self):
        request = json.loads(VECTORS.read_text())["known_answers"][0]["request"]
        reordered = dict(reversed(list(request.items())))
        self.assertEqual(
            digest_canonical_request(request, algorithm="sha256"),
            digest_canonical_request(reordered, algorithm="sha256"),
        )
        changed = {**request, "parameters": {**request["parameters"], "overwrite": True}}
        self.assertNotEqual(
            digest_canonical_request(request, algorithm="sha256"),
            digest_canonical_request(changed, algorithm="sha256"),
        )
        with self.assertRaises(ValidationError):
            canonical_request_bytes({**request, "unrecognized": True})

    def test_only_bounded_compact_ascii_and_named_algorithms(self):
        for proof, algorithm in (
            ("abc.def", "sha256"), ("abc..def", "sha256"),
            ("abc.def.ghi=", "sha256"), ("é.abc.def", "sha256"),
            ("abc.def.ghi", "md5"), ("abc.def.ghi", "SHA256"),
            ("a" * 65537, "sha256"),
        ):
            with self.subTest(proof=proof[:12], algorithm=algorithm):
                with self.assertRaises(ValidationError):
                    digest_complete_proof(proof, algorithm=algorithm)


if __name__ == "__main__":
    unittest.main()
