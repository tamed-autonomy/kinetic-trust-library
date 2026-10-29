import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.schema_formats import installed_format_checker


@unittest.skipUnless(find_spec("jsonschema") and find_spec("rfc8785"), "install v3-proofs")
class SchemaFormatTests(unittest.TestCase):
    def test_uri_enforcement_does_not_depend_on_optional_jsonschema_formats(self):
        checker=installed_format_checker()
        for value in ("example-minimal","https://host.invalid/a b","urn:bad%xx"):
            with self.subTest(uri=value): self.assertFalse(checker.conforms(value,"uri"))
        for value in ("urn:ktp:classifier:example","https://example.com/a%20b","agent:guarantor:7gen:optimized:a1b2c3d4"):
            with self.subTest(uri=value): self.assertTrue(checker.conforms(value,"uri"))
        from kinetic_trust_library.v3.request_binding import canonical_request_bytes
        root=Path(__file__).parents[3]
        request=json.loads((root/"spec/proposals/request-binding-v1.json").read_text())["base_request"]
        canonical_request_bytes(request)
        request["classification_profile"]["id"]="example-minimal"
        with self.assertRaises(ValidationError): canonical_request_bytes(request)


if __name__ == "__main__": unittest.main()
