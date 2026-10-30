import unittest
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier, AuthenticatedSoulResponse
from kinetic_trust_library.v3.core_projection import NativeCoreContext, project_classified_native_core


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"), "install v3-proofs")
class InstalledSoulTests(unittest.TestCase):
    def test_installed_frameworks_evidence_and_missing_query_are_retained(self):
        import rfc8785
        from tests.unit.core.test_v3_deployment_declaration import fixture
        from tests.unit.core._v3_declaration_fixture import complete_core_declaration,fixture_boundary
        declaration=fixture();declaration["soul_veto"]={"frameworks":["one","two"]}
        operation = dict(subject="urn:s", actor="urn:a", audience="urn:z", operation="urn:op", resource="urn:r", parameters={}, request_id="1", replay_domain="urn:replay")
        complete_core_declaration(declaration,operation)
        profile=rfc8785.dumps(declaration)
        class Adapter:
            def query(self, *, required_frameworks, **kwargs):
                self.required = required_frameworks
                return (AuthenticatedSoulResponse("one", "veto", b"signed veto"),)
        adapter = Adapter()
        result = InstalledSoulVerifier(profile, adapter, "sha256").evaluate(actual_operation=operation, evaluated_at=10)
        self.assertEqual(adapter.required, ("one", "two"))
        self.assertEqual(result.gate.state, "veto")
        self.assertEqual(result.gate.undefined_inputs[0].input, "two")
        self.assertEqual(result.responses[0].evidence_bytes, b"signed veto")
        core = project_classified_native_core(result, standing=object(), environment=object(), demand=object(),
            context=NativeCoreContext(profile, rfc8785.dumps(operation), 10, "sha256"),boundary=fixture_boundary(declaration,operation,10))
        self.assertIsNone(core.capacity)
        self.assertIs(core.soul_assessment, result)
        with self.assertRaisesRegex(ValidationError, "Soul assessment belongs"):
            project_classified_native_core(result, standing=object(), environment=object(), demand=object(),
                context=NativeCoreContext(profile, rfc8785.dumps(operation), 11, "sha256"),boundary=fixture_boundary(declaration,operation,11))
        class EmptyClear:
            def query(self, **kwargs):
                return (AuthenticatedSoulResponse("one", "clear", b""),)
        with self.assertRaises(ValidationError):
            InstalledSoulVerifier(profile, EmptyClear(), "sha256").evaluate(actual_operation=operation, evaluated_at=10)


if __name__ == "__main__": unittest.main()
