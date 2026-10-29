"""Installed adapter integration against every RFC demand supplier case."""

import base64
import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.v3.installed_demand import (
    AuthenticatedDemandEvidence, DemandVerificationFailure, InstalledDemandVerifier,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/demand-supplier-v1.json"


class FixtureAdapter:
    """Unsafe fixture-only ES256 profile; never a production encoding."""

    def __init__(self, vectors, context):
        self.vectors, self.context = vectors, context

    def verify(self, evidence, *, deployment_profile_bytes, operation_bytes, evaluated_at):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        context = self.context
        if (context["supplier_is_requester"] or context["supplier_acts_for_requester"]
                or not context["independence_established"] or not context["approved_source_path"]):
            raise DemandVerificationFailure("supplier_path")
        if not context["provenance_available"] or not context["provenance_admissible"]:
            raise DemandVerificationFailure("provenance")
        def decode(value):
            return base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4))
        try:
            header, body, signature = evidence.split(b".")
            protected = json.loads(decode(header))
            if protected != {"alg": "ES256", "kid": self.vectors["key"]["kid"],
                             "typ": "ktp-demand-input-test-v1"}:
                raise DemandVerificationFailure("authentication")
            key = self.vectors["key"]
            public = ec.EllipticCurvePublicNumbers(
                int.from_bytes(decode(key["x"].encode()), "big"),
                int.from_bytes(decode(key["y"].encode()), "big"), ec.SECP256R1(),
            ).public_key()
            raw = decode(signature)
            if len(raw) != 64:
                raise DemandVerificationFailure("authentication")
            public.verify(utils.encode_dss_signature(
                int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                header + b"." + body, ec.ECDSA(hashes.SHA256()))
        except (ValueError, InvalidSignature) as exc:
            raise DemandVerificationFailure("authentication") from exc
        provenance = context["provenance_payload"]
        return AuthenticatedDemandEvidence(
            payload_bytes=decode(body), provenance_bytes=rfc8785.dumps(provenance),
            provenance_reference=provenance["reference"], provenance_source=provenance["source"],
        )


@unittest.skipUnless(all(find_spec(name) for name in ("rfc8785", "jsonschema", "cryptography")),
                     "install the v3-proofs extra for installed supplier tests")
class InstalledDemandVerifierTests(unittest.TestCase):
    def test_operation_snapshot_survives_adapter_mutation_and_retains_evidence(self):
        import rfc8785
        vectors = json.loads(VECTORS.read_text())
        operation = vectors["operation"]
        fixture = FixtureAdapter(vectors, vectors["context"])
        class MutatingAdapter:
            def verify(self, evidence, **kwargs):
                operation["resource"] = "urn:changed"
                return fixture.verify(evidence, **kwargs)
        installed = InstalledDemandVerifier(
            deployment_profile_bytes=rfc8785.dumps(vectors["deployment_profile"]),
            supplier_profile_bytes=rfc8785.dumps(vectors["supplier_profile_payload"]),
            verification_profile_bytes=rfc8785.dumps(vectors["verification_profile_payload"]),
            adapter=MutatingAdapter(), algorithm="sha256",
        )
        result = installed.evaluate(vectors["cases"][0]["jws"].encode(),
                                    actual_operation=operation, evaluated_at=1030, clock_healthy=True)
        self.assertEqual(result.state, "observed")
        self.assertEqual(result.provenance_bytes, rfc8785.dumps(vectors["provenance_payload"]))
        self.assertEqual(result.payload_bytes, rfc8785.dumps(vectors["cases"][0]["payload"]))

    def test_installed_profile_mismatch_and_operational_failure(self):
        import rfc8785
        from kinetic_trust_library.errors import ValidationError
        vectors = json.loads(VECTORS.read_text())
        arguments = dict(
            deployment_profile_bytes=rfc8785.dumps(vectors["deployment_profile"]),
            supplier_profile_bytes=rfc8785.dumps(vectors["supplier_profile_payload"]),
            verification_profile_bytes=rfc8785.dumps(vectors["verification_profile_payload"]),
            adapter=FixtureAdapter(vectors, vectors["context"]), algorithm="sha256",
        )
        with self.assertRaises(ValidationError):
            InstalledDemandVerifier(**{**arguments, "supplier_profile_bytes": b'{"id":"wrong"}'})
        class BrokenAdapter:
            def verify(self, *args, **kwargs):
                raise RuntimeError("provider offline")
        installed = InstalledDemandVerifier(**{**arguments, "adapter": BrokenAdapter()})
        with self.assertRaisesRegex(RuntimeError, "provider offline"):
            installed.evaluate(b"evidence", actual_operation=vectors["operation"],
                               evaluated_at=1030, clock_healthy=True)

    def test_all_published_value_cases_through_installed_adapter(self):
        import rfc8785
        vectors = json.loads(VECTORS.read_text())
        for case in vectors["cases"]:
            with self.subTest(case=case["id"]):
                context = {**vectors["context"], **case["context_overrides"]}
                profile = json.loads(json.dumps(vectors["deployment_profile"]))
                if not context["declaration_installed"]:
                    profile.pop("demand_inputs")
                installed = InstalledDemandVerifier(
                    deployment_profile_bytes=rfc8785.dumps(profile),
                    supplier_profile_bytes=rfc8785.dumps(vectors["supplier_profile_payload"]),
                    verification_profile_bytes=rfc8785.dumps(vectors["verification_profile_payload"]),
                    adapter=FixtureAdapter(vectors, context), algorithm=context["digest_algorithm"],
                )
                result = installed.evaluate(
                    case["jws"].encode(), actual_operation=context["actual_operation"],
                    evaluated_at=context["evaluated_at"], clock_healthy=context["clock_healthy"],
                )
                self.assertEqual(result.state, case["expected"]["state"])
                self.assertEqual(float(result.decision_reading), case["expected"]["effectiveReading"])
                self.assertEqual(result.observed_value is not None, case["expected"]["valueAccepted"])
                self.assertEqual(result.original_evidence, case["jws"].encode())


if __name__ == "__main__":
    unittest.main()
