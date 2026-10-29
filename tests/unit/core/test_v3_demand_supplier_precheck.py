"""Deterministic candidate checks from unreleased RFC PR #202."""

import json
import hashlib
import unittest
from importlib.util import find_spec
from pathlib import Path

from kinetic_trust_library.v3.demand_supplier import precheck_demand_value


VECTORS = Path(__file__).parents[3] / "spec/proposals/demand-supplier-v1.json"


def provenance(payload):
    import rfc8785
    return dict(provenance_bytes=rfc8785.dumps(payload),
                provenance_reference=payload["reference"],
                provenance_source=payload["source"])


@unittest.skipUnless(
    find_spec("rfc8785") and find_spec("jsonschema"),
    "install the v3-proofs extra for demand supplier checks",
)
class ProposedDemandSupplierPrecheck(unittest.TestCase):
    def test_provenance_digest_covers_exact_non_json_evidence_bytes(self):
        vectors = json.loads(VECTORS.read_text())
        payload = vectors["cases"][0]["payload"]
        evidence = b"signed evidence\x00\xff\r\n"
        payload["provenance"]["digest"] = "sha256:" + hashlib.sha256(evidence).hexdigest()
        arguments = dict(
            payload=payload, declaration=vectors["declaration"],
            deployment_profile=vectors["deployment_profile"],
            actual_operation=vectors["operation"],
            provenance_reference=payload["provenance"]["reference"],
            provenance_source=vectors["declaration"]["source"],
            evaluated_at=vectors["context"]["evaluated_at"],
            clock_healthy=True, algorithm="sha256",
        )
        self.assertTrue(precheck_demand_value(**arguments, provenance_bytes=evidence))
        self.assertFalse(precheck_demand_value(**arguments, provenance_bytes=evidence + b"\n"))

    def test_missing_installed_demand_contract_is_unavailable(self):
        vectors = json.loads(VECTORS.read_text())
        self.assertFalse(precheck_demand_value(
            payload=vectors["cases"][0]["payload"],
            declaration=vectors["declaration"],
            deployment_profile={"demand_inputs": None},
            actual_operation=vectors["operation"],
            **provenance(vectors["provenance_payload"]),
            evaluated_at=vectors["context"]["evaluated_at"],
            clock_healthy=True,
            algorithm="sha256",
        ))

    def test_signature_failure_requires_separate_authentication(self):
        vectors = json.loads(VECTORS.read_text())
        case = next(item for item in vectors["cases"] if item["id"] == "wrong-signature")
        context = vectors["context"]
        self.assertTrue(precheck_demand_value(
            payload=case["payload"],
            declaration=vectors["declaration"],
            deployment_profile=vectors["deployment_profile"],
            actual_operation=context["actual_operation"],
            **provenance(context["provenance_payload"]),
            evaluated_at=context["evaluated_at"],
            clock_healthy=True,
            algorithm=context["digest_algorithm"],
        ))
        self.assertFalse(case["expected"]["valueAccepted"])

    def test_declaration_schema_cases(self):
        vectors = json.loads(VECTORS.read_text())
        for case in vectors["declaration_cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    precheck_demand_value(
                        payload=vectors["cases"][0]["payload"],
                        declaration=case["declaration"],
                        deployment_profile=vectors["deployment_profile"],
                        actual_operation=vectors["operation"],
                        **provenance(vectors["provenance_payload"]),
                        evaluated_at=vectors["context"]["evaluated_at"],
                        clock_healthy=True,
                        algorithm="sha256",
                    ),
                    case["schemaAccepted"],
                )

    def test_pure_boundary_cases(self):
        vectors = json.loads(VECTORS.read_text())
        positives = {
            "valid-value", "range-zero", "range-one",
            "equivalent-operation-member-order", "freshness-at-inclusive-limit",
        }
        negatives = {
            "stale-next-second", "reissued-old-observation-still-stale",
            "future-observation", "future-issuance", "issued-before-observation",
            "missing-observation-time", "clock-unhealthy", "different-operation",
            "different-resource", "different-parameters", "omitted-default",
            "different-actor", "different-subject", "different-audience",
            "different-request_id", "different-replay_domain",
            "missing-actual-invocation", "different-declaration",
            "missing-supplier-declaration", "wrong-supplier", "wrong-profile",
            "wrong-unit", "missing-provenance", "altered-provenance-bytes",
            "low-range-violation", "high-range-violation", "boolean-not-number",
        }
        for case in vectors["cases"]:
            if case["id"] not in positives | negatives:
                continue  # Authentication and source checks belong to installed profiles.
            with self.subTest(case=case["id"]):
                context = {**vectors["context"], **case["context_overrides"]}
                result = precheck_demand_value(
                    payload=case["payload"],
                    declaration=vectors["declaration"] if context["declaration_installed"] else None,
                    deployment_profile=vectors["deployment_profile"],
                    actual_operation=context["actual_operation"],
                    **provenance(context["provenance_payload"]),
                    evaluated_at=context["evaluated_at"],
                    clock_healthy=context["clock_healthy"],
                    algorithm=context["digest_algorithm"],
                )
                self.assertEqual(result, case["id"] in positives)


if __name__ == "__main__":
    unittest.main()
