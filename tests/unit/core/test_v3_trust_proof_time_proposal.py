"""Provisional stage-5 time checks from RFC PR #195, head 23061751da30."""

import base64
import json
import unittest
from pathlib import Path

from kinetic_trust_library.v3.trust_proof_time import (
    trust_proof_stage5_reason,
    trust_proof_time_valid,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/trust-proof-v3.json"
TIME_CASES = {
    "clear", "nbf-equals-iat", "short-lifetime", "at-expiry",
    "after-expiry", "eleven-second-lifetime", "zero-lifetime",
    "nbf-different", "key-expiry-insufficient", "negative-time",
    "boolean-time", "missing-time", "unhealthy-clock",
}


class ProposedTrustProofTime(unittest.TestCase):
    def test_published_stage5_reason_order(self):
        vectors = json.loads(VECTORS.read_text())
        key = next(item for item in vectors["keys"] if item["kid"] == "TEST-oracle-p256")
        expected_ids = {
            case["id"] for case in vectors["cases"]
            if case["expected"]["reason"] in {"TP_ISSUER", "TP_AUDIENCE", "TP_TIME"}
        }
        expected_ids.update({"clear", "nbf-equals-iat", "short-lifetime"})
        observed = set()
        for case in vectors["cases"]:
            if case["id"] not in expected_ids:
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                segment = case["jws"].split(".")[1]
                payload = json.loads(base64.urlsafe_b64decode(
                    segment + "=" * (-len(segment) % 4)
                ))
                context = {**vectors["context"], **case.get("context", {})}
                reason = trust_proof_stage5_reason(
                    payload,
                    expected_issuer=context["issuer"],
                    expected_audience=context["audience"],
                    now=context["now"],
                    clock_healthy=context["clock_healthy"],
                    key_not_before=key["not_before"],
                    key_not_after=key["not_after"],
                )
                wanted = case["expected"]["reason"]
                self.assertEqual(reason, wanted if wanted.startswith("TP_") and wanted in {
                    "TP_ISSUER", "TP_AUDIENCE", "TP_TIME"
                } else None)
        self.assertEqual(observed, expected_ids)

    def test_published_time_cases_after_prior_verification_stages(self):
        vectors = json.loads(VECTORS.read_text())
        key = next(item for item in vectors["keys"] if item["kid"] == "TEST-oracle-p256")
        observed = set()
        for case in vectors["cases"]:
            if case["id"] not in TIME_CASES:
                continue
            observed.add(case["id"])
            with self.subTest(case=case["id"]):
                payload_segment = case["jws"].split(".")[1]
                payload = json.loads(base64.urlsafe_b64decode(
                    payload_segment + "=" * (-len(payload_segment) % 4)
                ))
                context = {**vectors["context"], **case.get("context", {})}
                self.assertEqual(
                    trust_proof_time_valid(
                        payload,
                        now=context["now"],
                        clock_healthy=context["clock_healthy"],
                        key_not_before=key["not_before"],
                        key_not_after=key["not_after"],
                    ),
                    case["expected"]["reason"] != "TP_TIME",
                )
        self.assertEqual(observed, TIME_CASES)

    def test_safe_integer_boundaries_and_untrusted_context(self):
        claims = {"iat": 100, "exp": 110}
        valid = dict(now=100, clock_healthy=True, key_not_before=100, key_not_after=110)
        self.assertTrue(trust_proof_time_valid(claims, **valid))
        for change in (
            {"now": 110}, {"clock_healthy": 1}, {"key_not_before": 101},
            {"key_not_after": 109}, {"now": True}, {"now": -1},
            {"key_not_after": 2**53},
        ):
            with self.subTest(change=change):
                self.assertFalse(trust_proof_time_valid(claims, **(valid | change)))

    def test_optional_nbf_and_strict_claim_types(self):
        context = dict(now=100, clock_healthy=True, key_not_before=100, key_not_after=110)
        self.assertTrue(trust_proof_time_valid({"iat": 100, "exp": 110, "nbf": 100}, **context))
        for claims in (
            {"iat": True, "exp": 110}, {"iat": 100.0, "exp": 110},
            {"iat": 100, "exp": 110, "nbf": False},
            {"iat": 100, "exp": 110, "nbf": 101},
            {"iat": 100, "exp": 2**53},
        ):
            with self.subTest(claims=claims):
                self.assertFalse(trust_proof_time_valid(claims, **context))


if __name__ == "__main__":
    unittest.main()
