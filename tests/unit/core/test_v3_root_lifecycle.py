"""Lifecycle projection from independently authenticated RFC fixture events."""
import hashlib
import json
import unittest
from pathlib import Path
from kinetic_trust_library.v3.root_lifecycle import RootLifecycleEvent, project_root_lifecycle


class RootLifecycleTests(unittest.TestCase):
    def test_unbound_and_conflicting_findings_supply_no_credit(self):
        digest = "sha256:" + "a" * 64
        claim = RootLifecycleEvent("sha256:" + "b" * 64, digest, "subject", 2, "withdraw_for_cause")
        rejected = RootLifecycleEvent("sha256:" + "c" * 64, digest, "subject", 3, "finding", claim.digest, "rejected")
        sustained = RootLifecycleEvent("sha256:" + "d" * 64, digest, "subject", 4, "finding", claim.digest, "sustained")
        context = dict(instrument_digest=digest, subject="subject", start_time=1, end_time=10, now=5)
        self.assertEqual(project_root_lifecycle(**context, events=(rejected,)), "unverifiable")
        self.assertEqual(project_root_lifecycle(**context, events=(claim, rejected, sustained)), "unverifiable")
        foreign = RootLifecycleEvent("sha256:" + "e" * 64, digest, "another-subject", 2, "withdraw_for_cause")
        self.assertEqual(project_root_lifecycle(**context, events=(foreign,)), "unverifiable")

    def test_published_lifecycle_boundaries(self):
        vectors = json.loads((Path(__file__).parents[3] / "spec/proposals/external-root-v1.json").read_text())
        selected = {"current", "without-cause-before-end", "without-cause-at-end", "expired",
                    "pending-cause", "rejected-cause", "sustained-cause", "unresolved-at-end",
                    "event-not-yet-effective", "without-cause-cannot-erase-cause"}
        cases = [c for c in vectors["projection_cases"] if any(c["id"] == prefix + suffix
                 for prefix in ("bond-", "attestation-") for suffix in selected)]
        cases += [c for c in vectors["projection_cases"] if c["id"] in
                  ("attestation-misattestation", "rejected-does-not-revive-at-expiry")]
        self.assertEqual(len(cases), 22)
        for case in cases:
            with self.subTest(case=case["id"]):
                given = case["given"]
                instrument = vectors["instruments"][given["instrument"]]
                events = []
                for name in given["events"]:
                    event = vectors["events"][name]
                    body = event["body"]
                    events.append(RootLifecycleEvent(
                        digest="sha256:" + hashlib.sha256(event["jws"].encode()).hexdigest(),
                        instrument_digest=body["instrument_digest"], subject=body["subject"],
                        event_time=body["event_time"], action=body["action"],
                        claim_digest=body.get("claim_digest"), finding=body.get("finding"),
                    ))
                result = project_root_lifecycle(
                    instrument_digest=instrument["complete_digest"], subject=given["subject"],
                    start_time=instrument["body"]["start_time"], end_time=instrument["body"]["end_time"],
                    now=given["now"], events=tuple(reversed(events)),
                )
                expected = case["expected"]["projection"]
                self.assertEqual(result, expected.get("reason", expected["status"]))


if __name__ == "__main__": unittest.main()
