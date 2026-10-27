"""Factor-boundary checks against RFC PR #203, head 9ef31845baeb."""

import json
import unittest
from decimal import Decimal
from pathlib import Path

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.evidence_state import (
    FactorEvidenceState,
    UndefinedInputState,
    assess_required_factor,
    canonical_undefined_inputs,
)


VECTORS = Path(__file__).parents[3] / "spec/proposals/missing-evidence-v1.json"


class ProposedMissingEvidence(unittest.TestCase):
    def test_all_proposed_factor_boundary_projections(self):
        vectors = json.loads(VECTORS.read_text())["vectors"]
        for vector in vectors:
            if not vector["expected"]["factor_evaluated"]:
                continue
            with self.subTest(case=vector["id"]):
                expected = vector["expected"]
                factor = expected["factor_result"]
                feed_failures = tuple(
                    UndefinedInputState(item["input"], item["layer"], item["state"])
                    for item in expected["undefined_inputs"]
                    if item["layer"] == "feed"
                )
                result = assess_required_factor(
                    factor=vector["given"]["factor"],
                    required_signals=tuple(vector["given"]["required_signals"]),
                    populated_signals={
                        name: state.get("value")
                        for name, state in expected["signals"].items()
                    },
                    measured_stress=factor.get("value", 0),
                    feed_undefined=feed_failures,
                )
                self.assertEqual(result.state, factor["state"])
                self.assertEqual(
                    result.value,
                    None if "value" not in factor else Decimal(str(factor["value"])),
                )
                self.assertEqual(
                    result.decision_stress,
                    Decimal(str(factor.get("value", factor.get("decision_stress")))),
                )
                self.assertEqual(
                    [item.record() for item in result.undefined_inputs],
                    expected["undefined_inputs"],
                )

    def test_factor_result_cannot_be_fabricated_by_caller(self):
        with self.assertRaises(TypeError):
            FactorEvidenceState("evidence_density", "observable", Decimal(0), Decimal(0), ())

    def test_redundant_backup_preserves_failed_feed_without_inventing_unknown_signal(self):
        vector = self._case("one-failed-independent-backup")
        feed_failure = UndefinedInputState("feed-a", "feed", "unanswered")
        result = assess_required_factor(
            factor="evidence_density",
            required_signals=tuple(vector["given"]["required_signals"]),
            populated_signals={name: value["value"] for name, value in vector["expected"]["signals"].items()},
            measured_stress=vector["expected"]["factor_result"]["value"],
            feed_undefined=(feed_failure,),
        )
        self.assertEqual(result.state, "observable")
        self.assertEqual(result.value, Decimal("0.4"))
        self.assertEqual(result.decision_stress, Decimal("0.4"))
        self.assertEqual([entry.record() for entry in result.undefined_inputs], vector["expected"]["undefined_inputs"])

    def test_unknown_required_signal_cannot_become_a_zero_measurement(self):
        vector = self._case("all-feeds-for-required-signal-fail")
        result = assess_required_factor(
            factor="evidence_density",
            required_signals=tuple(vector["given"]["required_signals"]),
            populated_signals={
                name: state.get("value")
                for name, state in vector["expected"]["signals"].items()
            },
            measured_stress=Decimal(0),
            feed_undefined=(
                UndefinedInputState("feed-b", "feed", "unanswered"),
                UndefinedInputState("feed-a", "feed", "unanswered"),
            ),
        )
        self.assertEqual(result.state, "unobservable")
        self.assertIsNone(result.value)
        self.assertEqual(result.decision_stress, Decimal(1))
        self.assertEqual([entry.record() for entry in result.undefined_inputs], vector["expected"]["undefined_inputs"])

    def test_empty_required_subset_is_unobservable(self):
        vector = self._case("no-factor-inputs")
        result = assess_required_factor(
            factor="evidence_density",
            required_signals=(),
            populated_signals={},
            measured_stress=Decimal(0),
        )
        self.assertEqual(result.state, "unobservable")
        self.assertIsNone(result.value)
        self.assertEqual([entry.record() for entry in result.undefined_inputs], vector["expected"]["undefined_inputs"])

    def test_genuine_zero_remains_observable(self):
        vector = self._case("genuine-zero-is-observable")
        result = assess_required_factor(
            factor="evidence_density",
            required_signals=tuple(vector["given"]["required_signals"]),
            populated_signals={name: state["value"] for name, state in vector["expected"]["signals"].items()},
            measured_stress=0,
        )
        self.assertEqual(result.state, "observable")
        self.assertEqual(result.value, 0)

    def test_query_undefined_is_distinct_and_canonical(self):
        records = canonical_undefined_inputs((
            UndefinedInputState("framework-b", "query", "unanswered"),
            UndefinedInputState("feed-a", "feed", "stale"),
            UndefinedInputState("feed-a", "feed", "stale"),
        ))
        self.assertEqual([entry.record() for entry in records], [
            {"input": "feed-a", "layer": "feed", "state": "stale"},
            {"input": "framework-b", "layer": "query", "state": "unanswered"},
        ])
        with self.assertRaises(ValidationError):
            canonical_undefined_inputs((
                UndefinedInputState("feed-a", "feed", "stale"),
                UndefinedInputState("feed-a", "feed", "absent"),
            ))

    @staticmethod
    def _case(name):
        return next(
            item for item in json.loads(VECTORS.read_text())["vectors"]
            if item["id"] == name
        )


if __name__ == "__main__":
    unittest.main()
