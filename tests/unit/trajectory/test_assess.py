from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from importlib import import_module
import unittest

from tests.unit.trajectory._fixtures import adjacent_transaction, official_transaction


class TrajectoryAssessmentTests(unittest.TestCase):
    def test_assess_returns_no_findings_for_valid_adjacent_pair(self):
        trajectory = import_module("kinetic_trust_library.trajectory")
        assess = getattr(trajectory, "assess_trajectory_link", None)
        self.assertTrue(callable(assess), "missing trajectory assessor")
        previous_mapping = official_transaction()
        previous = trajectory.parse_trajectory_transaction(previous_mapping)
        current = trajectory.parse_trajectory_transaction(adjacent_transaction(previous_mapping))
        for wrong in (None, {}, [], "transaction", 1, object()):
            for pair in ((wrong, current), (previous, wrong)):
                with self.subTest(pair=pair), self.assertRaises(TypeError):
                    assess(*pair)
        before = (repr(previous), repr(current))
        self.assertEqual(assess(previous, current), ())
        self.assertEqual(assess(previous, current), ())
        self.assertEqual((repr(previous), repr(current)), before)

    def test_assess_reports_each_pairwise_finding(self):
        trajectory = import_module("kinetic_trust_library.trajectory")
        finding = trajectory.TrajectoryLinkFinding
        cases = (
            ({"chain_id": "other-chain"}, finding.CHAIN_ID_MISMATCH),
            ({"sequence": 2}, finding.SEQUENCE_DISCONTINUITY),
            ({"previous_hash": None}, finding.MISSING_PREVIOUS_HASH),
            ({"previous_hash": "different-hash"}, finding.PREVIOUS_HASH_MISMATCH),
            ({"timestamp": "2025-06-30T23:59:60Z"}, finding.TIMESTAMP_ORDER_UNDEFINED),
            ({"timestamp": "2025-01-15T10:00:00Z"}, finding.NON_INCREASING_TIMESTAMP),
            ({"previous_state": None}, finding.MISSING_PREVIOUS_STATE),
            ({"previous_state": {**official_transaction()["current_state"], "location": "other-zone"}},
             finding.PREVIOUS_STATE_MISMATCH),
        )
        for changes, expected in cases:
            with self.subTest(finding=expected):
                previous_mapping = official_transaction()
                current_mapping = adjacent_transaction(previous_mapping)
                current_mapping.update(changes)
                self.assertEqual(
                    trajectory.assess_trajectory_link(
                        trajectory.parse_trajectory_transaction(previous_mapping),
                        trajectory.parse_trajectory_transaction(current_mapping),
                    ),
                    (expected,),
                )

    def test_assess_accumulates_findings_in_canonical_order(self):
        trajectory = import_module("kinetic_trust_library.trajectory")
        finding = trajectory.TrajectoryLinkFinding
        previous_mapping = official_transaction()
        current_mapping = adjacent_transaction(previous_mapping)
        current_mapping.update(
            chain_id="other-chain", sequence=7, previous_hash="different-hash",
            timestamp="2025-01-15T09:59:59Z",
        )
        current_mapping["previous_state"]["location"] = "other-zone"
        self.assertEqual(
            trajectory.assess_trajectory_link(
                trajectory.parse_trajectory_transaction(previous_mapping),
                trajectory.parse_trajectory_transaction(current_mapping),
            ),
            (
                finding.CHAIN_ID_MISMATCH, finding.SEQUENCE_DISCONTINUITY,
                finding.PREVIOUS_HASH_MISMATCH, finding.NON_INCREASING_TIMESTAMP,
                finding.PREVIOUS_STATE_MISMATCH,
            ),
        )

    def test_assess_compares_rfc3339_instants(self):
        trajectory = import_module("kinetic_trust_library.trajectory")
        finding = trajectory.TrajectoryLinkFinding
        not_increasing = (finding.NON_INCREASING_TIMESTAMP,)
        undefined = (finding.TIMESTAMP_ORDER_UNDEFINED,)
        cases = (
            ("2025-01-15T10:00:00Z", "2025-01-15T11:30:00+01:30", not_increasing),
            ("2025-01-15T10:00:00Z", "2025-01-15T11:30:01+01:30", ()),
            ("2025-01-15T10:00:00Z", "2025-01-15T11:00:00+02:00", not_increasing),
            ("2024-12-31T23:30:00-01:00", "2025-01-01T00:30:00Z", not_increasing),
            ("2025-01-15t10:00:00z", "2025-01-15T10:00:00-00:00", not_increasing),
            ("2025-01-15T10:00:00-00:00", "2025-01-15T10:00:00+00:00", not_increasing),
            ("2025-01-15T10:00:00-00:00", "2025-01-15T10:00:01Z", ()),
            ("2025-01-15T10:00:00.1Z", "2025-01-15T10:00:00.100Z", not_increasing),
            ("2025-01-15T10:00:00Z", "2025-01-15T10:00:00.000Z", not_increasing),
            ("2025-01-15T10:00:00.000000001Z", "2025-01-15T10:00:00.000000002Z", ()),
            ("2025-01-15T10:00:00.1234567890123456789012345678901Z",
             "2025-01-15T10:00:00.1234567890123456789012345678900Z", not_increasing),
            ("0000-01-01T00:00:00+01:00", "0000-01-01T00:00:00Z", ()),
            ("9999-12-31T23:59:59-01:00", "9999-12-31T23:59:59Z", not_increasing),
            ("2016-12-31T23:59:60Z", "2017-01-01T00:00:00Z", undefined),
            ("2016-12-31T23:59:59Z", "2017-01-01T01:29:60+01:30", undefined),
            ("2025-06-30T23:59:60Z", "2025-06-30T23:59:60Z", undefined),
        )
        for previous_time, current_time, expected in cases:
            with self.subTest(times=(previous_time, current_time)):
                previous_mapping = official_transaction()
                current_mapping = adjacent_transaction(previous_mapping)
                previous_mapping["timestamp"] = previous_time
                current_mapping["timestamp"] = current_time
                self.assertEqual(
                    trajectory.assess_trajectory_link(
                        trajectory.parse_trajectory_transaction(previous_mapping),
                        trajectory.parse_trajectory_transaction(current_mapping),
                    ),
                    expected,
                )

    def test_assess_uses_typed_semantic_state_equality(self):
        trajectory = import_module("kinetic_trust_library.trajectory")
        mismatch = (trajectory.TrajectoryLinkFinding.PREVIOUS_STATE_MISMATCH,)
        for member, changed in (
            ("e_base", 5), ("e_trust", 4), ("location", "other-zone"),
            ("tier", "observer"), ("lineage", "independent"), ("generation", 1),
        ):
            with self.subTest(member=member):
                previous_mapping = official_transaction()
                current_mapping = adjacent_transaction(previous_mapping)
                current_mapping["previous_state"][member] = changed
                self.assertEqual(
                    trajectory.assess_trajectory_link(
                        trajectory.parse_trajectory_transaction(previous_mapping),
                        trajectory.parse_trajectory_transaction(current_mapping),
                    ),
                    mismatch,
                )
        cases = (
            ({"a": 1, "b": [True, None, "é"]}, {"b": [True, None, "é"], "a": Decimal("1.00")}, ()),
            ({"n": 1}, {"n": 1.0}, ()),
            ({"n": 0.1}, {"n": Decimal("0.1")}, ()),
            ({"n": 10**80}, {"n": Decimal(10**80)}, ()),
            ({"n": Decimal("1.00000000000000000000000000001")},
             {"n": Decimal("1.00000000000000000000000000002")}, mismatch),
            ({"n": True}, {"n": 1}, mismatch),
            ({"n": False}, {"n": Decimal("0.00")}, mismatch),
            ({"n": 1.0}, {"n": True}, mismatch),
            ({"n": None}, {"n": False}, mismatch),
            ({"n": None}, {"n": 0}, mismatch),
            ({"n": "1"}, {"n": 1}, mismatch),
            ({"n": "é"}, {"n": "e\u0301"}, mismatch),
            ({"n": [1, 2]}, {"n": [2, 1]}, mismatch),
            ({"n": [1]}, {"n": [1, 2]}, mismatch),
            ({"n": [1]}, {"n": {"0": 1}}, mismatch),
            ({"n": {"deep": [True]}}, {"n": {"deep": [1]}}, mismatch),
            ({"n": None}, {}, mismatch),
            ({}, {"n": None}, mismatch),
        )
        for previous_extension, current_extension, expected in cases:
            with self.subTest(extensions=(previous_extension, current_extension)):
                previous_mapping = official_transaction()
                previous_mapping["current_state"].update(deepcopy(previous_extension))
                current_mapping = adjacent_transaction(previous_mapping)
                current_mapping["previous_state"] = {
                    **official_transaction()["current_state"], **deepcopy(current_extension),
                }
                # Reorder all known members too; object order has no semantics.
                current_mapping["previous_state"] = dict(
                    reversed(tuple(current_mapping["previous_state"].items()))
                )
                self.assertEqual(
                    trajectory.assess_trajectory_link(
                        trajectory.parse_trajectory_transaction(previous_mapping),
                        trajectory.parse_trajectory_transaction(current_mapping),
                    ),
                    expected,
                )
