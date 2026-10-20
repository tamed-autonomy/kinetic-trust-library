from __future__ import annotations

from dataclasses import FrozenInstanceError
from decimal import Decimal
from importlib import import_module
from importlib.util import find_spec
import unittest

from kinetic_trust_library.errors import ValidationError
from tests.unit.trajectory._fixtures import adjacent_transaction, official_transaction


RISK_KEYS = (
    "adversarial_pressure", "attestation_coverage", "evidence_density",
    "moment_criticality", "trust_trend", "update_resistance",
)
REQUIRED = {
    (): ("record_id", "chain_id", "sequence", "timestamp", "current_state", "action",
         "friction", "velocity", "agent_signature", "oracle_attestation", "record_hash"),
    ("current_state",): ("e_base", "e_trust", "location", "tier", "lineage", "generation"),
    ("action",): ("action_type", "action_risk", "result"),
    ("oracle_attestation",): ("oracle_id", "attestation_time", "risk_factors", "oracle_signature"),
    ("oracle_attestation", "risk_factors"): RISK_KEYS,
}


def _at(data, path):
    for key in path:
        data = data[key]
    return data


class TrajectoryParseTests(unittest.TestCase):
    def _parse(self, data):
        self.assertIsNotNone(find_spec("kinetic_trust_library.trajectory"), "missing trajectory seam")
        module = import_module("kinetic_trust_library.trajectory")
        parser = getattr(module, "parse_trajectory_transaction", None)
        self.assertTrue(callable(parser), "missing trajectory parser")
        return parser(data)

    def test_parse_accepts_official_example_and_preserves_fields(self):
        parsed = self._parse(official_transaction())
        self.assertEqual(parsed.record_id, "tr-001-genesis")
        self.assertEqual(parsed.chain_id, "chain-aria-7f8a9b2c")
        self.assertEqual(parsed.sequence, 0)
        self.assertEqual(parsed.timestamp, "2025-01-15T10:00:00Z")
        self.assertIsNone(parsed.previous_hash)
        self.assertIsNone(parsed.previous_state)
        self.assertEqual(parsed.current_state.e_base, Decimal("4.35"))
        self.assertEqual(parsed.current_state.e_trust, Decimal("3.92"))
        self.assertEqual(parsed.current_state.location, "zone-alpha")
        self.assertEqual(parsed.current_state.tier, "hibernation")
        self.assertEqual(parsed.current_state.lineage, "sponsored")
        self.assertEqual(parsed.current_state.generation, 0)
        self.assertEqual(parsed.action.action_type, "GENESIS")
        self.assertEqual(parsed.action.action_risk, Decimal("0"))
        self.assertIsNone(parsed.action.target)
        self.assertEqual(parsed.action.result, "success")
        self.assertEqual(dict(parsed.action.details), {"sponsor": "acme-deploy", "bond_id": "bond-acme-001"})
        self.assertEqual(parsed.friction, Decimal("0.1"))
        self.assertEqual(parsed.velocity, Decimal("0"))
        self.assertEqual(parsed.agent_signature, "MEUCIQDr...")
        self.assertEqual(parsed.record_hash, "sha256:abc123...")
        self.assertEqual(parsed.oracle_attestation.oracle_id, "oracle-alpha-1")
        self.assertEqual(parsed.oracle_attestation.attestation_time, "2025-01-15T10:00:01Z")
        self.assertEqual(parsed.oracle_attestation.oracle_signature, "MEQCIG...")
        self.assertEqual(dict(parsed.oracle_attestation.risk_factors), dict(zip(RISK_KEYS, map(Decimal, ("0.05", "0.05", "0.1", "0.2", "0.15", "0.1")))))
        linked = self._parse(adjacent_transaction(official_transaction()))
        self.assertEqual(linked.previous_state, parsed.current_state)
        self.assertEqual(linked.previous_hash, parsed.record_hash)

    def test_parse_preserves_open_extensions_and_enforces_schema_boundaries(self):
        data = official_transaction()
        for path in ((), ("current_state",), ("action",), ("oracle_attestation",)):
            _at(data, path)["custom"] = {"array": [True, None, "é"]}
        parsed = self._parse(data)
        for value in (parsed, parsed.current_state, parsed.action, parsed.oracle_attestation):
            self.assertIn("custom", value.extensions)
            self.assertEqual(value.extensions["custom"]["array"], (True, None, "é"))
        for path, keys in REQUIRED.items():
            for key in keys:
                with self.subTest(missing=path + (key,)):
                    data = official_transaction()
                    del _at(data, path)[key]
                    with self.assertRaises(ValidationError):
                        self._parse(data)
        for path in ((), ("current_state",), ("previous_state",), ("action",),
                     ("oracle_attestation",), ("oracle_attestation", "risk_factors"), ("action", "details")):
            for bad in ([], "object", 1, True, None):
                if path == ("previous_state",) and bad is None:
                    continue
                with self.subTest(object=path, bad=bad):
                    data = official_transaction()
                    if path:
                        _at(data, path[:-1])[path[-1]] = bad
                    else:
                        data = bad
                    with self.assertRaises(ValidationError):
                        self._parse(data)
        strings = ("record_id", "chain_id", "agent_signature", "record_hash", "timestamp", "previous_hash")
        string_paths = [(key,) for key in strings]
        string_paths += [("current_state", key) for key in ("location", "tier", "lineage")]
        string_paths += [("action", key) for key in ("action_type", "target", "result")]
        string_paths += [("oracle_attestation", key) for key in ("oracle_id", "attestation_time", "oracle_signature")]
        for path in string_paths:
            for bad in (1, False, [], {}, None):
                if path in (("previous_hash",), ("action", "target")) and bad is None:
                    continue
                with self.subTest(string=path, bad=bad):
                    data = official_transaction()
                    _at(data, path[:-1])[path[-1]] = bad
                    with self.assertRaises(ValidationError):
                        self._parse(data)
        for path, choices in ((("current_state", "tier"), ("hibernation", "observer", "analyst", "operator", "admin")),
                              (("current_state", "lineage"), ("sponsored", "independent", "guarantor")),
                              (("action", "result"), ("success", "denied"))):
            for choice in choices:
                data = official_transaction()
                _at(data, path[:-1])[path[-1]] = choice
                self._parse(data)
            data = official_transaction()
            _at(data, path[:-1])[path[-1]] = "unknown"
            with self.assertRaises(ValidationError):
                self._parse(data)
        data = official_transaction()
        data["oracle_attestation"]["risk_factors"]["unknown"] = 0
        with self.assertRaises(ValidationError):
            self._parse(data)
        for missing in (True, False):
            data = official_transaction()
            if missing:
                del data["previous_hash"], data["previous_state"], data["action"]["target"]
            parsed = self._parse(data)
            self.assertIsNone(parsed.previous_hash)
            self.assertIsNone(parsed.previous_state)
            self.assertIsNone(parsed.action.target)
        data = official_transaction()
        del data["action"]["details"]
        self.assertIsNone(self._parse(data).action.details)
        data["action"]["details"] = None
        with self.assertRaises(ValidationError):
            self._parse(data)

    def test_parse_normalizes_numbers_and_rejects_invalid_numeric_values(self):
        number_paths = [("friction",), ("velocity",), ("current_state", "e_base"),
                        ("current_state", "e_trust"), ("action", "action_risk")]
        number_paths += [("oracle_attestation", "risk_factors", key) for key in RISK_KEYS]
        integer_paths = [("sequence",), ("current_state", "generation")]
        for path in number_paths + integer_paths:
            for bad in (True, False, "1", None, [], {}, float("inf"), float("nan"), Decimal("NaN"), Decimal("-Infinity"), -1):
                with self.subTest(path=path, bad=bad):
                    data = official_transaction()
                    _at(data, path[:-1])[path[-1]] = bad
                    with self.assertRaises(ValidationError):
                        self._parse(data)
        for path in integer_paths:
            for bad in (0.5, Decimal("1.0001")):
                data = official_transaction()
                _at(data, path[:-1])[path[-1]] = bad
                with self.assertRaises(ValidationError):
                    self._parse(data)
            for value in (0, 1.0, Decimal("1.00"), 10**80):
                data = official_transaction()
                _at(data, path[:-1])[path[-1]] = value
                parsed = self._parse(data)
                actual = parsed.sequence if path == ("sequence",) else parsed.current_state.generation
                self.assertIs(type(actual), int)
                self.assertEqual(actual, int(value))
        for path in number_paths:
            maximum = 100 if path[-1] in ("e_base", "e_trust", "action_risk") else 1
            if path == ("velocity",):
                maximum = None
            for value in (0, 0.1, Decimal("0.12345678901234567890123456789"), maximum or 10**80):
                data = official_transaction()
                _at(data, path[:-1])[path[-1]] = value
                parsed = self._parse(data)
                actual = parsed
                for key in path:
                    actual = actual[key] if isinstance(actual, dict) or key in RISK_KEYS else getattr(actual, key)
                self.assertIs(type(actual), Decimal)
                self.assertEqual(actual, Decimal(repr(value)) if isinstance(value, float) else Decimal(value))
            if maximum is not None:
                data = official_transaction()
                _at(data, path[:-1])[path[-1]] = Decimal(maximum) + Decimal("0.0001")
                with self.assertRaises(ValidationError):
                    self._parse(data)
        data = official_transaction()
        data["custom"] = [1, 1.0, Decimal("1.00"), True, False, 0.1]
        self.assertEqual(self._parse(data).extensions["custom"], (Decimal(1), Decimal(1), Decimal("1.00"), True, False, Decimal("0.1")))
        self.assertIs(type(self._parse(data).extensions["custom"][3]), bool)
        for path in (("custom",), ("action", "details", "custom")):
            for bad in (float("inf"), Decimal("NaN")):
                data = official_transaction()
                _at(data, path[:-1])[path[-1]] = bad
                with self.assertRaises(ValidationError):
                    self._parse(data)

    def test_parse_returns_detached_frozen_values_and_rejects_cycles(self):
        data = adjacent_transaction(official_transaction())
        data["custom"] = {"nested": ["original", {"ok": True}]}
        data["action"]["details"]["items"] = ["original"]
        parsed = self._parse(data)
        data["custom"]["nested"][0] = "changed"
        data["action"]["details"]["items"].append("changed")
        data["current_state"]["location"] = "changed"
        data["oracle_attestation"]["risk_factors"]["trust_trend"] = 1
        self.assertIn("custom", parsed.extensions)
        self.assertEqual(parsed.extensions["custom"]["nested"][0], "original")
        self.assertEqual(parsed.action.details["items"], ("original",))
        self.assertEqual(parsed.current_state.location, "zone-alpha")
        self.assertEqual(parsed.oracle_attestation.risk_factors["trust_trend"], Decimal("0.15"))
        for value, field in ((parsed, "record_id"), (parsed.current_state, "location"),
                             (parsed.previous_state, "location"), (parsed.action, "result"),
                             (parsed.oracle_attestation, "oracle_id")):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, "changed")
        for mapping in (parsed.extensions, parsed.extensions["custom"], parsed.extensions["custom"]["nested"][1],
                        parsed.action.details, parsed.current_state.extensions, parsed.oracle_attestation.risk_factors):
            with self.assertRaises(TypeError):
                mapping["new"] = "changed"
        for path in ((), ("current_state",), ("previous_state",), ("action",), ("oracle_attestation",), ("action", "details")):
            for kind in ("mapping", "list"):
                data = adjacent_transaction(official_transaction())
                container = _at(data, path)
                if kind == "mapping":
                    container["cycle"] = container
                else:
                    cycle = []
                    cycle.append(cycle)
                    container["cycle"] = cycle
                with self.subTest(path=path, kind=kind), self.assertRaises(ValidationError):
                    self._parse(data)
        for bad in ({1: "bad"}, (1, 2), {1, 2}, object(), b"bytes"):
            data = official_transaction()
            data["custom"] = bad
            with self.assertRaises(ValidationError):
                self._parse(data)

    def test_parse_validates_both_rfc3339_fields(self):
        valid = (
            "2025-01-15T10:00:00Z", "2025-01-15t10:00:00z", "2025-01-15T11:30:00+01:30",
            "2025-01-15T10:00:00-00:00", "2025-01-15T10:00:00+00:00",
            "2025-01-15T10:00:00.123456789012345678901234567890Z",
            "0000-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59", "2000-02-29T00:00:00Z",
            "2016-12-31T23:59:60Z", "2025-06-30T23:59:60.1z", "2017-01-01T01:29:60+01:30",
            "2016-12-31T22:59:60-01:00",
        )
        invalid = (
            "2025-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2025-04-31T00:00:00Z",
            "2025-00-01T00:00:00Z", "2025-13-01T00:00:00Z", "2025-01-00T00:00:00Z",
            "2025-01-15T24:00:00Z", "2025-01-15T00:60:00Z", "2025-01-15T00:00:61Z",
            "2025-01-15T00:00:60Z", "2025-06-30T22:59:60Z", "2025-07-31T23:59:60Z",
            "2025-06-30T23:59:60+01:00", "2025-01-15T00:00:00+24:00", "2025-01-15T00:00:00+00:60",
            "2025-01-15 00:00:00Z", "2025-01-15T00:00:00", "2025-01-15T00:00:00.Z",
            "2025-01-15T00:00:00,1Z", "2025-01-15T00:00:00Z\n", "2025-01-15T00:00:00Z[UTC]",
            "10000-01-01T00:00:00Z", "２０２５-01-15T00:00:00Z", None, 1,
        )
        for path in (("timestamp",), ("oracle_attestation", "attestation_time")):
            for value in valid:
                with self.subTest(path=path, valid=value):
                    data = official_transaction()
                    _at(data, path[:-1])[path[-1]] = value
                    parsed = self._parse(data)
                    actual = parsed.timestamp if len(path) == 1 else parsed.oracle_attestation.attestation_time
                    self.assertEqual(actual, value)
            for value in invalid:
                with self.subTest(path=path, invalid=value):
                    data = official_transaction()
                    _at(data, path[:-1])[path[-1]] = value
                    with self.assertRaises(ValidationError):
                        self._parse(data)
