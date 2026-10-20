import hashlib
import math
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from enum import Enum

from kinetic_trust_library.models._common import freeze_mapping

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library.errors import ValidationError


class Level(Enum):
    TRUSTED = "trusted"


@dataclass(frozen=True)
class Snapshot:
    observed_at: datetime
    level: Level
    score: Decimal


@dataclass(frozen=True)
class FrozenSnapshot:
    value: str


class CanonicalJsonTests(unittest.TestCase):
    def test_encodes_dataclasses_enums_utc_and_normalized_decimals(self):
        value = Snapshot(
            observed_at=datetime(2026, 8, 20, 12, 34, 56, 120000, tzinfo=timezone.utc),
            level=Level.TRUSTED,
            score=Decimal("-0.000"),
        )
        self.assertEqual(
            canonical_json_bytes(value),
            b'{"level":"trusted","observed_at":"2026-08-20T12:34:56.12Z","score":0}',
        )

    def test_encodes_deterministically_and_hashes_exact_bytes(self):
        value = {"z": Decimal("12.3400"), "a": [True, None, "caf\u00e9"]}
        expected = b'{"a":[true,null,"caf\xc3\xa9"],"z":12.34}'
        self.assertEqual(canonical_json_bytes(value), expected)
        self.assertEqual(canonical_json_bytes(value), expected)
        self.assertEqual(canonical_sha256(value), hashlib.sha256(expected).hexdigest())

    def test_rejects_nonfinite_numbers_and_unsupported_values(self):
        values = (
            Decimal("NaN"),
            Decimal("Infinity"),
            math.nan,
            math.inf,
            {"unsupported": object()},
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                canonical_json_bytes(value)

    def test_rejects_invalid_unicode_and_non_string_mapping_keys(self):
        values = ("bad\ud800", {"bad\ud800": "value"}, {1: "value"})
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                canonical_json_bytes(value)

    def test_preserves_exact_decimals_independent_of_ambient_precision(self):
        large = Decimal("123456789012345678901234567890.1200")
        expected = b"123456789012345678901234567890.12"
        self.assertEqual(canonical_json_bytes(large), expected)
        with localcontext() as context:
            context.prec = 5
            self.assertEqual(canonical_json_bytes(large), expected)
            self.assertEqual(
                canonical_sha256(large), hashlib.sha256(expected).hexdigest()
            )
        self.assertEqual(Decimal(expected.decode("ascii")), large)
        for value, canonical in (
            (Decimal("1.2300E+5"), b"123000"),
            (Decimal("1.2300E-5"), b"0.0000123"),
            (Decimal("-0E+99"), b"0"),
        ):
            with self.subTest(value=value):
                self.assertEqual(canonical_json_bytes(value), canonical)

    def test_reuses_frozen_values_without_allowing_mutable_aliases_or_cycles(self):
        snapshot = FrozenSnapshot("ok")
        owned = freeze_mapping({"ready": Decimal("1.0")})
        self.assertEqual(
            canonical_json_bytes(
                {"dataclasses": [snapshot, snapshot], "mappings": [owned, owned]}
            ),
            b'{"dataclasses":[{"value":"ok"},{"value":"ok"}],'
            b'"mappings":[{"ready":1},{"ready":1}]}',
        )

        for mutable in (["value"], {"value": "ok"}):
            with self.subTest(mutable=mutable), self.assertRaises(ValidationError):
                canonical_json_bytes({"first": mutable, "second": mutable})

        cycle: list[object] = []
        cycle.append(cycle)
        with self.assertRaises(ValidationError):
            canonical_json_bytes(cycle)
