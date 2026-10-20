import math
import unittest
from decimal import Decimal

from kinetic_trust_library._canonical import canonical_json_bytes
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ConfigurationError, ValidationError


class DecimalBoundaryTests(unittest.TestCase):
    def test_accepts_owned_exact_values(self):
        self.assertEqual(as_decimal("0.30", name="weight"), Decimal("0.30"))
        self.assertEqual(as_decimal(3, name="count"), Decimal(3))
        self.assertEqual(as_decimal(0.1, name="factor"), Decimal("0.1"))

    def test_rejects_bool_nonfinite_and_out_of_range(self):
        for value in (True, False, math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                as_decimal(value, name="factor", minimum=0, maximum=1)
        with self.assertRaises(ValidationError):
            as_decimal("1.0001", name="factor", minimum=0, maximum=1)

    def test_rejects_invalid_bounds_as_validation_errors(self):
        for bound_name, bound in (
            ("minimum", True),
            ("maximum", False),
            ("minimum", math.nan),
            ("maximum", math.nan),
            ("minimum", math.inf),
            ("maximum", -math.inf),
            ("minimum", "not-a-number"),
            ("maximum", "not-a-number"),
        ):
            with self.subTest(bound_name=bound_name, bound=bound):
                try:
                    as_decimal("0.5", name="factor", **{bound_name: bound})
                except Exception as exc:
                    self.assertIsInstance(exc, ValidationError)
                else:
                    self.fail(f"{bound_name}={bound!r} was accepted")

    def test_accepts_equal_inclusive_bounds(self):
        self.assertEqual(
            as_decimal("0.5", name="factor", minimum="0.5", maximum="0.5"),
            Decimal("0.5"),
        )

    def test_rejects_reversed_bounds_as_configuration_error(self):
        try:
            as_decimal("0.5", name="factor", minimum=1, maximum=0)
        except Exception as exc:
            self.assertIsInstance(exc, ConfigurationError)
        else:
            self.fail("reversed bounds were accepted")

    def test_accepts_decimal128_precision_exponent_and_text_edges(self):
        accepted = (
            ("9" * 34, Decimal("9" * 34)),
            ("1e6144", Decimal("1e6144")),
            ("1e-6143", Decimal("1e-6143")),
            (("0" * 127) + "1", Decimal(1)),
        )
        for source, expected in accepted:
            with self.subTest(source=source):
                self.assertEqual(as_decimal(source, name="bounded"), expected)

    def test_rejects_unbounded_precision_exponent_and_text_before_use(self):
        invalid = (
            "9" * 35,
            "1e6145",
            "1e-6144",
            ("0" * 128) + "1",
            "1e" + ("9" * 10_000),
            10**34,
            Decimal("1e6145"),
        )
        for value in invalid:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(
                ValidationError
            ):
                as_decimal(value, name="bounded")

    def test_canonical_decimal_extremes_are_compact_and_bounded(self):
        for value, expected in (
            (Decimal("1e6144"), b"1e6144"),
            (Decimal("-1e-6143"), b"-1e-6143"),
        ):
            with self.subTest(value=value):
                encoded = canonical_json_bytes(value)
                self.assertEqual(encoded, expected)
                self.assertLessEqual(len(encoded), 42)
        for invalid in (Decimal("1e6145"), 10**34):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                canonical_json_bytes(invalid)
