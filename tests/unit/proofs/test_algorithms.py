"""Closed Trust Proof algorithm-shape tests."""

import unittest

import kinetic_trust_library.proofs as proofs
from kinetic_trust_library.proofs._algorithms import (
    _PublicKeyShapeError,
    _SignatureShapeError,
    validate_es256_public_key,
    validate_es256_signature,
    validate_ed25519_public_key,
    validate_ed25519_signature,
)

from ._fixtures import ed25519_signature, es256_signature


P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
)
P256_HALF_ORDER = int(
    "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    16,
)
ED25519_ORDER = int(
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    16,
)
RFC8032_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
RFC8032_ENCODED_R = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
)
RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
NONCANONICAL_ED25519_POINTS = (
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
)
SMALL_ORDER_ED25519_POINTS = (
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
)

_ED25519_REFERENCE_P = (1 << 255) - 19
_ED25519_REFERENCE_D = (
    -121665 * pow(121666, _ED25519_REFERENCE_P - 2, _ED25519_REFERENCE_P)
) % _ED25519_REFERENCE_P
_ED25519_REFERENCE_IDENTITY = (0, 1)


def _reference_square_root(value: int) -> int | None:
    candidate = pow(
        value % _ED25519_REFERENCE_P,
        (_ED25519_REFERENCE_P + 3) // 8,
        _ED25519_REFERENCE_P,
    )
    if candidate * candidate % _ED25519_REFERENCE_P != value % _ED25519_REFERENCE_P:
        candidate = (
            candidate
            * pow(2, (_ED25519_REFERENCE_P - 1) // 4, _ED25519_REFERENCE_P)
            % _ED25519_REFERENCE_P
        )
    if candidate * candidate % _ED25519_REFERENCE_P != value % _ED25519_REFERENCE_P:
        return None
    return candidate


def _reference_decode_ed25519(encoded: bytes) -> tuple[int, int] | None:
    encoded_integer = int.from_bytes(encoded, "little")
    x_sign = encoded_integer >> 255
    y = encoded_integer & ((1 << 255) - 1)
    if y >= _ED25519_REFERENCE_P:
        return None
    numerator = (y * y - 1) % _ED25519_REFERENCE_P
    denominator = (_ED25519_REFERENCE_D * y * y + 1) % _ED25519_REFERENCE_P
    x = _reference_square_root(
        numerator * pow(denominator, _ED25519_REFERENCE_P - 2, _ED25519_REFERENCE_P)
    )
    if x is None or (x == 0 and x_sign == 1):
        return None
    if x & 1 != x_sign:
        x = _ED25519_REFERENCE_P - x
    return x, y


def _reference_encode_ed25519(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _reference_add_ed25519(
    left: tuple[int, int],
    right: tuple[int, int],
) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _ED25519_REFERENCE_D * x1 * x2 * y1 * y2
    x_denominator = pow(
        (1 + product) % _ED25519_REFERENCE_P,
        _ED25519_REFERENCE_P - 2,
        _ED25519_REFERENCE_P,
    )
    y_denominator = pow(
        (1 - product) % _ED25519_REFERENCE_P,
        _ED25519_REFERENCE_P - 2,
        _ED25519_REFERENCE_P,
    )
    return (
        (x1 * y2 + x2 * y1) * x_denominator % _ED25519_REFERENCE_P,
        (y1 * y2 + x1 * x2) * y_denominator % _ED25519_REFERENCE_P,
    )


def _reference_multiply_ed25519(
    scalar: int,
    point: tuple[int, int],
) -> tuple[int, int]:
    result = _ED25519_REFERENCE_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _reference_add_ed25519(result, addend)
        addend = _reference_add_ed25519(addend, addend)
        scalar >>= 1
    return result


def _derive_ed25519_torsion_encodings() -> frozenset[bytes]:
    """Derive the cofactor subgroup from RFC 8032 field and curve equations.

    The order-4 points have ``y = 0``.  An exact order-8 point doubles to one
    of them, so the affine doubling numerator gives
    ``d * (y**2)**2 + 2 * y**2 - 1 = 0``.  Solving that field equation yields
    the four order-8 points without using a point-encoding table.
    """
    square_root_minus_one = _reference_square_root(-1)
    square_root_one_plus_d = _reference_square_root(1 + _ED25519_REFERENCE_D)
    if square_root_minus_one is None or square_root_one_plus_d is None:
        raise AssertionError("RFC 8032 field constants must have the required roots")
    points = {
        _ED25519_REFERENCE_IDENTITY,
        (0, _ED25519_REFERENCE_P - 1),
        (square_root_minus_one, 0),
        (_ED25519_REFERENCE_P - square_root_minus_one, 0),
    }
    inverse_d = pow(
        _ED25519_REFERENCE_D,
        _ED25519_REFERENCE_P - 2,
        _ED25519_REFERENCE_P,
    )
    for square_root_sign in (square_root_one_plus_d, -square_root_one_plus_d):
        y_squared = (-1 + square_root_sign) * inverse_d % _ED25519_REFERENCE_P
        y_root = _reference_square_root(y_squared)
        if y_root is None:
            continue
        for y in (y_root, -y_root % _ED25519_REFERENCE_P):
            x_squared = (
                (y * y - 1)
                * pow(
                    (_ED25519_REFERENCE_D * y * y + 1) % _ED25519_REFERENCE_P,
                    _ED25519_REFERENCE_P - 2,
                    _ED25519_REFERENCE_P,
                )
                % _ED25519_REFERENCE_P
            )
            x_root = _reference_square_root(x_squared)
            if x_root is None:
                raise AssertionError("derived order-8 y-coordinate must decode")
            points.add((x_root, y))
            points.add((_ED25519_REFERENCE_P - x_root, y))
    return frozenset(_reference_encode_ed25519(point) for point in points)


class AlgorithmShapeTests(unittest.TestCase):
    def test_es256_uncompressed_point_shape_is_accepted(self):
        public_key = bytes.fromhex(
            "04"
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )

        validate_es256_public_key(public_key)

    def test_structural_failure_categories_are_private_and_context_neutral(self):
        self.assertIsNot(_PublicKeyShapeError, _SignatureShapeError)
        self.assertEqual(_PublicKeyShapeError.__name__, "_PublicKeyShapeError")
        self.assertEqual(_SignatureShapeError.__name__, "_SignatureShapeError")
        self.assertTrue(issubclass(_PublicKeyShapeError, Exception))
        self.assertTrue(issubclass(_SignatureShapeError, Exception))

    def test_es256_public_key_requires_exact_immutable_bytes_before_hooks(self):
        class HostileBytes(bytes):
            def __getitem__(self, key: object) -> object:
                raise AssertionError("bytes hook must not run")

        valid_shape = b"\x04" + (b"\x00" * 64)
        for public_key in (
            bytearray(valid_shape),
            memoryview(valid_shape),
            HostileBytes(valid_shape),
        ):
            with (
                self.subTest(public_key_type=type(public_key).__name__),
                self.assertRaises(_PublicKeyShapeError),
            ):
                validate_es256_public_key(public_key)  # type: ignore[arg-type]

    def test_es256_public_key_rejects_wrong_width_and_sec1_prefix(self):
        invalid_keys = (
            b"\x04" + (b"\x00" * 63),
            b"\x04" + (b"\x00" * 65),
            b"\x00" + (b"\x00" * 64),
            b"\x02" + (b"\x00" * 64),
            b"\x03" + (b"\x00" * 64),
        )
        for public_key in invalid_keys:
            with (
                self.subTest(public_key=public_key),
                self.assertRaises(_PublicKeyShapeError),
            ):
                validate_es256_public_key(public_key)

    def test_proofs_package_exports_facade_but_no_task_2_helpers(self):
        self.assertEqual(proofs.__all__, ["AsyncTrustProofs", "TrustProofs"])
        for name in (
            "parse_compact",
            "parse_payload",
            "canonical_payload_bytes",
            "validate_es256_public_key",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(proofs, name))


class ES256SignatureShapeTests(unittest.TestCase):
    def test_boundary_scalars_and_low_s_maximum_are_accepted(self):
        for signature in (
            es256_signature(r=1, s=1),
            es256_signature(r=P256_ORDER - 1, s=P256_HALF_ORDER),
        ):
            with self.subTest(signature=signature):
                validate_es256_signature(signature)

    def test_signature_requires_exact_64_byte_immutable_value_before_hooks(self):
        class HostileBytes(bytes):
            def __getitem__(self, key: object) -> object:
                raise AssertionError("bytes hook must not run")

        valid = es256_signature(r=1, s=1)
        for signature in (
            bytearray(valid),
            memoryview(valid),
            HostileBytes(valid),
            valid[:-1],
            valid + b"\x00",
        ):
            with (
                self.subTest(signature_type=type(signature).__name__),
                self.assertRaises(_SignatureShapeError),
            ):
                validate_es256_signature(signature)  # type: ignore[arg-type]

    def test_zero_and_curve_order_scalars_are_rejected(self):
        signatures = (
            es256_signature(r=0, s=1),
            es256_signature(r=1, s=0),
            es256_signature(r=P256_ORDER, s=1),
            es256_signature(r=1, s=P256_ORDER),
        )
        for signature in signatures:
            with (
                self.subTest(signature=signature),
                self.assertRaises(_SignatureShapeError),
            ):
                validate_es256_signature(signature)

    def test_high_s_is_rejected_without_normalization(self):
        high_s = es256_signature(r=1, s=P256_HALF_ORDER + 1)

        with self.assertRaises(_SignatureShapeError):
            validate_es256_signature(high_s)
        self.assertEqual(
            high_s.hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
            "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        )


class Ed25519ReferenceArithmeticTests(unittest.TestCase):
    def test_literal_points_are_exactly_the_rfc8032_eight_torsion_points(self):
        expected_orders = (4, 4, 1, 2, 8, 8, 8, 8)
        literal_encodings = frozenset(SMALL_ORDER_ED25519_POINTS)

        self.assertEqual(len(literal_encodings), 8)
        self.assertEqual(_derive_ed25519_torsion_encodings(), literal_encodings)

        decoded_points: list[tuple[int, int]] = []
        for encoded, expected_order in zip(
            SMALL_ORDER_ED25519_POINTS,
            expected_orders,
            strict=True,
        ):
            with self.subTest(encoded=encoded.hex(), expected_order=expected_order):
                point = _reference_decode_ed25519(encoded)
                self.assertIsNotNone(point)
                assert point is not None
                x, y = point
                self.assertEqual(
                    (-x * x + y * y - 1 - _ED25519_REFERENCE_D * x * x * y * y)
                    % _ED25519_REFERENCE_P,
                    0,
                )
                self.assertEqual(_reference_encode_ed25519(point), encoded)
                self.assertEqual(
                    _reference_multiply_ed25519(expected_order, point),
                    _ED25519_REFERENCE_IDENTITY,
                )
                if expected_order > 1:
                    self.assertNotEqual(
                        _reference_multiply_ed25519(expected_order // 2, point),
                        _ED25519_REFERENCE_IDENTITY,
                    )
                decoded_points.append(point)

        for left in decoded_points:
            for right in decoded_points:
                self.assertIn(
                    _reference_encode_ed25519(_reference_add_ed25519(left, right)),
                    literal_encodings,
                )


class Ed25519PublicKeyShapeTests(unittest.TestCase):
    def test_rfc8032_public_key_encoding_is_accepted(self):
        validate_ed25519_public_key(RFC8032_PUBLIC_KEY)

    def test_public_key_requires_exact_32_byte_immutable_value_before_hooks(self):
        class HostileBytes(bytes):
            def __getitem__(self, key: object) -> object:
                raise AssertionError("bytes hook must not run")

        for public_key in (
            bytearray(RFC8032_PUBLIC_KEY),
            memoryview(RFC8032_PUBLIC_KEY),
            HostileBytes(RFC8032_PUBLIC_KEY),
            RFC8032_PUBLIC_KEY[:-1],
            RFC8032_PUBLIC_KEY + b"\x00",
        ):
            with (
                self.subTest(public_key_type=type(public_key).__name__),
                self.assertRaises(_PublicKeyShapeError),
            ):
                validate_ed25519_public_key(public_key)  # type: ignore[arg-type]

    def test_noncanonical_point_encodings_are_rejected(self):
        for public_key in NONCANONICAL_ED25519_POINTS:
            with (
                self.subTest(public_key=public_key),
                self.assertRaises(_PublicKeyShapeError),
            ):
                validate_ed25519_public_key(public_key)

    def test_all_eight_canonical_small_order_points_are_rejected(self):
        self.assertEqual(len(SMALL_ORDER_ED25519_POINTS), 8)
        for public_key in SMALL_ORDER_ED25519_POINTS:
            with (
                self.subTest(public_key=public_key),
                self.assertRaises(_PublicKeyShapeError),
            ):
                validate_ed25519_public_key(public_key)


class Ed25519SignatureShapeTests(unittest.TestCase):
    def test_rfc8032_signature_encoding_is_accepted(self):
        validate_ed25519_signature(RFC8032_SIGNATURE)

    def test_signature_requires_exact_64_byte_immutable_value_before_hooks(self):
        class HostileBytes(bytes):
            def __getitem__(self, key: object) -> object:
                raise AssertionError("bytes hook must not run")

        for signature in (
            bytearray(RFC8032_SIGNATURE),
            memoryview(RFC8032_SIGNATURE),
            HostileBytes(RFC8032_SIGNATURE),
            RFC8032_SIGNATURE[:-1],
            RFC8032_SIGNATURE + b"\x00",
        ):
            with (
                self.subTest(signature_type=type(signature).__name__),
                self.assertRaises(_SignatureShapeError),
            ):
                validate_ed25519_signature(signature)  # type: ignore[arg-type]

    def test_scalar_zero_and_order_minus_one_are_canonical_but_order_is_not(self):
        validate_ed25519_signature(ed25519_signature(encoded_r=RFC8032_ENCODED_R, s=0))
        validate_ed25519_signature(
            ed25519_signature(encoded_r=RFC8032_ENCODED_R, s=ED25519_ORDER - 1)
        )
        with self.assertRaises(_SignatureShapeError):
            validate_ed25519_signature(
                ed25519_signature(encoded_r=RFC8032_ENCODED_R, s=ED25519_ORDER)
            )

    def test_noncanonical_and_small_order_encoded_r_values_are_rejected(self):
        for encoded_r in NONCANONICAL_ED25519_POINTS + SMALL_ORDER_ED25519_POINTS:
            signature = ed25519_signature(encoded_r=encoded_r, s=1)
            with (
                self.subTest(encoded_r=encoded_r),
                self.assertRaises(_SignatureShapeError),
            ):
                validate_ed25519_signature(signature)


if __name__ == "__main__":
    unittest.main()
