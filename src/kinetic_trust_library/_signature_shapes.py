"""Provider-neutral ES256 and Ed25519 representation checks."""

_P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
)
_P256_HALF_ORDER = int(
    "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    16,
)
_ED25519_FIELD_PRIME = int(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    16,
)
_ED25519_ORDER = int(
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    16,
)
_ED25519_SMALL_ORDER_ENCODINGS = frozenset(
    {
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000080"
        ),
        bytes.fromhex(
            "0100000000000000000000000000000000000000000000000000000000000000"
        ),
        bytes.fromhex(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        ),
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
        ),
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"
        ),
        bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
        ),
        bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
        ),
    }
)


class _PublicKeyShapeError(Exception):
    """A provider-neutral public-key representation is structurally invalid."""


class _SignatureShapeError(Exception):
    """A provider-neutral signature representation is structurally invalid."""


def validate_es256_public_key(public_key: bytes, /) -> None:
    if type(public_key) is not bytes:
        raise _PublicKeyShapeError("ES256 public key must be exact immutable bytes")
    if len(public_key) != 65:
        raise _PublicKeyShapeError("ES256 public key must contain exactly 65 bytes")
    if public_key[0] != 0x04:
        raise _PublicKeyShapeError("ES256 public key must use uncompressed SEC1 form")


def validate_es256_signature(signature: bytes, /) -> None:
    if type(signature) is not bytes:
        raise _SignatureShapeError("ES256 signature must be exact immutable bytes")
    if len(signature) != 64:
        raise _SignatureShapeError("ES256 signature must contain exactly 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 0 < r < _P256_ORDER or not 0 < s < _P256_ORDER:
        raise _SignatureShapeError("ES256 signature scalars are out of range")
    if s > _P256_HALF_ORDER:
        raise _SignatureShapeError("ES256 signature must use low-S form")


def validate_ed25519_public_key(public_key: bytes, /) -> None:
    if type(public_key) is not bytes:
        raise _PublicKeyShapeError("Ed25519 public key must be exact immutable bytes")
    if len(public_key) != 32:
        raise _PublicKeyShapeError("Ed25519 public key must contain exactly 32 bytes")
    _validate_ed25519_point_encoding(public_key, failure=_PublicKeyShapeError)


def validate_ed25519_signature(signature: bytes, /) -> None:
    if type(signature) is not bytes:
        raise _SignatureShapeError("Ed25519 signature must be exact immutable bytes")
    if len(signature) != 64:
        raise _SignatureShapeError("Ed25519 signature must contain exactly 64 bytes")
    encoded_r = signature[:32]
    _validate_ed25519_point_encoding(encoded_r, failure=_SignatureShapeError)
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ED25519_ORDER:
        raise _SignatureShapeError("Ed25519 signature scalar is noncanonical")


def _validate_ed25519_point_encoding(
    encoded: bytes,
    *,
    failure: type[_PublicKeyShapeError] | type[_SignatureShapeError],
) -> None:
    encoded_y = bytearray(encoded)
    x_sign = encoded_y[31] >> 7
    encoded_y[31] &= 0x7F
    y = int.from_bytes(encoded_y, "little")
    if y >= _ED25519_FIELD_PRIME:
        raise failure("Ed25519 point encoding is noncanonical")
    if x_sign == 1 and y in (1, _ED25519_FIELD_PRIME - 1):
        raise failure("Ed25519 point encoding has an invalid x sign")
    if encoded in _ED25519_SMALL_ORDER_ENCODINGS:
        raise failure("Ed25519 point encoding has small order")
