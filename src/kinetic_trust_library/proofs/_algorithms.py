"""Legacy private import location for shared signature representation checks."""
from kinetic_trust_library._signature_shapes import (
    _P256_ORDER,
    _P256_HALF_ORDER,
    _ED25519_FIELD_PRIME,
    _ED25519_ORDER,
    _ED25519_SMALL_ORDER_ENCODINGS,
    _PublicKeyShapeError,
    _SignatureShapeError,
    validate_es256_public_key,
    validate_es256_signature,
    validate_ed25519_public_key,
    validate_ed25519_signature,
    _validate_ed25519_point_encoding,
)
