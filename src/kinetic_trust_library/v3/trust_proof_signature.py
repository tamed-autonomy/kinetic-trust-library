"""Provisional RFC PR #195 raw Trust Proof signature check (stage 4).

Requires the original compact bytes and a locally trusted, stage-3 bound key.
This is one stage of verification, never complete proof acceptance.
"""

from __future__ import annotations

from collections.abc import Mapping

from kinetic_trust_library.errors import ProofFormatError
from kinetic_trust_library._signature_shapes import (
    _PublicKeyShapeError,
    _SignatureShapeError,
    validate_ed25519_public_key,
    validate_ed25519_signature,
    validate_es256_public_key,
    validate_es256_signature,
)
from kinetic_trust_library._jws_encoding import _decode_segment


def trust_proof_signature_valid(
    compact: str, *, algorithm: str, trusted_key: Mapping[str, object] | None
) -> bool:
    """Verify raw ES256/EdDSA JWS bytes under an already authorized key."""
    if type(compact) is not str or not isinstance(trusted_key, Mapping):
        return False
    if algorithm not in ("ES256", "EdDSA") or trusted_key.get("alg") != algorithm:
        return False
    segments = compact.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        return False
    try:
        signature = _decode_segment(segments[2], name="signature")
        signed_bytes = (segments[0] + "." + segments[1]).encode("ascii")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

        if algorithm == "ES256":
            if trusted_key.get("kty") != "EC" or trusted_key.get("crv") != "P-256":
                return False
            x = _decode_segment(trusted_key["x"], name="key x")
            y = _decode_segment(trusted_key["y"], name="key y")
            if len(x) != 32 or len(y) != 32:
                return False
            public_bytes = b"\x04" + x + y
            validate_es256_public_key(public_bytes)
            validate_es256_signature(signature)
            public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
            encoded_der = utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            public_key.verify(encoded_der, signed_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            if trusted_key.get("kty") != "OKP" or trusted_key.get("crv") != "Ed25519":
                return False
            public_bytes = _decode_segment(trusted_key["x"], name="key x")
            validate_ed25519_public_key(public_bytes)
            validate_ed25519_signature(signature)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(signature, signed_bytes)
    except ImportError:
        return False
    except (
        InvalidSignature, ProofFormatError, _PublicKeyShapeError,
        _SignatureShapeError, KeyError, TypeError, ValueError, UnicodeEncodeError,
    ):
        return False
    return True


__all__ = ["trust_proof_signature_valid"]
