"""Shared immutable JWK loading; no artifact-specific verification policy.

Registry authenticity and role authority are preconditions. Callers separately
check purpose, issuer/zone, trusted strength, signature and artifact validity.
"""
from dataclasses import dataclass
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from kinetic_trust_library._jws_encoding import _decode_segment


@dataclass(frozen=True, slots=True)
class KeyBinding:
    key_id: str
    subject: str
    algorithm: str
    purpose: str
    public_key: object
    zone_id: str


def unb64(value):
    return _decode_segment(value,name="JWS key/header")


def load_key_binding(keys, compact):
    """Build an internal RFC key binding only from authenticated registry data."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
    if type(compact) is not str or len(compact)>524288:
        raise ValueError("unbounded purpose-separated JWS signature")
    parts=compact.split(".")
    if len(parts)!=3:
        raise ValueError("invalid purpose-separated JWS signature framing")
    header_bytes=unb64(parts[0])
    if len(header_bytes)>1024:
        raise ValueError("unbounded purpose-separated JWS header")
    header=_parse_jcs_object(header_bytes)
    key=keys.get(header.get("kid"))
    if type(key) is not dict or key.get("kid")!=header.get("kid") or key.get("revoked") is not False:
        raise ValueError("purpose-separated JWS key is not currently trusted")
    if not _time(key.get("not_before")) or not _time(key.get("not_after")):
        raise ValueError("invalid key/role validity interval")
    algorithm,curve=key.get("alg"),key.get("crv")
    if algorithm in ("ES256","ES384") and key.get("kty")=="EC":
        size=32 if algorithm=="ES256" else 48
        expected_curve="P-256" if size==32 else "P-384"
        x,y=unb64(key.get("x")),unb64(key.get("y"))
        if curve!=expected_curve or len(x)!=size or len(y)!=size:
            raise ValueError("purpose-separated JWS curve/coordinate mismatch")
        public=ec.EllipticCurvePublicNumbers(int.from_bytes(x,"big"),int.from_bytes(y,"big"),
            ec.SECP256R1() if size==32 else ec.SECP384R1()).public_key()
    elif algorithm=="EdDSA" and key.get("kty")=="OKP" and curve in ("Ed25519","Ed448"):
        public=(ed25519.Ed25519PublicKey if curve=="Ed25519" else ed448.Ed448PublicKey).from_public_bytes(unb64(key.get("x")))
    else:
        raise ValueError("unsupported purpose-separated JWS signing key")
    return KeyBinding(key["kid"],key["subject"],algorithm,key["purpose"],public,key["zone_id"]),key


