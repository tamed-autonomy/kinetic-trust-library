"""Provisional RFC PR #195 Trust Proof trusted-key metadata checks (stage 3).

The key record must be obtained from authenticated local state. This module
does not perform key lookup, revocation retrieval or signature verification.
"""

from __future__ import annotations

from collections.abc import Mapping


_KEY_TYPES = {"ES256": ("EC", "P-256"), "EdDSA": ("OKP", "Ed25519")}


def trust_proof_stage3_reason(
    header: Mapping[str, object],
    *,
    trusted_key: Mapping[str, object] | None,
    expected_issuer: str,
    expected_zone: str,
) -> str | None:
    """Return first proposed key-metadata failure after stages 1–2 pass."""
    if (
        not isinstance(header, Mapping)
        or not isinstance(trusted_key, Mapping)
        or trusted_key.get("kid") != header.get("kid")
    ):
        return "TP_KEY_UNTRUSTED"
    if trusted_key.get("revoked") is not False:
        return "TP_KEY_REVOKED"
    if (
        trusted_key.get("role") != "trust-proof-oracle"
        or type(expected_issuer) is not str
        or not expected_issuer
        or trusted_key.get("issuer") != expected_issuer
        or type(expected_zone) is not str
        or not expected_zone
        or trusted_key.get("zone") != expected_zone
    ):
        return "TP_KEY_ROLE"
    algorithm = header.get("alg")
    expected_type = _KEY_TYPES.get(algorithm) if type(algorithm) is str else None
    if (
        expected_type is None
        or trusted_key.get("alg") != header.get("alg")
        or (trusted_key.get("kty"), trusted_key.get("crv")) != expected_type
    ):
        return "TP_KEY_ALGORITHM"
    return None


__all__ = ["trust_proof_stage3_reason"]
