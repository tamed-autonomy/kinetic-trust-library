"""Provisional RFC PR #195 Trust Proof protected-header predicate (stage 2).

Call only after strict stage-1 compact/JCS parsing; a passing header is not a
verified Trust Proof. Installed algorithms must come from trusted local policy.
"""

from __future__ import annotations

from collections.abc import Mapping


_PROTECTED_TYPE = "ktp-trust-proof+jwt"
_SUPPORTED_ALGORITHMS = frozenset({"ES256", "EdDSA"})


def trust_proof_stage2_reason(
    header: Mapping[str, object], *, installed_algorithms: tuple[str, ...]
) -> str | None:
    """Return the first proposed stage-2 failure or ``None`` if it passes."""
    if not isinstance(header, Mapping) or header.get("typ") != _PROTECTED_TYPE:
        return "TP_TYPE"
    algorithm = header.get("alg")
    if (
        type(algorithm) is not str
        or type(installed_algorithms) is not tuple
        or algorithm not in _SUPPORTED_ALGORITHMS
        or algorithm not in installed_algorithms
    ):
        return "TP_ALGORITHM"
    if (
        set(header) != {"alg", "kid", "typ"}
        or any(type(header[name]) is not str or not header[name]
               for name in ("alg", "kid", "typ"))
    ):
        return "TP_HEADER"
    return None


__all__ = ["trust_proof_stage2_reason"]
