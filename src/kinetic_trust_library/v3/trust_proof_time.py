"""Provisional RFC PR #195 Trust Proof time predicate (verification stage 5).

Call only after stages 1–4 have authenticated the original compact JWS and
after trusted key/context lookup. A true result is not proof acceptance.
"""

from __future__ import annotations

from collections.abc import Mapping


_MAX_SAFE_INTEGER = 2**53 - 1


def _safe_time(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER


def trust_proof_time_valid(
    claims: Mapping[str, object],
    *,
    now: int,
    clock_healthy: bool,
    key_not_before: int,
    key_not_after: int,
) -> bool:
    """Check v3 NumericDates, ten-second lifetime, clock and key interval.

    Caller supplies authenticated clock and key binding. This predicate does
    not parse or verify a JWS and must not be used as an authorization gate.
    """
    if not isinstance(claims, Mapping) or clock_healthy is not True:
        return False
    if not all(_safe_time(value) for value in (
        now, key_not_before, key_not_after,
        claims.get("iat"), claims.get("exp"),
    )):
        return False
    issued_at = claims["iat"]
    expires_at = claims["exp"]
    if "nbf" in claims and (
        not _safe_time(claims["nbf"]) or claims["nbf"] != issued_at
    ):
        return False
    return (
        0 < expires_at - issued_at <= 10
        and issued_at <= now < expires_at
        and key_not_before <= issued_at
        and expires_at <= key_not_after
    )


def trust_proof_stage5_reason(
    claims: Mapping[str, object],
    *,
    expected_issuer: str,
    expected_audience: str,
    now: int,
    clock_healthy: bool,
    key_not_before: int,
    key_not_after: int,
) -> str | None:
    """Return the first proposed stage-5 failure, after stages 1–4 pass.

    A ``None`` result only means these issuer, audience and time checks pass.
    It does not mean the proof is valid or authorization may continue.
    """
    if not isinstance(claims, Mapping):
        return "TP_ISSUER"
    issuer = claims.get("iss")
    if type(expected_issuer) is not str or not expected_issuer or (
        type(issuer) is not str or issuer != expected_issuer
    ):
        return "TP_ISSUER"
    audience = claims.get("aud")
    if type(expected_audience) is not str or not expected_audience or (
        type(audience) is not str or audience != expected_audience
    ):
        return "TP_AUDIENCE"
    if not trust_proof_time_valid(
        claims,
        now=now,
        clock_healthy=clock_healthy,
        key_not_before=key_not_before,
        key_not_after=key_not_after,
    ):
        return "TP_TIME"
    return None


__all__ = ["trust_proof_stage5_reason", "trust_proof_time_valid"]
