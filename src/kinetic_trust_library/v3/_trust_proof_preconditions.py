"""Internal provisional orchestration of RFC PR #195 Trust Proof stages 1–5.

Returning ``None`` means only that preconditions passed. It is never a proof
validity or authorization result; schema, invariants and gates remain pending.
"""

from __future__ import annotations

from collections.abc import Mapping

from kinetic_trust_library.errors import ProofFormatError
from kinetic_trust_library.v3.trust_proof_framing import parse_compact_framing
from kinetic_trust_library.v3.trust_proof_header import trust_proof_stage2_reason
from kinetic_trust_library.v3.trust_proof_json import parse_proof_json_objects
from kinetic_trust_library.v3.trust_proof_key import trust_proof_stage3_reason
from kinetic_trust_library.v3.trust_proof_signature import trust_proof_signature_valid
from kinetic_trust_library.v3.trust_proof_time import trust_proof_stage5_reason


def first_precondition_failure(
    compact: str,
    *,
    expected_issuer: str,
    expected_audience: str,
    expected_zone: str,
    now: int,
    clock_healthy: bool,
    installed_algorithms: tuple[str, ...],
    trusted_keys: Mapping[str, Mapping[str, object]],
) -> str | None:
    """Return first failure through stage 5, given authenticated local state."""
    try:
        framing = parse_compact_framing(compact)
        header, payload = parse_proof_json_objects(framing)
    except ProofFormatError:
        return "TP_FORMAT"
    stage2 = trust_proof_stage2_reason(
        header, installed_algorithms=installed_algorithms
    )
    if stage2 is not None:
        return stage2
    key = trusted_keys.get(header["kid"])
    stage3 = trust_proof_stage3_reason(
        header, trusted_key=key,
        expected_issuer=expected_issuer, expected_zone=expected_zone,
    )
    if stage3 is not None:
        return stage3
    if not trust_proof_signature_valid(
        compact, algorithm=header["alg"], trusted_key=key
    ):
        return "TP_SIGNATURE"
    return trust_proof_stage5_reason(
        payload,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        now=now,
        clock_healthy=clock_healthy,
        key_not_before=key.get("not_before"),
        key_not_after=key.get("not_after"),
    )
