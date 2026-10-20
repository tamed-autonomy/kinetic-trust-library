"""Proof-of-Resilience validation and authoritative decimal calculation."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT, as_decimal
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import utc_time, validate_identifier
from kinetic_trust_library.models.standing import (
    FrictionCategory,
    PoRAttestationDeclaration,
    PoRResult,
)


_CATEGORY_RANGES = {
    FrictionCategory.ELEVATED: (Decimal("0.3"), Decimal("0.5"), False),
    FrictionCategory.HIGH: (Decimal("0.5"), Decimal("0.7"), False),
    FrictionCategory.SEVERE: (Decimal("0.7"), Decimal("0.9"), False),
    FrictionCategory.CRISIS: (Decimal("0.9"), Decimal("1"), True),
}
_CATEGORY_WEIGHTS = {
    FrictionCategory.ELEVATED: Decimal(1),
    FrictionCategory.HIGH: Decimal(2),
    FrictionCategory.SEVERE: Decimal(5),
    FrictionCategory.CRISIS: Decimal(10),
}


def calculate_por(
    attestations: Iterable[PoRAttestationDeclaration],
    agent_id: str,
    cutoff: datetime,
) -> PoRResult:
    """Calculate PoR from raw declarations without accepting a computed term."""
    subject = _identifier(agent_id, name="PoR agent ID")
    effective_cutoff = utc_time(cutoff, name="PoR cutoff")
    normalized = _validate_attestations(
        attestations, agent_id=subject, cutoff=effective_cutoff
    )
    eligible = tuple(value for value in normalized if _is_eligible_attestation(value))
    with localcontext(KTP_CONTEXT):
        score = sum(
            (
                _CATEGORY_WEIGHTS[value.friction_category] * value.action_risk
                for value in eligible
            ),
            Decimal(0),
        )
        contribution = _por_contribution(score)
    result = object.__new__(PoRResult)
    for name, value in (
        ("eligible_attestation_ids", tuple(item.attestation_id for item in eligible)),
        ("resilience_score", score),
        ("contribution", contribution),
        ("_agent_id", subject),
        ("_cutoff", effective_cutoff),
        ("_attestations", normalized),
    ):
        object.__setattr__(result, name, value)
    object.__setattr__(result, "digest", canonical_sha256(_por_digest_input(result)))
    return result


def require_validated_por_result(value: object) -> PoRResult:
    """Structurally rederive the represented PoR result and its digest."""
    if type(value) is not PoRResult:
        raise ValidationError("value is not a validated PoR result")
    try:
        _require_por_structure(value)
        normalized = calculate_por(
            value._attestations, agent_id=value._agent_id, cutoff=value._cutoff
        )
        actual = canonical_json_bytes(_por_public_projection(value))
        expected = canonical_json_bytes(_por_public_projection(normalized))
        if actual != expected:
            raise ValidationError("PoR result does not match represented attestations")
    except Exception as exc:
        raise ValidationError("PoR result integrity is invalid") from exc
    return value


def _require_por_structure(value: PoRResult) -> None:
    if (
        type(value.eligible_attestation_ids) is not tuple
        or any(type(item) is not str for item in value.eligible_attestation_ids)
        or type(value.resilience_score) is not Decimal
        or not value.resilience_score.is_finite()
        or type(value.contribution) is not Decimal
        or not value.contribution.is_finite()
        or type(value.digest) is not str
        or type(value._agent_id) is not str
        or type(value._cutoff) is not datetime
        or type(value._attestations) is not tuple
    ):
        raise ValidationError("PoR result structure is invalid")
    _identifier(value._agent_id, name="represented PoR agent ID")
    utc_time(value._cutoff, name="represented PoR cutoff")
    for item in value.eligible_attestation_ids:
        _identifier(item, name="represented eligible attestation ID")
    for item in value._attestations:
        if (
            type(item) is not PoRAttestationDeclaration
            or type(item.attestation_id) is not str
            or type(item.agent_id) is not str
            or type(item.transaction_ref) is not str
            or type(item.friction) is not Decimal
            or not item.friction.is_finite()
            or type(item.friction_category) is not FrictionCategory
            or type(item.action_risk) is not Decimal
            or not item.action_risk.is_finite()
            or type(item.outcome) is not str
            or type(item.timestamp) is not datetime
            or type(item.oracle_id) is not str
            or type(item.verification_ref) is not str
        ):
            raise ValidationError("represented PoR attestation structure is invalid")
        utc_time(item.timestamp, name="represented PoR attestation timestamp")


def _validate_attestations(
    values: Iterable[PoRAttestationDeclaration],
    *,
    agent_id: str,
    cutoff: datetime,
) -> tuple[PoRAttestationDeclaration, ...]:
    if type(values) not in (list, tuple):
        raise ValidationError(
            "PoR attestations must be a finite built-in list or tuple"
        )
    supplied = tuple(values)
    normalized: list[PoRAttestationDeclaration] = []
    seen_ids: set[str] = set()
    seen_transactions: set[str] = set()
    for declaration in supplied:
        value = _validate_attestation(declaration, agent_id=agent_id, cutoff=cutoff)
        if value.attestation_id in seen_ids:
            raise ValidationError(
                f"duplicate PoR attestation ID: {value.attestation_id}"
            )
        if value.transaction_ref in seen_transactions:
            raise ValidationError(
                f"duplicate PoR transaction reference: {value.transaction_ref}"
            )
        seen_ids.add(value.attestation_id)
        seen_transactions.add(value.transaction_ref)
        normalized.append(value)
    return tuple(sorted(normalized, key=lambda item: item.attestation_id))


def _validate_attestation(
    value: object, *, agent_id: str, cutoff: datetime
) -> PoRAttestationDeclaration:
    if type(value) is not PoRAttestationDeclaration:
        raise ValidationError("PoR attestation must use the explicit declaration")
    try:
        attestation_id = value.attestation_id
        declared_agent = value.agent_id
        transaction_ref = value.transaction_ref
        friction = value.friction
        friction_category = value.friction_category
        action_risk = value.action_risk
        outcome = value.outcome
        timestamp = value.timestamp
        oracle_id = value.oracle_id
        verification_ref = value.verification_ref
    except AttributeError as exc:
        raise ValidationError("PoR attestation structure is invalid") from exc
    attestation_id = _identifier(attestation_id, name="PoR attestation ID")
    declared_agent = _identifier(declared_agent, name="PoR attestation agent ID")
    if declared_agent != agent_id:
        raise ValidationError("PoR attestation agent does not match the subject")
    transaction_ref = _identifier(
        transaction_ref, name="PoR transaction reference"
    )
    friction = as_decimal(friction, name="PoR friction", minimum=0, maximum=1)
    if type(friction_category) is not FrictionCategory:
        raise ValidationError("PoR friction category is invalid")
    _require_matching_category(friction, friction_category)
    action_risk = as_decimal(
        action_risk, name="PoR action risk", minimum=0, maximum=1
    )
    if type(outcome) is not str or outcome not in {
        "success",
        "graceful_degrade",
    }:
        raise ValidationError("PoR outcome must be success or graceful_degrade")
    timestamp = utc_time(timestamp, name="PoR attestation timestamp")
    if timestamp > cutoff:
        raise ValidationError("PoR attestation timestamp is in the future")
    oracle_id = _identifier(oracle_id, name="PoR Oracle ID")
    verification_ref = _identifier(
        verification_ref, name="PoR verification reference"
    )
    return PoRAttestationDeclaration(
        attestation_id=attestation_id,
        agent_id=declared_agent,
        transaction_ref=transaction_ref,
        friction=friction,
        friction_category=friction_category,
        action_risk=action_risk,
        outcome=outcome,
        timestamp=timestamp,
        oracle_id=oracle_id,
        verification_ref=verification_ref,
    )


def _require_matching_category(friction: Decimal, category: FrictionCategory) -> None:
    lower, upper, upper_inclusive = _CATEGORY_RANGES[category]
    if (
        friction < lower
        or friction > upper
        or (friction == upper and not upper_inclusive)
    ):
        raise ValidationError("PoR friction category does not match friction")


def _is_eligible_attestation(value: PoRAttestationDeclaration) -> bool:
    if value.friction <= Decimal("0.3"):
        return False
    if value.outcome == "graceful_degrade" and value.friction < Decimal("0.5"):
        return False
    return True


def _por_contribution(score: Decimal) -> Decimal:
    if score == 0:
        return Decimal(0)
    with localcontext(KTP_CONTEXT):
        calculated = Decimal(10) * (Decimal(1) + score).log10()
        return min(Decimal(70), calculated)


def _por_digest_input(value: PoRResult) -> dict[str, object]:
    return {
        "agent_id": value._agent_id,
        "cutoff": value._cutoff,
        "attestations": value._attestations,
        "eligible_attestation_ids": value.eligible_attestation_ids,
        "resilience_score": value.resilience_score,
        "contribution": value.contribution,
    }


def _por_public_projection(value: PoRResult) -> dict[str, object]:
    return {
        "eligible_attestation_ids": value.eligible_attestation_ids,
        "resilience_score": value.resilience_score,
        "contribution": value.contribution,
        "digest": value.digest,
    }


def _identifier(value: object, *, name: str) -> str:
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    return validate_identifier(value, name=name)


__all__ = ["calculate_por", "require_validated_por_result"]
