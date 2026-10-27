"""Provisional RFC PR #195 Trust Proof invariants and ingress gate (stage 7).

Call only after the corrected stage-6 schema and authenticated proof have
passed. A caller-supplied receipt list is never ingress verification.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from decimal import Decimal, InvalidOperation
import math

from kinetic_trust_library.agent_identity import validate_agent_uri
from kinetic_trust_library.errors import ValidationError


def _number(value: object) -> Decimal | None:
    if type(value) not in (int, float):
        return None
    if type(value) is float and not math.isfinite(value):
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def _invariants_hold(
    claims: Mapping[str, object], *, expected_subject: str,
    expected_zone: str, required_ceilings: Mapping[str, object],
) -> bool:
    ktp = claims["ktp"]
    if not isinstance(ktp, Mapping):
        return False
    subject = claims["sub"]
    if type(subject) is not str or subject != expected_subject:
        return False
    validate_agent_uri(subject)
    parts = subject.split(":")
    lineage = ktp["lineage"]
    generation = ktp["generation"]
    if type(generation) is not int or generation < 0 or lineage != parts[1]:
        return False
    if lineage == "sponsored":
        if generation > 2:
            return False
    elif lineage == "independent":
        if not 3 <= generation <= 6 or parts[2] != f"{generation}gen":
            return False
    elif lineage == "guarantor":
        if generation < 7 or parts[2] != f"{generation}gen":
            return False
    else:
        return False
    if ktp["zone"] != expected_zone:
        return False
    ceilings = ktp["applicable_ceilings"]
    if type(ceilings) is not list or not ceilings or not isinstance(required_ceilings, Mapping):
        return False
    declared: dict[str, Decimal] = {}
    for ceiling in ceilings:
        if not isinstance(ceiling, Mapping):
            return False
        name = ceiling.get("ceiling")
        value = _number(ceiling.get("value"))
        if type(name) is not str or value is None or name in declared:
            return False
        declared[name] = value
    generation_limit = Decimal(25 + 10 * generation) if generation <= 6 else Decimal(100)
    if declared.get("generation") != generation_limit:
        return False
    for name, value in required_ceilings.items():
        if type(name) is not str or declared.get(name) != _number(value):
            return False
    base = ktp.get("e_base")
    trust = ktp.get("e_trust")
    if base is not None:
        base_number = _number(base)
        if base_number is None or any(base_number > limit for limit in declared.values()):
            return False
        if trust is not None:
            trust_number = _number(trust)
            if trust_number is None or trust_number > base_number:
                return False
    root = ktp["root_instrument"]
    if not isinstance(root, Mapping):
        return False
    if root.get("status") in ("current", "non_renewable"):
        end_time = root.get("end_time")
        if type(end_time) is not int or claims["exp"] > end_time:
            return False
    return True


def trust_proof_stage7_reason(
    claims: Mapping[str, object],
    *,
    expected_subject: str,
    expected_zone: str,
    required_ceilings: Mapping[str, object],
    ring_depth: int,
    ingress_verifier: Callable[[tuple[object, ...]], bool] | None,
) -> str | None:
    """Return first stage-7 failure; ``None`` is not proof acceptance."""
    try:
        if not _invariants_hold(
            claims, expected_subject=expected_subject,
            expected_zone=expected_zone, required_ceilings=required_ceilings,
        ):
            return "TP_INVARIANT"
    except (KeyError, TypeError, ValueError, ValidationError):
        return "TP_INVARIANT"
    path = claims["ktp"].get("ingress_path")
    if type(ring_depth) is not int or not 0 <= ring_depth <= 5:
        return "TP_INGRESS"
    if ring_depth == 0:
        return "TP_INGRESS" if path is not None else None
    if type(path) is not list or len(path) != ring_depth:
        return "TP_INGRESS"
    if ingress_verifier is None:
        return "TP_INGRESS"
    try:
        if ingress_verifier(tuple(path)) is not True:
            return "TP_INGRESS"
    except Exception:
        return "TP_INGRESS"
    return None


__all__ = ["trust_proof_stage7_reason"]
