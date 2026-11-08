"""Provisional person tier and operational-capacity checks from RFC PR #165.

This is a pure projection of two checks, not execution permission. Eligibility,
Soul, proof, request binding and enforcement remain separate prerequisites.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError


_TIERS = ("hibernation", "observer", "analyst", "operator", "admin")
_CLASS_FLOORS = {
    "Heartbeat": "hibernation",
    "Read (public)": "observer",
    "Write (logs)": "observer",
    "Read (internal)": "analyst",
    "Read (private)": "analyst",
    "Read (sensitive)": "analyst",
    "Write (append)": "analyst",
    "Write (modify)": "operator",
    "Execute (safe)": "operator",
    "Write (sensitive)": "admin",
    "Execute (unsafe)": "admin",
    "Delete (recoverable)": "admin",
    "Delete (permanent)": "admin",
    "Admin (config)": "admin",
    "Admin (security)": "admin",
    "Admin (infra)": "admin",
}
_LEDGER_ACTS = frozenset(("bond_posted", "attestation_issued", "approval", "veto_clear"))


@dataclass(frozen=True, slots=True)
class PersonActionChecks:
    tier: str
    tier_checked: bool
    capacity_e: Decimal
    capacity_passed: bool
    silent_veto: bool
    veto_reason: str | None


def assess_person_tier_and_capacity(
    *,
    effective_trust: DecimalLike,
    operational_e: DecimalLike,
    action_risk: DecimalLike,
    action_class: str | None = None,
    ledger_act: str | None = None,
) -> PersonActionChecks:
    """Check the two person-specific boundaries using authenticated inputs.

    Exactly one of an executed action class and a signed ledger act is needed.
    The caller must authenticate the adapter's E and classify the actual act.
    """
    if (action_class is None) == (ledger_act is None):
        raise ValidationError("person check requires one action class or ledger act")
    if action_class is not None and action_class not in _CLASS_FLOORS:
        raise ValidationError("unknown person action class")
    if ledger_act is not None and ledger_act not in _LEDGER_ACTS:
        raise ValidationError("unknown person ledger act")
    trust = as_decimal(effective_trust, name="person effective trust", minimum=0, maximum=100)
    operational = as_decimal(operational_e, name="person operational E", minimum=0, maximum=100)
    risk = as_decimal(action_risk, name="person action risk", minimum=0, maximum=100)
    tier = "admin" if trust >= 85 else "operator" if trust >= 72 else "analyst" if trust >= 58 else "observer" if trust >= 22 else "hibernation"
    tier_checked = action_class is not None
    tier_passed = not tier_checked or _TIERS.index(tier) >= _TIERS.index(_CLASS_FLOORS[action_class])
    capacity_passed = risk <= operational
    reason = "TIER_RESTRICTION" if not tier_passed else "TRUST_INSUFFICIENT" if not capacity_passed else None
    return PersonActionChecks(tier, tier_checked, operational, capacity_passed, reason is not None, reason)


__all__ = ["PersonActionChecks", "assess_person_tier_and_capacity"]
