"""Native KTP v3 implementation under construction.

This namespace is a candidate 3.0 surface, not a complete authorization API.
"""

from .core_risk import NativeRiskAssessment, assess_five_factor_risk
from .core import NativeCorePreflight, preflight_core
from .evidence_state import FactorEvidenceState, assess_required_factor
from .soul import SoulGate, SoulGateState, SoulQueryState, assess_soul_queries


__all__ = (
    "FactorEvidenceState",
    "NativeCorePreflight",
    "NativeRiskAssessment",
    "SoulGate",
    "SoulGateState",
    "SoulQueryState",
    "assess_five_factor_risk",
    "assess_required_factor",
    "assess_soul_queries",
    "preflight_core",
)
