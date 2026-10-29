"""Native KTP v3 implementation under construction.

This namespace is a candidate 3.0 surface, not a complete authorization API.
"""

from .core_risk import NativeRiskAssessment, assess_five_factor_risk
from .core import NativeCorePreflight, preflight_core
from .core_capacity import NativeCapacityProjection, project_native_capacity
from .base_trust import NativeBaseTrust, calculate_native_base_trust
from .core_projection import NativeCoreProjection, project_native_core
from .evidence_state import FactorEvidenceState, assess_required_factor
from .soul import SoulGate, SoulGateState, SoulQueryState, assess_soul_queries


__all__ = (
    "FactorEvidenceState",
    "NativeCorePreflight",
    "NativeCapacityProjection",
    "NativeBaseTrust",
    "NativeCoreProjection",
    "NativeRiskAssessment",
    "SoulGate",
    "SoulGateState",
    "SoulQueryState",
    "assess_five_factor_risk",
    "assess_required_factor",
    "assess_soul_queries",
    "calculate_native_base_trust",
    "preflight_core",
    "project_native_capacity",
    "project_native_core",
)
