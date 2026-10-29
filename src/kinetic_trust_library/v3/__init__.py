"""Native KTP v3 implementation under construction.

This namespace is a candidate 3.0 surface, not a complete authorization API.
"""

from .core_risk import NativeRiskAssessment, assess_five_factor_risk
from .core import NativeCorePreflight, preflight_core
from .core_capacity import NativeCapacityProjection, project_native_capacity
from .base_trust import NativeBaseTrust, calculate_native_base_trust
from .core_projection import NativeCoreContext, NativeCoreProjection, project_native_core, project_classified_native_core
from .installed_demand import InstalledDemandVerifier, DemandAssessment, AuthenticatedDemandEvidence, DemandVerificationFailure
from .demand_classification import InstalledDemandClassifier, NativeClassifiedDemand
from .native_envelope import NativeEnvelopeThresholds, NativeEnvelopeProjection, project_native_envelope
from .evidence_state import FactorEvidenceState, assess_required_factor
from .soul import SoulGate, SoulGateState, SoulQueryState, assess_soul_queries
from .native_evaluation import InstalledNativeEvaluationVerifier, NativeEvaluationResult


__all__ = (
    "InstalledNativeEvaluationVerifier",
    "NativeEvaluationResult",
    "FactorEvidenceState",
    "NativeCorePreflight",
    "NativeCapacityProjection",
    "NativeBaseTrust",
    "NativeCoreProjection",
    "NativeCoreContext",
    "InstalledDemandVerifier",
    "DemandAssessment",
    "AuthenticatedDemandEvidence",
    "DemandVerificationFailure",
    "InstalledDemandClassifier",
    "NativeClassifiedDemand",
    "NativeEnvelopeThresholds",
    "NativeEnvelopeProjection",
    "project_native_envelope",
    "project_classified_native_core",
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
