"""Installed demand classification; formulas belong to the declared substrate.

The adapter must implement the deployment's common-scale, non-decreasing A
formula. Per-evaluation endpoint checks below enforce the restrictive direction
for this invocation; they do not prove global calibration or monotonicity.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from kinetic_trust_library._decimal import DecimalLike, as_decimal
from kinetic_trust_library.errors import ValidationError
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
from .demand_supplier import _digest
from .installed_demand import DemandAssessment
from .trust_proof_json import _parse_jcs_object


class DemandClassificationAdapter(Protocol):
    def classify(self, operation_bytes: bytes, *, criticality: Decimal) -> DecimalLike:
        """Return finite conservative A on the installed common scale."""
        ...


@dataclass(frozen=True, slots=True, init=False)
class NativeClassifiedDemand:
    demand: Decimal
    baseline_demand: Decimal
    maximum_criticality_demand: Decimal
    operation_digest: str
    deployment_digest: str
    evaluated_at: int
    conservative: bool
    evidence: DemandAssessment

    def __init__(self, *args, **kwargs):
        raise TypeError("NativeClassifiedDemand is derived by an installed classifier")


@dataclass(frozen=True, slots=True)
class InstalledDemandClassifier:
    deployment_profile_bytes: bytes
    adapter: DemandClassificationAdapter
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes
                or self.algorithm not in ("sha256", "sha384")
                or not callable(getattr(self.adapter, "classify", None))):
            raise ValidationError("installed demand classifier is invalid")
        _parse_jcs_object(self.deployment_profile_bytes)

    def classify(self, assessment: DemandAssessment, *, actual_operation: dict,
                 evaluated_at: int) -> NativeClassifiedDemand:
        if type(assessment) is not DemandAssessment:
            raise ValidationError("installed demand assessment is required")
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        operation = _parse_jcs_object(operation_bytes)
        operation_digest = digest_demand_operation(operation, algorithm=self.algorithm)
        deployment_digest = _digest(_parse_jcs_object(self.deployment_profile_bytes), self.algorithm)
        if (type(evaluated_at) is not int or evaluated_at != assessment.evaluated_at
                or assessment.operation_digest != operation_digest
                or assessment.deployment_digest != deployment_digest):
            raise ValidationError("demand assessment belongs to another invocation, deployment or time")
        if (assessment.state not in ("observed", "unavailable")
                or (assessment.state == "unavailable" and assessment.decision_reading != 1)):
            raise ValidationError("demand evidence state is inconsistent")
        reading = as_decimal(assessment.decision_reading, name="criticality", minimum=0, maximum=1)
        values = {}
        for criticality in sorted({Decimal(0), reading, Decimal(1)}):
            values[criticality] = as_decimal(
                self.adapter.classify(operation_bytes, criticality=criticality),
                name="classified demand", minimum=0, maximum=100,
            )
        baseline, demand, maximum = values[Decimal(0)], values[reading], values[Decimal(1)]
        if not baseline <= demand <= maximum:
            raise ValidationError("demand criticality must not lower A")
        result = object.__new__(NativeClassifiedDemand)
        for name, value in (
            ("demand", demand), ("baseline_demand", baseline),
            ("maximum_criticality_demand", maximum), ("operation_digest", operation_digest),
            ("deployment_digest", deployment_digest), ("evaluated_at", evaluated_at),
            ("conservative", assessment.state == "unavailable"), ("evidence", assessment),
        ):
            object.__setattr__(result, name, value)
        return result


__all__ = ["DemandClassificationAdapter", "InstalledDemandClassifier", "NativeClassifiedDemand"]
