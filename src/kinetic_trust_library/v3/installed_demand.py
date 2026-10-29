"""Installed demand verification boundary under provisional RFC PR #202.

Adapters are trusted deployment configuration, never selected by a candidate.
They authenticate the complete value, supplier independence and declared source
path, provenance meaning/admissibility and current revocation state. No universal
production signature encoding is prescribed by the RFC.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
from .demand_supplier import _digest, _schemas, precheck_demand_value
from .trust_proof_json import _parse_jcs_object


class DemandVerificationFailure(Exception):
    """An established authentication/source failure; operational errors propagate."""


@dataclass(frozen=True, slots=True)
class AuthenticatedDemandEvidence:
    payload_bytes: bytes
    provenance_bytes: bytes
    provenance_reference: str
    provenance_source: str


class DemandVerificationAdapter(Protocol):
    def verify(self, evidence: bytes, *, deployment_profile_bytes: bytes,
               operation_bytes: bytes, evaluated_at: int) -> AuthenticatedDemandEvidence:
        """Authenticate all profile prerequisites or raise DemandVerificationFailure."""
        ...


@dataclass(frozen=True, slots=True, init=False)
class DemandAssessment:
    state: str
    observed_value: Decimal | None
    decision_reading: Decimal
    reason: str | None
    original_evidence: bytes
    operation_digest: str | None
    deployment_digest: str
    evaluated_at: int
    payload_bytes: bytes | None
    provenance_bytes: bytes | None
    provenance_reference: str | None
    provenance_source: str | None

    def __init__(self, *args, **kwargs):
        raise TypeError("DemandAssessment is derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledDemandVerifier:
    deployment_profile_bytes: bytes
    supplier_profile_bytes: bytes
    verification_profile_bytes: bytes
    adapter: DemandVerificationAdapter
    algorithm: str

    def __post_init__(self):
        if self.algorithm not in ("sha256", "sha384") or not callable(getattr(self.adapter, "verify", None)):
            raise ValidationError("installed demand verifier policy is invalid")
        for raw in (self.deployment_profile_bytes, self.supplier_profile_bytes, self.verification_profile_bytes):
            if type(raw) is not bytes:
                raise ValidationError("installed demand profiles must be immutable JCS bytes")
            _parse_jcs_object(raw)
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        demand_inputs = profile.get("demand_inputs", {})
        if type(demand_inputs) is not dict:
            raise ValidationError("installed demand declaration is invalid")
        declaration = demand_inputs.get("moment_criticality")
        if declaration is not None:
            if not _schemas()[0].is_valid(declaration):
                raise ValidationError("installed demand declaration is invalid")
            for field, raw in (("supplier_profile", self.supplier_profile_bytes),
                               ("verification_profile", self.verification_profile_bytes)):
                parsed = _parse_jcs_object(raw)
                binding = declaration.get(field, {})
                if binding.get("id") != parsed.get("id") or binding.get("digest") != _digest(parsed, self.algorithm):
                    raise ValidationError("installed demand profile binding mismatch")

    def evaluate(self, evidence: bytes, *, actual_operation: dict | None,
                 evaluated_at: int, clock_healthy: bool) -> DemandAssessment:
        if type(evidence) is not bytes:
            raise ValidationError("demand evidence must be immutable bytes")
        if type(evaluated_at) is not int or not 0 <= evaluated_at <= 2**53 - 1:
            raise ValidationError("demand evaluation time is invalid")
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        declaration = profile.get("demand_inputs", {}).get("moment_criticality")
        operation_digest = None
        value = None
        authenticated = None
        reason = "unavailable"
        try:
            if type(clock_healthy) is not bool or not clock_healthy or declaration is None:
                raise DemandVerificationFailure("clock_or_declaration")
            operation_bytes = canonical_demand_operation_bytes(actual_operation)
            operation = _parse_jcs_object(operation_bytes)
            operation_digest = digest_demand_operation(operation, algorithm=self.algorithm)
            authenticated = self.adapter.verify(
                evidence, deployment_profile_bytes=self.deployment_profile_bytes,
                operation_bytes=operation_bytes, evaluated_at=evaluated_at,
            )
            if type(authenticated) is not AuthenticatedDemandEvidence:
                authenticated = None
                raise DemandVerificationFailure("adapter_result")
            if (type(authenticated.payload_bytes) is not bytes
                    or type(authenticated.provenance_bytes) is not bytes
                    or type(authenticated.provenance_reference) is not str
                    or type(authenticated.provenance_source) is not str):
                authenticated = None
                raise DemandVerificationFailure("payload")
            payload = _parse_jcs_object(authenticated.payload_bytes)
            if not precheck_demand_value(
                payload=payload, declaration=declaration, deployment_profile=profile,
                actual_operation=operation, provenance_bytes=authenticated.provenance_bytes,
                provenance_reference=authenticated.provenance_reference,
                provenance_source=authenticated.provenance_source,
                evaluated_at=evaluated_at, clock_healthy=clock_healthy, algorithm=self.algorithm,
            ):
                raise DemandVerificationFailure("value_preconditions")
            value = Decimal(str(payload["value"]))
            reason = None
        except (DemandVerificationFailure, ValidationError, ProofFormatError) as exc:
            reason = str(exc) or "unavailable"
        result = object.__new__(DemandAssessment)
        for name, member in (
            ("state", "observed" if value is not None else "unavailable"),
            ("observed_value", value), ("decision_reading", Decimal(1) if value is None else value),
            ("reason", reason), ("original_evidence", evidence),
            ("operation_digest", operation_digest),
            ("deployment_digest", _digest(profile, self.algorithm)), ("evaluated_at", evaluated_at),
            ("payload_bytes", None if authenticated is None else authenticated.payload_bytes),
            ("provenance_bytes", None if authenticated is None else authenticated.provenance_bytes),
            ("provenance_reference", None if authenticated is None else authenticated.provenance_reference),
            ("provenance_source", None if authenticated is None else authenticated.provenance_source),
        ):
            object.__setattr__(result, name, member)
        return result


__all__ = ["AuthenticatedDemandEvidence", "DemandVerificationAdapter",
           "DemandVerificationFailure", "DemandAssessment", "InstalledDemandVerifier"]
