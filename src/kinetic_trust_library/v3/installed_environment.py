"""Installed authenticated environment evidence and factor-state boundary.

The adapter establishes feed authenticity/currentness, signal population,
independent redundancy, normalization and the exact installed factor aggregate.
The Library enforces required signal coverage and never permits that aggregate
to replace missing measurements. Operational provider failures propagate.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .risk import _FACTORS
from .evidence_state import FactorEvidenceState, UndefinedInputState, assess_required_factor
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
from .demand_supplier import _digest
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True)
class AuthenticatedEnvironmentEvidence:
    body_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class NativeEnvironmentAssessment:
    factors: tuple[FactorEvidenceState, ...]
    original_evidence: bytes
    authenticated_body_bytes: bytes
    deployment_digest: str
    operation_digest: str
    evaluated_at: int

    def __init__(self, *args, **kwargs):
        raise TypeError("NativeEnvironmentAssessment is derived by an installed environment verifier")


@dataclass(frozen=True, slots=True)
class InstalledEnvironmentVerifier:
    deployment_profile_bytes: bytes
    adapter: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or self.algorithm not in ("sha256", "sha384")
                or not callable(getattr(self.adapter, "verify", None))):
            raise ValidationError("installed environment verifier is invalid")
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        declared = profile.get("risk_factors")
        if type(declared) is not dict or set(declared) != set(_FACTORS):
            raise ValidationError("installed environment requires exactly five Risk Factors")
        for config in declared.values():
            signals = config.get("signals") if type(config) is dict else None
            if (type(signals) is not list or not signals or any(type(s) is not str or not s for s in signals)
                    or len(set(signals)) != len(signals)):
                raise ValidationError("installed factor signal subset is invalid")

    def evaluate(self, evidence: bytes, *, actual_operation: dict, evaluated_at: int) -> NativeEnvironmentAssessment:
        if type(evidence) is not bytes or not _time(evaluated_at):
            raise ValidationError("environment evidence or evaluation time is invalid")
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        operation = _parse_jcs_object(operation_bytes)
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        authenticated = self.adapter.verify(evidence, deployment_profile_bytes=self.deployment_profile_bytes,
                                            operation_bytes=operation_bytes, evaluated_at=evaluated_at)
        if type(authenticated) is not AuthenticatedEnvironmentEvidence or type(authenticated.body_bytes) is not bytes:
            raise ValidationError("environment adapter returned invalid evidence")
        body = _parse_jcs_object(authenticated.body_bytes)
        supplied = body.get("factors")
        if set(body) != {"factors"} or type(supplied) is not dict or not set(supplied) <= set(_FACTORS):
            raise ValidationError("authenticated environment factor population is invalid")
        factors = []
        for name in _FACTORS:
            required = tuple(profile["risk_factors"][name]["signals"])
            candidate = supplied.get(name, {})
            if type(candidate) is not dict or not set(candidate) <= {"signals", "measured_stress", "feed_undefined"}:
                raise ValidationError("authenticated factor fields are invalid")
            signals = candidate.get("signals", {})
            failures = candidate.get("feed_undefined", [])
            if (type(signals) is not dict or not set(signals) <= set(required) or type(failures) is not list):
                raise ValidationError("authenticated factor signal population is invalid")
            undefined = []
            for failure in failures:
                if (type(failure) is not dict or set(failure) != {"input", "layer", "state"}
                        or failure["layer"] != "feed"):
                    raise ValidationError("authenticated feed failure is invalid")
                undefined.append(UndefinedInputState(**failure))
            factors.append(assess_required_factor(factor=name, required_signals=required,
                populated_signals=signals, measured_stress=candidate.get("measured_stress"), feed_undefined=tuple(undefined)))
        result = object.__new__(NativeEnvironmentAssessment)
        for name, value in (("factors", tuple(factors)), ("original_evidence", evidence),
                            ("authenticated_body_bytes", authenticated.body_bytes),
                            ("deployment_digest", _digest(profile, self.algorithm)),
                            ("operation_digest", digest_demand_operation(operation, algorithm=self.algorithm)),
                            ("evaluated_at", evaluated_at)):
            object.__setattr__(result, name, value)
        return result


__all__ = ["AuthenticatedEnvironmentEvidence", "NativeEnvironmentAssessment", "InstalledEnvironmentVerifier"]
