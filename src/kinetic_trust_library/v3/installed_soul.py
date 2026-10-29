"""Installed, invocation-bound Soul framework query boundary.

The trusted adapter authenticates framework responses, applicability, freshness
and the current on-demand invocation. Norm content remains externally authored.
Missing responses remain absent; operational adapter failures propagate.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .soul import SoulGate, SoulQueryState, assess_soul_queries
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
from .demand_supplier import _digest
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True)
class AuthenticatedSoulResponse:
    framework: str
    state: str
    evidence_bytes: bytes

    def __post_init__(self):
        SoulQueryState(self.framework, self.state)
        if type(self.evidence_bytes) is not bytes or (self.state in ("clear", "veto") and not self.evidence_bytes):
            raise ValidationError("authenticated Soul decision must retain complete response evidence")


@dataclass(frozen=True, slots=True, init=False)
class NativeSoulAssessment:
    gate: SoulGate
    required_frameworks: tuple[str, ...]
    responses: tuple[AuthenticatedSoulResponse, ...]
    deployment_digest: str
    operation_digest: str
    evaluated_at: int

    def __init__(self, *args, **kwargs):
        raise TypeError("NativeSoulAssessment is derived by an installed Soul verifier")


@dataclass(frozen=True, slots=True)
class InstalledSoulVerifier:
    deployment_profile_bytes: bytes
    adapter: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or self.algorithm not in ("sha256", "sha384")
                or not callable(getattr(self.adapter, "query", None))):
            raise ValidationError("installed Soul verifier is invalid")
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        try:
            required = profile["soul_veto"]["frameworks"]
            if type(required) is not list:
                raise ValidationError("Soul framework declaration is invalid")
            assess_soul_queries(required_frameworks=tuple(required), responses=())
        except (KeyError, TypeError) as exc:
            raise ValidationError("Soul framework declaration is missing") from exc

    def evaluate(self, *, actual_operation: dict, evaluated_at: int) -> NativeSoulAssessment:
        if not _time(evaluated_at):
            raise ValidationError("Soul evaluation time is invalid")
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        operation = _parse_jcs_object(operation_bytes)
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        required = tuple(profile["soul_veto"]["frameworks"])
        responses = self.adapter.query(
            deployment_profile_bytes=self.deployment_profile_bytes, operation_bytes=operation_bytes,
            required_frameworks=required, evaluated_at=evaluated_at)
        if type(responses) is not tuple or any(type(r) is not AuthenticatedSoulResponse for r in responses):
            raise ValidationError("Soul adapter responses must be immutable authenticated evidence")
        gate = assess_soul_queries(required_frameworks=required,
            responses=tuple(SoulQueryState(r.framework, r.state) for r in responses))
        result = object.__new__(NativeSoulAssessment)
        for name, value in (("gate", gate), ("required_frameworks", required), ("responses", responses),
                            ("deployment_digest", _digest(profile, self.algorithm)),
                            ("operation_digest", digest_demand_operation(operation, algorithm=self.algorithm)),
                            ("evaluated_at", evaluated_at)):
            object.__setattr__(result, name, value)
        return result


__all__ = ["AuthenticatedSoulResponse", "NativeSoulAssessment", "InstalledSoulVerifier"]
