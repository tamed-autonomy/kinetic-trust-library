"""Pure precheck for a proposed per-operation demand supplier value.

This does not accept a value for authorization. An installed profile must still
authenticate the complete signed payload, supplier path, independence,
provenance source and clock before the value can be used.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import hashlib
import json

from .demand_operation import digest_demand_operation


@lru_cache(maxsize=1)
def _schemas():
    from .schema_formats import installed_format_checker
    from jsonschema import Draft202012Validator

    root = files("kinetic_trust_library.v3")
    deployment = json.loads(root.joinpath("schemas/deployment-profile-v3.json").read_text("utf-8"))
    value = json.loads(root.joinpath("schemas/demand-input-value-v3.json").read_text("utf-8"))
    # The published demand contract points to this local definition. Resolve
    # it here so a verification attempt never retrieves a remote schema.
    return (
        Draft202012Validator(deployment["$defs"]["demand_input"], format_checker=installed_format_checker()),
        Draft202012Validator(value, format_checker=installed_format_checker()),
    )


def _digest(value: object, algorithm: str) -> str:
    import rfc8785

    return f"{algorithm}:{hashlib.new(algorithm, rfc8785.dumps(value)).hexdigest()}"


def precheck_demand_value(
    *,
    payload: dict[str, object] | None,
    declaration: dict[str, object] | None,
    deployment_profile: dict[str, object],
    actual_operation: dict[str, object] | None,
    provenance_bytes: bytes | None,
    provenance_reference: str | None,
    provenance_source: str | None,
    evaluated_at: int,
    clock_healthy: bool,
    algorithm: str,
) -> bool:
    """Check deterministic eligibility only; ``True`` is not authentication.

    The declaration, profile, actual invocation, provenance bytes, clock and
    algorithm must be supplied from independently established local context.
    Never derive authority or an invocation from the candidate payload.
    Provenance bytes are hashed exactly, including any signature envelope.
    Reference/source metadata must come from the installed verifier; this
    function does not infer their authenticity from a matching digest.
    """
    try:
        if (
            algorithm not in ("sha256", "sha384")
            or type(clock_healthy) is not bool or not clock_healthy
            or type(evaluated_at) is not int
            or evaluated_at < 0 or evaluated_at > 2**53 - 1
            or type(payload) is not dict
            or type(declaration) is not dict
            or type(deployment_profile) is not dict
            or type(actual_operation) is not dict
            or type(provenance_bytes) is not bytes
            or type(provenance_reference) is not str
            or type(provenance_source) is not str
        ):
            return False
        declaration_validator, value_validator = _schemas()
        if not declaration_validator.is_valid(declaration) or not value_validator.is_valid(payload):
            return False
        demand_inputs = deployment_profile.get("demand_inputs")
        if type(demand_inputs) is not dict or demand_inputs.get("moment_criticality") != declaration:
            return False
        if payload["supplier"] != declaration["supplier"]:
            return False
        if payload["supplier_profile"] != declaration["supplier_profile"]:
            return False
        if payload["unit"] != declaration["unit"]:
            return False
        if payload["declaration_digest"] != _digest(deployment_profile, algorithm):
            return False
        if payload["operation_digest"] != digest_demand_operation(actual_operation, algorithm=algorithm):
            return False
        observed, issued = payload["observed_at"], payload["issued_at"]
        if not (observed <= issued <= evaluated_at):
            return False
        if evaluated_at - observed > declaration["freshness"]["max_age_seconds"]:
            return False
        provenance = payload["provenance"]
        if provenance["reference"] != provenance_reference:
            return False
        if provenance_source != declaration["source"]:
            return False
        evidence_digest = f"{algorithm}:{hashlib.new(algorithm, provenance_bytes).hexdigest()}"
        if provenance["digest"] != evidence_digest:
            return False
        return True
    except (KeyError, TypeError, ValueError, OverflowError, ImportError):
        return False


__all__ = ["precheck_demand_value"]
