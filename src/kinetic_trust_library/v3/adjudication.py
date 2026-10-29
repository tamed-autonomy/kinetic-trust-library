"""Exact adjudication bindings and declared-gate satisfaction, never capacity.

The installed source authenticates schema/issuer approval, actual whole action,
possession, current grant/evidence/zone/epoch. The token adapter authenticates
the complete JWS under the installed named cryptographic profile. Invalid or
void tokens are absent; only the independently declared gate can restrict use.
"""
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
import json

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation


class AdjudicationUnavailable(Exception):
    pass


class AdjudicationInvalid(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedAdjudicationContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedAdjudicationPayload:
    payload_bytes: bytes
    evidence_bytes: bytes
    key_id: str
    issuer: str


@dataclass(frozen=True, slots=True, init=False)
class AdjudicationAssessment:
    reason: str
    gate_required: bool
    gate_satisfied: bool
    checked_at: int
    deployment_digest: str
    operation_bytes: bytes
    profile_bytes: bytes
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None
    authenticated_payload_bytes: bytes | None
    token_evidence_bytes: bytes | None
    token_bytes: bytes | None
    verified_key_id: str | None
    verified_issuer: str | None
    expires_at: int | None

    def __init__(self, *args, **kwargs):
        raise TypeError("adjudication assessments are derived by an installed verifier")


@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator
    from .schema_formats import installed_format_checker
    schema = json.loads(files("kinetic_trust_library.v3").joinpath("schemas/adjudication-token.json").read_text("utf-8"))
    return Draft202012Validator(schema, format_checker=installed_format_checker())


@dataclass(frozen=True, slots=True)
class InstalledAdjudicationVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    external_schema_bytes: bytes
    context_source: object
    token_adapter: object

    def __post_init__(self):
        from . import _readiness_crypto as c
        from jsonschema import Draft202012Validator
        if (any(type(raw) is not bytes for raw in (self.deployment_profile_bytes, self.profile_bytes, self.external_schema_bytes))
                or not callable(getattr(self.context_source, "resolve", None))
                or not callable(getattr(self.token_adapter, "verify", None))):
            raise ValidationError("installed adjudication verifier is invalid")
        _parse_jcs_object(self.deployment_profile_bytes)
        profile = _parse_jcs_object(self.profile_bytes)
        external = _parse_jcs_object(self.external_schema_bytes)
        if (set(profile) != {"id", "version", "gate_id", "gate_required", "issuer", "zone_id", "external_schema_id", "external_schema_digest", "token_profile_id"}
                or not _time(profile["version"]) or profile["version"] == 0 or type(profile["gate_required"]) is not bool
                or external.get("$id") != profile["external_schema_id"]
                or c.digest(external, 2) != profile["external_schema_digest"]):
            raise ValidationError("invalid adjudication profile/external-schema binding")
        for name in ("id", "gate_id", "issuer", "zone_id", "external_schema_id", "token_profile_id"):
            if type(profile[name]) is not str or not profile[name] or any(char.isspace() for char in profile[name]):
                raise ValidationError("invalid adjudication profile identifier")
        Draft202012Validator.check_schema(external)

    def evaluate(self, token_bytes: bytes | None, *, actual_operation: dict,
                 evaluated_at: int, clock_healthy: bool) -> AdjudicationAssessment:
        from . import _readiness_crypto as c
        from . import _human_reference as h
        if token_bytes is not None and type(token_bytes) is not bytes or not _time(evaluated_at):
            raise ValidationError("adjudication requires immutable token bytes and trusted time")
        profile = _parse_jcs_object(self.profile_bytes)
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        operation = _parse_jcs_object(operation_bytes)
        deployment_digest = c.digest(_parse_jcs_object(self.deployment_profile_bytes), 2)
        values = dict(reason="ADJ_UNAVAILABLE", gate_required=profile["gate_required"], gate_satisfied=False,
                      checked_at=evaluated_at, deployment_digest=deployment_digest, operation_bytes=operation_bytes,
                      profile_bytes=self.profile_bytes, authenticated_state_bytes=None, source_evidence_bytes=None,
                      authenticated_payload_bytes=None, token_evidence_bytes=None, token_bytes=None,
                      verified_key_id=None, verified_issuer=None, expires_at=None)

        def result():
            value = object.__new__(AdjudicationAssessment)
            for name, member in values.items():
                object.__setattr__(value, name, member)
            return value

        if clock_healthy is not True:
            return result()
        try:
            source = self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,
                profile_bytes=self.profile_bytes, external_schema_bytes=self.external_schema_bytes,
                operation_bytes=operation_bytes, evaluated_at=evaluated_at)
        except AdjudicationUnavailable:
            return result()
        if (type(source) is not AuthenticatedAdjudicationContext or type(source.state_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("adjudication source returned invalid authenticated state")
        try:
            state = _parse_jcs_object(source.state_bytes)
            if (set(state) != {"deployment_digest", "operation_digest", "profile_digest", "checked_at", "actor", "action_digest", "cnf_jkt",
                              "grant_digest", "evidence_digest", "zone_id", "topology_epoch", "expires_at"}
                    or state["deployment_digest"] != deployment_digest
                    or state["operation_digest"] != digest_demand_operation(operation, algorithm="sha256")
                    or state["profile_digest"] != c.digest(profile, 2) or state["actor"] != operation["actor"]
                    or state["zone_id"] != profile["zone_id"] or not _time(state["checked_at"]) or state["checked_at"] != evaluated_at
                    or not _time(state["topology_epoch"]) or not _time(state["expires_at"]) or state["expires_at"] <= evaluated_at
                    or type(state["cnf_jkt"]) is not str or not state["cnf_jkt"]):
                return result()
            for name in ("action_digest", "grant_digest", "evidence_digest"):
                h.check_digest(state[name], 2)
        except (ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError):
            return result()
        values.update(reason="ADJ_ABSENT", authenticated_state_bytes=source.state_bytes, source_evidence_bytes=source.evidence_bytes)
        if token_bytes is None or not 0 < len(token_bytes) <= 262144:
            return result()
        try:
            authenticated = self.token_adapter.verify(token_bytes, deployment_profile_bytes=self.deployment_profile_bytes,
                profile_bytes=self.profile_bytes, external_schema_bytes=self.external_schema_bytes,
                authenticated_context_bytes=source.state_bytes, evaluated_at=evaluated_at)
            if (type(authenticated) is not AuthenticatedAdjudicationPayload or type(authenticated.payload_bytes) is not bytes
                    or type(authenticated.evidence_bytes) is not bytes or not authenticated.evidence_bytes
                    or type(authenticated.key_id) is not str or not authenticated.key_id or authenticated.issuer != profile["issuer"]
                    or len(authenticated.payload_bytes) > 65536):
                raise AdjudicationInvalid()
            token = _parse_jcs_object(authenticated.payload_bytes)
            if (not _validator().is_valid(token) or type(token["favorable"]) is not bool or token["iss"] != profile["issuer"]
                    or "kid" in token and token["kid"] != authenticated.key_id
                    or any(token[name] != state[name] for name in ("actor", "action_digest", "cnf_jkt", "grant_digest", "evidence_digest", "zone_id", "topology_epoch"))
                    or not _time(token["topology_epoch"]) or not _time(token["iat"]) or not _time(token["exp"])
                    or not token["iat"] <= evaluated_at < token["exp"] or type(token["jti"]) is not str or not token["jti"]):
                raise AdjudicationInvalid()
        except (AdjudicationInvalid, AdjudicationUnavailable, ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError):
            return result()
        values.update(reason="ADJ_FAVORABLE" if token["favorable"] else "ADJ_UNFAVORABLE", gate_satisfied=token["favorable"],
                      authenticated_payload_bytes=authenticated.payload_bytes, token_evidence_bytes=authenticated.evidence_bytes,
                      token_bytes=token_bytes, verified_key_id=authenticated.key_id, verified_issuer=authenticated.issuer,
                      expires_at=min(state["expires_at"], token["exp"]))
        return result()


__all__ = ("InstalledAdjudicationVerifier", "AdjudicationAssessment", "AuthenticatedAdjudicationContext",
           "AuthenticatedAdjudicationPayload", "AdjudicationUnavailable", "AdjudicationInvalid")
