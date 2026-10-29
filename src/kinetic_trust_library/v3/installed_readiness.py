"""Installed, current-use readiness verification; a prerequisite, never a permit.

The adapter independently authenticates approved profiles/registry, running
subject and resolved scope, current durable epoch/active registration, challenge
and check evidence, assessor independence and key revocation. It never derives
those facts from the candidate. The Library verifies exact semantic and signed
bindings. Products own activation, storage, safe transitions and effect fencing.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .demand_operation import canonical_demand_operation_bytes
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from ._jws_keys import load_key_binding as _binding


class ReadinessVerificationFailure(Exception):
    """The installed source established unavailable/restrictive verification."""


@dataclass(frozen=True, slots=True)
class AuthenticatedReadinessContext:
    actual_request_bytes: bytes
    current_state_bytes: bytes
    trusted_keys_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class ReadinessVerificationResult:
    reason: str
    conformance_level: int
    checked_at: int
    operation_bytes: bytes
    attestation_bytes: bytes | None
    actual_request_bytes: bytes | None
    authenticated_state_bytes: bytes | None
    trusted_keys_bytes: bytes | None
    attestation_digest: str | None
    request_digest: str | None
    readiness_profile_digest: str | None
    deployment_profile_digest: str | None
    readiness_epoch: int | None
    expires_at: int | None

    def __init__(self,*args,**kwargs):
        raise TypeError("readiness results are derived by an installed verifier")

    @property
    def valid(self):
        return self.reason=="READINESS_VALID"


@dataclass(frozen=True, slots=True)
class InstalledReadinessVerifier:
    deployment_profile_bytes: bytes
    readiness_profile_bytes: bytes
    adapter: object
    conformance_level: int
    receiving_zone: str

    def __post_init__(self):
        from . import _readiness_reference as r
        if (type(self.deployment_profile_bytes) is not bytes or type(self.readiness_profile_bytes) is not bytes
                or not callable(getattr(self.adapter,"resolve",None))
                or type(self.conformance_level) is not int or self.conformance_level not in (1,2,3)):
            raise ValidationError("installed readiness policy is invalid")
        deployment=_parse_jcs_object(self.deployment_profile_bytes)
        profile=_parse_jcs_object(self.readiness_profile_bytes)
        try:
            r.literal(self.receiving_zone)
            r.validate("profile",profile,self.conformance_level)
            expected=dict(mode="history-with-scoped-readiness-v1",profile_id=profile["profile_id"],
                version=profile["version"],digest=r.digest(profile,self.conformance_level))
            if r.canonical(deployment.get("standing_policy"))!=r.canonical(expected):
                raise r.InvalidRecord("installed deployment/readiness profile relationship differs")
        except r.InvalidRecord as error:
            raise ValidationError(str(error)) from error

    def evaluate(self, attestation_bytes: bytes, *, actual_operation: dict,
                 evaluated_at: int, clock_healthy: bool) -> ReadinessVerificationResult:
        from . import _readiness_reference as r
        if type(attestation_bytes) is not bytes or not _time(evaluated_at):
            raise ValidationError("readiness evaluation requires immutable evidence and trusted time")
        operation_bytes=canonical_demand_operation_bytes(actual_operation)
        operation=_parse_jcs_object(operation_bytes)
        values=dict(reason="READINESS_UNAVAILABLE",conformance_level=self.conformance_level,checked_at=evaluated_at,operation_bytes=operation_bytes,
            attestation_bytes=None,actual_request_bytes=None,authenticated_state_bytes=None,trusted_keys_bytes=None,
            attestation_digest=None,request_digest=None,readiness_profile_digest=None,deployment_profile_digest=None,
            readiness_epoch=None,expires_at=None)
        def result():
            value=object.__new__(ReadinessVerificationResult)
            for name,member in values.items(): object.__setattr__(value,name,member)
            return value
        if clock_healthy is not True:
            return result()
        try:
            context=self.adapter.resolve(deployment_profile_bytes=self.deployment_profile_bytes,
                readiness_profile_bytes=self.readiness_profile_bytes,operation_bytes=operation_bytes,
                evaluated_at=evaluated_at,conformance_level=self.conformance_level,receiving_zone=self.receiving_zone)
        except ReadinessVerificationFailure:
            return result()
        if (type(context) is not AuthenticatedReadinessContext
                or any(type(raw) is not bytes for raw in
                       (context.actual_request_bytes,context.current_state_bytes,context.trusted_keys_bytes))):
            raise ValidationError("readiness adapter returned invalid authenticated context")
        try:
            if len(attestation_bytes)>262144:
                raise r.InvalidRecord("unbounded readiness attestation")
            attestation=_parse_jcs_object(attestation_bytes)
            request=_parse_jcs_object(context.actual_request_bytes)
            state=_parse_jcs_object(context.current_state_bytes)
            keys=_parse_jcs_object(context.trusted_keys_bytes)
            profile=_parse_jcs_object(self.readiness_profile_bytes)
            r.request_digest(request,self.conformance_level)
            if (request["request_id"]!=operation["request_id"] or request["operation_id"]!=operation["operation"]
                    or request["subject"]["agent_id"]!=operation["actor"]
                    or request["scope"]["zone_id"]!=self.receiving_zone
                    or request["scope"]["resource_id"]!=operation["resource"]
                    or request["scope"]["parameters_digest"]!=r.digest(operation["parameters"],self.conformance_level)
                    or request["deployment_profile_digest"]!=r.digest_bytes(self.deployment_profile_bytes,self.conformance_level)):
                raise r.InvalidRecord("readiness request does not match actual invocation")
            expected_fields={"profile_id","profile_digest","deployment_profile_digest","assessor_registry_digest",
                "minimum_profile_version","readiness_epoch","active_attestation_digest","challenge","checked_at","status"}
            if set(state)!=expected_fields:
                raise r.InvalidRecord("authenticated readiness state shape differs")
            assessor,key=_binding(keys,attestation["signature"])
            trusted=r.TrustedState(**state,assessor_valid_from=key["not_before"],assessor_valid_until=key["not_after"],
                issuer_valid_from=0,issuer_valid_until=2**53-1)
            evidence=r.verify_readiness(attestation,profile,request,state=trusted,assessor=assessor,
                now=evaluated_at,level=self.conformance_level)
        except (r.InvalidRecord,ProofFormatError,KeyError,ValueError,TypeError,UnicodeError,RecursionError):
            values["reason"]="READINESS_INVALID"
            return result()
        values.update(reason="READINESS_VALID",attestation_bytes=attestation_bytes,
            actual_request_bytes=context.actual_request_bytes,authenticated_state_bytes=context.current_state_bytes,
            trusted_keys_bytes=context.trusted_keys_bytes,attestation_digest=evidence.attestation_digest,
            request_digest=evidence.request_digest,readiness_profile_digest=evidence.readiness_profile_digest,
            deployment_profile_digest=evidence.deployment_profile_digest,readiness_epoch=evidence.readiness_epoch,
            expires_at=evidence.expires_at)
        return result()


__all__=["InstalledReadinessVerifier","AuthenticatedReadinessContext","ReadinessVerificationResult","ReadinessVerificationFailure"]
