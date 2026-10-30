"""Ordered request/proof association with installed invocation and replay adapters.

The invocation adapter authenticates actual identities, delegation/eligibility,
resolved parameters/defaults, audience, replay domain and installed classifier.
The replay adapter must atomically reserve both maps under authoritative durable
state, enforce domain activation/retirement and retain IDs for domain lifetime.
RB_BOUND is a prerequisite only; it grants no execution permission.
"""
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _reject_duplicate, _reject_constant, _check_tree, _parse_jcs_object
from .request_binding import _request_validator, canonical_request_bytes, digest_canonical_request, digest_complete_proof
from .complete_proof_verifier import InstalledProofVerifier, ProofVerificationResult


class RequestContextFailure(Exception):
    pass


@dataclass(frozen=True,slots=True,init=False)
class VerifiedAssociationCarrier:
    compact_carrier: str
    canonical_geometry_bytes: bytes
    canonical_request_bytes: bytes
    canonical_association_bytes: bytes
    compact_proof: str
    verified_at: int

    def __init__(self,*args,**kwargs):
        raise TypeError("VerifiedAssociationCarrier is derived by the installed carrier bridge")


def _verified_carrier_binding(**fields):
    value=object.__new__(VerifiedAssociationCarrier)
    for name,member in fields.items(): object.__setattr__(value,name,member)
    return value


class _Failure(Exception):
    def __init__(self, reason, proof_reason=None):
        self.reason,self.proof_reason=reason,proof_reason


def _parse(raw):
    import rfc8785
    if type(raw) is not bytes or len(raw)>65536:
        raise ValueError("unbounded request input")
    value=json.loads(raw.decode("utf-8"),object_pairs_hook=_reject_duplicate,parse_constant=_reject_constant)
    if type(value) is not dict: raise ValueError("request root must be an object")
    _check_tree(value,1)
    canonical=rfc8785.dumps(value)
    if len(canonical)>65536: raise ValueError("unbounded canonical request")
    return value,canonical


@lru_cache(maxsize=1)
def _association_validator():
    from .schema_formats import installed_format_checker
    from jsonschema import Draft202012Validator
    schema=json.loads(files("kinetic_trust_library.v3").joinpath("schemas/request-proof-association-v1.json").read_text("utf-8"))
    return Draft202012Validator(schema,format_checker=installed_format_checker())


@dataclass(frozen=True,slots=True,init=False)
class RequestAssociationResult:
    verifier: object
    checked_at: int
    expires_at: int | None
    reservation_state_bytes: bytes | None
    reservation_evidence_bytes: bytes | None
    reason: str
    proof_reason: str | None
    canonical_request_bytes: bytes | None
    canonical_association_bytes: bytes | None
    compact_proof: str
    carrier_binding: VerifiedAssociationCarrier | None
    proof_verification: ProofVerificationResult | None

    def __init__(self,*args,**kwargs):
        raise TypeError("RequestAssociationResult is derived by an installed verifier")


@dataclass(frozen=True,slots=True)
class InstalledRequestAssociationVerifier:
    invocation_adapter: object
    proof_verifier: InstalledProofVerifier
    replay_adapter: object
    algorithm: str
    crosses_trust_boundary: bool = False
    carrier_verifier: object | None = None

    def __post_init__(self):
        if (self.algorithm not in ("sha256","sha384") or type(self.crosses_trust_boundary) is not bool
                or type(self.proof_verifier) is not InstalledProofVerifier
                or not callable(getattr(self.invocation_adapter,"reconstruct",None))
                or not callable(getattr(self.replay_adapter,"reserve",None))):
            raise ValidationError("installed request association policy is invalid")

    def verify(self,request_bytes: bytes,association_bytes: bytes,proof: str,*,
               invocation_evidence: bytes,now: int,clock_healthy: bool) -> RequestAssociationResult:
        return self._verify(request_bytes,association_bytes,proof,invocation_evidence=invocation_evidence,
            now=now,clock_healthy=clock_healthy,reservation_verifier=None,previous=None)

    def _verify(self,request_bytes,association_bytes,proof,*,invocation_evidence,now,clock_healthy,reservation_verifier,previous):
        import rfc8785
        canonical=association_canonical=None
        carrier_binding=None
        verified=None
        reservation_state=reservation_evidence=expiry=None
        try:
            try:
                request,canonical=_parse(request_bytes)
                association,association_canonical=_parse(association_bytes)
            except (ValueError,TypeError,UnicodeError,RecursionError):
                raise _Failure("RB_ENCODING")
            if request.get("version")!="request-binding-v1" or association.get("version")!="request-proof-association-v1":
                raise _Failure("RB_VERSION")
            if not _request_validator().is_valid(request) or not _association_validator().is_valid(association):
                raise _Failure("RB_SCHEMA")
            if type(invocation_evidence) is not bytes:
                raise ValidationError("actual invocation evidence must be immutable bytes")
            try:
                actual_bytes=self.invocation_adapter.reconstruct(invocation_evidence,evaluated_at=now)
            except RequestContextFailure as exc:
                raise _Failure(str(exc) if str(exc) in ("RB_CONTEXT","RB_PROFILE") else "RB_CONTEXT") from exc
            try:
                actual=_parse_jcs_object(actual_bytes)
            except Exception:
                raise _Failure("RB_CONTEXT")
            context_fields = set(request) - {"demand", "classification_profile"}
            if rfc8785.dumps({k:request[k] for k in context_fields}) != rfc8785.dumps({k:actual[k] for k in context_fields if k in actual}):
                raise _Failure("RB_CONTEXT")
            if (not _request_validator().is_valid(actual) or request["demand"]!=actual.get("demand")
                    or request["classification_profile"]!=actual.get("classification_profile")
                    or canonical != actual_bytes
                    or any(not digest.startswith(self.algorithm+":") for digest in
                           (association["request_digest"],association["proof_digest"],request["classification_profile"]["digest"]))):
                raise _Failure("RB_PROFILE")
            try:
                request_digest=digest_canonical_request(request,algorithm=self.algorithm)
                proof_digest=digest_complete_proof(proof,algorithm=self.algorithm)
            except ValidationError:
                raise _Failure("RB_DIGEST")
            if association["request_digest"]!=request_digest or association["proof_digest"]!=proof_digest:
                raise _Failure("RB_DIGEST")
            verified=self.proof_verifier.verify(proof,now=now,clock_healthy=clock_healthy)
            if verified.stage!=8:
                raise _Failure("RB_PROOF",verified.reason)
            claims=_parse_jcs_object(verified.authenticated_payload_bytes)
            if claims["sub"]!=actual["actor"]:
                raise _Failure("RB_PROOF","TP_INVARIANT")
            if claims["aud"]!=actual["audience"]:
                raise _Failure("RB_PROOF","TP_AUDIENCE")
            if association["proof_jti"]!=claims["jti"]:
                raise _Failure("RB_MATCH")
            if verified.reason!="TP_CLEAR":
                raise _Failure("RB_GATE",verified.reason)
            if self.crosses_trust_boundary:
                if self.carrier_verifier is None:
                    raise _Failure("RB_CARRIER")
                carrier_binding=self.carrier_verifier.verify(canonical_request_bytes=canonical,
                        canonical_association_bytes=association_canonical,proof=verified,now=now,clock_healthy=clock_healthy)
                if (type(carrier_binding) is not VerifiedAssociationCarrier
                        or carrier_binding.canonical_request_bytes!=canonical
                        or carrier_binding.canonical_association_bytes!=association_canonical
                        or carrier_binding.compact_proof!=proof or carrier_binding.verified_at!=now):
                    carrier_binding=None
                    raise _Failure("RB_CARRIER")
            scope=dict(replay_domain=actual["replay_domain"],request_id=actual["request_id"],
                request_digest=request_digest,proof_digest=proof_digest,issuer=claims["iss"],proof_jti=claims["jti"])
            if reservation_verifier is None:
                reason=self.replay_adapter.reserve(**scope)
                if reason not in ("RB_BOUND","RB_REPLAY_STATE","RB_COLLISION","RB_REPLAY","RB_JTI_COLLISION"):
                    reason="RB_REPLAY_STATE"
                if reason!="RB_BOUND": raise _Failure(reason)
            else:
                reason,expiry,reservation_state,reservation_evidence=reservation_verifier._current(scope,previous,now)
                if reason!="RB_CURRENT":raise _Failure(reason)
            proof_reason=None
        except _Failure as exc:
            reason,proof_reason=exc.reason,exc.proof_reason
        result=object.__new__(RequestAssociationResult)
        for name,value in (("verifier",self),("checked_at",now),("expires_at",expiry),
                           ("reservation_state_bytes",reservation_state),("reservation_evidence_bytes",reservation_evidence),
                           ("reason",reason),("proof_reason",proof_reason),("canonical_request_bytes",canonical),
                           ("canonical_association_bytes",association_canonical),("compact_proof",proof),
                           ("carrier_binding",carrier_binding),("proof_verification",verified)):
            object.__setattr__(result,name,value)
        return result


__all__=["InstalledRequestAssociationVerifier","RequestAssociationResult","RequestContextFailure"]
