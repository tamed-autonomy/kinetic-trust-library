"""Verify the readiness sidecar against a bound ordinary request and live state.

This is a prerequisite verifier, not an ordinary authorizer or permission issuer.
Every use rechecks readiness through its installed source. Protected effects must
still fence that state and satisfy grants, Core/envelope and remaining controls.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .installed_readiness import InstalledReadinessVerifier, ReadinessVerificationResult, _binding
from .complete_proof_verifier import InstalledProofVerifier
from .request_association import RequestAssociationResult
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True, init=False)
class ReadinessDecisionResult:
    reason: str
    readiness: ReadinessVerificationResult | None
    association: RequestAssociationResult
    decision_bytes: bytes | None
    expires_at: int | None

    def __init__(self,*args,**kwargs):
        raise TypeError("readiness decision results are derived by an installed verifier")

    @property
    def valid(self):
        return self.reason=="READINESS_DECISION_VALID"


@dataclass(frozen=True, slots=True)
class InstalledReadinessDecisionVerifier:
    readiness_verifier: InstalledReadinessVerifier
    proof_verifier: InstalledProofVerifier

    def __post_init__(self):
        if (type(self.readiness_verifier) is not InstalledReadinessVerifier
                or type(self.proof_verifier) is not InstalledProofVerifier):
            raise ValidationError("installed readiness decision policy is invalid")
        if self.readiness_verifier.conformance_level==3:
            raise ValidationError("native ordinary proof verification does not yet establish the Level 3 cryptographic profile")
        context=_parse_jcs_object(self.proof_verifier.expected_context_bytes)
        if context["zone"]!=self.readiness_verifier.receiving_zone or context["subject_kind"]!="software_agent":
            raise ValidationError("readiness and ordinary proof scope/subject class differ")

    def verify(self, decision_bytes: bytes, attestation_bytes: bytes, association: RequestAssociationResult,
               *, evaluated_at: int, clock_healthy: bool) -> ReadinessDecisionResult:
        from . import _readiness_reference as r
        if (type(decision_bytes) is not bytes or type(attestation_bytes) is not bytes
                or type(association) is not RequestAssociationResult or not _time(evaluated_at)):
            raise ValidationError("readiness sidecar requires immutable evidence and a derived association")
        readiness=None
        def result(reason,expiry=None):
            value=object.__new__(ReadinessDecisionResult)
            for name,member in (("reason",reason),("readiness",readiness),("association",association),
                ("decision_bytes",decision_bytes if reason=="READINESS_DECISION_VALID" else None),("expires_at",expiry)):
                object.__setattr__(value,name,member)
            return value
        if association.reason!="RB_BOUND" or association.canonical_request_bytes is None:
            return result("READINESS_BINDING_INVALID")
        if clock_healthy is not True:
            return result("READINESS_UNAVAILABLE")
        actual=_parse_jcs_object(association.canonical_request_bytes)
        operation={k:v for k,v in actual.items() if k not in ("version","demand","classification_profile")}
        readiness=self.readiness_verifier.evaluate(attestation_bytes,actual_operation=operation,
            evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        if not readiness.valid:
            return result(readiness.reason)
        proof=self.proof_verifier.verify(association.compact_proof,now=evaluated_at,clock_healthy=clock_healthy)
        if proof.reason!="TP_CLEAR":
            return result("READINESS_PROOF_INVALID")
        try:
            claims=_parse_jcs_object(proof.authenticated_payload_bytes)
            if claims["sub"]!=actual["actor"] or claims["aud"]!=actual["audience"]:
                raise r.InvalidRecord("ordinary proof does not match current executor/audience")
            if len(decision_bytes)>262144:
                raise r.InvalidRecord("unbounded readiness decision")
            decision=_parse_jcs_object(decision_bytes)
            attestation=_parse_jcs_object(readiness.attestation_bytes)
            request=_parse_jcs_object(readiness.actual_request_bytes)
            state=_parse_jcs_object(readiness.authenticated_state_bytes)
            keys=_parse_jcs_object(readiness.trusted_keys_bytes)
            assessor,assessor_key=_binding(keys,attestation["signature"])
            issuer,issuer_key=_binding(keys,decision["signature"])
            trusted=r.TrustedState(**state,assessor_valid_from=assessor_key["not_before"],assessor_valid_until=assessor_key["not_after"],
                issuer_valid_from=issuer_key["not_before"],issuer_valid_until=issuer_key["not_after"])
            ordinary=r.VerifiedOrdinaryProof(association.compact_proof,readiness.request_digest,claims["iat"],claims["exp"])
            r.verify_decision(decision,attestation,_parse_jcs_object(self.readiness_verifier.readiness_profile_bytes),request,ordinary,
                state=trusted,assessor=assessor,issuer=issuer,now=evaluated_at,level=self.readiness_verifier.conformance_level)
        except (r.InvalidRecord,ProofFormatError,KeyError,ValueError,TypeError,UnicodeError,RecursionError):
            return result("READINESS_DECISION_INVALID")
        return result("READINESS_DECISION_VALID",decision["expires_at"])


__all__=["InstalledReadinessDecisionVerifier","ReadinessDecisionResult"]
