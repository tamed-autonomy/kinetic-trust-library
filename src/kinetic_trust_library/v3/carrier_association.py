"""Exact signed-carrier bridge for cross-boundary request association.

The original verified geometry remains attached to association evidence so its
supervision and every tightened constraint survive. No boolean 'verified' flag
can replace this binding, and replay reservation remains a later prerequisite.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .geometry_carrier import InstalledGeometryCarrierVerifier
from .complete_proof_verifier import ProofVerificationResult
from .request_binding import canonical_request_bytes as _canonical_request
from .trust_proof_json import _parse_jcs_object
from .request_association import _verified_carrier_binding


@dataclass(frozen=True,slots=True)
class AssociationGeometryCarrier:
    compact_carrier: str
    verifier: InstalledGeometryCarrierVerifier

    def __post_init__(self):
        if type(self.compact_carrier) is not str or type(self.verifier) is not InstalledGeometryCarrierVerifier:
            raise ValidationError("installed association carrier is invalid")

    def verify(self,*,canonical_request_bytes: bytes,canonical_association_bytes: bytes,
               proof: ProofVerificationResult,now: int,clock_healthy: bool):
        import rfc8785
        if (type(proof) is not ProofVerificationResult or proof.stage!=8 or proof.reason!="TP_CLEAR"
                or type(canonical_request_bytes) is not bytes or type(canonical_association_bytes) is not bytes):
            return None
        context=_parse_jcs_object(self.verifier.expected_context_bytes)
        if (_canonical_request(context["request"])!=canonical_request_bytes or context["proof"]!=proof.compact):
            return None
        verified=self.verifier.verify(self.compact_carrier,now=now,clock_healthy=clock_healthy)
        if verified.reason!="DG_CARRIER_VALID": return None
        payload=_parse_jcs_object(verified.canonical_payload_bytes)
        geometry=payload["geometry"]
        if rfc8785.dumps(geometry["association"])!=canonical_association_bytes:
            return None
        return _verified_carrier_binding(compact_carrier=self.compact_carrier,
            canonical_geometry_bytes=rfc8785.dumps(geometry),canonical_request_bytes=canonical_request_bytes,
            canonical_association_bytes=canonical_association_bytes,compact_proof=proof.compact,verified_at=now)


__all__=["AssociationGeometryCarrier"]
