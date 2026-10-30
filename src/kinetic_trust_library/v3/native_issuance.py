"""Native proof issuance through installed claim and private-key adapters.

The claim source owns authorization to assert the claims. The signing adapter
owns key custody and returns the algorithm's raw JWS signature. Issuance never
grants execution; the installed verifier checks the completed artifact.
"""
import base64
from dataclasses import dataclass

from kinetic_trust_library.errors import ValidationError
from .complete_proof_verifier import InstalledProofVerifier, ProofVerificationResult
from .trust_proof_json import _parse_jcs_object
from .trust_proof_key import trust_proof_stage3_reason
from .trust_proof_time import trust_proof_stage5_reason


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class IssuedProof:
    compact: str
    payload_bytes: bytes
    verification: ProofVerificationResult


@dataclass(frozen=True, slots=True)
class InstalledProofIssuer:
    claim_source: object
    signer: object
    verifier: InstalledProofVerifier
    algorithm: str
    kid: str

    def __post_init__(self):
        if (type(self.verifier) is not InstalledProofVerifier
                or not callable(getattr(self.claim_source, "produce", None))
                or not callable(getattr(self.signer, "sign", None))
                or self.algorithm not in ("ES256", "EdDSA")
                or self.algorithm not in self.verifier.installed_algorithms
                or type(self.kid) is not str or not self.kid):
            raise ValidationError("installed proof issuance policy is invalid")
        if self.verifier.fixture_software_default:
            raise ValidationError("native proof issuance cannot select fixture semantics")

    def issue(self, *, now: int, clock_healthy: bool) -> IssuedProof:
        import rfc8785
        if type(now) is not int or not 0 <= now <= 9007199254740991 or clock_healthy is not True:
            raise ValidationError("proof issuance requires a healthy installed clock")
        payload = self.claim_source.produce(evaluated_at=now)
        if type(payload) is not bytes:
            raise ValidationError("claim source must return immutable canonical payload bytes")
        try:
            claims = _parse_jcs_object(payload)
        except Exception as error:
            raise ValidationError("claim source returned invalid canonical JSON") from error
        if not self.verifier.schema_bundle.valid(payload):
            raise ValidationError("claim source returned claims outside the installed schema")
        header_object = {"alg": self.algorithm, "kid": self.kid, "typ": "ktp-trust-proof+jwt"}
        context = _parse_jcs_object(self.verifier.expected_context_bytes)
        key = _parse_jcs_object(self.verifier.trusted_keys_bytes).get(self.kid)
        reason = trust_proof_stage3_reason(header_object, trusted_key=key,
            expected_issuer=context["issuer"], expected_zone=context["zone"])
        if reason is None:
            reason = trust_proof_stage5_reason(claims, expected_issuer=context["issuer"],
                expected_audience=context["audience"], now=now, clock_healthy=clock_healthy,
                key_not_before=key.get("not_before"), key_not_after=key.get("not_after"))
        if reason is not None:
            raise ValidationError("proof issuance precondition failed: " + reason)
        header = rfc8785.dumps(header_object)
        signing_input = (_segment(header) + "." + _segment(payload)).encode("ascii")
        signature = self.signer.sign(signing_input, algorithm=self.algorithm, kid=self.kid)
        if type(signature) is not bytes:
            raise ValidationError("signer must return raw signature bytes")
        compact = signing_input.decode("ascii") + "." + _segment(signature)
        verification = self.verifier.verify(compact, now=now, clock_healthy=clock_healthy)
        if verification.stage != 8:
            raise ValidationError("issued proof failed installed verification: " + verification.reason)
        return IssuedProof(compact, payload, verification)
