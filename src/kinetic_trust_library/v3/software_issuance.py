"""Issue software sidecars through installed claims and key-custody adapters.

Inputs are independently validated before signing. Completed artifacts are
rechecked against current state and the retained preparation checkpoint before
return. Neither preparation nor issuance authorizes an effect.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .software_consumption import InstalledSoftwareConsumptionVerifier
from .software_decision_signature import SOFTWARE_DECISION_PURPOSE
from .trust_proof_json import _parse_jcs_object
from .native_issuance import _segment
from .execution_observation import _name
from .root_lifecycle import _time
from .demand_operation import canonical_demand_operation_bytes


@dataclass(frozen=True,slots=True)
class IssuedSoftwareDecision:
    decision_bytes: bytes
    payload_bytes: bytes
    verification: object


@dataclass(frozen=True,slots=True)
class InstalledSoftwareDecisionIssuer:
    consumer: InstalledSoftwareConsumptionVerifier
    claim_source: object
    signer: object
    algorithm: str
    kid: str

    def __post_init__(self):
        if (type(self.consumer) is not InstalledSoftwareConsumptionVerifier or not callable(getattr(self.claim_source,"produce",None))
                or not callable(getattr(self.signer,"sign",None)) or self.algorithm not in ("ES256","EdDSA") or not _name(self.kid)):
            raise ValidationError("installed software consumer, claim authority and private signing adapter required")

    def issue(self,native_result,*,actual_operation,evaluated_at,clock_healthy,previous_assessment=None):
        import rfc8785
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("software issuance requires healthy current time")
        payload=self.claim_source.produce(operation_bytes=canonical_demand_operation_bytes(actual_operation),
            consumer_profile_bytes=self.consumer.profile_bytes,evaluated_at=evaluated_at)
        preparation=self.consumer.prepare_issuance(payload,native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,
            clock_healthy=clock_healthy,algorithm=self.algorithm,kid=self.kid,previous_assessment=previous_assessment)
        if not preparation.issuance_prepared:raise ValidationError("software issuance input rejected: "+preparation.reason)
        body=_parse_jcs_object(payload)
        header=rfc8785.dumps(dict(alg=self.algorithm,kid=self.kid,typ=SOFTWARE_DECISION_PURPOSE))
        signing_input=(_segment(header)+"."+_segment(payload)).encode("ascii")
        raw=self.signer.sign(signing_input,algorithm=self.algorithm,kid=self.kid)
        if type(raw) is not bytes or not raw or len(raw)>1024:raise ValidationError("software signer must return bounded raw signature bytes")
        decision=rfc8785.dumps(dict(body,signature=signing_input.decode("ascii")+"."+_segment(raw)))
        verification=self.consumer.evaluate(decision,native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,
            clock_healthy=clock_healthy,previous_assessment=preparation)
        if not verification.verified:raise ValidationError("signed software decision failed current verification: "+verification.reason)
        return IssuedSoftwareDecision(decision,payload,verification)
