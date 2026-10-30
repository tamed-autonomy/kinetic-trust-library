"""Installed continuing-use composition; no ordinary replay acceptance occurs."""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .software_consumption import InstalledSoftwareConsumptionVerifier,SoftwareConsumptionAssessment
from .existing_association import InstalledExistingAssociationVerifier
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes
from .demand_supplier import _digest
from .execution_observation import _name
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True,init=False)
class SoftwareCheckpointAssessment:
    verifier: object
    consumption: SoftwareConsumptionAssessment
    native_result: object
    checked_at: int
    expires_at: int | None
    conditional_consumption: bool
    action_permitted: bool
    commit_conditions_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("software checkpoints require the installed current native/software graph")


@dataclass(frozen=True,slots=True)
class InstalledSoftwareCheckpointVerifier:
    consumer: InstalledSoftwareConsumptionVerifier
    reservation_verifier: InstalledExistingAssociationVerifier
    profile_bytes: bytes

    def __post_init__(self):
        if (type(self.consumer) is not InstalledSoftwareConsumptionVerifier or type(self.reservation_verifier) is not InstalledExistingAssociationVerifier
                or type(self.profile_bytes) is not bytes):
            raise ValidationError("installed software consumer and current-reservation policies required")
        p=_parse_jcs_object(self.profile_bytes);algorithm=self.consumer.evidence_verifier.algorithm
        if (set(p)!={"id","version","zone","formula","consumer_profile_digest","reservation_profile_digest"}
                or not _name(p["id"]) or not _time(p["version"]) or p["version"]==0
                or p["formula"]!="native-software-checkpoint-v1" or p["zone"]!=_parse_jcs_object(self.consumer.profile_bytes)["zone"]
                or p["consumer_profile_digest"]!=_digest(_parse_jcs_object(self.consumer.profile_bytes),algorithm)
                or p["reservation_profile_digest"]!=_digest(_parse_jcs_object(self.reservation_verifier.profile_bytes),algorithm)
                or self.reservation_verifier.association_verifier is not self.consumer.clearance_verifier.native_verifier.association_verifier):
            raise ValidationError("checkpoint must pin the exact native/software/reservation graph before use")

    def evaluate(self,decision_bytes,previous_assessment,*,actual_operation,invocation_evidence,evaluated_at,clock_healthy,
            readiness_decision_bytes=None,readiness_attestation_bytes=None):
        import rfc8785
        if type(previous_assessment) is SoftwareCheckpointAssessment:
            if previous_assessment.verifier is not self:raise ValidationError("prior checkpoint belongs to another installed graph")
            previous=previous_assessment.consumption
        else:previous=previous_assessment
        if (type(previous) is not SoftwareConsumptionAssessment or previous.verifier is not self.consumer
                or previous.operation_bytes!=canonical_demand_operation_bytes(actual_operation) or previous.native_checkpoint is None
                or not _time(evaluated_at) or clock_healthy is not True or previous.checked_at>evaluated_at
                or (readiness_decision_bytes is None)!=(readiness_attestation_bytes is None)):
            raise ValidationError("checkpoint requires the actual retained operation, native acceptance and healthy current time")
        native=self.consumer.clearance_verifier.native_verifier.revalidate_existing(previous.native_checkpoint,
            reservation_verifier=self.reservation_verifier,invocation_evidence=invocation_evidence,now=evaluated_at,clock_healthy=clock_healthy,
            decision_bytes=readiness_decision_bytes,attestation_bytes=readiness_attestation_bytes)
        consumption=self.consumer.evaluate(decision_bytes,native,actual_operation=actual_operation,evaluated_at=evaluated_at,
            clock_healthy=clock_healthy,previous_assessment=previous)
        conditions=None
        if consumption.commit_conditions_bytes is not None:
            frame=_parse_jcs_object(consumption.commit_conditions_bytes)
            frame.update(checkpoint_profile_digest=_digest(_parse_jcs_object(self.profile_bytes),self.consumer.evidence_verifier.algorithm),
                current_reservation=_parse_jcs_object(native.association.reservation_state_bytes))
            conditions=rfc8785.dumps(frame)
        result=object.__new__(SoftwareCheckpointAssessment)
        for k,v in dict(verifier=self,consumption=consumption,native_result=native,checked_at=evaluated_at,expires_at=consumption.expires_at,
                conditional_consumption=consumption.conditional_consumption,action_permitted=False,commit_conditions_bytes=conditions).items():object.__setattr__(result,k,v)
        return result
