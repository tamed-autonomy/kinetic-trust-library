"""Registered Exceeded return paths for actual current software condition loss.

Source owns genuine sealing, durable stop registration and delivery. The SDK
rechecks the pinned current native/software graph and validates the prepared
record through the same current clearance/hand-back path as other native stops.
"""
from dataclasses import dataclass
import hashlib
from kinetic_trust_library.errors import ValidationError
from .software_checkpoint import InstalledSoftwareCheckpointVerifier,SoftwareCheckpointAssessment
from .software_consumption import SoftwareConsumptionAssessment,_current_conditions_withhold
from .native_stop_resolution import PreparedNativeStop as PreparedSoftwareStop,_prepare_registered_stop
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes
from .demand_supplier import _digest
from .request_binding import digest_complete_proof
from .root_lifecycle import _time
from .execution_observation import _name


@dataclass(frozen=True,slots=True,init=False)
class SoftwareStopResolution:
    checkpoint: SoftwareCheckpointAssessment
    clearance: object
    template: object
    cause_bytes: bytes
    preparation: PreparedSoftwareStop
    evaluated_at: int
    expires_at: int
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("software stops require actual current registered return-path validation")


@dataclass(frozen=True,slots=True)
class InstalledSoftwareStopResolver:
    checkpoint_verifier: InstalledSoftwareCheckpointVerifier
    profile_bytes: bytes
    preparation_source: object

    def __post_init__(self):
        if (type(self.checkpoint_verifier) is not InstalledSoftwareCheckpointVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.preparation_source,"prepare",None))):
            raise ValidationError("software stop requires installed current checkpoint and genuine preparation source")
        p=_parse_jcs_object(self.profile_bytes);cp=self.checkpoint_verifier
        if (set(p)!={"id","version","zone","formula","checkpoint_profile_digest"} or not _name(p["id"])
                or not _time(p["version"]) or p["version"]==0 or p["formula"]!="software-permit-condition-return-path-v1"
                or p["zone"]!=_parse_jcs_object(cp.profile_bytes)["zone"]
                or p["checkpoint_profile_digest"]!=_digest(_parse_jcs_object(cp.profile_bytes),cp.consumer.evidence_verifier.algorithm)):
            raise ValidationError("software stop differs from the exact installed checkpoint/return-path declaration")

    def evaluate(self,failed,*,actual_operation,invocation_evidence,evaluated_at,clock_healthy):
        cp=self.checkpoint_verifier;consumer=cp.consumer
        prior=failed.consumption if type(failed) is SoftwareCheckpointAssessment and failed.verifier is cp else failed
        if (type(prior) is not SoftwareConsumptionAssessment or prior.verifier is not consumer or prior.conditional_consumption
                or prior.observed_decision_bytes is None or not prior.hand_back_required
                or not _time(evaluated_at) or prior.checked_at>evaluated_at or clock_healthy is not True):
            raise ValidationError("software stop requires an actual retained failed current software assessment")
        checkpoint=cp.evaluate(prior.observed_decision_bytes,failed,actual_operation=actual_operation,
            invocation_evidence=invocation_evidence,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        current=checkpoint.consumption;initial=current.clearance;e=current.evidence
        if (current.conditional_consumption or not current.hand_back_required or not initial.conditional_clear
                or initial.lease is None or not initial.lease.active or e is None or e.checked_at!=evaluated_at
                or initial.management is None or not initial.management.valid or initial.management.management.regime!="managed"
                or not (_current_conditions_withhold(e)
                    or current.verified and current.reason in ("SOFTWARE_RESTRICTED","SOFTWARE_REVISED_OPERATION_REQUIRED"))):
            raise ValidationError("software stop condition is no longer current or belongs to another native return path")
        import rfc8785
        cv=consumer.clearance_verifier;algorithm=consumer.evidence_verifier.algorithm
        state=_parse_jcs_object(initial.authenticated_state_bytes);template=initial.template
        if (template is None or template.subject!=state["subject"] or template.principal!=state["principal"]
                or template.consequence_class!=initial.lease.consequence_class or template.registered_at>initial.lease.issued_at):
            raise ValidationError("software stop must use the actual original grant's registered template")
        native=current.clearance.native_result
        def raw_digest(raw):return algorithm+":"+hashlib.new(algorithm,raw).hexdigest()
        cause=rfc8785.dumps(dict(profile_digest=_digest(_parse_jcs_object(self.profile_bytes),algorithm),
            checkpoint_profile_digest=_digest(_parse_jcs_object(cp.profile_bytes),algorithm),
            operation_digest=_digest(_parse_jcs_object(current.operation_bytes),algorithm),evaluated_at=evaluated_at,
            reason="exceeded_permit_condition",software_reason=current.reason,evidence_reason=e.reason,
            repair_path_verified=e.repair_path_verified,supervision_available=e.supervision_available,
            unresolved_restrictions=list(e.unresolved_restrictions),template_digest=template.template_digest,
            grant_digest=_digest(state["lease"],algorithm),clearance_state_digest=_digest(state,algorithm),
            proof_digest=digest_complete_proof(native.association.compact_proof,algorithm=algorithm),
            geometry_digest=_digest(_parse_jcs_object(native.canonical_geometry_bytes),algorithm),
            software_candidate_digest=raw_digest(prior.observed_decision_bytes),software_candidate_verified=current.verified,
            software_state_digest=_digest(_parse_jcs_object(e.source_state_bytes),algorithm),software_frame_digest=e.frame_digest,
            software_assessment=_parse_jcs_object(e.assessment_bytes),
            software_source_evidence_digest=raw_digest(e.source_evidence_bytes)))
        prepared,clearance=_prepare_registered_stop(cv=cv,initial=initial,native_result=native,template=template,
            profile_bytes=self.profile_bytes,cause=cause,op_bytes=canonical_demand_operation_bytes(actual_operation),
            preparation_source=self.preparation_source,evaluated_at=evaluated_at)
        result=object.__new__(SoftwareStopResolution)
        for k,v in dict(checkpoint=checkpoint,clearance=clearance,template=template,cause_bytes=cause,preparation=prepared,
                evaluated_at=evaluated_at,expires_at=min(clearance.expires_at,template.expires_at),action_permitted=False).items():object.__setattr__(result,k,v)
        return result
