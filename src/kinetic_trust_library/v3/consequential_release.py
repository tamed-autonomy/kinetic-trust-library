"""Fresh installed software/native checks plus restrictive atomic budget terms.

No queue, reservation, dispatch or commit is performed. Even a conditional result
requires the Service to atomically enforce every returned condition before the
exact action is released. The target's tested CAS boundary remains external.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .software_checkpoint import InstalledSoftwareCheckpointVerifier
from .effect_budget import InstalledEffectBudgetVerifier
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes
from .root_lifecycle import _time
from .execution_observation import _name


@dataclass(frozen=True,slots=True,init=False)
class ConsequentialReleaseAssessment:
    verifier: object
    checkpoint: object
    budget: object
    conditional_release: bool
    reason: str
    checked_at: int
    expires_at: int | None
    commit_conditions_bytes: bytes | None
    operation_bytes: bytes
    action_permitted: bool
    commit_time_authorization_guarantee: bool
    safe_transition_required: bool
    evidence_state: str
    observation_record_required: bool
    def __init__(self,*args,**kwargs):raise TypeError('release assessments require the complete installed current graph')

@dataclass(frozen=True,slots=True)
class InstalledConsequentialReleaseVerifier:
    checkpoint_verifier: InstalledSoftwareCheckpointVerifier
    budget_verifier: InstalledEffectBudgetVerifier
    profile_bytes: bytes

    def __post_init__(self):
        if (type(self.checkpoint_verifier) is not InstalledSoftwareCheckpointVerifier or type(self.budget_verifier) is not InstalledEffectBudgetVerifier
                or type(self.profile_bytes) is not bytes):raise ValidationError('complete installed software checkpoint and effect-budget graph required')
        p=_parse_jcs_object(self.profile_bytes);cp=_parse_jcs_object(self.checkpoint_verifier.profile_bytes)
        bp=_parse_jcs_object(self.budget_verifier.profile_bytes);algorithm=self.budget_verifier.algorithm
        if (set(p)!={'id','version','formula','checkpoint_profile_digest','budget_profile_digest'} or not _name(p['id'])
                or not _time(p['version']) or p['version']==0 or p['formula']!='native-software-effect-release-v1'
                or p['checkpoint_profile_digest']!=_digest(cp,algorithm) or p['budget_profile_digest']!=_digest(bp,algorithm)
                or cp['zone']!=bp['zone'] or self.checkpoint_verifier.consumer.evidence_verifier.algorithm!=algorithm):
            raise ValidationError('release must pin the exact installed checkpoint/budget profiles, zone and algorithm')

    def evaluate(self,decision_bytes,previous_assessment,*,actual_operation,invocation_evidence,evaluated_at,clock_healthy,
            non_dispatch=None,**checkpoint_inputs):
        import rfc8785
        operation_bytes=canonical_demand_operation_bytes(actual_operation);old_budget=None
        previous=previous_assessment
        if type(previous_assessment) is ConsequentialReleaseAssessment:
            if (previous_assessment.verifier is not self or previous_assessment.operation_bytes!=operation_bytes
                    or not _time(evaluated_at) or previous_assessment.checked_at>evaluated_at):
                raise ValidationError('prior release belongs to another installed operation, policy or clock')
            previous=previous_assessment.checkpoint;old_budget=previous_assessment.budget
        checkpoint=self.checkpoint_verifier.evaluate(decision_bytes,previous,actual_operation=actual_operation,
            invocation_evidence=invocation_evidence,evaluated_at=evaluated_at,clock_healthy=clock_healthy,**checkpoint_inputs)
        budget=old_budget;conditions=None;expiry=checkpoint.expires_at;eligible=False
        reason=checkpoint.consumption.reason
        if checkpoint.conditional_consumption:
            source=_parse_jcs_object(checkpoint.consumption.evidence.source_state_bytes)
            budget=self.budget_verifier.evaluate(decision_bytes,actual_operation=actual_operation,target_revision=source['target_revision'],
                evaluated_at=evaluated_at,clock_healthy=clock_healthy,previous_assessment=old_budget,non_dispatch=non_dispatch)
            eligible=budget.budget_eligible;reason=budget.reason;expiry=min(checkpoint.expires_at,budget.expires_at)
            if eligible:
                conditions=rfc8785.dumps(dict(release_profile_digest=_digest(_parse_jcs_object(self.profile_bytes),self.budget_verifier.algorithm),
                    software=_parse_jcs_object(checkpoint.commit_conditions_bytes),effect_budget=_parse_jcs_object(budget.commit_conditions_bytes),expires_at=expiry))
        result=object.__new__(ConsequentialReleaseAssessment)
        for k,v in dict(verifier=self,checkpoint=checkpoint,budget=budget,conditional_release=eligible,reason=reason,
                checked_at=evaluated_at,expires_at=expiry,commit_conditions_bytes=conditions,operation_bytes=operation_bytes,
                action_permitted=False,commit_time_authorization_guarantee=False,evidence_state='unknown',observation_record_required=True,
                safe_transition_required=checkpoint.consumption.hand_back_required).items():object.__setattr__(result,k,v)
        return result
