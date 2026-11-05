"""Restrictive current shared-budget/replay checks; never a reservation write.

Source authenticates the complete durable scope across all actors, resources and
replicas, historical decisions/reconciliation, actual maximum effects, live target
and recorder. The selected cumulative accounting policy has no automatic reset or
charge expiry. Even a positive result requires atomic Service compare/reserve.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .software_evidence import software_binding
from .software_decision_shape import parse_software_decision
from .consequential_evidence import InstalledConsequentialEvidenceVerifier,ConsequentialEvidenceAssessment,STATES
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time


def _installed(p):
    fields={'id','version','zone','formula','scope','units','maximum','registry','replay_domain','retention_seconds',
        'longest_recovery_seconds','recovery_boundary','target_contract_digest','conditional_commit','checkpoint_seconds','safe_transition',
        'abandon_after_seconds','observer_profile_digest','recorder_required','accounting_period','reset_conditions','charge_expiry'}
    if (set(p)!=fields or any(not _name(p[n]) for n in ('id','zone','scope','units','registry','replay_domain','recovery_boundary','safe_transition'))
            or any(not _time(p[n]) or p[n]==0 for n in ('version','maximum','retention_seconds','longest_recovery_seconds','checkpoint_seconds','abandon_after_seconds'))
            or p['retention_seconds']<p['longest_recovery_seconds'] or p['retention_seconds']<p['abandon_after_seconds']
            or not is_digest(p['target_contract_digest']) or not is_digest(p['observer_profile_digest'])
            or type(p['conditional_commit']) is not bool or type(p['recorder_required']) is not bool
            or p['formula']!='cumulative-effect-budget-v1' or p['accounting_period']!='cumulative'
            or p['reset_conditions']!='none' or p['charge_expiry']!='none'):
        raise ValidationError('explicit supported replay, recovery, cumulative accounting, target and observer declarations required')


def _ledger(entries,algorithm,now):
    if type(entries) is not list or len(entries)>1024:raise ValidationError('bounded complete scoped effect inventory required')
    by_ref={};attempts={}
    for e in entries:
        if (type(e) is not dict or set(e)!={'request_id','request_binding','fingerprint_digest','attempt','created_at','reservation_reference',
                'reservation_digest','units','reservation_status','evidence_state','decision_digests','last_evidence_digest','protected_interval'}
                or not _name(e['request_id']) or not _name(e['reservation_reference']) or e['reservation_reference'] in by_ref
                or not _time(e['attempt']) or e['attempt']==0 or not _time(e['created_at']) or e['created_at']>now
                or not _time(e['units']) or e['reservation_status'] not in ('held','charged','released') or e['evidence_state'] not in STATES
                or not is_digest(e['reservation_digest']) or not e['reservation_digest'].startswith(algorithm+':')
                or e['fingerprint_digest']!=_digest(software_binding(e['request_binding']),algorithm) or e['request_id']!=e['request_binding']['request_id']
                or type(e['decision_digests']) is not list or not e['decision_digests'] or len(e['decision_digests'])>1024
                or any(not is_digest(d) or not d.startswith(algorithm+':') for d in e['decision_digests'])
                or len(set(e['decision_digests']))!=len(e['decision_digests'])
                or e['last_evidence_digest'] is not None and (not is_digest(e['last_evidence_digest']) or not e['last_evidence_digest'].startswith(algorithm+':'))
                or e['reservation_status']=='released' and (e['evidence_state']!='withheld' or e['last_evidence_digest'] is None)
                or type(e['protected_interval']) is not dict or set(e['protected_interval'])!={'start','end'}
                or any(not _time(e['protected_interval'][n]) for n in ('start','end'))
                or not e['created_at']<=e['protected_interval']['start']<=e['protected_interval']['end']):
            raise ValidationError('actual original per-attempt reservations and accountable disposition history required')
        by_ref[e['reservation_reference']]=e;attempts.setdefault(e['request_id'],[]).append(e)
    for group in attempts.values():
        ordered=sorted(group,key=lambda e:e['attempt'])
        if ([e['attempt'] for e in ordered]!=list(range(1,len(ordered)+1))
                or len({e['fingerprint_digest'] for e in ordered})!=1
                or any(e['reservation_status']!='released' for e in ordered[:-1])):
            raise ValidationError('request attempts must retain one fingerprint and every completed prior non-dispatch')
    return by_ref


def _continuity(old,s,p,algorithm,now):
    if s['epoch']<old['epoch'] or s['revision']<old['revision']:raise ValidationError('protected effect ledger rolled back')
    if s['epoch']==old['epoch'] and s['revision']==old['revision'] and (s['ledger']!=old['ledger'] or s['checkpoint_anchor']!=old['checkpoint_anchor']):
        raise ValidationError('effect ledger changed under the same protected head')
    current={e['reservation_reference']:e for e in s['ledger']}
    for e in old['ledger']:
        n=current.get(e['reservation_reference'])
        if n is None:
            if e['reservation_status']!='released' or now-e['created_at']<p['retention_seconds']:
                raise ValidationError('recovery cannot erase unresolved or retained effect history')
            continue
        immutable=('request_id','request_binding','fingerprint_digest','attempt','created_at','reservation_reference','reservation_digest','units')
        if (any(n[k]!=e[k] for k in immutable) or n['decision_digests'][:len(e['decision_digests'])]!=e['decision_digests']
                or n['protected_interval']['start']!=e['protected_interval']['start'] or n['protected_interval']['end']<e['protected_interval']['end']
                or e['reservation_status']=='released' and n!=e
                or e['evidence_state'] in ('dispatched','effect_confirmed','no_effect') and n['reservation_status']=='released'):
            raise ValidationError('effect reconciliation rewrote original history or freed dispatched state')


@dataclass(frozen=True,slots=True)
class AuthenticatedEffectBudgetContext:
    state_bytes: bytes
    evidence_bytes: bytes

@dataclass(frozen=True,slots=True,init=False)
class EffectBudgetAssessment:
    verifier: object
    budget_eligible: bool
    reason: str
    remaining_units: int
    checked_at: int
    expires_at: int
    source_state_bytes: bytes
    source_evidence_bytes: bytes
    operation_bytes: bytes
    commit_conditions_bytes: bytes | None
    action_permitted: bool
    def __init__(self,*args,**kwargs):raise TypeError('effect budget assessments require installed current verification')

@dataclass(frozen=True,slots=True)
class InstalledEffectBudgetVerifier:
    profile_bytes: bytes
    context_source: object
    evidence_verifier: InstalledConsequentialEvidenceVerifier
    algorithm: str

    def __post_init__(self):
        if (type(self.profile_bytes) is not bytes or self.algorithm not in ('sha256','sha384')
                or type(self.evidence_verifier) is not InstalledConsequentialEvidenceVerifier or self.evidence_verifier.algorithm!=self.algorithm
                or not callable(getattr(self.context_source,'resolve',None))):raise ValidationError('installed effect budget/source/evidence graph required')
        p=_parse_jcs_object(self.profile_bytes);_installed(p);ep=_parse_jcs_object(self.evidence_verifier.profile_bytes)
        if (p['observer_profile_digest']!=_digest(ep,self.algorithm) or p['zone']!=ep['zone'] or p['recovery_boundary']!=ep['recovery_boundary']):
            raise ValidationError('effect budget must pin the installed observer graph and recovery boundary')

    def evaluate(self,decision_bytes,*,actual_operation,target_revision,evaluated_at,clock_healthy,previous_assessment=None,non_dispatch=None):
        import rfc8785
        if not _time(evaluated_at) or clock_healthy is not True or not _name(target_revision):raise ValidationError('actual target revision and healthy current effect clock required')
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes);p=_parse_jcs_object(self.profile_bytes)
        decision=parse_software_decision(decision_bytes);binding=software_binding(decision['request_binding'])
        if (op['replay_domain']!=p['replay_domain'] or binding['request_id']!=op['request_id'] or binding['actor_id']!=op['subject']
                or binding['workload_id']!=op['actor'] or binding['operation_id']!=op['operation'] or binding['resource_id']!=op['resource']
                or binding['parameters_digest']!=_digest(op['parameters'],self.algorithm) or decision['request_digest']!=_digest(binding,self.algorithm)):
            raise ValidationError('budget candidate must bind the actual operation and installed replay domain')
        context=self.context_source.resolve(actual_operation_bytes=op_bytes,consumption_decision_bytes=decision_bytes,
            profile_bytes=self.profile_bytes,evaluated_at=evaluated_at)
        if (type(context) is not AuthenticatedEffectBudgetContext or type(context.state_bytes) is not bytes
                or type(context.evidence_bytes) is not bytes or not 0<len(context.evidence_bytes)<=1048576):raise ValidationError('authenticated complete persistent effect inventory required')
        s=_parse_jcs_object(context.state_bytes)
        if (set(s)!={'profile_digest','operation_digest','request_binding','checked_at','expires_at','epoch','revision','checkpoint_anchor',
                'recovery_boundary','registry','scope','units','maximum','ledger','requested_units','reservation_units','recorder_available','target_revision'}
                or s['profile_digest']!=_digest(p,self.algorithm) or s['operation_digest']!=digest_demand_operation(op,algorithm=self.algorithm)
                or s['request_binding']!=binding or any(s[n]!=p[n] for n in ('recovery_boundary','registry','scope','units','maximum'))
                or not _time(s['checked_at']) or s['checked_at']!=evaluated_at or not _time(s['expires_at']) or s['expires_at']<=evaluated_at
                or any(not _time(s[n]) or s[n]==0 for n in ('epoch','revision')) or not _name(s['checkpoint_anchor'])
                or any(not _time(s[n]) for n in ('requested_units','reservation_units')) or type(s['recorder_available']) is not bool):
            raise ValidationError('effect Source differs from complete actual current policy/action/scope/head')
        _ledger(s['ledger'],self.algorithm,evaluated_at)
        if previous_assessment is not None:
            if (type(previous_assessment) is not EffectBudgetAssessment or previous_assessment.verifier is not self
                    or previous_assessment.operation_bytes!=op_bytes or previous_assessment.checked_at>evaluated_at):
                raise ValidationError('retained budget evidence belongs to another installed operation or clock')
            _continuity(_parse_jcs_object(previous_assessment.source_state_bytes),s,p,self.algorithm,evaluated_at)
        remaining=max(0,p['maximum']-sum(e['units'] for e in s['ledger'] if e['reservation_status']!='released'))
        group=sorted((e for e in s['ledger'] if e['request_id']==op['request_id']),key=lambda e:e['attempt'])
        reason='EFFECT_BUDGET_CURRENT'
        if s['target_revision']!=target_revision:reason='EFFECT_TARGET_CHANGED'
        elif p['recorder_required'] and not s['recorder_available']:reason='EFFECT_RECORDER_UNAVAILABLE'
        elif not p['conditional_commit']:reason='EFFECT_TARGET_ATOMICITY_UNSUPPORTED'
        elif s['reservation_units']<s['requested_units']:reason='EFFECT_RESERVATION_UNDERESTIMATED'
        elif any(e['fingerprint_digest']!=decision['request_digest'] for e in group):reason='EFFECT_IDENTITY_COLLISION'
        elif group:
            last=group[-1]
            if any(e['reservation_status']!='released' for e in group):reason='EFFECT_REPLAY_UNRESOLVED'
            elif (type(non_dispatch) is not ConsequentialEvidenceAssessment or non_dispatch.verifier is not self.evidence_verifier
                    or not non_dispatch.verified or not non_dispatch.reservation_release_candidate or non_dispatch.operation_bytes!=op_bytes
                    or non_dispatch.checked_at!=evaluated_at or non_dispatch.expires_at<=evaluated_at):reason='EFFECT_RECONCILIATION_REQUIRED'
            else:
                record=_parse_jcs_object(non_dispatch.record_bytes);interval=last['protected_interval']
                if (record['reservation_reference']!=last['reservation_reference'] or record['reservation_digest']!=last['reservation_digest']
                        or _digest(record,self.algorithm)!=last['last_evidence_digest'] or record['operation_fingerprint_digest']!=decision['request_digest']
                        or record['consumption_decision_digest'] not in last['decision_digests']
                        or record['observation']['interval_start']>interval['start'] or record['observation']['interval_end']<interval['end']):
                    reason='EFFECT_RECONCILIATION_MISMATCH'
        if reason=='EFFECT_BUDGET_CURRENT' and s['reservation_units']>remaining:reason='EFFECT_BUDGET_INSUFFICIENT'
        eligible=reason=='EFFECT_BUDGET_CURRENT';conditions=None
        expiry=min(s['expires_at'],evaluated_at+p['checkpoint_seconds'])
        if eligible and group:expiry=min(expiry,non_dispatch.expires_at)
        if eligible:
            conditions=rfc8785.dumps(dict(profile_digest=s['profile_digest'],registry=p['registry'],scope=p['scope'],units=p['units'],maximum=p['maximum'],
                epoch=s['epoch'],revision=s['revision'],checkpoint_anchor=s['checkpoint_anchor'],ledger_digest=_digest(s['ledger'],self.algorithm),
                request_id=op['request_id'],operation_fingerprint_digest=decision['request_digest'],consumption_decision_digest=_digest(decision,self.algorithm),
                enforcement_destination=binding['enforcement_destination'],target_revision=target_revision,target_contract_digest=p['target_contract_digest'],
                next_attempt=len(group)+1,reservation_units=s['reservation_units'],remaining_units=remaining,recovery_boundary=p['recovery_boundary'],
                expires_at=expiry,atomic_compare_reserve_and_commit_required=True))
        result=object.__new__(EffectBudgetAssessment)
        for k,v in dict(verifier=self,budget_eligible=eligible,reason=reason,remaining_units=remaining,checked_at=evaluated_at,expires_at=expiry,
                source_state_bytes=context.state_bytes,source_evidence_bytes=context.evidence_bytes,operation_bytes=op_bytes,
                commit_conditions_bytes=conditions,action_permitted=False).items():object.__setattr__(result,k,v)
        return result
