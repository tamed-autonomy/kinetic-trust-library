"""Installed historical effect evidence; never authorization or execution.

Source authenticates original observed facts, actual destination/request, required
protected interval, complete path coverage, recovery boundary and current scoped
issuer keys. Library checks those independent facts against the signed record.
A release candidate is an accountable reconciliation obligation, not a write.
"""
from dataclasses import dataclass
import hashlib
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from kinetic_trust_library._jws_encoding import _decode_segment
from .trust_proof_json import _parse_jcs_object
from .trust_proof_signature import trust_proof_signature_valid
from .software_decision_signature import _software_public_key_valid
from .software_decision_shape import parse_software_decision
from .software_evidence import software_binding
from .consequential_evidence_shape import parse_consequential_evidence
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name
from .root_lifecycle import _time

EVIDENCE_PURPOSE='ktp-consequential-action-evidence-v1'
STATES=('withheld','dispatched','effect_confirmed','no_effect','unknown')

@dataclass(frozen=True,slots=True)
class AuthenticatedConsequentialEvidenceContext:
    state_bytes: bytes
    signing_keys_bytes: bytes
    original_observation_bytes: bytes

@dataclass(frozen=True,slots=True,init=False)
class ConsequentialEvidenceAssessment:
    verifier: object
    verified: bool
    evidence_state: str
    reservation_release_candidate: bool
    action_permitted: bool
    checked_at: int
    expires_at: int
    record_bytes: bytes
    operation_bytes: bytes
    source_state_bytes: bytes
    source_evidence_bytes: bytes
    def __init__(self,*args,**kwargs):raise TypeError('evidence assessments require installed independent verification')

@dataclass(frozen=True,slots=True)
class InstalledConsequentialEvidenceVerifier:
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.profile_bytes) is not bytes or self.algorithm not in ('sha256','sha384')
                or not callable(getattr(self.context_source,'resolve',None))):raise ValidationError('installed evidence policy/source required')
        p=_parse_jcs_object(self.profile_bytes)
        if (set(p)!={'id','version','zone','formula','protected_path','recovery_boundary','max_observation_age_seconds','sources','issuer_ids','algorithms'}
                or any(not _name(p[n]) for n in ('id','zone','protected_path','recovery_boundary'))
                or not _time(p['version']) or p['version']==0 or p['formula']!='consequential-evidence-v1'
                or not _time(p['max_observation_age_seconds']) or p['max_observation_age_seconds']==0
                or type(p['sources']) is not dict or not p['sources']
                or any(not _name(k) or type(v) is not list or not v or any(type(n) is not str or n not in STATES for n in v) or len(set(v))!=len(v) for k,v in p['sources'].items())
                or type(p['issuer_ids']) is not list or not p['issuer_ids'] or any(not _name(n) for n in p['issuer_ids'])
                or len(set(p['issuer_ids']))!=len(p['issuer_ids'])
                or type(p['algorithms']) is not list or not p['algorithms'] or any(type(n) is not str or n not in ('ES256','EdDSA') for n in p['algorithms'])
                or len(set(p['algorithms']))!=len(p['algorithms'])):raise ValidationError('exact installed evidence declaration required')

    def evaluate(self,record_bytes,*,actual_operation,consumption_decision_bytes,evaluated_at,clock_healthy):
        import rfc8785
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError('current healthy trusted evidence clock required')
        operation_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(operation_bytes)
        body=parse_consequential_evidence(record_bytes);decision=parse_software_decision(consumption_decision_bytes)
        p=_parse_jcs_object(self.profile_bytes)
        context=self.context_source.resolve(actual_operation_bytes=operation_bytes,record_bytes=record_bytes,
            consumption_decision_bytes=consumption_decision_bytes,profile_bytes=self.profile_bytes,evaluated_at=evaluated_at)
        if (type(context) is not AuthenticatedConsequentialEvidenceContext or type(context.state_bytes) is not bytes
                or type(context.signing_keys_bytes) is not bytes or type(context.original_observation_bytes) is not bytes
                or not 0<len(context.original_observation_bytes)<=1048576):raise ValidationError('original authenticated effect observation required')
        s=_parse_jcs_object(context.state_bytes);keys=_parse_jcs_object(context.signing_keys_bytes)
        if (set(s)!={'profile_digest','operation_digest','checked_at','expires_at','recovery_boundary','request_binding','required_interval','reservation','recorder_evidence_digest','observed'}
                or s['profile_digest']!=_digest(p,self.algorithm) or s['operation_digest']!=digest_demand_operation(op,algorithm=self.algorithm)
                or not _time(s['checked_at']) or s['checked_at']!=evaluated_at or not _time(s['expires_at']) or s['expires_at']<=evaluated_at
                or s['recovery_boundary']!=p['recovery_boundary']):raise ValidationError('effect evidence Source differs from actual current installed scope')
        binding=software_binding(s['request_binding']);obs=body['observation'];observed=s['observed'];interval=s['required_interval']
        if (binding!=decision['request_binding'] or _digest(binding,self.algorithm)!=decision['request_digest']
                or binding['actor_id']!=op['subject'] or binding['workload_id']!=op['actor'] or binding['request_id']!=op['request_id']
                or binding['operation_id']!=op['operation'] or binding['resource_id']!=op['resource'] or binding['parameters_digest']!=_digest(op['parameters'],self.algorithm)
                or body['request_id']!=binding['request_id'] or body['operation_fingerprint_digest']!=decision['request_digest']
                or body['consumption_decision_digest']!=_digest(decision,self.algorithm) or body['enforcement_destination']!=binding['enforcement_destination']
                or type(observed) is not dict or set(observed)!={'evidence_state','observation','target_marker'}
                or observed!={'evidence_state':body['evidence_state'],'observation':obs,'target_marker':body.get('target_marker')}
                or obs['source_id'] not in p['sources'] or body['evidence_state'] not in p['sources'][obs['source_id']]
                or obs['provenance_digest']!=self.algorithm+':'+hashlib.new(self.algorithm,context.original_observation_bytes).hexdigest()
                or obs['interval_start']>obs['interval_end'] or obs['interval_end']>evaluated_at
                or evaluated_at-obs['interval_end']>=p['max_observation_age_seconds']
                or type(interval) is not dict or set(interval)!={'start','end'} or any(not _time(interval[n]) for n in interval)
                or interval['start']>interval['end']):raise ValidationError('signed evidence differs from actual request, observed facts, source or interval')
        if body['evidence_state']=='withheld' and (obs.get('protected_path_coverage')!=p['protected_path']
                or obs['interval_start']>interval['start'] or obs['interval_end']<interval['end']):
            raise ValidationError('non-dispatch must cover the entire installed protected path and interval')
        reservation=s['reservation']
        if reservation is None:
            if 'reservation_reference' in body or 'reservation_digest' in body:raise ValidationError('invented reservation correlation')
        elif (type(reservation) is not dict or set(reservation)!={'reference','digest'}
                or body.get('reservation_reference')!=reservation['reference'] or body.get('reservation_digest')!=reservation['digest']):
            raise ValidationError('evidence reservation differs from actual original reservation')
        if body.get('recorder_evidence_digest')!=s['recorder_evidence_digest']:raise ValidationError('recorder evidence correlation differs')
        verified=False
        try:
            pieces=body['signature'].split('.')
            if len(pieces)!=3:raise ValidationError('invalid evidence JWS framing')
            header=_parse_jcs_object(_decode_segment(pieces[0],name='evidence header'))
            key=keys.get(header.get('kid'))
            if (type(key) is not dict or key.get('alg') not in p['algorithms'] or not _software_public_key_valid(key)
                    or key.get('revoked') is not False or key.get('purpose')!=EVIDENCE_PURPOSE or key.get('subject') not in p['issuer_ids']
                    or key.get('zone_id')!=p['zone'] or type(key.get('source_ids')) is not list or obs['source_id'] not in key['source_ids']
                    or not _time(key.get('not_before')) or not _time(key.get('not_after'))
                    or not key['not_before']<=obs['interval_end']<=evaluated_at<key['not_after']
                    or header!={'alg':key['alg'],'kid':key.get('kid'),'typ':EVIDENCE_PURPOSE}
                    or _decode_segment(pieces[1],name='evidence payload')!=rfc8785.dumps({k:v for k,v in body.items() if k!='signature'})):
                raise ValidationError('evidence signature differs from installed issuer, role, source, purpose or canonical payload')
            verified=trust_proof_signature_valid(body['signature'],algorithm=key['alg'],trusted_key=key)
        except (ValidationError,ProofFormatError,ValueError,TypeError,KeyError):pass
        result=object.__new__(ConsequentialEvidenceAssessment)
        for k,v in dict(verifier=self,verified=verified,evidence_state=body['evidence_state'] if verified else 'unknown',
                reservation_release_candidate=verified and body['evidence_state']=='withheld' and reservation is not None,
                action_permitted=False,checked_at=evaluated_at,expires_at=min(s['expires_at'],obs['interval_end']+p['max_observation_age_seconds']),
                record_bytes=record_bytes,operation_bytes=operation_bytes,source_state_bytes=context.state_bytes,
                source_evidence_bytes=context.original_observation_bytes).items():object.__setattr__(result,k,v)
        return result
