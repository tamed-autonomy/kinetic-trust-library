"""Registered limited counterparty context alongside an original full hand-back.

A private installed semantic profile, not another public hand-back wire format.
Source authenticates actual registry, decryption/content, complete original
reference inventory, identity/key custody and the agent's inability to decrypt.
Library checks exact bindings and disclosure limits; construction never proves
delivery, performs disclosure or grants permission.
"""
from dataclasses import dataclass
import hashlib
from kinetic_trust_library.errors import ValidationError
from .hand_back import InstalledHandBackVerifier,_strings
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name
from .root_lifecycle import _time

_FULL={'action','lease_history','environment_attestations','work_product'}
_LIMITED={'action','reason_class','attestation_references'}


def _raw_digest(raw,algorithm):return algorithm+':'+hashlib.new(algorithm,raw).hexdigest()


def _profile(p):
    if (set(p)!={'id','version','zone','formula','hand_back_profile_digest','registry'}
            or any(not _name(p[k]) for k in ('id','zone','registry')) or not _time(p['version']) or p['version']==0
            or p['formula']!='registered-counterparty-limited-context-v1'):
        raise ValidationError('invalid installed counterparty context profile')
    return p


def _policy(p,template,subject,kind,grant_time):
    if (set(p)!={'id','version','registered_at','template_id','template_version','subject','consequence_class',
                    'reason_class_source','delegator','counterparty','attestation_reference_rule'}
            or not _name(p['id']) or not _time(p['version']) or p['version']==0
            or not _time(p['registered_at']) or p['registered_at']!=template['registered_at'] or p['registered_at']>grant_time
            or p['template_id']!=template['id'] or type(p['template_version']) is not int
            or p['template_version']!=template['version'] or p['subject']!=subject or p['consequence_class']!=kind
            or p['reason_class_source']!='hand-back.reason'
            or p['attestation_reference_rule']!='all-primary-environment-attestations'):
        raise ValidationError('redaction policy differs from the original pre-grant template')
    for name,tier,sections in (('delegator','full',_FULL),('counterparty','counterparty',_LIMITED)):
        r=p[name]
        if (type(r) is not dict or set(r)!={'principal','endpoint','key_id','tier','sections'}
                or any(not _name(r[k]) for k in ('principal','endpoint','key_id'))
                or r['tier']!=tier or _strings(r['sections'])!=sections):
            raise ValidationError('registered recipient disclosure tier is incomplete')
    primary=template['recipient'];own=p['delegator'];other=p['counterparty']
    if (any(own[k]!=primary[k] for k in ('principal','endpoint','key_id'))
            or any(other[k]==own[k] for k in ('principal','endpoint','key_id')) or other['principal']==subject):
        raise ValidationError('selected limited-recipient profile requires distinct registered counterparty custody')
    return other


@dataclass(frozen=True,slots=True)
class AuthenticatedCounterpartyContext:
    state_bytes: bytes
    redaction_policy_bytes: bytes
    ciphertext_bytes: bytes
    limited_projection_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class CounterpartyHandBackAssessment:
    valid: bool
    primary: object
    action_permitted: bool
    delivery_required: bool
    recipient_endpoint: str
    recipient_key_id: str
    recipient_principal: str
    ciphertext_bytes: bytes
    limited_projection_digest: str
    profile_bytes: bytes
    redaction_policy_bytes: bytes
    operation_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    evaluated_at: int
    expires_at: int

    def __init__(self,*args,**kwargs):raise TypeError('counterparty contexts require installed original-policy verification')


@dataclass(frozen=True,slots=True)
class InstalledCounterpartyHandBackVerifier:
    hand_back_verifier: InstalledHandBackVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.hand_back_verifier) is not InstalledHandBackVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,'resolve',None))):
            raise ValidationError('invalid installed counterparty context verifier')
        hb=self.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes));hp=_parse_jcs_object(hb.profile_bytes)
        if p['zone']!=hp['zone'] or p['hand_back_profile_digest']!=_digest(hp,hb.algorithm):
            raise ValidationError('counterparty profile differs from the original hand-back profile')

    def evaluate(self,hand_back_bytes,*,actual_operation,evaluated_at,clock_healthy):
        hb=self.hand_back_verifier;algorithm=hb.algorithm;p=_profile(_parse_jcs_object(self.profile_bytes))
        operation_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(operation_bytes)
        original=hb.evaluate(hand_back_bytes,actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        if not original.valid:raise ValidationError('counterparty context requires a valid original full hand-back')
        hs=_parse_jcs_object(original.authenticated_state_bytes);wire=_parse_jcs_object(hand_back_bytes)
        if hs['lease'] is None:raise ValidationError('selected counterparty profile requires an original registered grant')
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            hand_back_bytes=hand_back_bytes,primary_ciphertext_bytes=original.ciphertext_bytes,
            operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedCounterpartyContext
                or any(type(raw) is not bytes or not raw or len(raw)>262144 for raw in
                    (source.state_bytes,source.redaction_policy_bytes,source.limited_projection_bytes,source.evidence_bytes))
                or type(source.ciphertext_bytes) is not bytes or not 1<=len(source.ciphertext_bytes)<=4194304):
            raise ValidationError('counterparty Source must authenticate bounded actual policy/content/custody facts')
        state=_parse_jcs_object(source.state_bytes);policy=_parse_jcs_object(source.redaction_policy_bytes)
        projection=_parse_jcs_object(source.limited_projection_bytes);template=hs['template']
        recipient=_policy(policy,template,hs['subject'],hs['consequence_class'],hs['lease']['issued_at'])
        expected=dict(deployment_digest=_digest(_parse_jcs_object(hb.deployment_profile_bytes),algorithm),
            profile_digest=_digest(p,algorithm),operation_digest=digest_demand_operation(op,algorithm=algorithm),
            primary_hand_back_digest=_digest(wire,algorithm),primary_ciphertext_digest=_raw_digest(original.ciphertext_bytes,algorithm),
            template_digest=_digest(template,algorithm),policy_digest=_raw_digest(source.redaction_policy_bytes,algorithm),
            checked_at=evaluated_at,zone=p['zone'],registry=p['registry'],agent_can_read=False,
            recipient_endpoint=recipient['endpoint'],recipient_key_id=recipient['key_id'],recipient_principal=recipient['principal'],
            counterparty_ciphertext_digest=_raw_digest(source.ciphertext_bytes,algorithm),
            limited_projection_digest=_raw_digest(source.limited_projection_bytes,algorithm))
        remaining={'expires_at','registration_anchor','registration_epoch','registration_revision','registration_status','primary_attestation_references'}
        if (set(state)!=set(expected)|remaining or any(state[k]!=v for k,v in expected.items())
                or state['agent_can_read'] is not False or type(state['checked_at']) is not int
                or any(not _time(state[k]) or state[k]==0 for k in ('registration_epoch','registration_revision'))
                or not _name(state['registration_anchor']) or state['registration_status']!='active'
                or not _time(state['expires_at']) or state['expires_at']<=evaluated_at
                or state['policy_digest']!=template['redaction_policy_digest']):
            raise ValidationError('counterparty context differs from current original policy/operation/ciphertext registration')
        refs=state['primary_attestation_references'];_strings(refs)
        if (set(projection)!=_LIMITED or projection['action']!=wire['action'] or projection['reason_class']!=wire['reason']
                or projection['attestation_references']!=refs):
            raise ValidationError('counterparty context must contain only original action/reason class/complete registered references')
        result=object.__new__(CounterpartyHandBackAssessment)
        for name,value in dict(valid=True,primary=original,action_permitted=False,delivery_required=True,
            recipient_endpoint=recipient['endpoint'],recipient_key_id=recipient['key_id'],recipient_principal=recipient['principal'],
            ciphertext_bytes=source.ciphertext_bytes,limited_projection_digest=state['limited_projection_digest'],
            profile_bytes=self.profile_bytes,redaction_policy_bytes=source.redaction_policy_bytes,operation_bytes=operation_bytes,
            authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,
            evaluated_at=evaluated_at,expires_at=min(original.expires_at,state['expires_at'])).items():object.__setattr__(result,name,value)
        return result
