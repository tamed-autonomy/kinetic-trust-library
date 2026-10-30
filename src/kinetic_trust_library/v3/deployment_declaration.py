"""Offline validation of the installed, provisional native deployment.

Shape and catalog joins establish a legal declaration, not its approval or the
truth of measurements. Source adapters still authenticate class-specific
measurement envelopes, category/predicate mappings and normalization execution.
No catalog ID, method or authority is fetched from a candidate URL.
"""
from fractions import Fraction
from functools import lru_cache
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .schema_formats import installed_format_checker


@lru_cache(maxsize=1)
def _resources():
    from jsonschema import Draft202012Validator
    root=files('kinetic_trust_library.v3')
    schema=json.loads(root.joinpath('schemas/deployment-profile-v3.json').read_text())
    Draft202012Validator.check_schema(schema)
    validator=Draft202012Validator(schema,format_checker=installed_format_checker())
    signals={}
    for domain in ('world','information','time','soul','relational','body','meta'):
        doc=json.loads(root.joinpath('catalog/'+domain+'.json').read_text())
        for group in doc['groups']:
            for row in group['signals']:
                signals[row['id']]=(row.get('zero_one'),row['type'])
    index=json.loads(root.joinpath('catalog/index.json').read_text())
    aliases={a['set']:frozenset(a.get('canonical',[])+a.get('aliases',[])+a.get('members',[])) for a in index['alias_sets']}
    labels=json.loads(root.joinpath('catalog/label-requirements.json').read_text())
    required=frozenset(labels['entropy']+labels['predicates'])
    return validator,signals,aliases,required


def _catalog_checks(profile):
    """Check catalog joins after schema validation of declaration sections."""
    _,signals,sets,required=_resources()
    factors=profile['risk_factors']
    aggregated={s for f in factors.values() for s in f['signals']}
    populated=aggregated|{s for f in profile.get('feeds',{}).values() for s in f['populates']}
    declared=populated|set(profile.get('normalization',{}))|set(profile.get('label_sets',{}))
    if declared-set(signals):raise ValidationError('deployment signal is not in the installed native catalog')
    aliases=profile.get('aliases',{})
    if set(aliases)-set(sets):raise ValidationError('deployment alias set is not in the installed catalog')
    for name,selected in aliases.items():
        if selected not in sets[name]:raise ValidationError('deployment alias selection is not a member of its set')
    for name,members in sets.items():
        used=populated&members
        if used and (len(used)!=1 or aliases.get(name) not in used):
            raise ValidationError('deployment alias selection must identify its single populated member')
        if any(len(set(f['signals'])&members)>1 for f in factors.values()):
            raise ValidationError('deployment factor aggregates multiple alias members')
    for signal in aggregated:
        zero_one,kind=signals[signal]
        if zero_one=='synthetic' and signal not in profile.get('normalization',{}):
            raise ValidationError('aggregated synthetic signal requires normalization')
        if (kind in ('enum','bool') or signal in required) and signal not in profile.get('label_sets',{}):
            raise ValidationError('aggregated categorical signal requires a label set')


def required_label_signals(profile):
    """Known pinned dependencies; the authenticated Source may add more."""
    _,signals,_,required=_resources()
    return frozenset(s for f in profile['risk_factors'].values() for s in f['signals']
                     if signals[s][1] in ('enum','bool') or s in required)


def validate_environment_declaration(profile):
    """Validate the environmental component without asserting full installation.

    Other components can inspect a sparse declaration, but the production
    native evaluator requires validate_deployment_declaration as well.
    """
    validator,_,_,_=_resources()
    schema=validator.schema
    from jsonschema import Draft202012Validator
    for name in ('risk_factors','feeds','normalization','label_sets','aliases'):
        if name not in profile:
            if name=='risk_factors':raise ValidationError('five declared Risk Factors are required')
            continue
        component={'$defs':schema['$defs'],**schema['properties'][name]}
        if not Draft202012Validator(component).is_valid(profile[name]):
            raise ValidationError('invalid deployment '+name+' declaration')
    weights=[f['weight'] for f in profile['risk_factors'].values()]
    if sum((Fraction(str(w)) for w in weights),Fraction(0))!=1:
        raise ValidationError('deployment Risk Factor weights must sum exactly to one')
    _catalog_checks(profile)


def validate_deployment_declaration(raw):
    """Return a fresh complete validated declaration; never authorize install."""
    if type(raw) is not bytes:raise ValidationError('installed deployment must be immutable JCS bytes')
    profile=_parse_jcs_object(raw)
    validator,_,_,_=_resources()
    if not validator.is_valid(profile):raise ValidationError('invalid complete native deployment declaration')
    # JSON Schema considers integral floats integers. Installed version and hop
    # controls are integer values, never booleans or floating representations.
    controls=[profile['version'],profile['external_root']['hop_bound'],profile['standing_policy']['version']]
    if 'human_policy' in profile:controls.append(profile['human_policy']['version'])
    if 'emergency_policy' in profile:controls.append(profile['emergency_policy']['version'])
    if any(type(v) is not int or not 1<=v<=2**53-1 for v in controls):
        raise ValidationError('deployment integer controls must be positive safe integers')
    validate_environment_declaration(profile)
    thresholds=profile.get('envelope_thresholds')
    if thresholds is not None and not thresholds['m_veto']<thresholds['m_allow']:
        raise ValidationError('deployment thresholds require m_veto < m_allow')
    if 'oracle_consensus' in profile:
        c=profile['oracle_consensus'];n=len(c['members']);f=c['fault_tolerance'];q=c['quorum']
        if (any(type(v) is not int for v in (c['membership_epoch'],f,q)) or n<3*f+1 or not (n+f)//2+1<=q<=n-f
                or any(len({m[k] for m in c['members']})!=n for k in ('node_id','key_id','control_domain'))):
            raise ValidationError('invalid deployment consensus roster or quorum')
    # Reuse existing boundary semantics for duplicate identifiers/review routes.
    from .boundary import _boundary
    _boundary(raw)
    return profile
