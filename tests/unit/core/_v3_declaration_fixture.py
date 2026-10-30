"""Explicit test-only augmentation of older draft component declarations.

The retained proposal fixtures predate mandatory category declarations. These
labels describe the modeled BMC predicate; production never fills defaults.
"""
def declare_bmc_labels(profile):
    profile.setdefault('label_sets',{})['body.hardware.bmc_reachable']={'labels':['reachable','unreachable']}
    return profile


def rebind_valid_supplier(vectors):
    """Re-sign only the modeled valid case under the declared public test key.

    A declaration edit invalidates original evidence; retain the original file
    and all invalid-signature cases. This is never a production signer.
    """
    import base64,rfc8785
    from cryptography.hazmat.primitives.asymmetric import ec,utils
    from cryptography.hazmat.primitives import hashes
    from kinetic_trust_library.v3.demand_supplier import _digest
    case=next(c for c in vectors['cases'] if c['id']=='valid-value')
    case['payload']['declaration_digest']=_digest(vectors['deployment_profile'],'sha256')
    def encode(b):return base64.urlsafe_b64encode(b).rstrip(b'=')
    head=case['jws'].split('.')[0].encode();body=encode(rfc8785.dumps(case['payload']))
    r,s=utils.decode_dss_signature(ec.derive_private_key(10,ec.SECP256R1()).sign(head+b'.'+body,ec.ECDSA(hashes.SHA256())))
    case['jws']=(head+b'.'+body+b'.'+encode(r.to_bytes(32,'big')+s.to_bytes(32,'big'))).decode()


def complete_core_declaration(profile,operation):
    """Explicit test declaration for an installed Core operation, not defaults."""
    declare_bmc_labels(profile)
    profile['boundary']=dict(resources=[operation['resource']],entitled_subjects=['guarantor'],affected_outside=[],
        jurisdictions=['fixture jurisdiction'],authority_limits=['fixture operation only'])
    return profile


def fixture_boundary(profile,operation,now,*,zone='zone:alpha',parent_zone=None,subject_class='guarantor'):
    """Model current boundary authority separately from the declaration."""
    import rfc8785,copy
    from kinetic_trust_library.v3.boundary import InstalledBoundaryVerifier,AuthenticatedBoundaryContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    raw=rfc8785.dumps(profile);parent=None
    if parent_zone is not None:
        parent=copy.deepcopy(profile);parent['profile_id']='fixture-enclosing-deployment'
    state=dict(deployment_digest=_digest(profile,'sha256'),operation_digest=digest_demand_operation(operation,algorithm='sha256'),
        enclosing_deployment_digest=None if parent is None else _digest(parent,'sha256'),checked_at=now,expires_at=now+10,
        zone_id=zone,enclosure_zone=parent_zone,topology_epoch=5,subject=operation['actor'],subject_class=subject_class,
        resource=operation['resource'],affected_outside_classes=[],authority_within_limits=True,
        resolved_resources={operation['resource']:[operation['resource']]},
        enclosing_resolved_resources=None if parent is None else {operation['resource']:[operation['resource']]})
    class Source:
        def resolve(self,**kwargs):return AuthenticatedBoundaryContext(rfc8785.dumps(state),b'modeled current fixture boundary authority')
    return InstalledBoundaryVerifier(raw,Source(),'sha256',None if parent is None else rfc8785.dumps(parent)).evaluate(
        actual_operation=operation,evaluated_at=now,clock_healthy=True)
