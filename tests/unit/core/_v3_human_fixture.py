"""Modeled approved human evidence, never real identity/qualification proof."""
def human_fixture(operation,zone="zone:alpha",level=2):
    from kinetic_trust_library.v3 import _human_reference as h
    d=lambda label:h.digest({"human_fixture":label},level)
    principal,actor=operation["subject"],operation["actor"]
    scope=dict(zone_id=zone,resource_id=operation["resource"],parameters_digest=h.digest(operation["parameters"],level),purpose_id="service-recovery")
    requirements=[dict(requirement_id=name,assessment_spec_digest=d(name),issuer_ids=["qualified-issuer"],max_age_seconds=300)
        for name in ("recovery-training","current-assignment")]
    profile=dict(profile_version="ktp-human-eligibility-profile-v1",profile_id="human-test",version=2,conformance_level=level,
        issuer_registry_digest=d("registry"),governance_authority_id="governance",review_route_id="review",retention_policy_id="retention",
        operations=[dict(operation_id=operation["operation"],scope=scope,requirements=requirements,grant_issuer_ids=["grant-authority"],allow_delegation=True)])
    request=dict(request_id=operation["request_id"],actor_id=actor,operation_id=operation["operation"],scope=scope,profile_digest=h.digest(profile,level))
    evidence=[dict(evidence_id="evidence-"+str(i),version=2,principal_id=principal,requirement_id=r["requirement_id"],
        operation_id=operation["operation"],scope=scope,assessment_spec_digest=r["assessment_spec_digest"],issuer_id="qualified-issuer",
        observed_at=900,issued_at=905,expires_at=1100,status="active",outcome="satisfied",content_digest=d(r["requirement_id"]))
        for i,r in enumerate(requirements)]
    grants=[dict(grant_id="grant-1",version=1,principal_id=principal,operation_id=operation["operation"],scope=scope,issuer_id="grant-authority",
        valid_from=850,expires_at=1200,status="active",delegation_allowed=True)]
    delegations=[] if actor==principal else [dict(delegation_id="delegation-1",version=1,principal_id=principal,delegate_id=actor,
        operation_id=operation["operation"],scope=scope,source_grant_digest=h.digest(grants[0],level),valid_from=950,expires_at=1150,status="active")]
    context=dict(principal_id=principal,actor_id=actor,actor_type="human" if actor==principal else "agent",authentication_digest=d("authenticated-session"),
        profile_id=profile["profile_id"],profile_digest=h.digest(profile,level),minimum_profile_version=2,issuer_registry_digest=profile["issuer_registry_digest"],
        state_epoch=4,checked_at=1000,status="active",active_evidence={r["evidence_id"]:h.digest(r,level) for r in evidence},
        active_grants={r["grant_id"]:h.digest(r,level) for r in grants},active_delegations={r["delegation_id"]:h.digest(r,level) for r in delegations})
    return dict(profile=profile,request=request,context=context,claims=dict(evidence=evidence,grants=grants,delegations=delegations))
