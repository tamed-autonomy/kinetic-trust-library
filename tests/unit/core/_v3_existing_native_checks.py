"""Real signed native inputs, modeled current protected reservation Source."""
def check_native_revalidation(test,native,combined,readiness_state,boundary_state):
    import json,rfc8785
    from kinetic_trust_library.v3.existing_association import InstalledExistingAssociationVerifier,AuthenticatedExistingAssociation
    from kinetic_trust_library.v3.demand_supplier import _digest
    assoc=json.loads(combined.association.canonical_association_bytes);request=json.loads(combined.association.canonical_request_bytes)
    claims=json.loads(combined.association.proof_verification.authenticated_payload_bytes)
    p=dict(id="native-current:a",version=1,zone="zone:alpha",formula="reserved-invocation-current-use-v1",registry="registry:current",maximum_recheck_seconds=2)
    s=dict(profile_digest=_digest(p,"sha256"),registry=p["registry"],registry_epoch=1,state_revision=1,
        replay_domain=request["replay_domain"],request_id=request["request_id"],request_digest=assoc["request_digest"],proof_digest=assoc["proof_digest"],
        issuer=claims["iss"],proof_jti=assoc["proof_jti"],reservation_anchor="audit:original-reservation",accepted_at=1000,checked_at=1000,expires_at=1002,status="active")
    class Source:
        def resolve(self,**kwargs):return AuthenticatedExistingAssociation(rfc8785.dumps(s),b"modeled current protected original invocation reservation")
    rv=InstalledExistingAssociationVerifier(native.association_verifier,rfc8785.dumps(p),Source())
    def current(previous=combined,now=1000):return native.revalidate_existing(previous,reservation_verifier=rv,
        invocation_evidence=b"fixture-actual-invocation",now=now,clock_healthy=True)
    value=current();test.assertEqual(value.reason,"NATIVE_PREREQUISITES_VALID");test.assertEqual(value.association.reason,"RB_CURRENT")
    test.assertEqual(value.expires_at,1002)
    readiness_state["checked_at"]=1002
    stale=native.readiness_verifier.verify(combined.readiness.decision_bytes,combined.readiness.readiness.attestation_bytes,
        value.association,evaluated_at=1002,clock_healthy=True)
    test.assertEqual(stale.reason,"READINESS_BINDING_INVALID")
    readiness_state["checked_at"]=1000
    readiness_state["readiness_epoch"]+=1
    test.assertEqual(current().reason,"READINESS_INVALID")
    readiness_state["readiness_epoch"]-=1
    s["checked_at"]=1001;s["expires_at"]=1003;readiness_state["checked_at"]=boundary_state["checked_at"]=1001
    renewed=current(value,1001);test.assertEqual(renewed.reason,"NATIVE_PREREQUISITES_VALID")
    test.assertEqual(renewed.checked_at,1001);test.assertEqual(renewed.expires_at,1003)
    test.assertEqual(renewed.readiness.proof_verification.root_verification.checked_at,1001)
    test.assertEqual(renewed.association.compact_proof,combined.association.compact_proof)
    s["checked_at"]=1000;s["expires_at"]=1002;readiness_state["checked_at"]=boundary_state["checked_at"]=1000
    return rv,s
