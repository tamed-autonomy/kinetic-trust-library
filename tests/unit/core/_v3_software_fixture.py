"""Modeled authenticated current sources; not real measurements or storage."""
def evidence_fixture(operation=None,deployment=None,now=1000,zone="zone:software"):
    import json,rfc8785
    from kinetic_trust_library.v3.software_evidence import (
        InstalledSoftwareEvidenceVerifier,AuthenticatedSoftwareContext,AuthenticatedSoftwareObservation)
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from tests.unit.core.test_v3_software_decision_signature import fixture as signature_fixture
    _,key,_,_,_=signature_fixture()
    op=operation or dict(subject="subject:a",actor="agent:guarantor:7gen:optimized:a1b2c3d4",audience="service:a",operation="action:write",
        resource="resource:a",parameters={},request_id="request:a",replay_domain="domain:a")
    dp=deployment or {"profile_id":"deployment:software"}
    units={"resource_pressure":"ratio","control_latency":"milliseconds","operation_assessment":"ratio-pair",
        "repair_path":"boolean","supervision_availability":"boolean","invalidation":"status"}
    p=dict(id="software-evidence:a",version=1,zone=zone,formula="native-software-current-evidence-v1",deployment_digest=_digest(dp,"sha256"),
        execution_profile_digest="sha256:"+"a"*64,policy_digest="sha256:"+"b"*64,scale="urn:ktp:unit:action-risk-points",
        mapping_digest="sha256:"+"c"*64,assessment_profile_digest="sha256:"+"d"*64,
        authority_classes={"class:coordination":"Coordination"},sources=[dict(kind=k,source="source:"+k,unit=u,max_age_seconds=5) for k,u in units.items()],
        state_registry="registry:software-state",key_registry="registry:software-keys",restriction_authority="authority:software-hold",
        checkpoint_seconds=1,maximum_control_latency_ms=50,allow_conservative_capacity=True,envelope_thresholds=None)
    binding=dict(request_id=op["request_id"],actor_id=op["actor"],workload_id="workload:actual",authority_class="class:coordination",
        operation_id=op["operation"],resource_id=op["resource"],enforcement_destination="destination:service-tenant-route",
        parameters_digest=_digest(op["parameters"],"sha256"),identity_session_digest=_digest({"actual_session":"session:a"},"sha256"),
        execution_profile_digest=p["execution_profile_digest"],policy_digest=p["policy_digest"])
    scope=dict(request_digest=_digest(binding,"sha256"),target_revision="revision:target:a",recovery_boundary="recovery:actual")
    values={"resource_pressure":0.1,"control_latency":10,"operation_assessment":{"irreversibility":0.1,"novelty":0},
        "repair_path":True,"supervision_availability":True,"invalidation":{"status":"active","consumption_epoch":1}}
    records=[];originals=[];heads={}
    for declaration in p["sources"]:
        kind=declaration["kind"];original=rfc8785.dumps({"modeled_authenticated_source":kind,"actual_value":values[kind],"observed_at":now-1})
        import hashlib
        record=dict(kind=kind,source=declaration["source"],scope=scope,epoch=1,sequence=1,observed_at=now-1,max_age_seconds=5,
            value=values[kind],unit=declaration["unit"],evidence_digest="sha256:"+hashlib.sha256(original).hexdigest())
        records.append(record);originals.append(original)
        heads[kind]=dict(source=declaration["source"],epoch=1,sequence=1,record_digest=_digest(record,"sha256"),
            health_anchor="audit:health:"+kind,checked_at=now,health_expires_at=now+5,status="healthy")
    key.update(zone_id=zone,not_before=now-50,not_after=now+100)
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=digest_demand_operation(op,algorithm="sha256"),
        subject=op["actor"],zone=zone,checked_at=now,expires_at=now+7,request_binding=binding,
        target_revision=scope["target_revision"],recovery_boundary=scope["recovery_boundary"],mapping_digest=p["mapping_digest"],
        requested_magnitudes={"effectBytes":1024,"affectedObjects":1,"fanoutTargets":1},existing_ceilings={"effectBytes":1024,"affectedObjects":1,"fanoutTargets":1},
        consumption_epoch=1,state_revision=1,existing_supervision="stable",state_registry=p["state_registry"],key_registry=p["key_registry"],key_registry_anchor="audit:keys",
        signing_keys_digest=_digest({key["kid"]:key},"sha256"),heads=heads,restriction_history=[],
        assessment=dict(profile_digest=p["assessment_profile_digest"],basis_anchor="audit:calibrated-assessment",evaluated_at=now,
            autonomyDemand=36,environmentalCapacity=40,capacityKnown=True))
    prerequisites=[]
    def refresh():
        for i,r in enumerate(records):heads[r["kind"]]["record_digest"]=_digest(r,"sha256")
        counters={k:{n:v[n] for n in ("source","epoch","sequence","record_digest")} for k,v in heads.items()}
        state["continuity_checkpoint"]=dict(anchor="audit:protected-checkpoint",registry=p["state_registry"],epoch=state["consumption_epoch"],
            revision=state["state_revision"],counter_heads_digest=_digest(counters,"sha256"),restriction_history_digest=_digest(state["restriction_history"],"sha256"))
    refresh()
    class Source:
        def resolve(self,**kwargs):return AuthenticatedSoftwareContext(rfc8785.dumps(state),rfc8785.dumps({key["kid"]:key}),
            tuple(AuthenticatedSoftwareObservation(rfc8785.dumps(r),b) for r,b in zip(records,originals)),tuple(prerequisites),
            b"modeled actual authenticated observations/current heads/protected restore and key registry")
    verifier=InstalledSoftwareEvidenceVerifier(rfc8785.dumps(dp),rfc8785.dumps(p),Source(),"sha256")
    return dict(v=verifier,state=state,profile=p,op=op,dp=dp,now=now,records=records,originals=originals,heads=heads,key=key,
        prerequisites=prerequisites,refresh=refresh)
