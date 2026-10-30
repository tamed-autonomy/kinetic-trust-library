"""Compose software checks with the real signed native readiness fixture."""
def check_consumption(test,native,combined,operation,deployment):
    import hashlib,json,rfc8785
    from dataclasses import replace
    from tests.unit.core._v3_clearance_fixture import fixture,install_management,install_authority
    from tests.unit.core._v3_software_fixture import evidence_fixture
    from tests.unit.core.test_v3_software_decision_signature import fixture as signed_fixture
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.software_evidence import AuthenticatedSoftwarePrerequisite
    from kinetic_trust_library.v3.software_consumption import InstalledSoftwareConsumptionVerifier
    cf=fixture(native,combined,operation,deployment)
    install_management(cf,operation,deployment,combined);install_authority(cf,operation,deployment)
    f=evidence_fixture(operation,deployment,zone=cf["state"]["zone"])
    _,key,sp,body,sign=signed_fixture()
    sp.update(zone=cf["state"]["zone"],execution_profile_digest=f["profile"]["execution_profile_digest"],policy_digest=f["profile"]["policy_digest"])
    key.update(f["key"])
    for kind in ("lease","intent"):
        # Vendor original signed formats are authenticated by the installed
        # Source; this fixture models that boundary, not real grant signatures.
        projection=rfc8785.dumps(cf["state"][kind])
        f["prerequisites"].append(AuthenticatedSoftwarePrerequisite(kind,"source-contract-original-bytes",
            b"modeled authenticated complete original signed "+kind.encode()+b":"+projection,projection))
    p=dict(id="software-consumer:a",version=1,zone=cf["state"]["zone"],formula="native-duration-software-consumption-v1",
        clearance_profile_digest=_digest(json.loads(cf["verifier"].profile_bytes),"sha256"),
        evidence_profile_digest=_digest(f["profile"],"sha256"),signature_profile_digest=_digest(sp,"sha256"),
        prerequisite_order=["readiness","lease","intent"],original_artifact_contract="authenticated-vendor-grant-intent-v1")
    v=InstalledSoftwareConsumptionVerifier(cf["verifier"],f["v"],rfc8785.dumps(sp),rfc8785.dumps(p))
    body.update(request_binding=f["state"]["request_binding"],request_digest=_digest(f["state"]["request_binding"],"sha256"),
        proof_digest="sha256:"+hashlib.sha256(combined.association.compact_proof.encode("ascii")).hexdigest(),
        evidence_digest=_digest(f["records"],"sha256"),consumption_epoch=1,evaluated_at=1000,expires_at=1004,
        prerequisite_digests=["sha256:"+hashlib.sha256(b).hexdigest() for b in
            (combined.readiness.decision_bytes,*(a.artifact_bytes for a in f["prerequisites"]))])
    body["result"]=dict(autonomyDemand=36,environmentalCapacity=40,capacityKnown=True,
        repairPathVerified=True,supervisionAvailable=True,supervision="stable",margin=0.1,rationale=["current calibrated software assessment"],
        tightenedConstraints=dict(profile="software-substrate-execution",ceilings=[dict(magnitude=k,max=n) for k,n in f["state"]["requested_magnitudes"].items()]))
    def evaluate(previous=None):return v.evaluate(sign(),combined,actual_operation=operation,evaluated_at=1000,clock_healthy=True,previous_assessment=previous)
    good=evaluate()
    test.assertTrue(good.verified,good.reason);test.assertTrue(good.conditional_consumption,good.reason);test.assertFalse(good.action_permitted)
    test.assertEqual(good.expires_at,1001);test.assertEqual(good.native_constraints_bytes,combined.tightened_constraints_bytes)
    test.assertIsNotNone(good.commit_conditions_bytes)
    test.assertEqual(str(good.restriction_projection.margin),"0.1")
    baseline=json.loads(rfc8785.dumps(body))
    mutations=[("epoch",lambda:body.update(consumption_epoch=2)),
        ("proof",lambda:body.update(proof_digest="sha256:"+"0"*64)),
        ("prerequisites",lambda:body.update(prerequisite_digests=body["prerequisite_digests"][:-1])),
        ("workload",lambda:body["request_binding"].update(workload_id="workload:other")),
        ("demand widening",lambda:body["result"].update(autonomyDemand=34)),
        ("capacity widening",lambda:body["result"].update(environmentalCapacity=46)),
        ("ceiling widening",lambda:body["result"]["tightenedConstraints"]["ceilings"][0].update(max=1025)),
        ("late expiry",lambda:body.update(expires_at=1005)),
        ("evaluation before evidence",lambda:body.update(evaluated_at=998)),
        ("wrong margin",lambda:body["result"].update(margin=0.2))]
    for label,mutate in mutations:
        body.clear();body.update(json.loads(rfc8785.dumps(baseline)));mutate()
        with test.subTest(software=label):test.assertFalse(evaluate().conditional_consumption)
    body.clear();body.update(json.loads(rfc8785.dumps(baseline)));body["result"].pop("margin")
    test.assertTrue(evaluate().conditional_consumption)
    body.clear();body.update(json.loads(rfc8785.dumps(baseline)))
    body["result"]["tightenedConstraints"]["ceilings"][0]["max"]=512
    tightened=evaluate();test.assertTrue(tightened.verified);test.assertFalse(tightened.conditional_consumption)
    test.assertEqual(tightened.reason,"SOFTWARE_REVISED_OPERATION_REQUIRED")
    body["result"]["tightenedConstraints"]["ceilings"][0]["max"]=1024
    cf["state"]["lease"]["revoked"]=True
    test.assertFalse(evaluate().conditional_consumption)
    cf["state"]["lease"]["revoked"]=False
    f["state"]["existing_supervision"]="assisted"
    test.assertFalse(evaluate().conditional_consumption)
    f["state"]["existing_supervision"]="stable"
    original=f["prerequisites"][0]
    f["prerequisites"][0]=replace(original,projection_bytes=rfc8785.dumps(dict(cf["state"]["lease"],id="lease:substituted")))
    test.assertFalse(evaluate().conditional_consumption)
    f["prerequisites"][0]=original
    for kind in ("repair_path","supervision_availability"):
        index=next(i for i,r in enumerate(f["records"]) if r["kind"]==kind)
        f["records"][index]["value"]=False;f["refresh"]()
        body["evidence_digest"]=_digest(f["records"],"sha256")
        # A still-true signed availability assertion is not authenticated truth.
        test.assertFalse(evaluate().conditional_consumption)
        body["result"]["repairPathVerified" if kind=="repair_path" else "supervisionAvailable"]=False
        body["result"]["supervision"]="silent_veto"
        for ceiling in body["result"]["tightenedConstraints"]["ceilings"]:ceiling["max"]=0
        unavailable=evaluate();test.assertTrue(unavailable.verified,unavailable.reason);test.assertFalse(unavailable.conditional_consumption)
        f["records"][index]["value"]=True;f["refresh"]()
        body.clear();body.update(json.loads(rfc8785.dumps(baseline)))
    # Protected evidence history is carried through the full sealed result.
    f["state"]["restriction_history"]=[dict(kind="impose",anchor="hold:software",sequence=1,occurred_at=999,
        authority="authority:software-hold",cause_anchor="cause:software")]
    f["state"]["state_revision"]=2;f["refresh"]()
    held=evaluate(good);test.assertFalse(held.conditional_consumption)
    cf["state"]["lease"]["revoked"]=True
    denied=evaluate(held);test.assertFalse(denied.conditional_consumption)
    cf["state"]["lease"]["revoked"]=False
    f["state"]["restriction_history"]=[];f["state"]["state_revision"]=3;f["refresh"]()
    from kinetic_trust_library.errors import ValidationError
    with test.assertRaisesRegex(ValidationError,"erase"):evaluate(held)
    with test.assertRaisesRegex(ValidationError,"erase"):evaluate(denied)
    f["state"]["restriction_history"]=[]
    f["key"]["revoked"]=True;f["state"]["signing_keys_digest"]=_digest({f["key"]["kid"]:f["key"]},"sha256")
    test.assertFalse(evaluate().conditional_consumption)
