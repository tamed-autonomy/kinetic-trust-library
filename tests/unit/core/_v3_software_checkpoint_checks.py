"""Continuing use never renews original evidence or ordinary acceptance."""
def check_software_checkpoint(test,consumer,f,cf,management,authority,good,sign,operation,inputs):
    import json,rfc8785
    from kinetic_trust_library.v3.software_checkpoint import InstalledSoftwareCheckpointVerifier
    from kinetic_trust_library.v3.demand_supplier import _digest
    rv,reservation,readiness,boundary=inputs
    p=dict(id="software-checkpoint:a",version=1,zone="zone:alpha",formula="native-software-checkpoint-v1",
        consumer_profile_digest=_digest(json.loads(consumer.profile_bytes),"sha256"),reservation_profile_digest=_digest(json.loads(rv.profile_bytes),"sha256"))
    verifier=InstalledSoftwareCheckpointVerifier(consumer,rv,rfc8785.dumps(p))
    states=(reservation,readiness,boundary,cf["state"],cf["template_state"],management,authority["s"],f["state"])
    def advance(now):
        for state in states:state["checked_at"]=now
        reservation["expires_at"]=now+2
        for head in f["heads"].values():head["checked_at"]=now
        f["state"]["assessment"]["evaluated_at"]=now
    raw=sign()
    try:
        advance(1001)
        current=verifier.evaluate(raw,good,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1001,clock_healthy=True)
        test.assertTrue(current.conditional_consumption,current.consumption.reason)
        test.assertEqual(current.consumption.decision_bytes,raw)
        test.assertEqual(current.consumption.evidence.observations_bytes,good.evidence.observations_bytes)
        test.assertEqual(current.native_result.association.reason,"RB_CURRENT");test.assertEqual(current.expires_at,1002)
        test.assertFalse(current.action_permitted)
        frame=json.loads(current.commit_conditions_bytes)
        test.assertEqual(frame["checkpoint_profile_digest"],_digest(p,"sha256"))
        test.assertEqual(frame["current_reservation"]["reservation_anchor"],"audit:original-reservation")
        readiness["readiness_epoch"]+=1
        denied=verifier.evaluate(raw,current,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1001,clock_healthy=True)
        test.assertFalse(denied.conditional_consumption)
        test.assertIs(denied.consumption.native_checkpoint,current.native_result)
        test.assertIs(denied.consumption.evidence,current.consumption.evidence)
        readiness["readiness_epoch"]-=1
        recovered=verifier.evaluate(raw,denied,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1001,clock_healthy=True)
        test.assertTrue(recovered.conditional_consumption,recovered.consumption.reason)
        from dataclasses import replace
        from kinetic_trust_library.errors import ValidationError
        other=replace(verifier,profile_bytes=rfc8785.dumps(dict(p,id="checkpoint:other")))
        with test.assertRaises(ValidationError):other.evaluate(raw,current,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1001,clock_healthy=True)
        advance(1004)
        stale=verifier.evaluate(raw,current,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1004,clock_healthy=True)
        test.assertFalse(stale.conditional_consumption)
        test.assertEqual(stale.consumption.reason,"SOFTWARE_OBSERVATION_UNAVAILABLE")
    finally:advance(1000)
