"""Typed return paths for authenticated current software permit-condition loss."""
def check_software_stop(test,consumer,cf,failed,operation,reservation):
    import json,rfc8785
    from kinetic_trust_library.v3.software_checkpoint import InstalledSoftwareCheckpointVerifier
    from kinetic_trust_library.v3.software_stop_resolution import InstalledSoftwareStopResolver,PreparedSoftwareStop
    from kinetic_trust_library.v3.demand_supplier import _digest
    algorithm=consumer.evidence_verifier.algorithm
    p=dict(id="software-stop-checkpoint:a",version=1,zone="zone:alpha",formula="native-software-checkpoint-v1",
        consumer_profile_digest=_digest(json.loads(consumer.profile_bytes),algorithm),reservation_profile_digest=_digest(json.loads(reservation.profile_bytes),algorithm))
    checkpoint=InstalledSoftwareCheckpointVerifier(consumer,reservation,rfc8785.dumps(p))
    sp=dict(id="software-stop:a",version=1,zone="zone:alpha",formula="software-permit-condition-return-path-v1",
        checkpoint_profile_digest=_digest(p,algorithm))
    def digest(value):return _digest(value,algorithm)
    class Preparation:
        def prepare(self,**kwargs):
            wire=cf["wire"];wire["reason"]="exceeded_permit_condition"
            cf["hand_back_state"].update(reason=wire["reason"],stop_origin="system")
            cf["state"]["adverse_stop"]=dict(id="audit:software-stop",kind="Exceeded",reason=wire["reason"],issued_at=wire["issued_at"],hand_back_digest=digest(wire))
            cf["records"]["hand_back"]=rfc8785.dumps(wire)
            return PreparedSoftwareStop(kwargs["cause_bytes"],"audit:software-stop",rfc8785.dumps(wire),b"modeled actual sealed software failure and durable stop")
    resolver=InstalledSoftwareStopResolver(checkpoint,rfc8785.dumps(sp),Preparation())
    from dataclasses import replace
    from kinetic_trust_library.errors import ValidationError
    class AckOnly:
        def prepare(self,**kwargs):return PreparedSoftwareStop(kwargs["cause_bytes"],"audit:unregistered-stop",rfc8785.dumps(cf["wire"]),b"ack without registry append")
    with test.assertRaises(ValidationError):replace(resolver,preparation_source=AckOnly()).evaluate(
        failed,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1000,clock_healthy=True)
    class WrongCause:
        def prepare(self,**kwargs):return PreparedSoftwareStop(b"different cause","audit:wrong-cause",rfc8785.dumps(cf["wire"]),b"wrong cause")
    with test.assertRaises(ValidationError):replace(resolver,preparation_source=WrongCause()).evaluate(
        failed,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1000,clock_healthy=True)
    class Revokes(Preparation):
        def prepare(self,**kwargs):
            result=super().prepare(**kwargs);cf["state"]["lease"]["revoked"]=True;return result
    try:
        with test.assertRaises(ValidationError):replace(resolver,preparation_source=Revokes()).evaluate(
            failed,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1000,clock_healthy=True)
    finally:
        cf["state"]["lease"]["revoked"]=False;cf["state"]["adverse_stop"]=None;cf["records"]["hand_back"]=None
    resolved=resolver.evaluate(failed,actual_operation=operation,invocation_evidence=b"fixture-actual-invocation",evaluated_at=1000,clock_healthy=True)
    test.assertEqual(resolved.clearance.kind,"Exceeded");test.assertFalse(resolved.action_permitted)
    test.assertEqual(json.loads(resolved.cause_bytes)["reason"],"exceeded_permit_condition")
    test.assertEqual(json.loads(resolved.preparation.hand_back_bytes)["recourse"],
        {k:cf["template_state"]["template"]["recourse"]["system"][k] for k in ("kind","ref")})
    cf["state"]["adverse_stop"]=None;cf["records"]["hand_back"]=None
