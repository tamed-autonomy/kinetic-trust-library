"""Measured excess is distinct from equality/unknown/zero-capacity conditions."""
def check_capacity_stop(test,native,whole,geometry,operation,deployment):
    import json,rfc8785
    from kinetic_trust_library.v3.native_stop_resolution import InstalledNativeCapacityStopResolver,PreparedNativeStop
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core._v3_clearance_fixture import fixture,install_management
    original=json.loads(rfc8785.dumps(geometry))
    try:
        for capacity,known,reason in ((30,True,"exceeded_zeroth_law"),(35,True,"exceeded_permit_condition"),(0,True,"exceeded_zeroth_law"),(0,False,"exceeded_permit_condition")):
            geometry.clear();geometry.update(json.loads(rfc8785.dumps(original)))
            geometry["capacity"].update(E=capacity,capacityKnown=known,relation="zero" if capacity==0 else "over" if capacity<35 else "within")
            geometry["result"].update(supervision="silent_veto");geometry["result"]["tightenedConstraints"]["ceilings"]=[]
            geometry["reason_codes"]=["TRUST_INSUFFICIENT"]
            geometry["gates"].update(capacity="passed" if capacity==35 else "failed",envelope="failed" if capacity==35 else "not_evaluated")
            if capacity==35:geometry["margin"]=0
            else:geometry.pop("margin",None)
            failed=whole();test.assertEqual(failed.reason,"NATIVE_EVALUATION_RESTRICTED")
            cf=fixture(native,failed,operation,deployment);install_management(cf,operation,deployment,failed)
            p=dict(id="capacity-stop:a",version=1,zone="zone:alpha",formula="native-capacity-return-path-v1",
                clearance_profile_digest=_digest(cf["profiles"]["clearance"],"sha256"))
            class Preparation:
                wrong_reason=False
                def prepare(self,**kwargs):
                    wire=cf["wire"];wire["reason"]="exceeded_permit_condition" if self.wrong_reason else json.loads(kwargs["cause_bytes"])["reason"]
                    cf["hand_back_state"].update(reason=wire["reason"],stop_origin="system")
                    cf["state"]["adverse_stop"]=dict(id="audit:capacity-stop",kind="Exceeded",reason=wire["reason"],issued_at=wire["issued_at"],hand_back_digest=_digest(wire,"sha256"))
                    cf["records"]["hand_back"]=rfc8785.dumps(wire)
                    return PreparedNativeStop(kwargs["cause_bytes"],"audit:capacity-stop",rfc8785.dumps(wire),b"modeled actual capacity stop with original return path")
            resolver=InstalledNativeCapacityStopResolver(cf["verifier"],rfc8785.dumps(p),Preparation())
            if reason=="exceeded_zeroth_law":
                from dataclasses import replace
                from kinetic_trust_library.errors import ValidationError
                bad=Preparation();bad.wrong_reason=True
                with test.assertRaises(ValidationError):replace(resolver,preparation_source=bad).evaluate(
                    failed,actual_operation=operation,evaluated_at=1000,clock_healthy=True)
                cf["state"]["adverse_stop"]=None;cf["records"]["hand_back"]=None
            result=resolver.evaluate(
                failed,actual_operation=operation,evaluated_at=1000,clock_healthy=True)
            with test.subTest(capacity=capacity,known=known):
                test.assertEqual(result.clearance.kind,"Exceeded");test.assertEqual(json.loads(result.preparation.hand_back_bytes)["reason"],reason)
                test.assertFalse(result.action_permitted)
    finally:geometry.clear();geometry.update(original)
