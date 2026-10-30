"""Actual signed Soul veto keeps the sovereign's closed destination."""
def check_soul_stop(test,native,operation,deployment,actual_bytes,association_bytes,ordinary,key,private,decision,attestation,geometry):
    import json,rfc8785
    from dataclasses import replace
    from kinetic_trust_library.errors import ValidationError
    from kinetic_trust_library.v3.native_issuance import _segment
    from kinetic_trust_library.v3.request_binding import digest_complete_proof
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.native_stop_resolution import InstalledNativeSoulStopResolver,PreparedNativeStop
    from tests.unit.core._v3_clearance_fixture import fixture,install_management
    proof=json.loads(rfc8785.dumps(ordinary));proof["jti"]="soul-veto-current"
    proof["ktp"].update(gate_state="veto",e_base=None,e_trust=None,r=None,context=None,
        soul=dict(soul=1,constraint_type="ocap",authority="urn:authority:community-a"))
    signing=(_segment(rfc8785.dumps(dict(alg="EdDSA",kid=key["kid"],typ="ktp-trust-proof+jwt")))+"."+_segment(rfc8785.dumps(proof))).encode("ascii")
    compact=signing.decode()+"."+_segment(private.sign(signing))
    association=json.loads(association_bytes);association.update(proof_digest=digest_complete_proof(compact,algorithm="sha256"),proof_jti=proof["jti"])
    failed=native.verify(actual_bytes,rfc8785.dumps(association),compact,decision_bytes=rfc8785.dumps(decision),attestation_bytes=rfc8785.dumps(attestation),
        invocation_evidence=b"fixture-actual-invocation",now=1000,clock_healthy=True,geometry_body_bytes=rfc8785.dumps(geometry))
    test.assertEqual((failed.reason,failed.association.proof_reason),("RB_GATE","TP_VETO"))
    cf=fixture(native,failed,operation,deployment);install_management(cf,operation,deployment,failed)
    p=dict(id="native-soul-stop:a",version=1,zone="zone:alpha",formula="native-soul-return-path-v1",
        clearance_profile_digest=_digest(cf["profiles"]["clearance"],"sha256"),soul_authority_bindings={"urn:authority:community-a":"community:a"})
    calls=[]
    class Preparation:
        contest=False
        def prepare(self,**kwargs):
            calls.append(kwargs["cause_bytes"]);wire=cf["wire"];wire["reason"]="exceeded_soul"
            cf["hand_back_state"].update(reason=wire["reason"],stop_origin="sovereign",sovereign_authority="community:a")
            route=cf["template_state"]["template"]["recourse"]["system" if self.contest else "sovereign"]
            if type(route) is list:route=route[0]
            wire["recourse"]={k:route[k] for k in ("kind","ref")}
            cf["state"]["adverse_stop"]=dict(id="audit:soul-stop",kind="Exceeded",reason=wire["reason"],issued_at=wire["issued_at"],hand_back_digest=_digest(wire,"sha256"))
            cf["records"]["hand_back"]=rfc8785.dumps(wire)
            return PreparedNativeStop(kwargs["cause_bytes"],"audit:soul-stop",rfc8785.dumps(wire),b"modeled genuine sovereign Soul hand-back")
    resolver=InstalledNativeSoulStopResolver(cf["verifier"],rfc8785.dumps(p),Preparation())
    unknown=replace(resolver,profile_bytes=rfc8785.dumps(dict(p,soul_authority_bindings={"urn:authority:other":"community:a"})))
    with test.assertRaises(ValidationError):unknown.evaluate(failed,actual_operation=operation,evaluated_at=1000,clock_healthy=True)
    test.assertEqual(calls,[])
    bad=Preparation();bad.contest=True
    with test.assertRaises(ValidationError):replace(resolver,preparation_source=bad).evaluate(failed,actual_operation=operation,evaluated_at=1000,clock_healthy=True)
    cf["state"]["adverse_stop"]=None;cf["records"]["hand_back"]=None
    resolved=resolver.evaluate(failed,actual_operation=operation,evaluated_at=1000,clock_healthy=True)
    test.assertEqual(resolved.clearance.kind,"Exceeded");test.assertFalse(resolved.action_permitted)
    wire=json.loads(resolved.preparation.hand_back_bytes)
    test.assertEqual(wire["reason"],"exceeded_soul");test.assertEqual(wire["recourse"]["kind"],"closed_by_authority")
    test.assertEqual(json.loads(resolved.cause_bytes)["soul_authority"],"urn:authority:community-a")
