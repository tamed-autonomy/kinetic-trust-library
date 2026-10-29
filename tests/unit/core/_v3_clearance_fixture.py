"""Modeled current managed relation around an actual signed native result."""
def fixture(native_verifier,native_result,operation,deployment,now=1000):
    import json,rfc8785
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from kinetic_trust_library.v3.non_clearance import InstalledNonClearanceVerifier,AuthenticatedNonClearanceContext
    from kinetic_trust_library.v3.clearance import InstalledClearanceVerifier,AuthenticatedClearanceContext
    from tests.unit.core.test_v3_hand_back_template import fixture as template_fixture
    zone=native_verifier.readiness_verifier.readiness_verifier.receiving_zone
    tv,ts,hs,wire,_,_,_=template_fixture(operation,deployment,now,zone)
    hb=tv.hand_back_verifier
    np=dict(id="urn:test:non-clearance",version=1,zone=zone,formula="authoritative-non-clearance-v1",
        hand_back_profile_digest=_digest(json.loads(hb.profile_bytes),"sha256"),lease_authority="authority:lease",
        principal_token_max_age_seconds=100,reissue_path="admission:reissue")
    p=dict(id="urn:test:clearance",version=1,zone=zone,formula="native-template-lease-clearance-v1",
        non_clearance_profile_digest=_digest(np,"sha256"),relational_clear="unsupported")
    invocation=digest_demand_operation(operation,algorithm="sha256")
    intent=dict(actor=operation["actor"],operation_digest=invocation,consequence_class="Coordination",principal=hs["delegator"],
        issued_at=now-60,expires_at=now,record_digest="sha256:"+"a"*64)
    lease=dict(id=hs["lease"]["id"],issuer=np["lease_authority"],subject=operation["actor"],operation_digest=invocation,
        consequence_class="Coordination",issued_at=hs["lease"]["issued_at"],expires_at=now+100,kind="duration",nonce=None,
        consumed=False,revoked=False,template_digest=hs["lease"]["template_digest"],principal_token_digest=intent["record_digest"],grant_epoch=5)
    state=dict(deployment_digest=_digest(deployment,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=invocation,
        subject=operation["actor"],zone=zone,managed_relation_id="managed:relation:1",checked_at=now,expires_at=now+7,
        principal=hs["delegator"],consequence_class="Coordination",mutates_relation=False,current_grant_epoch=5,
        template_digest=lease["template_digest"],lease=lease,intent=intent,adverse_stop=None,
        native_geometry_digest=None if native_result.canonical_geometry_bytes is None else _digest(json.loads(native_result.canonical_geometry_bytes),"sha256"))
    records=dict(hand_back=None)
    class StopSource:
        def resolve(self,**kw):
            s={k:v for k,v in state.items() if k!="native_geometry_digest"};s["profile_digest"]=_digest(np,"sha256")
            return AuthenticatedNonClearanceContext(rfc8785.dumps(s),b"modeled authoritative current relation/grant/stop registry")
    non_clear=InstalledNonClearanceVerifier(hb,rfc8785.dumps(np),StopSource())
    class Source:
        def resolve(self,**kw):return AuthenticatedClearanceContext(rfc8785.dumps(state),records["hand_back"],b"modeled authoritative current relation/grant/intent/stop registry")
    verifier=InstalledClearanceVerifier(native_verifier,tv,non_clear,rfc8785.dumps(p),Source())
    return dict(verifier=verifier,state=state,template_state=ts,hand_back_state=hs,wire=wire,records=records)
