"""Modeled current managed relation around an actual signed native result."""
def install_authority(cf,operation,deployment,now=1000):
    import rfc8785,json
    from dataclasses import replace
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core.test_v3_installed_authority_separation import fixture as authority_fixture
    old=cf["verifier"]
    f=authority_fixture(operation,deployment,cf["state"]["zone"],cf["state"]["native_geometry_digest"],
        cf["profiles"]["non_clearance"]["lease_authority"],now)
    p=cf["profiles"]["clearance"];p["authority_profile_digest"]=_digest(json.loads(f["v"].profile_bytes),"sha256")
    cf["state"]["profile_digest"]=_digest(p,"sha256")
    cf["verifier"]=replace(old,profile_bytes=rfc8785.dumps(p),authority_verifier=f["v"])
    return f


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
    state["formation"]=dict(subject=operation["actor"],relation_id=state["managed_relation_id"],
        consequence_class="Coordination",template_digest=lease["template_digest"],counterparty="person:counterparty",
        registered_at=ts["template"]["registered_at"],formed_at=now-70,countersigned_at=now-70,
        witness_anchor="audit:formation",countersignature_anchor="audit:signature",objection_at=None)
    records=dict(hand_back=None)
    class StopSource:
        def resolve(self,**kw):
            s={k:v for k,v in state.items() if k not in ("native_geometry_digest","formation")};s["profile_digest"]=_digest(np,"sha256")
            return AuthenticatedNonClearanceContext(rfc8785.dumps(s),b"modeled authoritative current relation/grant/stop registry")
    non_clear=InstalledNonClearanceVerifier(hb,rfc8785.dumps(np),StopSource())
    class Source:
        def resolve(self,**kw):return AuthenticatedClearanceContext(rfc8785.dumps(state),records["hand_back"],b"modeled authoritative current relation/grant/intent/stop registry")
    verifier=InstalledClearanceVerifier(native_verifier,tv,non_clear,rfc8785.dumps(p),Source())
    return dict(verifier=verifier,state=state,template_state=ts,hand_back_state=hs,wire=wire,records=records,profiles=dict(non_clearance=np,clearance=p))


def install_reissue(cf,operation,deployment,now=1000):
    import rfc8785,json
    from dataclasses import replace
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core.test_v3_reissue import fixture as reissue_fixture
    old=cf["verifier"]
    rv,rs,lease,_,_,refresh=reissue_fixture(operation,deployment,now,
        old.native_verifier.readiness_verifier.readiness_verifier.receiving_zone,cf["state"]["lease"])
    hp=json.loads(old.template_verifier.hand_back_verifier.profile_bytes)
    hp["hysteresis_profile_digest"]=_digest(json.loads(rv.hysteresis_verifier.profile_bytes),"sha256")
    hb=replace(old.template_verifier.hand_back_verifier,profile_bytes=rfc8785.dumps(hp),hysteresis_verifier=rv.hysteresis_verifier)
    cf["hand_back_state"].update(profile_digest=_digest(hp,"sha256"),stop_anchor="sha256:"+"e"*64)
    cf["template_state"]["profile_digest"]=_digest(hp,"sha256")
    np=cf["profiles"]["non_clearance"];np["hand_back_profile_digest"]=_digest(hp,"sha256")
    nc=replace(old.non_clearance_verifier,hand_back_verifier=hb,profile_bytes=rfc8785.dumps(np))
    cp=cf["profiles"]["clearance"];cp.update(non_clearance_profile_digest=_digest(np,"sha256"),reissue_profile_digest=_digest(json.loads(rv.profile_bytes),"sha256"))
    cf["state"]["profile_digest"]=_digest(cp,"sha256")
    cf["verifier"]=replace(old,template_verifier=replace(old.template_verifier,hand_back_verifier=hb),
        non_clearance_verifier=nc,profile_bytes=rfc8785.dumps(cp),reissue_verifier=rv)
    return rv,rs,refresh


def install_relational(cf,operation,deployment,repair_ref_override=None,production_review=False):
    import json,rfc8785
    from dataclasses import replace
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core.test_v3_relational_decision import fixture as decision_fixture
    from tests.unit.core.test_v3_relational_commit import fixture as commit_fixture
    from tests.unit.core.test_v3_hand_back_hysteresis import event
    s=cf["state"];t=cf["template_state"]["template"]
    s.update(consequence_class="Relational",mutates_relation=True)
    t["consequence_class"]="Relational"
    cf["template_state"]["consequence_class"]=cf["hand_back_state"]["consequence_class"]="Relational"
    s["intent"]["consequence_class"]="Relational"
    s["lease"].update(consequence_class="Relational",kind="single-use",nonce="nonce:one-step",expires_at=None,template_digest=_digest(t,"sha256"))
    s["template_digest"]=cf["hand_back_state"]["lease"]["template_digest"]=s["lease"]["template_digest"]
    s["formation"].update(consequence_class="Relational",template_digest=s["template_digest"])
    old,history,refresh=install_reissue(cf,operation,deployment)
    zone=json.loads(old.profile_bytes)["zone"]
    f=decision_fixture(operation,deployment,zone,s["lease"],old.hysteresis_verifier,repair_ref_override or t["repair"]["ref"])
    refresh()
    f["s"]["evidence_digest"]=f["s"]["decision"]["evidence_digest"]=s["native_geometry_digest"]
    f["f"]["state"]["evidence_digest"]=f["f"]["payload"]["evidence_digest"]=s["native_geometry_digest"]
    f["refresh"]()
    review_state=None
    if production_review:
        from tests.unit.core.test_v3_relational_decision import install_review
        _,review_state=install_review(f)
    c=commit_fixture(f)
    if review_state is not None:
        from tests.unit.core.test_v3_relational_commit import install_commit_review
        install_commit_review(c,review_state);c["review_state"]=review_state
    rp=json.loads(old.profile_bytes)
    rp.update(relational_reissue="relationship-record-v1",relational_profile_digest=_digest(json.loads(f["v"].relational_verifier.profile_bytes),"sha256"))
    history["profile_digest"]=_digest(rp,"sha256")
    stop=f["rs"]["stops"][0]
    e=event(2,operation["actor"],occurred=stop["occurred_at"])
    e.update(stop_anchor=stop["anchor"],consequence_class="Relational")
    e["adjudications"][0]["stop_anchor"]=stop["anchor"]
    history.update(history=[e],pricing_profiles={stop["anchor"]:rp["hysteresis_profile_digest"]})
    rv=replace(old,profile_bytes=rfc8785.dumps(rp),relational_verifier=f["v"].relational_verifier)
    cp=cf["profiles"]["clearance"]
    cp.update(relational_clear="conditional-single-use-v1",reissue_profile_digest=_digest(rp,"sha256"),
              relational_commit_profile_digest=_digest(c["p"],"sha256"))
    s["profile_digest"]=_digest(cp,"sha256")
    cf["verifier"]=replace(cf["verifier"],profile_bytes=rfc8785.dumps(cp),reissue_verifier=rv,relational_commit_verifier=c["v"])
    return c,history
