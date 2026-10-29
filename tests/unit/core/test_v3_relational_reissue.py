from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785
    from tests.unit.core.test_v3_reissue import fixture as base
    from tests.unit.core.test_v3_reconciliation_record import facts
    from dataclasses import asdict
    from kinetic_trust_library.v3.relational_reissue import InstalledRelationalReissueVerifier,AuthenticatedRelationalReissueContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    v,_,lease,op,now,_=base()
    hv=v.hysteresis_verifier
    lease.update(consequence_class="Relational",kind="single-use",nonce="nonce:1",expires_at=None)
    p=dict(id="relational:1",version=1,zone="zone-a",formula="adverse-stop-relationship-record-v1",
           hysteresis_profile_digest=_digest(__import__('json').loads(hv.profile_bytes),"sha256"),
           repair_ref="repair:registered",decline_clock_seconds=20)
    anchor="sha256:"+"a"*64
    record=dict(anchor="sha256:"+"b"*64,sequence=30,facts=asdict(facts(anchored_at=940)),repair_ref=p["repair_ref"],
                disposition="reconciled",route_started_at=None,route_completed_at=None)
    stop=dict(anchor=anchor,sequence=20,occurred_at=900,required_grant_epoch=5,
              accountable_terminator="person:root",required_parties=["person:root","person:counterparty"],record=record)
    s=dict(deployment_digest=_digest(__import__('json').loads(hv.deployment_profile_bytes),"sha256"),
           profile_digest=_digest(p,"sha256"),operation_digest=lease["operation_digest"],subject=lease["subject"],zone=p["zone"],
           checked_at=now,expires_at=now+7,ledger_owner="zone-ledger",append_protocol="serial-append-v1",
           ledger_head=dict(anchor="sha256:"+"f"*64,sequence=100),current_grant_epoch=5,
           latest_barrier={k:stop[k] for k in ("anchor","sequence","occurred_at","required_grant_epoch")},stops=[stop],
           registered_route=dict(ref=p["repair_ref"],registered_at=800,withdrawn_at=None,decline_clock_seconds=20,
                                 clock_origin="stop",record_anchor="sha256:"+"e"*64),
           nonce_state=dict(nonce=lease["nonce"],consumed=False,revoked=False),grant={})
    hp=__import__('json').loads(hv.profile_bytes)
    s.update(ledger_owner=hp["ledger_owner"],append_protocol=hp["append_protocol"])
    def refresh():
        s["grant"]=dict(lease_digest=_digest(lease,"sha256"),id=lease["id"],subject=lease["subject"],operation_digest=lease["operation_digest"],
            consequence_class=lease["consequence_class"],issued_at=lease["issued_at"],grant_epoch=lease["grant_epoch"],sequence=40,
            record_anchor="sha256:"+"d"*64)
    refresh()
    class Source:
        def resolve(self,**kw):
            return AuthenticatedRelationalReissueContext(rfc8785.dumps(s),b"modeled complete persistent relational stops/current signed records/live nonce")
    return InstalledRelationalReissueVerifier(hv,rfc8785.dumps(p),Source()),s,lease,op,now,refresh


def combined_fixture():
    import json,rfc8785
    from dataclasses import replace
    from tests.unit.core.test_v3_reissue import fixture as base
    from tests.unit.core.test_v3_hand_back_hysteresis import event
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.reissue import InstalledHandBackReissueVerifier
    rv,rs,lease,op,now,_=fixture()
    v,s,_,_,_,refresh=base(lease=lease)
    rv=replace(rv,hysteresis_verifier=v.hysteresis_verifier)
    p=json.loads(v.profile_bytes)
    p.update(relational_reissue="relationship-record-v1",relational_profile_digest=_digest(json.loads(rv.profile_bytes),"sha256"))
    s["profile_digest"]=_digest(p,"sha256")
    e=event(2,occurred=900);e.update(consequence_class="Relational",stop_anchor=rs["stops"][0]["anchor"])
    e["adjudications"][0]["stop_anchor"]=e["stop_anchor"]
    s.update(history=[e],pricing_profiles={e["stop_anchor"]:p["hysteresis_profile_digest"]})
    return InstalledHandBackReissueVerifier(v.hysteresis_verifier,rfc8785.dumps(p),v.context_source,rv),s,rs,lease,op,now,refresh


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class RelationalReissueTests(unittest.TestCase):
    def evaluate(self,v,s,lease,op,now,refresh):
        import rfc8785
        return v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_new_grant_follows_current_reconciliation_without_standing_cost(self):
        r=self.evaluate(*fixture())
        self.assertTrue(r.eligible)
        self.assertFalse(hasattr(r,"delta"))
        self.assertFalse(r.action_permitted)

    def test_repaired_later_does_not_retroactively_authorize_early_mint(self):
        args=fixture();args[1]["stops"][0]["record"]["facts"]["anchored_at"]=960
        self.assertEqual(self.evaluate(*args).reason,"RELATIONAL_GRANT_PRECEDES_REPAIR")

    def test_old_epoch_and_actual_nonce_state_override_stale_wire_flags(self):
        for change,reason in ((lambda s:s.update(current_grant_epoch=6),"RELATIONAL_GRANT_EPOCH"),
                              (lambda s:s["nonce_state"].update(consumed=True),"RELATIONAL_NONCE_CONSUMED"),
                              (lambda s:s["nonce_state"].update(revoked=True),"RELATIONAL_NONCE_REVOKED")):
            args=fixture();change(args[1])
            with self.subTest(reason=reason):self.assertEqual(self.evaluate(*args).reason,reason)

    def test_persistent_barrier_cannot_disappear_with_retained_pricing_history(self):
        from kinetic_trust_library.errors import ValidationError
        args=fixture();args[1]["stops"].clear()
        with self.assertRaises(ValidationError):self.evaluate(*args)

    def test_missing_repair_and_false_current_anchor_remain_ineligible(self):
        for change in (lambda s:s["stops"][0].update(record=None),
                       lambda s:s["stops"][0]["record"]["facts"].update(current_anchor_verified=False)):
            args=fixture();change(args[1])
            with self.subTest(change=change):self.assertEqual(self.evaluate(*args).reason,"RELATIONAL_RECONCILIATION_REQUIRED")

    def test_declined_party_waits_for_published_clock_and_remains_open(self):
        args=fixture();r=args[1]["stops"][0]["record"]
        r.update(disposition="open-to-declined",route_started_at=900,route_completed_at=925)
        r["facts"].update(declined_parties=["person:counterparty"],open_to=["person:counterparty"],route_followed=True)
        self.assertTrue(self.evaluate(*args).eligible)
        r["route_completed_at"]=919
        self.assertEqual(self.evaluate(*args).reason,"RELATIONAL_RECONCILIATION_REQUIRED")

    def test_actual_record_audit_order_is_not_replaced_by_matching_timestamp(self):
        args=fixture();args[1]["stops"][0]["record"]["sequence"]=41
        self.assertEqual(self.evaluate(*args).reason,"RELATIONAL_GRANT_PRECEDES_REPAIR")

    def test_first_grant_requires_explicit_authenticated_no_stop_state(self):
        args=fixture();args[1].update(stops=[],latest_barrier=None)
        self.assertTrue(self.evaluate(*args).eligible)

    def test_declared_route_must_be_actually_registered_before_stop_and_current(self):
        for change in (dict(registered_at=910),dict(withdrawn_at=990),dict(decline_clock_seconds=10)):
            args=fixture();args[1]["registered_route"].update(change)
            with self.subTest(change=change):
                self.assertFalse(self.evaluate(*args).eligible)

    def test_selected_gate_composes_with_historical_bounds_and_shortest_validity(self):
        import rfc8785
        v,s,rs,lease,op,now,_=combined_fixture();rs["expires_at"]=1003
        r=v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True)
        self.assertTrue(r.eligible);self.assertTrue(r.relational.eligible);self.assertEqual(r.expires_at,1003)
        rs["stops"][0]["record"]=None
        r=v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True)
        self.assertFalse(r.eligible);self.assertEqual(r.reason,"RELATIONAL_RECONCILIATION_REQUIRED")

    def test_cross_source_ledger_head_and_grant_disagreement_is_rejected(self):
        import rfc8785
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda rs:rs["ledger_head"].update(anchor="sha256:"+"0"*64),
                       lambda rs:rs["grant"].update(record_anchor="sha256:"+"0"*64),
                       lambda rs:rs.update(stops=[],latest_barrier=None)):
            v,s,rs,lease,op,now,_=combined_fixture();change(rs)
            with self.subTest(change=change),self.assertRaises(ValidationError):
                v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_expungement_does_not_discharge_relationship_reconciliation(self):
        import rfc8785
        v,s,rs,lease,op,now,_=combined_fixture()
        e=s["history"][0]
        e["adjudications"].append(dict(record_id="upheld:1",stop_anchor=e["stop_anchor"],sequence=60,decided_at=990,outcome="overturned"))
        s["pricing_profiles"].clear();rs["stops"][0]["record"]=None
        r=v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True)
        self.assertFalse(r.eligible);self.assertEqual(r.ignored_expunged,(e["stop_anchor"],))

    def test_old_barrier_survives_outside_bounded_pricing_history(self):
        import rfc8785
        v,s,rs,lease,op,now,_=combined_fixture()
        stop=rs["stops"][0];stop["occurred_at"]=100;rs["latest_barrier"]["occurred_at"]=100
        stop["record"]["facts"]["cause_at"]=100
        rs["registered_route"]["registered_at"]=50
        s.update(history=[],pricing_profiles={})
        self.assertTrue(v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True).eligible)
        stop["record"]=None
        self.assertFalse(v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True).eligible)

    def test_selection_is_symmetric_and_cannot_substitute_another_installed_ledger(self):
        import rfc8785
        from dataclasses import replace
        from kinetic_trust_library.errors import ValidationError
        v,*_=combined_fixture()
        with self.assertRaises(ValidationError):replace(v,relational_verifier=None)
        with self.assertRaises(ValidationError):replace(v,relational_verifier=replace(v.relational_verifier,hysteresis_verifier=replace(v.hysteresis_verifier)))

    def test_nonce_or_cause_substitution_is_not_a_negative_clearance(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["nonce_state"].update(nonce="other"),
                       lambda s:s["stops"][0]["record"]["facts"].update(cause_anchor="sha256:"+"c"*64),
                       lambda s:s["stops"][0]["record"]["facts"].update(required_parties=["other"]),
                       lambda s:s["stops"][0].update(required_grant_epoch=True)):
            args=fixture();change(args[1])
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(*args)
