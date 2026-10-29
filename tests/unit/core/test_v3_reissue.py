from importlib.util import find_spec
import unittest


def fixture(operation=None,deployment=None,now=1000,zone="zone-a",lease=None):
    import rfc8785
    from tests.unit.core.test_v3_hand_back_hysteresis import profile,event
    from kinetic_trust_library.v3.installed_hysteresis import InstalledHandBackHysteresisVerifier
    from kinetic_trust_library.v3.reissue import InstalledHandBackReissueVerifier,AuthenticatedReissueContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    op=operation or dict(subject="subject:a",actor="agent:a",audience="service:a",operation="action:write",resource="resource:a",
        parameters={},request_id="request:1",replay_domain="domain:a")
    dp=deployment or dict(id="deployment:a");hp=profile();hp.update(zone=zone,version=2)
    hd=_digest(hp,"sha256")
    class PricingSource:
        def resolve(self,**kw):raise AssertionError("grant checks must not invent a newly priced stop")
    hv=InstalledHandBackHysteresisVerifier(rfc8785.dumps(dp),rfc8785.dumps(hp),PricingSource(),"sha256")
    p=dict(id="reissue:a",version=1,zone=zone,formula="historical-capped-bound-and-grant-epoch-v1",hysteresis_profile_digest=hd,relational_reissue="unsupported")
    invocation=digest_demand_operation(op,algorithm="sha256")
    if lease is None:
        lease=dict(id="lease:1",issuer="authority:a",subject=op["actor"],operation_digest=invocation,consequence_class="Coordination",
            issued_at=now-50,expires_at=now+100,kind="duration",nonce=None,consumed=False,revoked=False,
            template_digest="sha256:"+"c"*64,principal_token_digest="sha256:"+"b"*64,grant_epoch=5)
    e=event(1,op["actor"],occurred=now-80);e["adjudications"][0]["decided_at"]=now-79
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=invocation,
        subject=op["actor"],zone=zone,checked_at=now,expires_at=now+7,ledger_owner=hp["ledger_owner"],append_protocol=hp["append_protocol"],
        retained_since=now-hp["retention_seconds"],ledger_head=dict(anchor="sha256:"+"f"*64,sequence=100),current_grant_epoch=lease["grant_epoch"],
        history=[e],pricing_profiles={e["stop_anchor"]:hd},profile_registry={hd:hp},grant={})
    def refresh(sequence=40):
        state["grant"]=dict(lease_digest=_digest(lease,"sha256"),id=lease["id"],subject=lease["subject"],operation_digest=lease["operation_digest"],
            consequence_class=lease["consequence_class"],issued_at=lease["issued_at"],grant_epoch=lease["grant_epoch"],sequence=sequence,
            record_anchor="sha256:"+"d"*64)
    refresh()
    class Source:
        def resolve(self,**kw):return AuthenticatedReissueContext(rfc8785.dumps(state),b"modeled actual signed grant/audit position/protected epoch/complete ledger/historical governing policies")
    v=InstalledHandBackReissueVerifier(hv,rfc8785.dumps(p),Source())
    return v,state,lease,op,now,refresh


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class ReissueTests(unittest.TestCase):
    def evaluate(self,v,lease,op,now):
        import rfc8785
        return v.evaluate(rfc8785.dumps(lease),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def add_stop(self,v,s,op,now,index=2,offset=60):
        from tests.unit.core.test_v3_hand_back_hysteresis import event
        e=event(index,op["actor"],occurred=now-offset);e["adjudications"][0]["decided_at"]=now-offset+1
        s["history"].append(e);s["pricing_profiles"][e["stop_anchor"]]=__import__('json').loads(v.profile_bytes)["hysteresis_profile_digest"]
        return e

    def test_surviving_bounds_apply_at_issuance_not_at_current_time(self):
        v,s,lease,op,now,refresh=fixture();self.assertTrue(self.evaluate(v,lease,op,now).eligible)
        self.add_stop(v,s,op,now)
        r=self.evaluate(v,lease,op,now)
        self.assertFalse(r.eligible);self.assertEqual(r.required_reissue_not_before,960)
        lease["issued_at"]=970;refresh()
        self.assertTrue(self.evaluate(v,lease,op,now).eligible)

    def test_historical_policy_not_latest_curve_governs_old_stop(self):
        from copy import deepcopy
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,lease,op,now,_=fixture();old=deepcopy(next(iter(s["profile_registry"].values())))
        old["version"]=1;old["classes"]["Coordination"].update(minimum_seconds=50,cap_seconds=100)
        digest=_digest(old,"sha256");s["profile_registry"][digest]=old;s["pricing_profiles"][s["history"][0]["stop_anchor"]]=digest
        r=self.evaluate(v,lease,op,now)
        self.assertFalse(r.eligible);self.assertEqual(r.required_reissue_not_before,970)

    def test_old_lease_cannot_revive_after_post_grant_stop_or_epoch_change(self):
        v,s,lease,op,now,_=fixture();self.add_stop(v,s,op,now,index=5,offset=20)
        self.assertEqual(self.evaluate(v,lease,op,now).reason,"REISSUE_GRANT_PRECEDES_STOP")
        v,s,lease,op,now,_=fixture();s["current_grant_epoch"]+=1
        self.assertEqual(self.evaluate(v,lease,op,now).reason,"REISSUE_GRANT_EPOCH")

    def test_expungement_removes_wrongful_history_without_forcing_subject_delay(self):
        v,s,lease,op,now,_=fixture();self.add_stop(v,s,op,now)
        e=s["history"][0]
        e["adjudications"].append(dict(record_id="upheld:1",stop_anchor=e["stop_anchor"],sequence=60,decided_at=990,outcome="overturned"))
        r=self.evaluate(v,lease,op,now)
        self.assertTrue(r.eligible);self.assertEqual(r.required_reissue_not_before,950)
        self.assertIn(e["id"],r.expungement_required)
        # Removed adversity needs no historical pricing policy to delay nobody.
        s["pricing_profiles"].pop(e["stop_anchor"])
        self.assertTrue(self.evaluate(v,lease,op,now).eligible)

    def test_missing_policy_scope_window_or_forged_grant_fails(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["pricing_profiles"].clear(),lambda s:s.update(retained_since=999),
                       lambda s:s["grant"].update(lease_digest="sha256:"+"0"*64),lambda s:s["grant"].update(sequence=10),
                       lambda s:s.update(subject="other")):
            v,s,lease,op,now,_=fixture();change(s)
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(v,lease,op,now)

    def test_elapsed_historical_cap_proves_safety_without_repricing_missing_window(self):
        v,s,lease,op,now,_=fixture();e=s["history"][0]
        e["occurred_at"]=700;e["adjudications"][0]["decided_at"]=701
        r=self.evaluate(v,lease,op,now)
        self.assertTrue(r.eligible);self.assertIn(e["stop_anchor"],r.cap_satisfied)

    def test_zero_logistics_delay_still_requires_real_post_stop_audit_order(self):
        from copy import deepcopy
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,s,lease,op,now,refresh=fixture();e=s["history"][0]
        lease["consequence_class"]=e["consequence_class"]="Logistics"
        e["occurred_at"]=lease["issued_at"];e["adjudications"][0]["decided_at"]=lease["issued_at"]+1
        old=deepcopy(next(iter(s["profile_registry"].values())));old["version"]=1;old["classes"]["Logistics"]["minimum_seconds"]=0
        digest=_digest(old,"sha256");s["profile_registry"][digest]=old;s["pricing_profiles"][e["stop_anchor"]]=digest
        refresh();self.assertTrue(self.evaluate(v,lease,op,now).eligible)
        refresh(sequence=5)
        self.assertEqual(self.evaluate(v,lease,op,now).reason,"REISSUE_GRANT_PRECEDES_STOP")

    def test_active_historical_window_cannot_be_silently_truncated(self):
        from copy import deepcopy
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.errors import ValidationError
        v,s,lease,op,now,_=fixture();old=deepcopy(next(iter(s["profile_registry"].values())))
        old.update(version=1,window_seconds=200,retention_seconds=300)
        digest=_digest(old,"sha256");s["profile_registry"][digest]=old;s["pricing_profiles"][s["history"][0]["stop_anchor"]]=digest
        with self.assertRaisesRegex(ValidationError,"historical pricing window"):self.evaluate(v,lease,op,now)

    def test_current_revoker_accounting_validity_ends_at_window_boundary(self):
        from tests.unit.core.test_v3_hand_back_hysteresis import event
        v,s,lease,op,now,_=fixture()
        s["history"]=[event(1,"other:a","Revoked","overturned",901),event(2,"other:b","Revoked","overturned",902)]
        s["pricing_profiles"]={}
        r=self.evaluate(v,lease,op,now)
        self.assertEqual(r.revoker_accountability_required,(("person:revoker","Coordination"),))
        self.assertEqual(r.expires_at,1002)
        s["checked_at"]=1002
        self.assertEqual(self.evaluate(v,lease,op,1002).revoker_accountability_required,())
