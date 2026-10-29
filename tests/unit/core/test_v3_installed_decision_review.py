from importlib.util import find_spec
import unittest


def fixture(operation=None,deployment=None,zone="zone-a"):
    import rfc8785
    from tests.unit.core.test_v3_decision_review import profile,event
    from kinetic_trust_library.v3.installed_decision_review import InstalledDecisionReviewVerifier,AuthenticatedDecisionReviewContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from tests.unit.core.test_v3_reissue import fixture as base
    _,_,_,op,now,_=base(operation,deployment,zone=zone);p=profile();p["zone"]=zone
    dp=dict(id="deployment:review") if deployment is None else deployment
    e=event(actor=op["actor"])
    s=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=digest_demand_operation(op,algorithm="sha256"),
        decided_by="person:decider",zone=p["zone"],checked_at=now,expires_at=now+8,ledger_owner=p["ledger_owner"],append_protocol=p["append_protocol"],
        coverage_start=900,coverage_end=now,ledger_head=dict(anchor="sha256:"+"f"*64,sequence=100),history=[e],
        governing_profiles={e["anchor"]:_digest(p,"sha256")},open_obligations=[],findings=[],open_findings=[],state_revision=17,
        profile_registry={_digest(p,"sha256"):p},registries={})
    s["registries"][s["profile_digest"]]=dict(
        sampler=dict(id=p["sampler_id"],owner="org:auditor",protocol="audited-uniform-draw-v1",space=2,registered_at=800,withdrawn_at=None,
                     anchor="sha256:"+"d"*64,independent_of=["person:decider",op["actor"]]),
        reviewer=dict(id=p["review_authority"],registered_at=800,withdrawn_at=None,anchor="sha256:"+"e"*64))
    class Source:
        def resolve(self,**kw):return AuthenticatedDecisionReviewContext(rfc8785.dumps(s),b"modeled complete production/first-draw/outcome/review ledger and durable open backlog")
    return InstalledDecisionReviewVerifier(rfc8785.dumps(dp),rfc8785.dumps(p),Source()),s,op,now


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class InstalledDecisionReviewTests(unittest.TestCase):
    def evaluate(self,args):
        v,s,op,now=args
        return v.evaluate(decided_by=s["decided_by"],actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_actual_current_inventory_and_independent_sampler_are_bound(self):
        r=self.evaluate(fixture());self.assertTrue(r.review_current);self.assertFalse(r.action_permitted)

    def test_missing_coverage_scope_or_real_governing_profile_rejected(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s.update(coverage_start=901),lambda s:s.update(zone="another-zone"),
                       lambda s:s["governing_profiles"].clear(),lambda s:s["registries"][s["profile_digest"]]["sampler"].update(owner="person:decider")):
            args=fixture();change(args[1])
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(args)

    def test_pending_review_clips_validity_and_durable_backlog_must_match(self):
        from kinetic_trust_library.errors import ValidationError
        args=fixture();e=args[1]["history"][0];e["sample"]["drawn_at"]=995;e["reviews"]=[]
        with self.assertRaises(ValidationError):self.evaluate(args)
        args[1]["open_obligations"]=[e["sample"]["anchor"]]
        self.assertEqual(self.evaluate(args).expires_at,1005)

    def test_full_gate_is_not_claimed_by_a_standalone_monitor(self):
        r=self.evaluate(fixture());self.assertFalse(hasattr(r,"conditional_clear"));self.assertFalse(hasattr(r,"gate_satisfied"))

    def test_older_backlog_and_historical_policy_cannot_be_silently_dropped(self):
        from kinetic_trust_library.errors import ValidationError
        args=fixture();e=args[1]["history"][0]
        e.update(decided_at=800,acknowledged_at=798,reviewed_at=799,reviews=[])
        e["sample"]["drawn_at"]=801
        args[1]["open_obligations"]=[e["sample"]["anchor"]]
        self.assertFalse(self.evaluate(args).review_current)
        args[1]["history"].clear();args[1]["governing_profiles"].clear()
        with self.assertRaises(ValidationError):self.evaluate(args)
        args=fixture();e=args[1]["history"][0];args[1]["governing_profiles"][e["anchor"]]="sha256:"+"0"*64
        with self.assertRaises(ValidationError):self.evaluate(args)

    def test_operational_source_failure_is_not_empty_history(self):
        from dataclasses import replace
        args=list(fixture())
        class Source:
            def resolve(self,**kw):raise RuntimeError("review ledger unavailable")
        args[0]=replace(args[0],context_source=Source())
        with self.assertRaisesRegex(RuntimeError,"ledger unavailable"):self.evaluate(args)

    def test_actual_historical_profiles_preserve_rate_and_deadline_after_change(self):
        from copy import deepcopy
        from kinetic_trust_library.v3.demand_supplier import _digest
        args=fixture();s=args[1];old=deepcopy(s["profile_registry"][s["profile_digest"]])
        old.update(version=2,review_sla_seconds=30);old["sampling_rate"]=dict(numerator=2,denominator=2)
        digest=_digest(old,"sha256");s["profile_registry"][digest]=old
        s["registries"][digest]=deepcopy(s["registries"][s["profile_digest"]])
        e=s["history"][0];s["governing_profiles"][e["anchor"]]=digest
        e["sample"].update(draw=1,drawn_at=980);e["reviews"]=[];s["open_obligations"]=[e["sample"]["anchor"]]
        r=self.evaluate(args);self.assertTrue(r.review_current);self.assertEqual(r.projection.pending_reviews[0][2],1010)
        self.assertEqual(r.projection.sampled_decisions,(e["anchor"],))

    def test_retired_historical_sampler_does_not_revoke_a_draw_valid_at_its_time(self):
        from copy import deepcopy
        from kinetic_trust_library.v3.demand_supplier import _digest
        args=fixture();s=args[1];old=deepcopy(s["profile_registry"][s["profile_digest"]]);old.update(version=2,sampler_id="sampler:retired")
        digest=_digest(old,"sha256");s["profile_registry"][digest]=old
        s["registries"][digest]=deepcopy(s["registries"][s["profile_digest"]])
        historical=s["registries"][digest]["sampler"];historical.update(id=old["sampler_id"],withdrawn_at=980)
        e=s["history"][0];e["sample"]["sampler_id"]=old["sampler_id"];s["governing_profiles"][e["anchor"]]=digest
        self.assertTrue(self.evaluate(args).review_current)
        historical["withdrawn_at"]=940
        from kinetic_trust_library.errors import ValidationError
        with self.assertRaises(ValidationError):self.evaluate(args)

    def test_missing_or_replaced_historical_body_or_role_registry_is_rejected(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["profile_registry"].clear(),lambda s:s["registries"].clear(),
                       lambda s:s["profile_registry"][s["profile_digest"]].update(review_sla_seconds=999)):
            args=fixture();change(args[1])
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(args)

    def historical_finding(self):
        import rfc8785
        from copy import deepcopy
        from dataclasses import replace
        from kinetic_trust_library.v3.demand_supplier import _digest
        from tests.unit.core.test_v3_decision_review import event
        args=list(fixture());s=args[1];old_digest=s["profile_digest"]
        current=deepcopy(s["profile_registry"][old_digest]);current.update(version=2,window_seconds=20,uniform_approval_threshold=3)
        digest=_digest(current,"sha256");s["profile_registry"][digest]=current;s["profile_digest"]=digest
        s["registries"][digest]=deepcopy(s["registries"][old_digest])
        args[0]=replace(args[0],profile_bytes=rfc8785.dumps(current))
        a=event(same_time=True);b=event(2,same_time=True)
        s.update(history=[a,b],governing_profiles={a["anchor"]:old_digest,b["anchor"]:old_digest},coverage_start=800)
        finding=dict(anchor="sha256:"+"a"*64,sequence=80,decided_by=s["decided_by"],profile_digest=old_digest,found_at=980,
            kind="uniform-approval",basis_decisions=[a["anchor"],b["anchor"]],resolution=None)
        s["findings"]=[finding];s["open_findings"]=[finding["anchor"]]
        return args,finding

    def test_old_unresolved_finding_survives_new_threshold_and_population_window(self):
        args,finding=self.historical_finding();r=self.evaluate(args)
        self.assertFalse(r.projection.rubber_stamp_finding);self.assertFalse(r.review_current)
        self.assertEqual(r.active_findings,(finding["anchor"],))
        finding["resolution"]=dict(anchor="sha256:"+"b"*64,sequence=90,resolved_at=995,authority="person:reviewer",disposition="resolved",profile_digest=args[1]["profile_digest"])
        args[1]["open_findings"]=[]
        r=self.evaluate(args);self.assertTrue(r.review_current);self.assertEqual(r.closed_findings,(finding["anchor"],))

    def test_finding_requires_its_actual_complete_historical_basis(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s,f:f["basis_decisions"].pop(),lambda s,f:s.update(coverage_start=900),
                       lambda s,f:f.update(found_at=950),lambda s,f:f.update(profile_digest="sha256:"+"0"*64)):
            args,finding=self.historical_finding();change(args[1],finding)
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(args)

    def test_finding_resolution_needs_actual_forward_authority_and_audit_order(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (dict(authority="person:decider"),dict(sequence=70),dict(resolved_at=970)):
            args,finding=self.historical_finding()
            finding["resolution"]=dict(anchor="sha256:"+"b"*64,sequence=90,resolved_at=995,authority="person:reviewer",disposition="resolved",profile_digest=args[1]["profile_digest"])
            finding["resolution"].update(change)
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(args)

    def test_dropping_a_finding_cannot_erase_the_authenticated_open_marker(self):
        from kinetic_trust_library.errors import ValidationError
        args,_=self.historical_finding();args[1]["findings"]=[]
        with self.assertRaises(ValidationError):self.evaluate(args)

    def test_exact_resolved_pattern_is_not_reopened_without_new_evidence(self):
        import rfc8785
        from dataclasses import replace
        args,finding=self.historical_finding();s=args[1]
        old=finding["profile_digest"];s["profile_digest"]=old
        args[0]=replace(args[0],profile_bytes=rfc8785.dumps(s["profile_registry"][old]))
        finding["resolution"]=dict(anchor="sha256:"+"b"*64,sequence=90,resolved_at=995,authority="person:reviewer",disposition="resolved",profile_digest=args[1]["profile_digest"])
        s["open_findings"]=[]
        r=self.evaluate(args);self.assertTrue(r.projection.rubber_stamp_finding);self.assertTrue(r.review_current)
        self.assertFalse(r.finding_record_required)
        from tests.unit.core.test_v3_decision_review import event
        e=event(3,same_time=True);e.update(sequence=84,decided_at=990,acknowledged_at=988,reviewed_at=988)
        e["sample"].update(sequence=85,drawn_at=991);e["reviews"][0].update(sequence=86,completed_at=992)
        s["history"].append(e);s["governing_profiles"][e["anchor"]]=old
        r=self.evaluate(args);self.assertFalse(r.review_current);self.assertTrue(r.finding_record_required)

    def test_resolution_remains_valid_after_its_reviewer_retires_and_policy_changes(self):
        import rfc8785
        from copy import deepcopy
        from dataclasses import replace
        from kinetic_trust_library.v3.demand_supplier import _digest
        args,finding=self.historical_finding();s=args[1];old=finding["profile_digest"]
        current=deepcopy(s["profile_registry"][s["profile_digest"]]);current.update(version=3,review_authority="person:new-reviewer")
        digest=_digest(current,"sha256");s["profile_registry"][digest]=current
        s["registries"][digest]=deepcopy(s["registries"][s["profile_digest"]])
        s["registries"][digest]["reviewer"].update(id=current["review_authority"],registered_at=996)
        s["profile_digest"]=digest;args[0]=replace(args[0],profile_bytes=rfc8785.dumps(current))
        s["registries"][old]["reviewer"]["withdrawn_at"]=995
        finding["resolution"]=dict(anchor="sha256:"+"b"*64,sequence=90,resolved_at=990,authority="person:reviewer",disposition="resolved",profile_digest=old)
        s["open_findings"]=[]
        self.assertTrue(self.evaluate(args).review_current)
