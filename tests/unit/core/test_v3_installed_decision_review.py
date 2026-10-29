from importlib.util import find_spec
import unittest


def fixture():
    import rfc8785
    from tests.unit.core.test_v3_decision_review import profile,event
    from kinetic_trust_library.v3.installed_decision_review import InstalledDecisionReviewVerifier,AuthenticatedDecisionReviewContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from tests.unit.core.test_v3_reissue import fixture as base
    _,_,_,op,now,_=base();p=profile();dp=dict(id="deployment:review")
    e=event()
    s=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=digest_demand_operation(op,algorithm="sha256"),
        decided_by="person:decider",zone=p["zone"],checked_at=now,expires_at=now+8,ledger_owner=p["ledger_owner"],append_protocol=p["append_protocol"],
        coverage_start=900,coverage_end=now,ledger_head=dict(anchor="sha256:"+"f"*64,sequence=100),history=[e],
        governing_profiles={e["anchor"]:_digest(p,"sha256")},open_obligations=[],
        sampler=dict(id=p["sampler_id"],owner="org:auditor",protocol="audited-uniform-draw-v1",space=2,registered_at=800,withdrawn_at=None,
                     anchor="sha256:"+"d"*64,independent_of=["person:decider","agent:a"]),
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
                       lambda s:s["governing_profiles"].clear(),lambda s:s["sampler"].update(owner="person:decider")):
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
