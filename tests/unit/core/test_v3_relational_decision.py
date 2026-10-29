"""Real test adjudication signatures; registry, liability and run evidence modeled."""
from importlib.util import find_spec
import unittest

HAS_EXTRAS=all(find_spec(n) for n in ("rfc8785","cryptography","jsonschema"))


def fixture(operation=None,deployment=None,zone="zone-a",lease=None,hysteresis_verifier=None,repair_ref="repair:registered"):
    import json,rfc8785,hashlib
    from dataclasses import replace
    from tests.unit.core.test_v3_relational_reissue import fixture as reissue
    from tests.unit.core.test_v3_adjudication import fixture as adjudication
    from kinetic_trust_library.v3.relational_decision import InstalledRelationalDecisionVerifier,AuthenticatedRelationalDecisionContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    rv,rs,lease,op,now,_=reissue(operation,deployment,zone,lease,hysteresis_verifier,repair_ref)
    dp=json.loads(rv.hysteresis_verifier.deployment_profile_bytes)
    f=adjudication(operation=op,deployment=dp,now=now)
    f["profile"]["zone_id"]=zone
    f["state"].update(zone_id=zone,profile_digest=_digest(f["profile"],"sha256"),grant_digest=_digest(lease,"sha256"))
    f["payload"].update(zone_id=zone,grant_digest=f["state"]["grant_digest"])
    f["verifier"]=replace(f["verifier"],profile_bytes=rfc8785.dumps(f["profile"]))
    p=dict(id="human-decision:1",version=1,zone=zone,formula="accountable-adjudication-endogenous-v1",
        adjudication_profile_digest=_digest(f["profile"],"sha256"),relational_profile_digest=_digest(json.loads(rv.profile_bytes),"sha256"),
        evidence_level="standard-endogenous",refusal_cases=[dict(id="must-refuse:1",case_digest="sha256:"+"a"*64,
            operation_digest="sha256:"+"4"*64,boundary_id="pep:declared")],max_run_age_seconds=100)
    principal="person:decider"
    signed_at=f["payload"]["iat"]
    decision=dict(anchor="sha256:"+"c"*64,token_digest="sha256:"+hashlib.sha256(f["sign"]()).hexdigest(),decided_by=principal,
        issuer=f["profile"]["issuer"],key_id="test-key",signed_at=signed_at,repair_ref=repair_ref,
        grant_digest=f["state"]["grant_digest"],evidence_digest=f["state"]["evidence_digest"],operation_digest=f["state"]["operation_digest"],
        current_grant_epoch=5,topology_epoch=5,review_kind="review",acknowledged_at=997,reviewed_at=998,
        offered_outcomes=["approve","refuse"],choice="approve")
    case=dict(id="must-refuse:1",case_digest="sha256:"+"a"*64,anchor="sha256:"+"1"*64,decided_by=principal,
              issuer=decision["issuer"],key_id="test-key",decided_at=980,choice="refuse",review_kind="review",
              execution=dict(scope=dict(actor=op["actor"],operation_digest="sha256:"+"4"*64,zone=zone,topology_epoch=5),
                decision=dict(decision_id="refusal:1",record_digest="sha256:"+"1"*64,decided_at=980,execution_permitted=False,supervision="stable"),
                observation=dict(decision_id="refusal:1",decision_digest="sha256:"+"1"*64,boundary_id="pep:declared",kind="non_dispatch",observed_at=981),
                enforcement_point_present=True))
    s=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=decision["operation_digest"],
        subject=op["actor"],zone=zone,checked_at=now,expires_at=now+7,lease_digest=f["state"]["grant_digest"],
        evidence_digest=f["state"]["evidence_digest"],current_grant_epoch=5,topology_epoch=5,ledger_head=rs["ledger_head"],
        principal=dict(id=principal,kind="person",issuer=decision["issuer"],key_id="test-key",key_holder=principal,
                       liability_ref="liability:signed",liability_anchor="sha256:"+"2"*64,liability_signed_by=principal,
                       liability_signed_at=900,valid_from=900,valid_until=1100,revoked_at=None),
        decision=decision,run=dict(anchor="sha256:"+"3"*64,profile_digest=_digest(p,"sha256"),
                                  decided_by=principal,started_at=970,completed_at=990,topology_epoch=5,cases=[case]))
    class Source:
        def resolve(self,**kw):return AuthenticatedRelationalDecisionContext(rfc8785.dumps(s),b"modeled actual liability/person-key registry/signed decision/anchored refusal run")
    v=InstalledRelationalDecisionVerifier(rv,f["verifier"],rfc8785.dumps(p),Source())
    def refresh():
        s["decision"]["token_digest"]="sha256:"+hashlib.sha256(f["sign"]()).hexdigest()
    return dict(v=v,s=s,rs=rs,lease=lease,op=op,now=now,f=f,p=p,refresh=refresh)


def evaluate(f,token=True):
    import rfc8785
    return f["v"].evaluate(f["f"]["sign"]() if token else None,rfc8785.dumps(f["lease"]),
        evidence_digest=f["s"]["evidence_digest"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)


def install_review(f):
    import json,rfc8785
    from dataclasses import replace
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core.test_v3_installed_decision_review import fixture as review_fixture
    from tests.unit.core.test_v3_decision_review import event
    v,s,_,_=review_fixture(f["op"],json.loads(f["v"].adjudication_verifier.deployment_profile_bytes),f["p"]["zone"])
    current=event(4,draw=1,actor=f["op"]["actor"]);d=f["s"]["decision"]
    current.update(anchor=d["anchor"],sequence=60,decided_by=d["decided_by"],decided_at=d["signed_at"],
                   acknowledged_at=d["acknowledged_at"],reviewed_at=d["reviewed_at"],choice=d["choice"])
    current["sample"].update(sequence=61,drawn_at=d["signed_at"]);current["reviews"]=[]
    s["history"].append(current);s["governing_profiles"][current["anchor"]]=s["profile_digest"]
    f["p"].update(formula="accountable-adjudication-dual-schedule-v1",evidence_level="full-exogenous",production_review_profile_digest=s["profile_digest"])
    digest=_digest(f["p"],"sha256");f["s"]["profile_digest"]=f["s"]["run"]["profile_digest"]=digest
    f["v"]=replace(f["v"],profile_bytes=rfc8785.dumps(f["p"]),review_verifier=v)
    return v,s


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class RelationalDecisionTests(unittest.TestCase):
    def test_dual_schedule_gate_preserves_endogenous_refusal_and_current_production_review(self):
        f=fixture();_,review=install_review(f)
        r=evaluate(f);self.assertTrue(r.gate_satisfied);self.assertTrue(r.production_review.review_current)
        f["s"]["run"]["cases"]=[];self.assertFalse(evaluate(f).gate_satisfied)

    def test_overdue_exogenous_review_blocks_real_signed_favorable_decision(self):
        f=fixture();_,s=install_review(f);old=s["history"][0]
        old["reviews"]=[];s["open_obligations"]=[old["sample"]["anchor"]]
        r=evaluate(f);self.assertFalse(r.gate_satisfied);self.assertEqual(r.reason,"DECISION_REVIEW_OVERDUE")

    def test_production_inventory_must_include_this_actual_signed_human_decision(self):
        f=fixture();_,s=install_review(f);s["history"].pop();s["governing_profiles"].pop(f["s"]["decision"]["anchor"])
        self.assertEqual(evaluate(f).reason,"RELATIONAL_PRODUCTION_DECISION_BINDING")

    def test_dual_schedule_selection_is_symmetric_and_clips_expiry(self):
        from dataclasses import replace
        from kinetic_trust_library.errors import ValidationError
        f=fixture();_,s=install_review(f);s["expires_at"]=1002
        self.assertEqual(evaluate(f).expires_at,1002)
        with self.assertRaises(ValidationError):replace(f["v"],review_verifier=None)
        import rfc8785
        standard=fixture()
        with self.assertRaises(ValidationError):replace(standard["v"],review_verifier=f["v"].review_verifier)
        mismatch=replace(f["v"].review_verifier,deployment_profile_bytes=rfc8785.dumps(dict(id="deployment:other")))
        with self.assertRaises(ValidationError):replace(f["v"],review_verifier=mismatch)
    def test_real_signed_decision_and_prior_refusal_run_satisfy_gate_without_authority(self):
        r=evaluate(fixture())
        self.assertTrue(r.gate_satisfied);self.assertEqual(r.decided_by,"person:decider")
        self.assertFalse(r.action_permitted);self.assertEqual(r.expires_at,1006)

    def test_absent_unfavorable_or_invalid_signature_does_not_satisfy_gate(self):
        f=fixture();self.assertFalse(evaluate(f,False).gate_satisfied)
        f["f"]["payload"]["favorable"]=False;f["s"]["decision"]["choice"]="refuse";f["refresh"]()
        self.assertFalse(evaluate(f).gate_satisfied)
        f=fixture();f["f"]["adapter"].invalid=True
        self.assertFalse(evaluate(f).gate_satisfied)

    def test_agent_unsigned_liability_or_agent_key_cannot_be_the_decider(self):
        for change in (dict(kind="software"),dict(liability_signed_by="agent:a"),dict(key_holder="agent:a"),dict(revoked_at=995)):
            f=fixture();f["s"]["principal"].update(change)
            with self.subTest(change=change):self.assertFalse(evaluate(f).gate_satisfied)
        f=fixture();f["s"]["decision"]["decided_by"]=f["op"]["actor"]
        self.assertFalse(evaluate(f).gate_satisfied)

    def test_signed_token_is_bound_to_actual_human_record_and_current_grant_evidence(self):
        for change in (dict(token_digest="sha256:"+"0"*64),dict(grant_digest="sha256:"+"0"*64),
                       dict(evidence_digest="sha256:"+"0"*64),dict(key_id="another-key"),dict(repair_ref="other-route"),
                       dict(current_grant_epoch=6),dict(topology_epoch=6),dict(choice="refuse")):
            f=fixture();f["s"]["decision"].update(change)
            with self.subTest(change=change):self.assertFalse(evaluate(f).gate_satisfied)

    def test_acknowledgment_or_no_refusal_control_is_not_review(self):
        for change in (dict(review_kind="acknowledgment"),dict(offered_outcomes=["approve"]),dict(reviewed_at=None)):
            f=fixture();f["s"]["decision"].update(change)
            with self.subTest(change=change):self.assertFalse(evaluate(f).gate_satisfied)

    def test_endogenous_run_requires_actual_refusal_and_no_dispatch(self):
        for change in (dict(choice="approve"),dict(review_kind="acknowledgment"),dict(execution=None),dict(case_digest="sha256:"+"b"*64)):
            f=fixture();f["s"]["run"]["cases"][0].update(change)
            with self.subTest(change=change):self.assertFalse(evaluate(f).gate_satisfied)
        f=fixture();f["s"]["run"]["cases"].clear();self.assertFalse(evaluate(f).gate_satisfied)

    def test_absence_of_dispatch_evidence_is_not_an_observed_refusal(self):
        for change in (lambda e:e.update(observation=None),lambda e:e["observation"].update(kind="dispatch"),
                       lambda e:e["observation"].update(decision_digest="sha256:"+"0"*64),
                       lambda e:e["scope"].update(operation_digest="sha256:"+"0"*64),
                       lambda e:e["observation"].update(boundary_id="pep:other")):
            f=fixture();change(f["s"]["run"]["cases"][0]["execution"])
            with self.subTest(change=change):self.assertFalse(evaluate(f).gate_satisfied)

    def test_expired_run_or_run_after_decision_cannot_certify_it(self):
        for start,end in ((800,850),(995,1000)):
            f=fixture();f["s"]["run"].update(started_at=start,completed_at=end)
            self.assertFalse(evaluate(f).gate_satisfied)

    def test_refusal_run_cannot_precede_current_principal_key_and_liability(self):
        f=fixture();f["s"]["run"].update(started_at=800)
        f["s"]["run"]["cases"][0]["decided_at"]=850
        self.assertFalse(evaluate(f).gate_satisfied)

    def test_shortest_run_or_principal_validity_bounds_result_and_new_evidence_voids_token(self):
        import rfc8785
        from dataclasses import replace
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture();f["s"]["principal"]["valid_until"]=1002
        self.assertEqual(evaluate(f).expires_at,1002)
        f=fixture();f["p"]["max_run_age_seconds"]=15
        digest=_digest(f["p"],"sha256");f["s"]["profile_digest"]=digest;f["s"]["run"]["profile_digest"]=digest
        f["v"]=replace(f["v"],profile_bytes=rfc8785.dumps(f["p"]))
        self.assertEqual(evaluate(f).expires_at,1005)
        f=fixture();f["s"]["evidence_digest"]="sha256:"+"f"*64
        self.assertFalse(evaluate(f).gate_satisfied)

    def test_each_declared_refusal_case_and_distinct_anchor_is_required(self):
        f=fixture();case=f["s"]["run"]["cases"][0]
        case["anchor"]=f["s"]["decision"]["anchor"]
        self.assertFalse(evaluate(f).gate_satisfied)
        f=fixture();f["s"]["run"]["cases"].append(dict(f["s"]["run"]["cases"][0]))
        self.assertFalse(evaluate(f).gate_satisfied)

    def test_source_failures_are_not_laundered_into_authentication(self):
        from dataclasses import replace
        class Source:
            def resolve(self,**kwargs):raise RuntimeError("current identity registry unavailable")
        f=fixture();f["v"]=replace(f["v"],context_source=Source())
        with self.assertRaisesRegex(RuntimeError,"registry unavailable"):evaluate(f)

    def test_shared_ledger_and_reconciliation_are_required_even_for_real_approval(self):
        f=fixture();f["rs"]["stops"][0]["record"]=None
        self.assertFalse(evaluate(f).gate_satisfied)
        f=fixture();f["s"]["ledger_head"]=dict(anchor="sha256:"+"0"*64,sequence=100)
        self.assertFalse(evaluate(f).gate_satisfied)

    def test_optional_adjudication_or_full_claim_is_not_silently_accepted(self):
        import rfc8785
        from dataclasses import replace
        from kinetic_trust_library.errors import ValidationError
        f=fixture();p=dict(f["f"]["profile"],gate_required=False)
        with self.assertRaises(ValidationError):replace(f["v"],adjudication_verifier=replace(f["f"]["verifier"],profile_bytes=rfc8785.dumps(p)))
        p=dict(f["p"],evidence_level="full-exogenous")
        with self.assertRaises(ValidationError):replace(f["v"],profile_bytes=rfc8785.dumps(p))
