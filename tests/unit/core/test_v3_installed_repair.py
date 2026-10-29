"""Current complete breach inventory and immutable native repair evidence."""
import json
import unittest
from dataclasses import asdict,replace
from decimal import Decimal
from importlib.util import find_spec
from tests.unit.core.test_v3_repair import facts
from kinetic_trust_library.errors import ValidationError


def fixture(operation=None,deployment=None,now=1000):
    import rfc8785
    from kinetic_trust_library.v3.installed_repair import InstalledRepairVerifier,AuthenticatedRepairContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    op=operation or dict(subject="urn:person:1",actor="urn:agent:1",audience="urn:service:1",operation="urn:operation:1",
        resource="urn:resource:1",parameters={},request_id="request-1",replay_domain="urn:replay:1")
    dp=deployment or dict(profile_id="repair-test",version=1)
    profile=dict(id="urn:test:repair",version=1,formula="fractional-reentry-with-additive-unrepaired-raise-v1",route="urn:repair:route",
        entry_classes={name:dict(hard=True,delta="0.25",unrepaired_raise="0.15") for name in
            ("act-outside-decision","withdrawal-for-cause","misattestation","seeking-without-attendance")})
    values={key:(str(value) if type(value) is Decimal else list(value) if type(value) is tuple else value) for key,value in asdict(facts()).items()}
    entry=dict(breach_anchor=values["breach_anchor"],entry_class="act-outside-decision",standing_at_breach="80",previous_delta="0",
        breached_at=900,breaching_terminator="terminator:a",required_parties=["terminator:a","terminator:b"],record_facts=values)
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=digest_demand_operation(op,algorithm="sha256"),checked_at=now,expires_at=now+7,
        actor=op["actor"],lineage="lineage:a",zone_id="zone:alpha",breaches=[entry])
    calls=[]
    class Source:
        def resolve(self,**kwargs):
            calls.append(kwargs)
            return AuthenticatedRepairContext(rfc8785.dumps(state),b"modeled-complete-lineage-breaches/current-anchors/independence/attendance")
    v=InstalledRepairVerifier(rfc8785.dumps(dp),rfc8785.dumps(profile),Source(),"sha256")
    return v,state,op,profile,calls


@unittest.skipUnless(all(find_spec(name) for name in ("rfc8785","jsonschema")),"install v3-proofs")
class InstalledRepairTests(unittest.TestCase):
    def test_earned_lift_requires_declared_policy_and_post_record_ordinary_acts(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,state,op,profile,calls=fixture()
        lift_profile=dict(id="urn:test:earned-repair",version=1,unit="ktp-standing-points",formula="test-only sum of authenticated ordinary points")
        profile["ceiling_lift"]={name:lift_profile[name] for name in ("id","version")}
        profile["ceiling_lift"]["digest"]=_digest(lift_profile,"sha256")
        class Lift:
            def project(self,*,base_ceiling,acts,**kwargs):
                return base_ceiling+sum(Decimal(json.loads(act.record_bytes)["points"]) for act in acts)
        v=replace(v,profile_bytes=rfc8785.dumps(profile),ceiling_lift_profile_bytes=rfc8785.dumps(lift_profile),ceiling_lift_adapter=Lift())
        state["profile_digest"]=_digest(profile,"sha256")
        def act(anchor,at,points,**kwargs):
            return dict(anchor="sha256:"+anchor*64,recorded_at=at,lineage=state["lineage"],
                ordinary_profile_digest="sha256:"+"9"*64,record=dict(points=str(points)),
                current_anchor_verified=True,ordinary_admissible=True,**kwargs)
        entry=state["breaches"][0]
        entry["post_record_acts"]=[act("2",949,40),act("3",951,5)]
        result=v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)
        self.assertEqual(result.standing_ceiling,65)
        self.assertEqual(result.lifted_ceilings,((entry["breach_anchor"],Decimal(65)),))
        second=entry["post_record_acts"][1]
        for patch in (dict(ordinary_admissible=False),dict(current_anchor_verified=False),dict(recorded_at=950),
                      dict(recorded_at=1001),dict(lineage="other-lineage")):
            original=dict(second);second.update(patch)
            self.assertEqual(v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True).standing_ceiling,60)
            second.clear();second.update(original)
        entry["post_record_acts"].append(dict(entry["post_record_acts"][1]))
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)
        with self.assertRaises(ValidationError):replace(v,ceiling_lift_adapter=None)
        class MagicLift:
            def project(self,*,base_ceiling,acts,**kwargs):return base_ceiling+1
        bad=replace(v,ceiling_lift_adapter=MagicLift())
        entry["post_record_acts"]=[]
        with self.assertRaisesRegex(ValidationError,"unearned"):
            bad.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)
        class DecreasingLift:
            def project(self,*,base_ceiling,acts,**kwargs):return base_ceiling+(0 if not acts else 5 if len(acts)==1 else 4)
        bad=replace(v,ceiling_lift_adapter=DecreasingLift())
        entry["post_record_acts"]=[act("3",951,5),act("4",952,5)]
        with self.assertRaisesRegex(ValidationError,"decreasing"):
            bad.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    def test_seeking_without_attendance_is_a_hard_entry(self):
        import rfc8785
        v,state,op,profile,calls=fixture()
        profile["entry_classes"]["seeking-without-attendance"].update(hard=False,delta="0")
        with self.assertRaises(ValidationError):replace(v,profile_bytes=rfc8785.dumps(profile))

    def test_current_inventory_and_record_closure(self):
        v,state,op,profile,calls=fixture()
        result=v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)
        self.assertTrue(result.reentry_eligible)
        self.assertEqual(result.standing_ceiling,60)
        self.assertEqual(result.readiness_after,950)
        self.assertEqual(result.expires_at,1007)
        state["breaches"][0]["record_facts"]=None
        result=v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)
        self.assertFalse(result.reentry_eligible)
        self.assertIsNone(result.standing_ceiling)
        self.assertNotIn("record_facts",calls[0])
        state["actor"]="urn:other"
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    def test_source_cannot_substitute_cost_or_record_frame(self):
        for field,value in (("declared_delta","0"),("previous_delta","0.5"),("breach_anchor","sha256:"+"2"*64),
                            ("required_parties",["terminator:a"])):
            v,state,op,profile,calls=fixture()
            state["breaches"][0]["record_facts"][field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    def test_duplicate_and_foreign_evaluation_fail(self):
        v,state,op,profile,calls=fixture()
        state["breaches"].append(dict(state["breaches"][0]))
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)
        state["breaches"].pop();state["checked_at"]=999
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    @unittest.skipUnless(find_spec("cryptography"),"install v3-proofs")
    def test_standing_core_and_claims_use_repair_ceiling(self):
        import rfc8785
        from tests.unit.core.test_v3_egress import fixture as core_fixture
        from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier,AuthenticatedStandingEvidence
        from kinetic_trust_library.v3.core_projection import project_classified_native_core
        from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource
        f=core_fixture();original=f["outward"]
        v,state,op,profile,calls=fixture(json.loads(original.context.operation_bytes),json.loads(original.context.deployment_profile_bytes),1030)
        state["zone_id"]="zone-1"
        class Standing:
            def verify(self,*args,**kwargs):return AuthenticatedStandingEvidence(original.standing.authenticated_body_bytes)
        verifier=InstalledStandingVerifier(original.context.deployment_profile_bytes,Standing(),"sha256",repair_verifier=v)
        standing=verifier.evaluate(b"modeled-standing",roots=original.standing.roots,actual_operation=op,evaluated_at=1030)
        self.assertEqual(standing.base.base_trust,60)
        self.assertEqual(dict(standing.base.ceilings)["repair_reentry"],60)
        context=replace(original.context,repair_profile_bytes=v.profile_bytes)
        core=project_classified_native_core(original.core.soul_assessment,standing=standing,environment=original.core.environment_assessment,
            context=context,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
        claims=NativeCoreClaimsSource(core,standing,context,original.assertion_metadata_bytes)
        self.assertEqual(json.loads(claims.produce(evaluated_at=1030))["ktp"]["e_trust"],36)
        from kinetic_trust_library.v3.demand_supplier import _digest
        lift_profile=dict(id="urn:test:earned-native",version=1,unit="ktp-standing-points",formula="test-only five per authenticated ordinary act")
        profile["ceiling_lift"]=dict(id=lift_profile["id"],version=1,digest=_digest(lift_profile,"sha256"))
        class Lift:
            def project(self,*,base_ceiling,acts,**kwargs):return base_ceiling+5*len(acts)
        v=replace(v,profile_bytes=rfc8785.dumps(profile),ceiling_lift_profile_bytes=rfc8785.dumps(lift_profile),ceiling_lift_adapter=Lift())
        state["profile_digest"]=_digest(profile,"sha256")
        state["breaches"][0]["post_record_acts"]=[dict(anchor="sha256:"+"3"*64,recorded_at=951,lineage=state["lineage"],
            ordinary_profile_digest="sha256:"+"4"*64,record=dict(fixture="verified-ordinary-act"),current_anchor_verified=True,ordinary_admissible=True)]
        lifted_standing=replace(verifier,repair_verifier=v).evaluate(b"modeled-standing",roots=original.standing.roots,actual_operation=op,evaluated_at=1030)
        self.assertEqual(lifted_standing.base.base_trust,65)
        lifted_context=replace(context,repair_profile_bytes=v.profile_bytes)
        lifted_core=project_classified_native_core(original.core.soul_assessment,standing=lifted_standing,environment=original.core.environment_assessment,
            context=lifted_context,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
        lifted_claims=NativeCoreClaimsSource(lifted_core,lifted_standing,lifted_context,original.assertion_metadata_bytes)
        self.assertEqual(json.loads(lifted_claims.produce(evaluated_at=1030))["ktp"]["e_trust"],39)
        with self.assertRaisesRegex(ValidationError,"repair"):
            replace(claims,context=replace(context,repair_profile_bytes=None))
        metadata=json.loads(original.assertion_metadata_bytes);metadata["exp"]=1038
        with self.assertRaisesRegex(ValidationError,"repair"):
            replace(claims,assertion_metadata_bytes=rfc8785.dumps(metadata))
        state["breaches"][0]["record_facts"]=None
        state["profile_digest"]=_digest(json.loads(verifier.repair_verifier.profile_bytes),"sha256")
        state["breaches"][0].pop("post_record_acts")
        with self.assertRaisesRegex(ValidationError,"REPAIR_UNRECONCILED"):
            verifier.evaluate(b"modeled-standing",roots=original.standing.roots,actual_operation=op,evaluated_at=1030)
