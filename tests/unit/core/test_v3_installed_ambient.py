"""Authenticated current ambient inputs and native risk composition."""
import json
import unittest
from dataclasses import replace
from fractions import Fraction
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError


def fixture(operation=None,deployment=None,now=1030,zone="zone-1",parent="zone-0"):
    import rfc8785
    from kinetic_trust_library.v3.installed_ambient_repair import InstalledAmbientRepairVerifier,AuthenticatedAmbientContext
    from kinetic_trust_library.v3.installed_repair import HARD_ENTRIES
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    if operation is None or deployment is None:
        from tests.unit.core.test_v3_egress import fixture as core_fixture
        original=core_fixture()["outward"]
        operation=json.loads(original.context.operation_bytes);deployment=json.loads(original.context.deployment_profile_bytes)
    normalizer=dict(id="urn:test:ambient-normalizer",version=1,unit="normalized-adversarial-pressure",
        formula="test-only 0.4*max(index-1,bank,0), capped at one")
    profile=dict(id="urn:test:ambient",version=1,zone_id=zone,formula="utilization-index-with-anchored-retirement-v1",
        criticality_model="idle-reproduction-reference-v1",window_seconds=10,recovery_windows=2,declared_capacity=4,
        criticality=2,single_lineage_share=1,repairer_interval=0,retirement_credit_per_weight=1,
        source_signals=["relational.obligation.breach_count","relational.repair.unresolved_count"],
        entry_classes={name:dict(hard=True,weight=1) for name in HARD_ENTRIES},
        normalizer=dict(id=normalizer["id"],version=1,digest=_digest(normalizer,"sha256")))
    windows=[]
    for n in range(2):
        start=now-20+10*n
        windows.append(dict(starts_at=start,ends_at=start+10,backlog_positive=True,records=[
            dict(anchor="sha256:"+format(2*n+i+1,"064x"),repairer="root:"+str(i),anchored_at=start+i+1,
                entry_class="act-outside-decision",current_anchor_verified=True,anchor_order=i) for i in range(2)]))
    state=dict(deployment_digest=_digest(deployment,"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=digest_demand_operation(operation,algorithm="sha256"),checked_at=now,expires_at=now+7,
        zone_id=zone,topology_epoch=5,parent=None if parent is None else dict(zone_id=parent,heard_index=0),
        ledger_head="sha256:"+"a"*64,window_ledger_head="sha256:"+"a"*64,accountable_roots=2,consequential=True,reproduction_at_idle=".1",
        prior_hard_times=[],capacity_windows=windows,current=dict(prior_stock=10,prior_banked_excess=0,retired_excess=0,
            arrivals=[dict(lineage="lineage:"+str(i),counts={"act-outside-decision":1}) for i in range(3)]))
    calls=[]
    class Source:
        def resolve(self,**kwargs):
            calls.append(kwargs)
            return AuthenticatedAmbientContext(rfc8785.dumps(state),b"modeled-complete-current-zone-ledger/backlog/ancestry/reproduction")
    class Normalizer:
        def normalize(self,*,index,banked_excess,**kwargs):
            value=min(Fraction(1),Fraction(2,5)*max(Fraction(0),index-1,banked_excess))
            from kinetic_trust_library.v3._exact import finite_decimal
            return finite_decimal(value)
    verifier=InstalledAmbientRepairVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),rfc8785.dumps(normalizer),
        Source(),Normalizer(),"sha256")
    return verifier,state,operation,profile,calls


@unittest.skipUnless(all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class InstalledAmbientTests(unittest.TestCase):
    def test_unknown_capacity_or_parent_retains_unobservable_pressure(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,state,op,profile,calls=fixture()
        state["parent"]["heard_index"]=None
        result=v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        self.assertIsNone(result.metrics.heard_index)
        self.assertIsNone(result.pressure_floor)
        self.assertEqual(result.supervision_floor,"assisted")
        profile["declared_capacity"]=None
        v=replace(v,profile_bytes=rfc8785.dumps(profile));state["profile_digest"]=_digest(profile,"sha256")
        result=v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        self.assertFalse(result.metrics.capacity_known)
        self.assertIsNone(result.pressure_floor)
        profile["declared_capacity"]=0;state["profile_digest"]=_digest(profile,"sha256")
        v=replace(v,profile_bytes=rfc8785.dumps(profile))
        self.assertTrue(v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True).consequential_hosting_forbidden)
        state["parent"]["heard_index"]=0
        state["current"].update(prior_stock=2,arrivals=[])
        empty=v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        self.assertFalse(empty.consequential_hosting_forbidden)
        self.assertEqual(empty.pressure_floor,0)
        self.assertIsNone(empty.metrics.utilization)  # No fabricated 0/0 measurement.

    def test_current_capacity_stock_heat_and_stable_frame_identity(self):
        v,state,op,profile,calls=fixture()
        value=v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        self.assertEqual(value.capacity.effective_capacity,2)
        self.assertEqual(value.metrics.open_stock,11)
        self.assertEqual(value.pressure_floor,Fraction(4,5))
        self.assertTrue(value.criticality_valid)
        state["checked_at"]=1031
        newer=v.evaluate(actual_operation=op,evaluated_at=1031,clock_healthy=True)
        self.assertEqual(value.frame_digest,newer.frame_digest)
        state["ledger_head"]="sha256:"+"b"*64
        with self.assertRaisesRegex(ValidationError,"ledger"):
            v.evaluate(actual_operation=op,evaluated_at=1031,clock_healthy=True)
        self.assertNotIn("candidate",calls[0])

    def test_binding_and_normalizer_policy_cannot_be_substituted(self):
        v,state,op,profile,calls=fixture()
        state["operation_digest"]="sha256:"+"0"*64
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        with self.assertRaises(ValidationError):replace(v,normalizer_profile_bytes=b"{}")
        class Permissive:
            def normalize(self,**kwargs):return 0
        v,state,op,profile,calls=fixture()
        with self.assertRaises(ValidationError):replace(v,normalizer=Permissive()).evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)

    def test_native_environment_core_claims_and_geometry_use_current_floor(self):
        import rfc8785
        from tests.unit.core.test_v3_egress import fixture as core_fixture
        from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier,AuthenticatedEnvironmentEvidence
        from kinetic_trust_library.v3.core_projection import project_classified_native_core
        from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        from kinetic_trust_library.v3.native_geometry import NativeGeometrySource,AuthenticatedGeometryAuthority
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=core_fixture();original=f["outward"]
        v,state,op,profile,calls=fixture(json.loads(original.context.operation_bytes),json.loads(original.context.deployment_profile_bytes))
        class Environment:
            def verify(self,*args,**kwargs):return AuthenticatedEnvironmentEvidence(original.core.environment_assessment.authenticated_body_bytes)
        env=InstalledEnvironmentVerifier(original.context.deployment_profile_bytes,Environment(),"sha256",ambient_verifier=v).evaluate(
            b"modeled-base-environment",actual_operation=op,evaluated_at=1030)
        context=replace(original.context,ambient_profile_bytes=v.profile_bytes)
        core=project_classified_native_core(original.core.soul_assessment,standing=original.standing,environment=env,
            context=context,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
        self.assertEqual(core.risk.measured_risk,Fraction(62,125))
        self.assertEqual(core.capacity.measured_effective_trust,Fraction(882,25))
        claims=NativeCoreClaimsSource(core,original.standing,context,original.assertion_metadata_bytes)
        proof=InstalledProofIssuer(claims,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        evaluation=dict(id="urn:test:ambient-geometry",release="unreleased-v3.0.0",evaluator="urn:test:evaluator",
            core_deployment_digest=_digest(json.loads(context.deployment_profile_bytes),"sha256"),input_order="layer-then-name-v1",
            numeric_convention="exact-decimal-boundaries-binary64-margin-v1",constraint_policy="retain-grant-and-prior-v1",
            sources={name:"urn:test:source:"+name for name in ("soul","core","environment","demand","authority")},
            magnitudes={"max_calls":{"unit":"calls","direction":"maximum"}},thresholds=dict(veto=0,assisted_floor=.05,metacognitive_floor=.1,allow=.2),
            ambient_repair_profile_digest=_digest(profile,"sha256"))
        class Authority:
            def verify(self,**kwargs):return AuthenticatedGeometryAuthority(rfc8785.dumps(dict(prior=dict(state="observed",supervision="stable",ceilings={}),
                grant=dict(state="observed",ceilings={"max_calls":8}))),b"modeled-current-grant")
        geometry=NativeGeometrySource(claims,core.classified_demand,proof.compact,f["outer_verifier"],rfc8785.dumps(evaluation),Authority(),"ambient-geometry",True)
        body=json.loads(geometry.produce(evaluated_at=1030))
        ambient=next(value for value in body["inputs"] if value["name"]=="ambient_repair")
        self.assertEqual(ambient["value"],env.ambient.geometry_value())
        without_marker=dict(evaluation);without_marker.pop("ambient_repair_profile_digest")
        with self.assertRaisesRegex(ValidationError,"ambient"):
            replace(geometry,evaluation_profile_bytes=rfc8785.dumps(without_marker))
        with self.assertRaisesRegex(ValidationError,"ambient"):replace(claims,context=replace(context,ambient_profile_bytes=None))
        metadata=json.loads(original.assertion_metadata_bytes);metadata["exp"]=1038
        with self.assertRaisesRegex(ValidationError,"ambient"):replace(claims,assertion_metadata_bytes=rfc8785.dumps(metadata))
        state["parent"]["heard_index"]=None
        unknown_env=InstalledEnvironmentVerifier(original.context.deployment_profile_bytes,Environment(),"sha256",ambient_verifier=v).evaluate(
            b"modeled-base-environment",actual_operation=op,evaluated_at=1030)
        pressure=next(item for item in unknown_env.factors if item.factor=="adversarial_pressure")
        self.assertIsNone(pressure.value)
        self.assertEqual(pressure.decision_stress,1)
        unknown_core=project_classified_native_core(original.core.soul_assessment,standing=original.standing,environment=unknown_env,
            context=context,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
        self.assertIsNone(unknown_core.risk.measured_risk)
        self.assertFalse(unknown_core.capacity.capacity_known)
        state["parent"]["heard_index"]=0;state["topology_epoch"]=4
        foreign_env=InstalledEnvironmentVerifier(original.context.deployment_profile_bytes,Environment(),"sha256",ambient_verifier=v).evaluate(
            b"modeled-base-environment",actual_operation=op,evaluated_at=1030)
        with self.assertRaisesRegex(ValidationError,"topology"):
            project_classified_native_core(original.core.soul_assessment,standing=original.standing,environment=foreign_env,
                context=context,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
        state["topology_epoch"]=5
        def current_geometry(policy):
            current_env=InstalledEnvironmentVerifier(original.context.deployment_profile_bytes,Environment(),"sha256",ambient_verifier=policy).evaluate(
                b"modeled-base-environment",actual_operation=op,evaluated_at=1030)
            selected=replace(context,ambient_profile_bytes=policy.profile_bytes)
            current_core=project_classified_native_core(original.core.soul_assessment,standing=original.standing,environment=current_env,
                context=selected,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
            current_claims=NativeCoreClaimsSource(current_core,original.standing,selected,original.assertion_metadata_bytes)
            current_proof=InstalledProofIssuer(current_claims,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
            selected_profile=dict(evaluation,ambient_repair_profile_digest=_digest(json.loads(policy.profile_bytes),"sha256"))
            return NativeGeometrySource(current_claims,current_core.classified_demand,current_proof.compact,f["outer_verifier"],
                rfc8785.dumps(selected_profile),Authority(),"ambient-geometry",True)
        state["reproduction_at_idle"]=".5"
        invalid=json.loads(current_geometry(v).produce(evaluated_at=1030))
        self.assertEqual(invalid["reason_codes"],["INPUT_UNAVAILABLE"])
        self.assertFalse(next(item for item in invalid["inputs"] if item["name"]=="ambient_repair")["value"]["criticality_valid"])
        self.assertEqual(invalid["result"]["supervision"],"silent_veto")
        state["reproduction_at_idle"]=".1";profile["declared_capacity"]=0
        zero=replace(v,profile_bytes=rfc8785.dumps(profile));state["profile_digest"]=_digest(profile,"sha256")
        prohibited=json.loads(current_geometry(zero).produce(evaluated_at=1030))
        self.assertEqual(prohibited["reason_codes"],["INPUT_UNAVAILABLE"])
        self.assertTrue(next(item for item in prohibited["inputs"] if item["name"]=="ambient_repair")["value"]["consequential_hosting_forbidden"])
