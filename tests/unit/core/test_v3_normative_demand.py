"""Modeled external authority; Library enforces restriction-only composition."""
from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture(operation=None,deployment=None,now=1000,zone="zone-a"):
    import rfc8785
    from kinetic_trust_library.v3.normative_demand import InstalledNormativeDemandVerifier,AuthenticatedNormativeDemandContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    if operation is None:
        operation=dict(subject="subject:a",actor="actor:a",audience="service:a",operation="action:write",resource="resource:a",
                       parameters={},request_id="request:1",replay_domain="domain:a")
    if deployment is None:deployment=dict(id="deployment:a")
    schema={"$id":"urn:test:external-demand","type":"object","required":["importance"],"additionalProperties":False,
            "properties":{"importance":{"type":"number","minimum":0,"maximum":1}}}
    profile=dict(id="urn:test:normative-demand",version=1,zone=zone,formula="maximum-whole-action-demand-v1",
        external_schema_id=schema["$id"],external_schema_digest=_digest(schema,"sha256"),
        inputs=[dict(id="priority",source="authority:a",kind="importance"),
                dict(id="mission",source="authority:b",kind="supplied-input")])
    state=dict(deployment_digest=_digest(deployment,"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=digest_demand_operation(operation,algorithm="sha256"),actor=operation["actor"],zone=zone,
        topology_epoch=5,grant_digest="sha256:"+"a"*64,evidence_digest="sha256:"+"b"*64,
        checked_at=now,expires_at=now+7,inputs=[dict(**p,payload=dict(importance=.9),demand=d,issued_at=now-1,expires_at=now+5)
            for p,d in zip(profile["inputs"],(48,46))])
    calls=[]
    class Source:
        def resolve(self,**kw):
            calls.append(kw)
            return AuthenticatedNormativeDemandContext(rfc8785.dumps(state),b"modeled actual authority, signed complete input records and calibrated whole-action demands")
    v=InstalledNormativeDemandVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),rfc8785.dumps(schema),Source(),"sha256")
    return v,state,operation,calls


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class NormativeDemandTests(unittest.TestCase):
    def evaluate(self,v,op,baseline=40):
        return v.evaluate(actual_operation=op,baseline_demand=baseline,evaluated_at=1000,clock_healthy=True)

    def test_whole_action_maximum_preserves_baseline_and_never_adds_capital(self):
        v,s,op,calls=fixture();r=self.evaluate(v,op)
        self.assertEqual(r.demand,48)
        self.assertEqual(r.baseline_demand,40)
        self.assertEqual(r.required_demand,48)
        self.assertEqual(r.expires_at,1005)
        self.assertEqual(self.evaluate(v,op,70).demand,70)
        self.assertEqual(r.source_evidence_bytes,b"modeled actual authority, signed complete input records and calibrated whole-action demands")
        with self.assertRaises(TypeError):type(r)()

    def test_any_number_of_lowering_inputs_cannot_reduce_existing_demand(self):
        v,s,op,_=fixture()
        for item in s["inputs"]:item["demand"]=1
        self.assertEqual(self.evaluate(v,op).demand,40)

    def test_complete_declared_sources_schema_and_current_scope_required(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["inputs"].pop(),lambda s:s["inputs"].append(s["inputs"][0]),
                       lambda s:s["inputs"][0].update(source="requester"),
                       lambda s:s["inputs"][0].update(payload=dict(importance=2)),
                       lambda s:s["inputs"][0].update(expires_at=1000),
                       lambda s:s.update(actor="other"),lambda s:s.update(checked_at=999),
                       lambda s:s.update(profile_digest="sha256:"+"0"*64)):
            v,s,op,_=fixture();change(s)
            with self.assertRaises(ValidationError):self.evaluate(v,op)

    def test_frame_changes_with_judgment_but_not_source_clock_refresh(self):
        v,s,op,_=fixture();r=self.evaluate(v,op)
        s["expires_at"]=1008
        self.assertEqual(self.evaluate(v,op).frame_digest,r.frame_digest)
        s["inputs"][0]["payload"]["importance"]=.8
        self.assertNotEqual(self.evaluate(v,op).frame_digest,r.frame_digest)

    def test_declaration_cannot_hide_capacity_or_risk_rewrite(self):
        import rfc8785,json
        from kinetic_trust_library.errors import ValidationError
        v,s,op,_=fixture();p=json.loads(v.profile_bytes);p["formula"]="capacity-multiplier"
        with self.assertRaises(ValidationError):replace(v,profile_bytes=rfc8785.dumps(p))

    def test_schema_references_never_retrieve_uninstalled_resources(self):
        import rfc8785,json
        from unittest.mock import patch
        from kinetic_trust_library.errors import ValidationError
        from kinetic_trust_library.v3.demand_supplier import _digest
        for ref in ("https://uninstalled.example/schema.json","file:///private/tmp/uninstalled-schema.json","#/$defs/missing"):
            v,s,op,_=fixture();schema=dict(json.loads(v.external_schema_bytes),**{"$ref":ref})
            profile=json.loads(v.profile_bytes);profile["external_schema_digest"]=_digest(schema,"sha256")
            s["profile_digest"]=_digest(profile,"sha256")
            v=replace(v,external_schema_bytes=rfc8785.dumps(schema),profile_bytes=rfc8785.dumps(profile))
            with patch("urllib.request.urlopen") as retrieve:
                with self.subTest(ref=ref),self.assertRaisesRegex(ValidationError,"not installed"):
                    self.evaluate(v,op)
                retrieve.assert_not_called()
        v,s,op,_=fixture();schema=json.loads(v.external_schema_bytes)
        schema["$defs"]={"importance":schema.pop("properties")["importance"]}
        schema["properties"]={"importance":{"$ref":"#/$defs/importance"}}
        profile=json.loads(v.profile_bytes);profile["external_schema_digest"]=_digest(schema,"sha256")
        s["profile_digest"]=_digest(profile,"sha256")
        v=replace(v,external_schema_bytes=rfc8785.dumps(schema),profile_bytes=rfc8785.dumps(profile))
        self.assertEqual(self.evaluate(v,op).demand,48)

    def test_classifier_core_claims_and_expiry_preserve_measurement(self):
        import json,rfc8785
        from kinetic_trust_library.errors import ValidationError
        from kinetic_trust_library.v3.demand_classification import InstalledDemandClassifier
        from kinetic_trust_library.v3.core_projection import project_classified_native_core
        from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource
        from tests.unit.core.test_v3_egress import fixture as core_fixture
        f=core_fixture();original=f["outward"];old=original.core.classified_demand
        op=json.loads(original.context.operation_bytes);dp=json.loads(original.context.deployment_profile_bytes)
        v,s,_,_=fixture(op,dp,1030,"zone-1")
        for item in s["inputs"]:item["demand"]=24
        p=json.loads(old.classifier_profile_bytes)
        from kinetic_trust_library.v3.demand_supplier import _digest
        p["normative_input_profile_digest"]=_digest(json.loads(v.profile_bytes),"sha256")
        class Classifier:
            def classify(self,*args,criticality,**kw):return 10+10*criticality
        classifier=InstalledDemandClassifier(original.context.deployment_profile_bytes,Classifier(),"sha256",rfc8785.dumps(p),v)
        demand=classifier.classify(old.evidence,actual_operation=op,evaluated_at=1030,clock_healthy=True)
        self.assertEqual(demand.pre_normative_demand,old.demand)
        self.assertEqual(demand.demand,24)
        context=replace(original.context,normative_demand_profile_bytes=v.profile_bytes)
        def core(ctx):return project_classified_native_core(original.core.soul_assessment,standing=original.standing,
            environment=original.core.environment_assessment,context=ctx,demand=demand,enclosure=original.core.enclosure_assessment)
        with self.assertRaises(ValidationError):core(original.context)
        projected=core(context)
        self.assertEqual(projected.capacity.base_trust,original.core.capacity.base_trust)
        self.assertEqual(projected.capacity.decision_effective_trust,original.core.capacity.decision_effective_trust)
        self.assertEqual(projected.risk,original.core.risk)
        with self.assertRaises(ValidationError):NativeCoreClaimsSource(projected,original.standing,context,original.assertion_metadata_bytes)
        metadata=json.loads(original.assertion_metadata_bytes);metadata["exp"]=1035
        claims=NativeCoreClaimsSource(projected,original.standing,context,rfc8785.dumps(metadata))
        self.assertEqual(json.loads(claims.produce(evaluated_at=1030))["ktp"]["e_trust"],42)
        with self.assertRaises(ValidationError):replace(classifier,normative_demand_verifier=None)
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        from kinetic_trust_library.v3.native_geometry import NativeGeometrySource,AuthenticatedGeometryAuthority
        proof=InstalledProofIssuer(claims,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        evaluation=dict(id="urn:test:normative-geometry",release="unreleased-v3.0.0",evaluator="urn:test:evaluator",
            core_deployment_digest=_digest(dp,"sha256"),input_order="layer-then-name-v1",
            numeric_convention="exact-decimal-boundaries-binary64-margin-v1",constraint_policy="retain-grant-and-prior-v1",
            sources={name:"urn:test:source:"+name for name in ("soul","core","environment","demand","authority")},
            magnitudes={"max_calls":{"unit":"calls","direction":"maximum"}},
            thresholds=dict(veto=0,assisted_floor=.05,metacognitive_floor=.1,allow=.2),
            normative_demand_profile_digest=demand.normative.profile_digest)
        class Authority:
            prior="stable"
            def verify(self,**kw):return AuthenticatedGeometryAuthority(rfc8785.dumps(dict(
                prior=dict(state="observed",supervision=self.prior,ceilings={"max_calls":6}),
                grant=dict(state="observed",ceilings={"max_calls":8}))),b"modeled current independent grant/prior")
        authority=Authority()
        geometry=NativeGeometrySource(claims,demand,proof.compact,f["outer_verifier"],rfc8785.dumps(evaluation),authority,"norm-geometry",True)
        body=json.loads(geometry.produce(evaluated_at=1030))
        self.assertEqual(body["capacity"]["A"],24)
        self.assertEqual(body["capacity"]["E"],42)
        self.assertEqual(body["result"]["tightenedConstraints"]["ceilings"],[dict(magnitude="max_calls",max=6)])
        entry=next(i for i in body["inputs"] if i["name"]=="normative_demand")
        self.assertEqual(entry["value"],demand.normative.geometry_value())
        self.assertIn(demand.normative.frame_digest,entry["evidence_digests"])
        authority.prior="silent_veto"
        self.assertEqual(json.loads(geometry.produce(evaluated_at=1030))["result"]["supervision"],"silent_veto")
        authority.prior="stable"
        for item in s["inputs"]:item["demand"]=70
        demand=classifier.classify(old.evidence,actual_operation=op,evaluated_at=1030,clock_healthy=True)
        higher=core(context)
        higher_claims=NativeCoreClaimsSource(higher,original.standing,context,rfc8785.dumps(metadata))
        higher_proof=InstalledProofIssuer(higher_claims,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        denied=json.loads(replace(geometry,claim_source=higher_claims,demand=demand,compact_proof=higher_proof.compact).produce(evaluated_at=1030))
        self.assertEqual(denied["capacity"]["A"],70)
        self.assertEqual(denied["capacity"]["E"],42)
        self.assertEqual(denied["result"]["supervision"],"silent_veto")
