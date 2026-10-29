"""Boundary decisions use authenticated facts, never candidate subject classes."""
import json
import unittest
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
from kinetic_trust_library.errors import ValidationError

HAS_EXTRAS=all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography"))


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class BoundaryTests(unittest.TestCase):
    def fixture(self,base_profile=None,actual_operation=None):
        import rfc8785
        from kinetic_trust_library.v3.boundary import InstalledBoundaryVerifier,AuthenticatedBoundaryContext
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.demand_operation import digest_demand_operation
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/zone-boundary-v1.json").read_text())
        boundary=vectors["vectors"][0]["given"]["boundary"]
        profile=dict(base_profile or dict(profile_id="boundary-test",version=1),boundary=boundary)
        operation=actual_operation or dict(subject="urn:person:1",actor="urn:agent:1",audience="urn:service:1",operation="urn:operation:1",
            resource="svc:example/ledger",parameters={},request_id="request-1",replay_domain="urn:replay:1")
        boundary["resources"]=[operation["resource"]]
        state=dict(deployment_digest=_digest(profile,"sha256"),operation_digest=digest_demand_operation(operation,algorithm="sha256"),
            enclosing_deployment_digest=None,checked_at=1030,expires_at=1037,zone_id="zone-1",enclosure_zone=None,topology_epoch=5,
            subject=operation["actor"],subject_class="sponsored-agent",resource=operation["resource"],affected_outside_classes=["customer-of-record"],
            authority_within_limits=True,resolved_resources={resource:[resource] for resource in boundary["resources"]},enclosing_resolved_resources=None)
        calls=[]
        class Source:
            def resolve(self,**kwargs):
                calls.append(kwargs)
                return AuthenticatedBoundaryContext(rfc8785.dumps(state),b"modeled-current-identity/resource/jurisdiction/limits")
        verifier=InstalledBoundaryVerifier(rfc8785.dumps(profile),Source(),"sha256")
        return verifier,profile,operation,state,calls,vectors

    def test_resource_entitlement_authority_and_review_route(self):
        v,p,op,state,calls,vectors=self.fixture()
        def check():return v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        allowed=check()
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.review_routes,())
        state["resolved_resources"]={"svc:example/ledger":[]}
        denied=check()
        self.assertEqual(denied.reason,"BOUNDARY_RESOURCE")
        self.assertEqual(denied.review_routes,(("customer-of-record","https://example.com/review"),))
        state["resolved_resources"]={"svc:example/ledger":["svc:example/ledger"]}
        state["subject_class"]="person"
        self.assertEqual(check().reason,"BOUNDARY_SUBJECT")
        state["subject_class"]="sponsored-agent";state["authority_within_limits"]=False
        self.assertEqual(check().reason,"BOUNDARY_AUTHORITY")
        self.assertNotIn("subject_class",calls[0])

    def test_no_boundary_invalid_context_and_unresolved_affected_party(self):
        import rfc8785
        from kinetic_trust_library.v3.boundary import InstalledBoundaryVerifier
        v,p,op,state,calls,vectors=self.fixture()
        for boundary in (None,{},dict(p["boundary"],affected_outside=[{"class":"x","review_route":""}])):
            with self.assertRaises(ValidationError):replace(v,deployment_profile_bytes=rfc8785.dumps(dict(p,boundary=boundary)))
        for patch in (dict(subject="urn:other"),dict(resource="other"),dict(checked_at=1029),dict(expires_at=1030),
                      dict(affected_outside_classes=["undeclared"]),dict(authority_within_limits=1)):
            original=dict(state);state.update(patch)
            with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
            state.clear();state.update(original)

    def test_nested_resource_containment(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        v,p,op,state,calls,vectors=self.fixture()
        parent=dict(profile_id="parent",version=1,boundary=dict(p["boundary"],resources=["svc:example/reports"]))
        v=replace(v,enclosing_deployment_profile_bytes=rfc8785.dumps(parent))
        state.update(enclosing_deployment_digest=_digest(parent,"sha256"),enclosure_zone="zone-0",
            enclosing_resolved_resources={"svc:example/reports":["svc:example/reports"]})
        self.assertEqual(v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True).reason,"BOUNDARY_ENCLOSURE")
        # A declared pattern is resolved by the installed authority; no glob is inferred.
        state["enclosing_resolved_resources"]={"svc:example/reports":["svc:example/reports","svc:example/ledger"]}
        self.assertTrue(v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True).allowed)

    def test_core_stops_before_other_inputs_on_boundary_denial(self):
        import rfc8785
        from kinetic_trust_library.v3.core_projection import NativeCoreContext,project_classified_native_core
        v,p,op,state,calls,vectors=self.fixture()
        state["subject_class"]="person"
        denied=v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        context=NativeCoreContext(rfc8785.dumps(p),rfc8785.dumps(op),1030,"sha256")
        with self.assertRaisesRegex(ValidationError,"BOUNDARY_SUBJECT"):
            project_classified_native_core(None,standing=None,environment=None,context=context,demand=None,boundary=denied)
        with self.assertRaisesRegex(ValidationError,"boundary"):
            project_classified_native_core(None,standing=None,environment=None,context=context,demand=None)

    def test_allowed_core_and_claims_retain_boundary_and_expiry(self):
        import rfc8785
        from tests.unit.core.test_v3_egress import fixture
        from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier,AuthenticatedSoulResponse
        from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier,AuthenticatedEnvironmentEvidence
        from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier,AuthenticatedStandingEvidence
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        from kinetic_trust_library.v3.installed_demand import InstalledDemandVerifier,DemandVerificationFailure
        from kinetic_trust_library.v3.demand_classification import InstalledDemandClassifier
        from kinetic_trust_library.v3.core_projection import NativeCoreContext,project_classified_native_core
        from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture();original=f["outward"]
        v,p,op,state,calls,vectors=self.fixture(json.loads(original.context.deployment_profile_bytes),json.loads(original.context.operation_bytes))
        raw=rfc8785.dumps(p)
        class Soul:
            def query(self,*,required_frameworks,**kwargs):return tuple(AuthenticatedSoulResponse(name,"clear",b"modeled-clear") for name in required_frameworks)
        class Environment:
            def verify(self,*args,**kwargs):return AuthenticatedEnvironmentEvidence(rfc8785.dumps({"factors":{
                name:dict(signals=dict.fromkeys(config["signals"],0),measured_stress=.4) for name,config in p["risk_factors"].items()}}))
        class Standing:
            def verify(self,*args,**kwargs):return AuthenticatedStandingEvidence(original.standing.authenticated_body_bytes)
        class Demand:
            def verify(self,*args,**kwargs):raise DemandVerificationFailure()
        roots=select_assessed_roots((),context_bytes=rfc8785.dumps(dict(subject=op["actor"],subject_profile="software",generation=7,
            lineage="guarantor",hop_bound=p["external_root"]["hop_bound"],deployment_digest=_digest(p,"sha256"))),evaluated_at=1030,algorithm="sha256")
        soul=InstalledSoulVerifier(raw,Soul(),"sha256").evaluate(actual_operation=op,evaluated_at=1030)
        environment=InstalledEnvironmentVerifier(raw,Environment(),"sha256").evaluate(b"modeled",actual_operation=op,evaluated_at=1030)
        standing=InstalledStandingVerifier(raw,Standing(),"sha256").evaluate(b"modeled",roots=roots,actual_operation=op,evaluated_at=1030)
        source_vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())
        demand_evidence=InstalledDemandVerifier(raw,rfc8785.dumps(source_vectors["supplier_profile_payload"]),
            rfc8785.dumps(source_vectors["verification_profile_payload"]),Demand(),"sha256").evaluate(b"unavailable",
                actual_operation=op,evaluated_at=1030,clock_healthy=True)
        class Classifier:
            def classify(self,*args,criticality,**kwargs):return 10+criticality*10
        demand=InstalledDemandClassifier(raw,Classifier(),"sha256",original.core.classified_demand.classifier_profile_bytes).classify(
            demand_evidence,actual_operation=op,evaluated_at=1030)
        context=NativeCoreContext(raw,rfc8785.dumps(op),1030,"sha256")
        boundary=v.evaluate(actual_operation=op,evaluated_at=1030,clock_healthy=True)
        core=project_classified_native_core(soul,standing=standing,environment=environment,context=context,demand=demand,boundary=boundary)
        self.assertIs(core.boundary_assessment,boundary)
        metadata=json.loads(original.assertion_metadata_bytes);metadata.pop("ingress_path",None)
        claims=NativeCoreClaimsSource(core,standing,context,rfc8785.dumps(metadata))
        self.assertEqual(json.loads(claims.produce(evaluated_at=1030))["ktp"]["e_trust"],42)
        for patch in (dict(zone="another-zone"),dict(exp=1038)):
            with self.assertRaisesRegex(ValidationError,"boundary"):
                replace(claims,assertion_metadata_bytes=rfc8785.dumps(dict(metadata,**patch)))
