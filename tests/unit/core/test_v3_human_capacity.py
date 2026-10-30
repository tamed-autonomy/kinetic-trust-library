from importlib.util import find_spec
from dataclasses import replace
import unittest
from kinetic_trust_library.errors import ValidationError


def fixture(soul_state="clear",deployment=None):
    import rfc8785
    from kinetic_trust_library.v3.human_capacity import InstalledHumanCapacityVerifier,AuthenticatedHumanCapacityContext
    from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier,AuthenticatedSoulResponse
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    dp=dict(soul_veto={"frameworks":["framework:care"]}) if deployment is None else deployment
    p=dict(id="capacity:human",version=1,zone="zone:clinical",formula="reviewed-operation-human-capacity-v1",deployment_digest=_digest(dp,"sha256"),
        measurement_profile_digest="sha256:"+"a"*64,unit="urn:ktp:unit:action-risk-points",max_age_seconds=10,
        review_authorities=["review:independent"],envelope_thresholds=None)
    op=dict(subject="person:clinician",actor="person:clinician",audience="service:clinical",operation="action:care",
        resource="resource:case",parameters={},request_id="request:a",replay_domain="domain:clinical")
    invocation=digest_demand_operation(op,algorithm="sha256")
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=invocation,
        subject=op["actor"],zone=p["zone"],checked_at=1000,expires_at=1007,
        approval=dict(profile_digest=p["measurement_profile_digest"],authority="review:independent",anchor="audit:approval",approved_at=900,expires_at=1100),
        measurement=dict(profile_digest=p["measurement_profile_digest"],operation_digest=invocation,actor=op["actor"],zone=p["zone"],
            observed_at=995,expires_at=1005,unit=p["unit"],demand=40,capacity=50,source_anchor="audit:measurement"))
    calls=[]
    class Source:
        def resolve(self,**kwargs):
            calls.append(kwargs)
            return AuthenticatedHumanCapacityContext(rfc8785.dumps(state),b"modeled approved comparable current human measurements")
    class SoulSource:
        def query(self,**kwargs):return tuple(AuthenticatedSoulResponse(f,soul_state,b"actual Soul response") for f in dp["soul_veto"]["frameworks"])
    soul=InstalledSoulVerifier(rfc8785.dumps(dp),SoulSource(),"sha256").evaluate(actual_operation=op,evaluated_at=1000)
    v=InstalledHumanCapacityVerifier(rfc8785.dumps(dp),rfc8785.dumps(p),Source(),"sha256")
    return v,state,op,soul,calls


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class HumanCapacityTests(unittest.TestCase):
    def test_real_closed_deployment_schema_needs_no_private_wire_field(self):
        import json
        from pathlib import Path
        from importlib.resources import files
        from jsonschema import Draft202012Validator
        root=Path(__file__).parents[3]
        dp=json.loads((root/"spec/proposals/demand-supplier-v1.json").read_text())["deployment_profile"]
        dp["boundary"]=dict(resources=["resource:case"],entitled_subjects=["person"],affected_outside=[],
            jurisdictions=["test"],authority_limits=["declared human capacity assessment"])
        schema=json.loads(files("kinetic_trust_library.v3").joinpath("schemas/deployment-profile-v3.json").read_text())
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(dp)),[])
        r=self.evaluate(fixture(deployment=dp));self.assertTrue(r.capacity_sufficient)
    def evaluate(self,f):
        v,s,op,soul,_=f
        return v.evaluate(actual_operation=op,soul=soul,evaluated_at=1000,clock_healthy=True)

    def test_actual_capacity_is_distinct_non_authorizing_evidence(self):
        r=self.evaluate(fixture());self.assertTrue(r.capacity_sufficient)
        self.assertEqual(r.supervision,"stable");self.assertFalse(r.action_permitted)
        self.assertEqual(r.expires_at,1005)

    def test_installed_capacity_profile_binds_exact_deployment(self):
        import json,rfc8785
        f=fixture();v=f[0];dp=json.loads(v.deployment_profile_bytes)
        dp["soul_veto"]["frameworks"].append("framework:other")
        with self.assertRaises(ValidationError):replace(v,deployment_profile_bytes=rfc8785.dumps(dp))

    def test_soul_first_never_queries_measurements_after_veto_or_missing(self):
        for state in ("veto","absent"):
            f=fixture(state);r=self.evaluate(f)
            self.assertFalse(r.capacity_sufficient);self.assertEqual(r.supervision,"silent_veto")
            self.assertEqual(f[-1],[]);self.assertIsNone(r.envelope)

    def test_zero_unknown_and_exceeded_capacity_never_divide(self):
        for demand,capacity in ((1,0),(0,0),(60,50),(40,None),(None,50)):
            f=fixture();f[1]["measurement"].update(demand=demand,capacity=capacity)
            r=self.evaluate(f);self.assertFalse(r.capacity_sufficient)
            self.assertTrue(r.envelope is None or r.envelope.margin is None)

    def test_equality_keeps_default_envelope_veto(self):
        f=fixture();f[1]["measurement"]["demand"]=50
        r=self.evaluate(f);self.assertFalse(r.capacity_sufficient)
        self.assertEqual(r.envelope.margin,0)

    def test_scope_freshness_unit_and_review_are_bound(self):
        patches=(("actor","person:other"),("unit","points"),("observed_at",989),("expires_at",1000),
            ("profile_digest","sha256:"+"b"*64),("demand",-1),("capacity",True))
        for key,value in patches:
            f=fixture();f[1]["measurement"][key]=value
            with self.subTest(key=key),self.assertRaises(ValidationError):self.evaluate(f)
        f=fixture();f[1]["approval"]["authority"]="review:self"
        with self.assertRaises(ValidationError):self.evaluate(f)
        f=fixture();f[1]["e_base"]=95
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_outage_and_clock_failure_cannot_create_capacity(self):
        f=fixture();v,s,op,soul,_=f
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,soul=soul,evaluated_at=1000,clock_healthy=False)
        class Offline:
            def resolve(self,**kwargs):raise OSError("measurement source unavailable")
        with self.assertRaises(OSError):self.evaluate((replace(v,context_source=Offline()),s,op,soul,[]))

    def test_declared_thresholds_and_exact_freshness_boundary(self):
        import json,rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier,AuthenticatedSoulResponse
        f=fixture();v,s,op,_,calls=f
        p=json.loads(v.profile_bytes)
        p["envelope_thresholds"]={"veto":0,"assisted_floor":"0.1","metacognitive_floor":"0.3","allow":"0.5"}
        dp=json.loads(v.deployment_profile_bytes)
        s.update(profile_digest=_digest(p,"sha256"),deployment_digest=_digest(dp,"sha256"))
        v=replace(v,profile_bytes=rfc8785.dumps(p),deployment_profile_bytes=rfc8785.dumps(dp))
        class Source:
            def query(self,**kwargs):return (AuthenticatedSoulResponse("framework:care","clear",b"current Soul"),)
        soul=InstalledSoulVerifier(rfc8785.dumps(dp),Source(),"sha256").evaluate(actual_operation=op,evaluated_at=1000)
        self.assertEqual(self.evaluate((v,s,op,soul,calls)).supervision,"assisted")
        s["measurement"]["observed_at"]=990
        with self.assertRaises(ValidationError):self.evaluate((v,s,op,soul,calls))

    def test_approval_must_precede_measurement_and_never_outlive_it(self):
        f=fixture();f[1]["approval"]["approved_at"]=996
        with self.assertRaises(ValidationError):self.evaluate(f)
        f=fixture();f[1]["approval"]["expires_at"]=1002
        self.assertEqual(self.evaluate(f).expires_at,1002)
        f=fixture();f[1]["measurement"].update(demand=None,capacity=True)
        with self.assertRaises(ValidationError):self.evaluate(f)
