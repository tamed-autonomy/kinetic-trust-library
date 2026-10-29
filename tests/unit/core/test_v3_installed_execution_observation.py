from importlib.util import find_spec
import hashlib
import unittest


def fixture():
    import rfc8785
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from kinetic_trust_library.v3.installed_execution_observation import (
        InstalledExecutionObservationVerifier,AuthenticatedExecutionObservationContext)
    operation=dict(subject="subject:a",actor="actor:a",audience="service:a",operation="action:write",
        resource="resource:r",parameters={"amount":5},request_id="request:1",replay_domain="domain:a")
    deployment=dict(id="deployment:a")
    profile=dict(id="observations:a",version=1,zone="zone-a",enforcement_level="declared-blue",
                 formula="decision-bound-boundary-observation-v1")
    scope=dict(actor=operation["actor"],operation_digest=digest_demand_operation(operation,algorithm="sha256"),zone="zone-a",topology_epoch=5)
    decision_raw=b"complete signed historical audit decision"
    observation_raw=b"complete signed actual execution-boundary observation"
    digest=lambda raw:"sha256:"+hashlib.sha256(raw).hexdigest()
    state=dict(deployment_digest=_digest(deployment,"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=scope["operation_digest"],checked_at=1000,expires_at=1007,scope=scope,
        enforcement_point_present=True,enforcement_level="declared-blue",
        decision=dict(scope=scope,decision_id="dec-1",record_digest=digest(decision_raw),decided_at=990,
                      execution_permitted=False,supervision="silent_veto"),
        observation=dict(scope=scope,decision_id="dec-1",decision_digest=digest(decision_raw),
                         boundary_id="pep:1",kind="dispatch",observed_at=991),
        observation_record_digest=digest(observation_raw))
    raw=dict(decision=decision_raw,observation=observation_raw);calls=[]
    class Source:
        def resolve(self,**kw):
            calls.append(kw)
            return AuthenticatedExecutionObservationContext(rfc8785.dumps(state),raw["decision"],raw["observation"],
                b"modeled actual signed decision and boundary identity/observation/absence/route evidence")
    verifier=InstalledExecutionObservationVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),Source(),"sha256")
    return verifier,state,raw,operation,calls


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class InstalledExecutionObservationTests(unittest.TestCase):
    def evaluate(self,v,op):return v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    def test_installed_boundary_classifies_obligation_and_retains_raw_evidence(self):
        v,s,raw,op,calls=fixture();r=self.evaluate(v,op)
        self.assertTrue(r.projection.breach_record_required)
        self.assertEqual(r.enforcement_level,"declared-blue")
        self.assertEqual(r.observation_record_bytes,raw["observation"])
        self.assertEqual(r.decision_record_bytes,raw["decision"])
        self.assertTrue(r.source_evidence_bytes)
        self.assertEqual(r.expires_at,1007)
        self.assertEqual(__import__('json').loads(calls[0]["operation_bytes"]),op)
        with self.assertRaises(TypeError):type(r)()

    def test_missing_observation_has_no_non_execution_claim(self):
        v,s,raw,op,_=fixture();s["observation"]=None;s["observation_record_digest"]=None;raw["observation"]=None
        self.assertEqual(self.evaluate(v,op).projection.effect,"unverified")

    def test_authenticated_absent_decision_and_unenforced_dispatch(self):
        v,s,raw,op,_=fixture();s["decision"]=None;raw["decision"]=None
        s["enforcement_point_present"]=False
        s["observation"].update(decision_id=None,decision_digest=None)
        self.assertTrue(self.evaluate(v,op).projection.bypass)

    def test_wrong_original_bytes_or_current_scope_never_supply_evidence(self):
        from kinetic_trust_library.errors import ValidationError
        for member in ("decision","observation"):
            v,s,raw,op,_=fixture();raw[member]=b"substituted record"
            with self.subTest(member=member),self.assertRaises(ValidationError):self.evaluate(v,op)
        for key,value in (("profile_digest","sha256:"+"0"*64),("checked_at",999),
                          ("expires_at",1000),("enforcement_level","other-level")):
            v,s,raw,op,_=fixture();s[key]=value
            with self.subTest(key=key),self.assertRaises(ValidationError):self.evaluate(v,op)
        v,s,raw,op,_=fixture();op["parameters"]["amount"]=6
        with self.assertRaises(ValidationError):self.evaluate(v,op)

    def test_future_observation_and_unhealthy_clock_are_rejected(self):
        from kinetic_trust_library.errors import ValidationError
        v,s,raw,op,_=fixture();s["observation"]["observed_at"]=1001
        with self.assertRaises(ValidationError):self.evaluate(v,op)
        with self.assertRaises(ValidationError):v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=False)

    def test_misbound_real_observation_retained_but_not_admitted_as_effect(self):
        v,s,raw,op,_=fixture();s["observation"]["decision_id"]="another-decision"
        r=self.evaluate(v,op)
        self.assertEqual(r.projection.effect,"unverified")
        self.assertFalse(r.projection.reportable_as_not_executed)
