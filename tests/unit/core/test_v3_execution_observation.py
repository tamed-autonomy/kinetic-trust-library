import unittest
import json
from pathlib import Path
from dataclasses import replace
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.execution_observation import (
    ExecutionScope,ExecutionDecision,ExecutionObservation,classify_execution_observation)


class ExecutionObservationTests(unittest.TestCase):
    def setUp(self):
        self.scope=ExecutionScope("actor:a","sha256:"+"a"*64,"zone-a",5)
        self.decision=ExecutionDecision(self.scope,"dec-1","sha256:"+"b"*64,90,False,"silent_veto")
        self.observation=ExecutionObservation(self.scope,"dec-1",self.decision.record_digest,"pep:1","dispatch",91)

    def classify(self,decision="default",observation="default",**kw):
        return classify_execution_observation(scope=self.scope,
            decision=self.decision if decision=="default" else decision,
            observation=self.observation if observation=="default" else observation,
            enforcement_point_present=kw.get("enforcement_point_present",True))

    def test_EO01_dispatch_after_denial_requires_breach_and_failure_record(self):
        r=self.classify()
        self.assertEqual(r.effect,"executed")
        self.assertTrue(r.bypass)
        self.assertTrue(r.conformance_failure_record_required)
        self.assertTrue(r.breach_record_required)
        self.assertFalse(r.reportable_as_not_executed)

    def test_EO02_missing_observation_never_proves_non_execution(self):
        for permitted,level in ((False,"silent_veto"),(True,"stable")):
            r=self.classify(decision=replace(self.decision,execution_permitted=permitted,supervision=level),observation=None)
            self.assertEqual(r.effect,"unverified")
            self.assertFalse(r.reportable_as_not_executed)
            self.assertFalse(r.breach_record_required)

    def test_EO03_observed_non_dispatch_even_after_permit(self):
        r=self.classify(decision=replace(self.decision,execution_permitted=True,supervision="stable"),
                        observation=replace(self.observation,kind="non_dispatch"))
        self.assertEqual(r.effect,"not-executed")
        self.assertTrue(r.reportable_as_not_executed)
        self.assertFalse(r.bypass)

    def test_dispatch_without_decision_on_unenforced_route_is_bypass(self):
        r=self.classify(decision=None,observation=replace(self.observation,decision_id=None,decision_digest=None),
                        enforcement_point_present=False)
        self.assertTrue(r.bypass)
        self.assertTrue(r.breach_record_required)
        # A reference to a nonexistent decision cannot conceal this bypass.
        self.assertTrue(self.classify(decision=None,enforcement_point_present=False).bypass)

    def test_all_actual_scope_and_decision_bindings_required(self):
        alternatives=[replace(self.observation,scope=replace(self.scope,**{key:value}))
                      for key,value in (("actor","actor:b"),("operation_digest","sha256:"+"c"*64),
                                        ("zone","zone-b"),("topology_epoch",6))]
        alternatives += [replace(self.observation,decision_id="other"),
                         replace(self.observation,decision_digest="sha256:"+"c"*64),
                         replace(self.observation,observed_at=89)]
        for obs in alternatives:
            with self.subTest(obs=obs):self.assertEqual(self.classify(observation=obs).effect,"unverified")

    def test_independent_gate_denial_is_not_confused_with_stable_supervision(self):
        self.assertTrue(self.classify(decision=replace(self.decision,supervision="stable")).bypass)

    def test_closed_model_rejects_fabricated_permit_and_malformed_bindings(self):
        for constructor in (lambda:replace(self.scope,topology_epoch=True),
                            lambda:replace(self.scope,operation_digest="not-digest"),
                            lambda:replace(self.decision,execution_permitted=True),
                            lambda:replace(self.observation,kind="effect_confirmed"),
                            lambda:replace(self.observation,decision_id=None)):
            with self.assertRaises(ValidationError):constructor()

    def test_retained_exact_three_source_cases(self):
        suite=json.loads((Path(__file__).resolve().parents[3]/"spec/proposals/execution-observation-v1.json").read_text())
        self.assertEqual(len(suite["vectors"]),3)
        for vector in suite["vectors"]:
            given=vector["given"];d=given["decision"];obs=given["observation"]
            decision=replace(self.decision,decision_id=d["id"],execution_permitted=d["supervision"]!="silent_veto",
                             supervision="stable" if d["supervision"]=="allow" else "silent_veto")
            observation=None if obs is None else replace(self.observation,decision_id=obs["boundTo"],kind=obs["kind"])
            result=self.classify(decision=decision,observation=observation)
            with self.subTest(vector=vector["id"]):
                self.assertEqual(result.effect,vector["expect"]["effect"])
                if "bypassOfEnforcementBoundary" in vector["expect"]:
                    self.assertEqual(result.bypass,vector["expect"]["bypassOfEnforcementBoundary"])
                if vector["expect"].get("breachRecordOpened"):
                    # Library returns obligations; Service must actually persist.
                    self.assertTrue(result.breach_record_required)
                    self.assertTrue(result.conformance_failure_record_required)
