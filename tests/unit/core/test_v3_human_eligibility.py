import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.human_eligibility import InstalledHumanEligibilityVerifier,AuthenticatedHumanContext


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class HumanEligibilityTests(unittest.TestCase):
    def test_current_qualifications_grants_delegation_and_correction(self):
        import rfc8785
        from kinetic_trust_library.v3 import _human_reference as h
        from tests.unit.core._v3_human_fixture import human_fixture
        operation=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())["operation"]
        f=human_fixture(operation)
        deployment=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())["deployment_profile"]
        deployment["human_policy"]=dict(mode="operation-eligibility-v1",profile_id=f["profile"]["profile_id"],version=2,digest=h.digest(f["profile"],2))
        class Adapter:
            def resolve(self,**kwargs):return AuthenticatedHumanContext(rfc8785.dumps(f["request"]),rfc8785.dumps(f["context"]),b"fixture-authenticated-registry-and-evidence")
        verifier=InstalledHumanEligibilityVerifier(rfc8785.dumps(deployment),rfc8785.dumps(f["profile"]),Adapter(),2,"zone:alpha","service-recovery")
        def evaluate():return verifier.evaluate(rfc8785.dumps(f["claims"]),actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        result=evaluate();self.assertEqual(result.reason,"HUMAN_ELIGIBLE")
        body=json.loads(result.decision_body_bytes)
        self.assertEqual(len(body["evidence_refs"]),2)
        self.assertNotIn("e_base",body)
        f["claims"]["evidence"][0]["outcome"]="unsatisfied"
        record=f["claims"]["evidence"][0]
        f["context"]["active_evidence"][record["evidence_id"]]=h.digest(record,2)
        denied=evaluate();self.assertEqual(denied.reason,"HUMAN_INELIGIBLE")
        self.assertEqual(len(json.loads(denied.decision_body_bytes)["evidence_refs"]),1)
        record.update(outcome="satisfied",version=3)
        self.assertEqual(evaluate().reason,"HUMAN_INELIGIBLE")
        f["context"]["active_evidence"][record["evidence_id"]]=h.digest(record,2);f["context"]["state_epoch"]+=1
        self.assertEqual(evaluate().reason,"HUMAN_ELIGIBLE")
        delegation=f["claims"]["delegations"].pop()
        self.assertEqual(evaluate().reason,"HUMAN_INELIGIBLE")
        f["claims"]["delegations"].append(delegation)
        delegation["expires_at"]=1300
        f["context"]["active_delegations"][delegation["delegation_id"]]=h.digest(delegation,2)
        self.assertEqual(evaluate().reason,"HUMAN_INELIGIBLE")
        delegation["expires_at"]=1150
        f["context"]["active_delegations"][delegation["delegation_id"]]=h.digest(delegation,2)
        f["claims"]["person_score"]=100
        self.assertEqual(evaluate().reason,"HUMAN_INVALID")
        f["claims"].pop("person_score")
        from kinetic_trust_library.errors import ValidationError
        missing_policy={k:v for k,v in deployment.items() if k!="human_policy"}
        with self.assertRaises(ValidationError):
            InstalledHumanEligibilityVerifier(rfc8785.dumps(missing_policy),rfc8785.dumps(f["profile"]),Adapter(),2,"zone:alpha","service-recovery")
        f["context"]["checked_at"]=999
        self.assertEqual(evaluate().reason,"HUMAN_UNAVAILABLE")


if __name__=="__main__":unittest.main()
