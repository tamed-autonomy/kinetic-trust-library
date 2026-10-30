import hashlib
import json
import unittest
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


class RecognitionTests(unittest.TestCase):
    def test_exact_source_recognition_and_class_standing_boundaries(self):
        from kinetic_trust_library.v3.recognition import assess_recognition_clause
        from kinetic_trust_library.v3.charter_amendment import assess_forward_amendment
        from tests.unit.core.test_v3_charter_amendment import fixture
        raw=(Path(__file__).parents[3]/"spec/proposals/recognition-v1.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),"22a313c5f432ba99487f1bb759ea3e50255f95a019b3d33d73382dce2e2d0c2d")
        cases={c["id"]:c for c in json.loads(raw)["vectors"]}
        rc1=cases["RC01-recognized-local-rule-as-membership-condition-is-void"]
        r=assess_recognition_clause("recognition-membership-condition")
        self.assertEqual(r.clause_void,rc1["expect"]["clauseVoid"])
        self.assertEqual(r.term_created,rc1["expect"]["termCreated"]);self.assertFalse(r.obligation_created)
        rc3=cases["RC03-amendment-removing-standing-to-object-is-void"]
        record=fixture();record.update(effects=("remove-class-amendment-standing","remove-class-objection-standing"),
            approvers=tuple("member:"+str(i) for i in range(19)))
        amended=assess_forward_amendment(record,evaluation_started_at=46*86400,council_members=tuple("member:"+str(i) for i in range(20)),
            measurement_sources=("zone-records",),expected_rule_id=record["rule_id"],expected_from_version=1,
            notice_minimum_seconds=30*86400,ratification_minimum_seconds=14*86400,approval_numerator=4,approval_denominator=5)
        self.assertEqual(amended.void,rc3["expect"]["amendmentVoid"]);self.assertFalse(amended.valid)

    def test_own_zone_coordination_adoption_and_withdrawal_create_no_term(self):
        from kinetic_trust_library.v3.recognition import project_coordination_history
        source=json.loads((Path(__file__).parents[3]/"spec/proposals/recognition-v1.json").read_text())
        case=next(c for c in source["vectors"] if c["id"].startswith("RC02"));g=case["given"]
        acts=tuple(dict(id="act:"+str(i),anchor="audit:"+str(i),sequence=i,occurred_at=0 if i==0 else 30*86400,
            zone=a["zone"],coordination=a["what"],kind=a["kind"]) for i,a in enumerate(g["acts"]))
        args=dict(zone=g["acts"][0]["zone"],coordination=g["acts"][0]["what"],
            offered_coordination=tuple(g["agreement"]["offeredCoordination"]),evaluated_at=30*86400)
        self.assertTrue(project_coordination_history(acts=acts[:1],**args).adopted)
        r=project_coordination_history(acts=acts,**args)
        self.assertFalse(r.adopted);self.assertEqual(r.adoption_is_agreement_term,case["expect"]["adoptionIsTerm"])
        self.assertEqual(r.withdrawal_is_breach,case["expect"]["withdrawalIsBreach"])
        self.assertFalse(r.changes_agreement);self.assertFalse(r.action_permitted)

    def test_foreign_reordered_or_future_coordination_act_is_not_own_adoption(self):
        from kinetic_trust_library.v3.recognition import project_coordination_history
        a=dict(id="act:1",anchor="audit:1",sequence=1,occurred_at=100,zone="zone-b",coordination="sensor:v2",kind="adopt")
        kwargs=dict(zone="zone-b",coordination="sensor:v2",offered_coordination=("sensor:v2",),evaluated_at=200)
        for patch in (dict(zone="zone-a"),dict(occurred_at=201),dict(coordination="other"),dict(kind="require-as-membership")):
            with self.subTest(patch=patch),self.assertRaises(ValidationError):project_coordination_history(acts=(dict(a,**patch),),**kwargs)
        with self.assertRaises(ValidationError):project_coordination_history(acts=(a,a),**kwargs)

    def test_recognition_does_not_enable_a_term_by_itself(self):
        from kinetic_trust_library.v3.recognition import assess_recognition_clause
        for effect in ("recognition-only","recognition-obligation","recognition-membership-condition"):
            r=assess_recognition_clause(effect)
            self.assertFalse(r.term_created);self.assertFalse(r.obligation_created)
        with self.assertRaises(ValidationError):assess_recognition_clause("unclassified")
