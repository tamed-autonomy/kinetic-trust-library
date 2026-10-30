import json
import hashlib
import unittest
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


class SoftwareRestrictionTests(unittest.TestCase):
    def project(self,**kw):
        from kinetic_trust_library.v3.software_restrictions import project_software_restrictions
        args=dict(requested={"effectBytes":1024,"affectedObjects":1,"fanoutTargets":1},candidate_ceilings={"effectBytes":1024,"affectedObjects":1,"fanoutTargets":1},
            prior_ceilings={"effectBytes":1024,"affectedObjects":1,"fanoutTargets":1},candidate_supervision="stable",prior_supervision="stable",
            demand="0.2",capacity=1,capacity_known=True,repair_path_verified=True,supervision_available=True)
        return project_software_restrictions(**dict(args,**kw))

    def test_existing_supervision_and_all_magnitude_ceilings_only_tighten(self):
        r=self.project(prior_supervision="regulated",prior_ceilings={"effectBytes":256,"affectedObjects":1,"fanoutTargets":1})
        self.assertEqual(r.supervision,"regulated");self.assertEqual(dict(r.ceilings)["effectBytes"],256)
        self.assertFalse(r.action_permitted)

    def test_missing_repair_or_supervision_withholds_every_magnitude(self):
        for kw in (dict(repair_path_verified=False),dict(supervision_available=False)):
            r=self.project(**kw);self.assertEqual(r.supervision,"silent_veto")
            self.assertEqual(set(dict(r.ceilings).values()),{0});self.assertFalse(r.conditional_candidate)

    def test_earlier_veto_zero_and_over_capacity_are_unconditional(self):
        for kw in (dict(prior_supervision="silent_veto"),dict(capacity=0),dict(demand=2,capacity=1)):
            r=self.project(**kw);self.assertEqual(r.supervision,"silent_veto");self.assertIsNone(r.margin)
        r=self.project(demand=1,capacity=1);self.assertEqual(r.supervision,"silent_veto");self.assertEqual(r.margin,0)

    def test_unknown_bound_boolean_and_negative_magnitude_are_not_zero(self):
        for value in (None,True,-1,1.0):
            with self.subTest(value=value),self.assertRaises(ValidationError):
                self.project(requested={"effectBytes":value,"affectedObjects":1,"fanoutTargets":1})
        with self.assertRaises(ValidationError):self.project(requested={"effectBytes":1})

    def test_unknown_capacity_keeps_assisted_floor(self):
        r=self.project(capacity_known=False);self.assertEqual(r.supervision,"assisted")
        self.assertFalse(r.capacity_known);self.assertFalse(r.action_permitted)

    def test_source_restriction_subset_not_trusted_fixture_authorization(self):
        original=(Path(__file__).parents[3]/"spec/proposals/software-substrate-execution.json").read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(),"2bc1ac15ba1608658dabd392ed60a114dfd6ca9778593a55c11d757a62cf0ebd")
        raw=json.loads(original)
        selected={"S01-current-bound-action","S02-existing-supervision-floor","S03-existing-ceiling","S04-earlier-veto",
            "S28-capacity-unknown-conservative","S29-capacity-veto","S35-repair-path-unverified","S36-supervision-unavailable"}
        for case in raw["vectors"]:
            if case["id"] not in selected:continue
            c=case["request"]["softwareContext"];e=c["candidateEnvelope"]
            r=self.project(requested=c["magnitudes"],candidate_ceilings=e["ceilings"],prior_ceilings=c["existingCeilings"],
                candidate_supervision=e["supervision"],prior_supervision=c["existingSupervision"],demand=e["autonomyDemand"],
                capacity=e["environmentalCapacity"],capacity_known=e["capacityKnown"],
                # Translate the vector's modeled authenticated establishment;
                # a candidate's true assertion cannot replace that source fact.
                repair_path_verified=c["conditions"]["repairPathVerified"] and c["trustedFixtures"]["repairPathVerified"],
                supervision_available=c["conditions"]["supervisionAvailable"] and c["trustedFixtures"]["supervisionAvailable"])
            with self.subTest(case=case["id"]):
                self.assertEqual(r.supervision,case["expect"]["supervision"])
                for name,bound in case["expect"].get("tightenedAtMost",{}).items():self.assertLessEqual(dict(r.ceilings)[name],bound)
                self.assertFalse(r.action_permitted)
