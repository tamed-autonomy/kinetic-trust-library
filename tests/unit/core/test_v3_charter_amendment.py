import json
import hashlib
import unittest
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


def fixture():
    return dict(id="amendment:a",rule_id="rule:tool-write",from_version=1,to_version=2,
        proposal_digest="sha256:"+"a"*64,records_cited=("record:1","record:2"),changes_constant=False,
        measurements_cited=(),effects=("ordinary-change",),notice_opened_at=0,notice_closed_at=30*86400,
        voted_at=31*86400,ratification_closed_at=45*86400,approvers=("council:1","council:2","council:3","council:4"),
        vote_anchor="audit:vote",governor_anchor="audit:governor",governor_decision="permit",governor_demand=25,governor_capacity=72)


class CharterAmendmentTests(unittest.TestCase):
    def evaluate(self,record=None,started=46*86400,**overrides):
        from kinetic_trust_library.v3.charter_amendment import assess_forward_amendment
        policy=dict(notice_minimum_seconds=30*86400,ratification_minimum_seconds=14*86400,approval_numerator=4,approval_denominator=5)
        policy.update(overrides)
        return assess_forward_amendment(fixture() if record is None else record,evaluation_started_at=started,
            council_members=tuple("council:"+str(i) for i in range(1,6)),measurement_sources=("zone-records",),
            expected_rule_id="rule:tool-write",expected_from_version=1,**policy)

    def test_forward_only_and_ambiguous_timestamp_has_no_fallback(self):
        r=self.evaluate();self.assertTrue(r.valid);self.assertEqual(r.version_for_evaluation,2)
        self.assertFalse(r.action_permitted);self.assertFalse(r.retroactive_breach);self.assertFalse(r.reevaluate_inflight)
        self.assertEqual(self.evaluate(started=44*86400).version_for_evaluation,1)
        self.assertIsNone(self.evaluate(started=45*86400).version_for_evaluation)

    def test_missing_records_or_constant_measurements_preserve_old_rule(self):
        record=fixture();record["records_cited"]=()
        r=self.evaluate(record);self.assertFalse(r.valid);self.assertEqual(r.version_for_evaluation,1)
        record=fixture();record["changes_constant"]=True
        self.assertFalse(self.evaluate(record).valid)
        record["measurements_cited"]=(dict(id="measure:a",source="zone-records",anchor="audit:measure"),)
        self.assertTrue(self.evaluate(record).valid)
        record["measurements_cited"][0]["source"]="source:unapproved"
        self.assertFalse(self.evaluate(record).valid)

    def test_full_council_basis_and_minimum_clocks(self):
        for patch in (dict(approvers=("council:1","council:2","council:3")),dict(notice_closed_at=29*86400),
                dict(ratification_closed_at=44*86400),dict(governor_decision="deny"),dict(governor_demand=80),dict(governor_capacity=0)):
            with self.subTest(patch=patch):self.assertFalse(self.evaluate(dict(fixture(),**patch)).valid)
        with self.assertRaises(ValidationError):self.evaluate(dict(fixture(),approvers=("council:1",)*4))

    def test_stricter_installed_charter_cannot_be_replaced_by_baseline(self):
        self.assertFalse(self.evaluate(notice_minimum_seconds=90*86400).valid)
        self.assertFalse(self.evaluate(approval_numerator=1,approval_denominator=1).valid)
        self.assertFalse(self.evaluate(ratification_minimum_seconds=30*86400).valid)
        with self.assertRaises(ValidationError):self.evaluate(notice_minimum_seconds=0)
        with self.assertRaises(ValidationError):self.evaluate(approval_numerator=1,approval_denominator=2)

    def test_predecessor_and_reference_inventory_cannot_be_substituted(self):
        with self.assertRaises(ValidationError):self.evaluate(dict(fixture(),from_version=3,to_version=4))
        with self.assertRaises(ValidationError):self.evaluate(dict(fixture(),rule_id="rule:other"))
        with self.assertRaises(ValidationError):self.evaluate(dict(fixture(),records_cited=("record:1","record:1")))
        with self.assertRaises(ValidationError):self.evaluate(dict(fixture(),effects=("unclassified-effect",)))

    def test_protected_classified_changes_are_void_even_after_unanimous_vote(self):
        from kinetic_trust_library.v3.charter_amendment import PROTECTED_EFFECTS
        for effect in PROTECTED_EFFECTS:
            r=self.evaluate(dict(fixture(),effects=(effect,),approvers=tuple("council:"+str(i) for i in range(1,6))))
            with self.subTest(effect=effect):
                self.assertTrue(r.void);self.assertFalse(r.valid);self.assertEqual(r.version_for_evaluation,1)

    def test_published_record_and_capacity_boundaries(self):
        raw=(Path(__file__).parents[3]/"spec/proposals/charter-amendment-v1.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),"27173e2e3c94ce62a15e53d97e1d22234192f3dae53d3e546f5ae8852ed7391b")
        source=json.loads(raw)
        cases={c["id"]:c for c in source["vectors"]}
        for name in ("AM07-amendment-cites-no-record-invalid","AM08-constant-change-cites-no-measurement-invalid","AM09-constant-change-cites-measurement-valid","AM11-amendment-exceeds-governor-E-not-made"):
            c=cases[name];a=c["given"]["amendment"];record=fixture()
            record.update(records_cited=tuple(a["recordsCited"]),changes_constant=name.startswith(("AM08","AM09")))
            record["measurements_cited"]=tuple(dict(m,anchor="audit:"+m["id"]) for m in a.get("measurementsCited",[]))
            g=c["given"].get("governor")
            if g:record.update(governor_demand=g["A"],governor_capacity=g["E_trust"])
            expected=c["expect"].get("valid",c["expect"].get("made",False))
            if name.startswith("AM11"):expected=False
            with self.subTest(case=name):self.assertEqual(self.evaluate(record).valid,expected)
