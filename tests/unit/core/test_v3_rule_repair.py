"""Rule repair closes by an anchored amendment, never by elapsed time."""
import unittest
from copy import deepcopy
from kinetic_trust_library.v3.rule_repair import project_rule_repairs
from kinetic_trust_library.errors import ValidationError


def fixture():
    h=lambda char:"sha256:"+char*64
    record=dict(anchor=h("a"),pattern_id="pattern:profile",profile_digest=h("1"),
        cause="Published admission exceeded durable repair capacity",anchored_at=10,current_anchor_verified=True)
    amendment=dict(anchor=h("b"),record_anchor=h("a"),pattern_id="pattern:profile",profile_digest=h("1"),
        previous_definition_digest=h("1"),amended_definition_digest=h("2"),
        anchored_at=20,current_anchor_verified=True,ratified=True,parties=["authority:zone","lineage:a"],
        acknowledged_by="authority:zone",residual_harm="declared: unresolved queue",
        verifier="verifier:independent",oracle="oracle:zone",independent_of=["authority:zone","lineage:a"],
        declined_parties=[],open_to=["lineage:a"],route_followed=True,route_published=True,cites=[h("c")])
    pattern=dict(pattern_id="pattern:profile",kind="profile",profile_digest=h("1"),occurrences=2,
        definition_digest=h("1"),previously_triggered=False,
        governing_authority="authority:zone",affected_parties=["lineage:a"],driving_reconciliation_anchors=[h("c")],record=record,amendment=amendment)
    return dict(tier_pattern_id="pattern:profile",patterns=[pattern],
        reconciliation_records=[dict(anchor=h("c"),anchored_at=5,current_anchor_verified=True)])


class RuleRepairTests(unittest.TestCase):
    def project(self,state,required=True):
        return project_rule_repairs(state,recurrence_limit=2,tier_record_required=required,evaluated_at=30,algorithm="sha256")

    def test_amendment_cites_actual_reconciliation_and_closes_only_that_pattern(self):
        state=fixture();result=self.project(state)
        self.assertTrue(result.records_complete)
        self.assertEqual(result.open_patterns,())
        self.assertEqual(result.closed_patterns,("pattern:profile",))
        for field,value in (("cites",[]),("cites",["sha256:"+"d"*64]),("ratified",False),
                            ("current_anchor_verified",False),("record_anchor","sha256:"+"d"*64),
                            ("amended_definition_digest","sha256:"+"1"*64),("previous_definition_digest","sha256:"+"2"*64),
                            ("acknowledged_by",None),("independent_of",[]),("residual_harm",None)):
            broken=deepcopy(state);broken["patterns"][0]["amendment"][field]=value
            self.assertEqual(self.project(broken).open_patterns,("pattern:profile",),field)
        for field,value in (("anchored_at",21),("current_anchor_verified",False)):
            broken=deepcopy(state);broken["reconciliation_records"][0][field]=value
            self.assertEqual(self.project(broken).open_patterns,("pattern:profile",),field)
        unrelated="sha256:"+"d"*64
        state["reconciliation_records"].append(dict(anchor=unrelated,anchored_at=6,current_anchor_verified=True))
        state["patterns"][0]["amendment"]["cites"]=[unrelated]
        self.assertEqual(self.project(state).open_patterns,("pattern:profile",))

    def test_missing_record_does_not_disappear_with_recovery(self):
        state=fixture();state["patterns"][0].update(record=None,amendment=None)
        result=self.project(state,required=False)
        self.assertFalse(result.records_complete)
        self.assertEqual(result.open_patterns,("pattern:profile",))
        state["patterns"][0]["occurrences"]=1
        state["patterns"][0]["previously_triggered"]=True
        self.assertEqual(self.project(state,required=False).open_patterns,("pattern:profile",))
        state["patterns"][0]["previously_triggered"]=False
        self.assertEqual(self.project(state,required=False).open_patterns,())
        self.assertFalse(self.project(state,required=True).records_complete)

    def test_affected_rights_and_independence_remain_in_force(self):
        state=fixture();amendment=state["patterns"][0]["amendment"]
        amendment["declined_parties"]=["lineage:a"];amendment["open_to"]=[]
        self.assertEqual(self.project(state).open_patterns,("pattern:profile",))
        amendment["open_to"]=["lineage:a"]
        self.assertEqual(self.project(state).open_patterns,())
        amendment["verifier"]=amendment["oracle"]
        self.assertEqual(self.project(state).open_patterns,("pattern:profile",))

    def test_incomplete_scope_duplicates_and_future_evidence_do_not_pass(self):
        for mutate in (lambda s:s["patterns"].append(deepcopy(s["patterns"][0])),
                       lambda s:s["reconciliation_records"].append(deepcopy(s["reconciliation_records"][0])),
                       lambda s:s["patterns"][0].update(occurrences=True),
                       lambda s:s["reconciliation_records"][0].update(anchored_at=31)):
            state=fixture();mutate(state)
            with self.assertRaises(ValidationError):self.project(state)
        state=fixture();state["patterns"][0]["record"]["profile_digest"]="sha256:"+"2"*64
        self.assertFalse(self.project(state).records_complete)
        state=fixture();state["tier_pattern_id"]="pattern:missing"
        self.assertFalse(self.project(state).records_complete)


if __name__ == "__main__":unittest.main()
