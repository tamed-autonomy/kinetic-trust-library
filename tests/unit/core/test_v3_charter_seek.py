import json
import unittest
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


def fixture(citations=("rec-001","rec-002","rec-003"),bound=("r-tool-write",)):
    from kinetic_trust_library.v3.charter_seek import assess_charter_seek
    filing=dict(id="seek:a",anchor="audit:filing",lineage="lineage:7",rule_id="r-tool-write",rule_version=1,
        filed_at=100*86400,records_cited=citations)
    records=tuple(dict(id="rec-00"+str(i),anchor="audit:record:"+str(i),rule_id="r-tool-write",rule_version=1,
        occurred_at=95*86400+i,status="current") for i in range(1,5))
    kwargs=dict(filing=filing,rule_id="r-tool-write",rule_version=1,bound_rules=bound,records=records,
        required_records=3,window_seconds=30*86400,attend_seconds=14*86400,published_route="route:amendment",
        dispute_route="route:zone-dispute",authority="authority:governance",window_start_inclusive=False,deadline_inclusive=False)
    return assess_charter_seek(**kwargs),kwargs


class CharterSeekTests(unittest.TestCase):
    def test_published_route_open_count_empty_and_unbound_boundaries(self):
        source=json.loads((Path(__file__).parents[3]/"spec/proposals/charter-amendment-v1.json").read_text())
        for case in source["vectors"][:4]:
            given=case["given"];r,_=fixture(tuple(given["filing"]["recordsCited"]),tuple(given["lineage"]["boundBy"]))
            with self.subTest(case=case["id"]):
                self.assertEqual(r.is_seek,case["expect"]["isSeek"])
                self.assertEqual(r.route_open,case["expect"].get("routeOpen",False))
                self.assertTrue(r.council_route_remains);self.assertFalse(r.breach_by_lineage)
                self.assertFalse(r.council_threshold_applied);self.assertFalse(r.action_permitted)
        r,_=fixture(("rec-001","rec-002"));self.assertEqual(r.eligible_count,2)

    def test_actual_records_rule_window_status_and_duplicates(self):
        from kinetic_trust_library.v3.charter_seek import assess_charter_seek
        r,k=fixture();records=list(k["records"])
        records[0]=dict(records[0],rule_id="other-rule")
        k["records"]=tuple(records);self.assertFalse(assess_charter_seek(**k).route_open)
        r,k=fixture();records=list(k["records"]);records[0]=dict(records[0],status="withdrawn")
        k["records"]=tuple(records);self.assertFalse(assess_charter_seek(**k).route_open)
        r,k=fixture();records=list(k["records"]);records[0]=dict(records[0],occurred_at=70*86400)
        k["records"]=tuple(records);self.assertFalse(assess_charter_seek(**k).route_open)
        k["window_start_inclusive"]=True;self.assertTrue(assess_charter_seek(**k).route_open)
        with self.assertRaises(ValidationError):fixture(("rec-001",)*3)

    def test_record_citing_refusal_attends_and_remains_contestable(self):
        from kinetic_trust_library.v3.charter_seek import assess_authority_attendance
        seek,_=fixture()
        response=dict(id="response:1",authority="authority:governance",filing_anchor="audit:filing",kind="refusal",
            published_at=109*86400,publication_anchor="audit:response",record_answers=tuple(dict(record_id=i,answer_ref="answer:"+i) for i in seek.records_cited))
        r=assess_authority_attendance(seek,responses=(response,),evaluated_at=110*86400)
        self.assertTrue(r.attended);self.assertTrue(r.refusal_contestable);self.assertEqual(r.contest_route,"route:zone-dispute")
        self.assertFalse(r.authority_breach_required);self.assertFalse(r.notice_period_opened)
        response["record_answers"]=response["record_answers"][:-1]
        r=assess_authority_attendance(seek,responses=(response,),evaluated_at=115*86400)
        self.assertFalse(r.attended);self.assertTrue(r.authority_breach_required)
        self.assertTrue(r.refusal_contestable)

    def test_absent_or_late_attendance_preserves_authority_debt(self):
        from kinetic_trust_library.v3.charter_seek import assess_authority_attendance
        seek,_=fixture()
        self.assertFalse(assess_authority_attendance(seek,responses=(),evaluated_at=113*86400).authority_breach_required)
        self.assertTrue(assess_authority_attendance(seek,responses=(),evaluated_at=115*86400).authority_breach_required)
        response=dict(id="response:late",authority="authority:governance",filing_anchor="audit:filing",kind="open-notice",
            published_at=115*86400,publication_anchor="audit:late",record_answers=())
        r=assess_authority_attendance(seek,responses=(response,),evaluated_at=116*86400)
        self.assertTrue(r.attended_late);self.assertFalse(r.attended);self.assertTrue(r.authority_breach_required)

    def test_response_cannot_change_filing_or_authority(self):
        from kinetic_trust_library.v3.charter_seek import assess_authority_attendance
        seek,_=fixture()
        response=dict(id="response:other",authority="authority:other",filing_anchor="audit:filing",kind="open-notice",
            published_at=101*86400,publication_anchor="audit:other",record_answers=())
        with self.assertRaises(ValidationError):assess_authority_attendance(seek,responses=(response,),evaluated_at=102*86400)

    def test_later_notice_preserves_earlier_refusal_and_its_contest(self):
        from kinetic_trust_library.v3.charter_seek import assess_authority_attendance
        seek,_=fixture()
        refusal=dict(id="response:1",authority=seek.authority,filing_anchor=seek.filing_anchor,kind="refusal",
            published_at=101*86400,publication_anchor="audit:refusal",record_answers=tuple(dict(record_id=i,answer_ref="answer:"+i) for i in seek.records_cited))
        notice=dict(id="response:2",authority=seek.authority,filing_anchor=seek.filing_anchor,kind="open-notice",
            published_at=102*86400,publication_anchor="audit:notice",record_answers=())
        r=assess_authority_attendance(seek,responses=(refusal,notice),evaluated_at=103*86400)
        self.assertTrue(r.attended);self.assertTrue(r.notice_period_opened);self.assertTrue(r.refusal_contestable)

    def test_explicit_deadline_edge_and_no_duty_for_below_threshold_filing(self):
        from kinetic_trust_library.v3.charter_seek import assess_charter_seek,assess_authority_attendance
        seek,k=fixture()
        self.assertTrue(assess_authority_attendance(seek,responses=(),evaluated_at=114*86400).authority_breach_required)
        k["deadline_inclusive"]=True;inclusive=assess_charter_seek(**k)
        self.assertFalse(assess_authority_attendance(inclusive,responses=(),evaluated_at=114*86400).authority_breach_required)
        below,_=fixture(("rec-001",))
        self.assertFalse(assess_authority_attendance(below,responses=(),evaluated_at=120*86400).authority_breach_required)

    def test_published_am16_procedural_chain_preserves_forward_binding(self):
        from kinetic_trust_library.v3.charter_seek import assess_authority_attendance
        from kinetic_trust_library.v3.charter_amendment import assess_forward_amendment
        from tests.unit.core.test_v3_charter_amendment import fixture as amendment_fixture
        source=json.loads((Path(__file__).parents[3]/"spec/proposals/charter-amendment-v1.json").read_text())
        case=next(c for c in source["vectors"] if c["id"]=="AM16-governed-change-reaches-enforcement-without-bypass")
        steps=case["given"]["steps"];seek,_=fixture(tuple(steps[0]["seek"]["recordsCited"]))
        response=dict(id="response:notice",authority=seek.authority,filing_anchor=seek.filing_anchor,kind="open-notice",
            published_at=(100+steps[1]["authority"]["day"])*86400,publication_anchor="audit:notice",record_answers=())
        attended=assess_authority_attendance(seek,responses=(response,),evaluated_at=111*86400)
        r=amendment_fixture();gov=steps[5]["governorAct"]
        r.update(rule_id="r-tool-write",notice_opened_at=response["published_at"],notice_closed_at=140*86400,
            voted_at=(100+steps[3]["vote"]["day"])*86400,ratification_closed_at=(100+gov["day"])*86400,
            governor_demand=gov["A"],governor_capacity=gov["E_trust"],approvers=tuple("council:"+str(i) for i in range(1,6)))
        amended=assess_forward_amendment(r,evaluation_started_at=(100+int(steps[6]["nextAct"]["evaluationBegan"].split()[-1]))*86400,
            council_members=r["approvers"],measurement_sources=("zone-records",),expected_rule_id="r-tool-write",expected_from_version=1,
            notice_minimum_seconds=30*86400,ratification_minimum_seconds=14*86400,approval_numerator=4,approval_denominator=5)
        self.assertEqual(seek.route_open,case["expect"]["routeOpen"]);self.assertEqual(attended.attended,case["expect"]["attended"])
        self.assertEqual(amended.version_for_evaluation,case["expect"]["nextAct"]["ruleVersion"])
        self.assertFalse(seek.action_permitted);self.assertFalse(attended.action_permitted);self.assertFalse(amended.action_permitted)
