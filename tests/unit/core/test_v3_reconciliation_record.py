from dataclasses import replace
import unittest
from kinetic_trust_library.v3.reconciliation_record import ReconciliationRecordFacts,project_reconciliation_record
from kinetic_trust_library.errors import ValidationError


def facts(**changes):
    values=dict(cause_anchor="sha256:"+"a"*64,record_cause_anchor="sha256:"+"a"*64,accountable_terminator="person:root",
        required_parties=("person:root","person:counterparty"),record_parties=("person:root","person:counterparty"),
        acknowledged_by="person:root",residual_harm="none-declared",verifier="person:independent",oracle="oracle:1",
        independent_of=("person:root","person:counterparty"),current_anchor_verified=True,anchored_at=950,cause_at=900,
        declined_parties=(),open_to=(),route_followed=False,route_published=True)
    values.update(changes)
    return ReconciliationRecordFacts(**values)


class ReconciliationRecordTests(unittest.TestCase):
    def test_malformed_facts_are_not_authenticated_failures(self):
        for change in (dict(current_anchor_verified=1),dict(required_parties=["person:root"]),
                       dict(record_parties=("person:root","person:root")),dict(cause_anchor="unanchored"),
                       dict(anchored_at=True),dict(cause_at=-1),dict(verifier="")):
            with self.subTest(change=change),self.assertRaises(ValidationError):
                project_reconciliation_record(facts(**change))

    def test_record_must_name_the_actual_cause_and_follow_it(self):
        for change in (dict(record_cause_anchor="sha256:"+"b"*64),dict(anchored_at=899)):
            with self.subTest(change=change):
                self.assertEqual(project_reconciliation_record(facts(**change)).reason,"REPAIR_ANCHOR")

    def test_declining_does_not_remove_the_party_or_open_record_requirement(self):
        for change in (dict(route_published=False),dict(open_to=()),dict(declined_parties=("person:outsider",))):
            f=facts(declined_parties=("person:counterparty",),open_to=("person:counterparty",),route_followed=True)
            with self.subTest(change=change):
                self.assertFalse(project_reconciliation_record(replace(f,**change)).record_valid)

    def test_relationship_record_has_no_breach_delta_or_standing(self):
        result=project_reconciliation_record(facts())
        self.assertTrue(result.record_valid)
        self.assertFalse(hasattr(result,"ceiling"))

    def test_declined_affected_party_can_leave_record_open_without_veto(self):
        f=facts(declined_parties=("person:counterparty",),open_to=("person:counterparty",),route_followed=True,residual_harm="undeclared-unrepairable")
        self.assertTrue(project_reconciliation_record(f).record_valid)
        self.assertFalse(project_reconciliation_record(replace(f,route_followed=False)).record_valid)

    def test_current_anchor_ack_and_independent_non_oracle_verifier_are_required(self):
        for change in (dict(current_anchor_verified=False),dict(acknowledged_by=None),dict(residual_harm=None),
                       dict(verifier="oracle:1"),dict(verifier="person:root"),dict(independent_of=())):
            with self.subTest(change=change):self.assertFalse(project_reconciliation_record(facts(**change)).record_valid)
