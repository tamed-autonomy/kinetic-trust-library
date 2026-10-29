"""Repair record preconditions and exact re-entry cost, not ceremony evidence."""
import unittest
from decimal import Decimal,localcontext
from dataclasses import replace
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.repair import ReconciliationFacts,project_reentry


def facts(**changes):
    values=dict(breach_anchor="sha256:"+"1"*64,record_breach_anchor="sha256:"+"1"*64,
        breaching_terminator="terminator:a",required_parties=("terminator:a","terminator:b"),
        record_parties=("terminator:a","terminator:b"),acknowledged_by="terminator:a",residual_harm="unrepairable",
        verifier="verifier:v",oracle="oracle:o",independent_of=("terminator:a","terminator:b"),
        current_anchor_verified=True,anchored_at=950,breached_at=900,declined_parties=(),open_to=(),route_followed=False,
        route_published=True,standing_at_breach=Decimal(80),declared_delta=Decimal(".25"),previous_delta=Decimal(0),
        hard_entry=True,unrepaired_declared=False,declared_unrepaired_raise=Decimal(".15"))
    values.update(changes)
    return ReconciliationFacts(**values)


class ReentryTests(unittest.TestCase):
    def test_record_cost_and_repeat_breach(self):
        result=project_reentry(facts())
        self.assertTrue(result.record_valid)
        self.assertEqual(result.ceiling,60)
        self.assertEqual(project_reentry(facts(standing_at_breach=70,previous_delta=Decimal(".3"))).ceiling,49)
        self.assertEqual(project_reentry(facts(unrepaired_declared=True)).ceiling,48)
        self.assertEqual(project_reentry(facts(previous_delta=Decimal(".4"),unrepaired_declared=True)).delta,Decimal(".55"))

    def test_record_integrity_and_all_parties_independence(self):
        for patch in (dict(record_breach_anchor="sha256:"+"2"*64),dict(acknowledged_by=None),dict(residual_harm=None),
            dict(current_anchor_verified=False),dict(verifier="terminator:a"),dict(verifier="oracle:o"),
            dict(independent_of=("terminator:a",)),dict(record_parties=("terminator:a",)),dict(anchored_at=899)):
            with self.subTest(patch=patch):self.assertFalse(project_reentry(facts(**patch)).record_valid)

    def test_declining_retains_route_and_open_record(self):
        declined=facts(declined_parties=("terminator:b",),open_to=("terminator:b",),route_followed=True,residual_harm="undeclared")
        self.assertTrue(project_reentry(declined).record_valid)
        for patch in (dict(route_followed=False),dict(route_published=False),dict(open_to=())):
            self.assertFalse(project_reentry(replace(declined,**patch)).record_valid)

    def test_hard_floor_and_exact_arithmetic(self):
        with self.assertRaises(ValidationError):project_reentry(facts(declared_delta=Decimal(".09")))
        with self.assertRaises(ValidationError):project_reentry(facts(declared_unrepaired_raise=0))
        with localcontext() as context:
            context.prec=4
            result=project_reentry(facts(standing_at_breach=Decimal("79.999999"),declared_delta=Decimal(".123456")))
        self.assertEqual(result.ceiling,Decimal("70.123519123456"))
