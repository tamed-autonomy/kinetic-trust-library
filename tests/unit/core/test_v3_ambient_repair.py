"""Exact ambient repair accounting; input authority remains external."""
import unittest
from fractions import Fraction
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.ambient_repair import project_ambient_window,reference_criticality_valid


class AmbientRepairTests(unittest.TestCase):
    def test_stock_is_uncapped_while_arrival_is_lineage_capped(self):
        value=project_ambient_window(prior_stock=0,arrivals=(("lineage:x",12),("lineage:y",1)),anchored_weight=0,
            effective_capacity=4,criticality=2,single_lineage_share=".25")
        self.assertEqual(value.open_stock,13)
        self.assertEqual(value.arrival,2)
        self.assertEqual(value.utilization,Fraction(1,2))
        self.assertEqual(value.local_index,1)
        with self.assertRaises(ValidationError):
            project_ambient_window(prior_stock=0,arrivals=(("lineage:x",6),("lineage:x",6)),anchored_weight=0,
                effective_capacity=4,criticality=2,single_lineage_share=".25")

    def test_time_and_restart_do_not_close_stock_or_clear_debt(self):
        prior=0;bank=0
        expected=(2,5,5,5,4)
        for index,(arrival,closed) in enumerate(((2,0),(3,0),(0,0),(0,0),(0,1))):
            result=project_ambient_window(prior_stock=prior,arrivals=(("lineage:x",arrival),),anchored_weight=closed,
                effective_capacity=4,criticality=2,single_lineage_share=1,prior_banked_excess=bank)
            self.assertEqual(result.open_stock,expected[index])
            prior,bank=result.open_stock,result.banked_excess
        self.assertEqual(bank,Fraction(1,2))
        cleared=project_ambient_window(prior_stock=prior,arrivals=(),anchored_weight=1,effective_capacity=4,
            criticality=2,single_lineage_share=1,prior_banked_excess=bank,retired_excess=bank)
        self.assertEqual(cleared.banked_excess,0)
        with self.assertRaises(ValidationError):
            project_ambient_window(prior_stock=prior,arrivals=(),anchored_weight=0,effective_capacity=4,
                criticality=2,single_lineage_share=1,prior_banked_excess=bank,retired_excess=bank)

    def test_unknown_zero_and_no_root_capacity_have_distinct_meanings(self):
        for capacity,roots,known in ((None,1,False),(0,1,True),(4,0,True)):
            value=project_ambient_window(prior_stock=1,arrivals=(),anchored_weight=0,effective_capacity=capacity,
                criticality=2,single_lineage_share=1,accountable_roots=roots)
            self.assertEqual(value.capacity_known,known)
            self.assertTrue(value.saturated)
            self.assertIsNone(value.utilization)
            self.assertEqual(value.supervision_floor,"assisted")
            self.assertEqual(value.consequential_hosting_forbidden,known)

    def test_enclosing_index_is_heard_without_rewriting_local_stock(self):
        value=project_ambient_window(prior_stock=0,arrivals=(),anchored_weight=0,effective_capacity=4,
            criticality=2,single_lineage_share=1,enclosing_indices=(Fraction(3,2),))
        self.assertEqual(value.local_index,0)
        self.assertEqual(value.heard_index,Fraction(3,2))
        self.assertEqual(value.open_stock,0)
        self.assertEqual(value.banked_excess,0)

    def test_durable_growth_is_distinct_from_observed_stock_change(self):
        value=project_ambient_window(prior_stock=10,arrivals=(("lineage:x",2),("lineage:y",1)),anchored_weight=4,
            effective_capacity=2,criticality=2,single_lineage_share=1)
        self.assertTrue(value.durable_capacity_exceeded)
        self.assertTrue(value.saturated)
        self.assertFalse(value.consequential_hosting_forbidden)
        self.assertEqual(value.supervision_floor,"stable")
        self.assertEqual(value.stock_change,-1)
        self.assertEqual(value.open_stock,9)

    def test_reference_criticality_uses_exact_inequality(self):
        self.assertFalse(reference_criticality_valid(2,".5"))
        self.assertTrue(reference_criticality_valid(4,".5"))
        self.assertFalse(reference_criticality_valid(2,".25"))
        self.assertTrue(reference_criticality_valid(Fraction(2000001,1000000),".25"))
