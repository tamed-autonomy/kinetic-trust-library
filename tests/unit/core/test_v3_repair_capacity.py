"""Demonstrated capacity counts durable anchored throughput under backlog."""
import unittest
from fractions import Fraction
from dataclasses import replace
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.repair_capacity import RepairCapacityRecord,RepairCapacityWindow,project_repair_capacity


def record(number,at,repairer="root:repairer",hard=True,verified=True):
    return RepairCapacityRecord("sha256:"+format(number,"064x"),repairer,at,hard,verified)


class RepairCapacityTests(unittest.TestCase):
    def test_same_instant_records_require_authenticated_order(self):
        soft=record(1,".4",hard=False)
        hard=record(2,".4")
        window=RepairCapacityWindow(0,1,True,(soft,hard))
        with self.assertRaises(ValidationError):
            project_repair_capacity(declared_capacity=4,windows=(window,),repairer_interval=1)
        ordered=replace(window,records=(replace(soft,anchor_order=1),replace(hard,anchor_order=2)))
        self.assertEqual(project_repair_capacity(declared_capacity=4,windows=(ordered,),repairer_interval=1).effective_capacity,2)
        reversed_order=replace(window,records=(replace(soft,anchor_order=2),replace(hard,anchor_order=1)))
        self.assertEqual(project_repair_capacity(declared_capacity=4,windows=(reversed_order,),repairer_interval=1).effective_capacity,1)

    def test_demonstrated_capacity_bounds_declared_rate(self):
        windows=tuple(RepairCapacityWindow(n,n+1,True,(record(2*n+1,n+Fraction(1,10)),record(2*n+2,n+Fraction(1,5)))) for n in range(3))
        value=project_repair_capacity(declared_capacity=4,windows=windows)
        self.assertEqual(value.demonstrated_capacity,2)
        self.assertEqual(value.effective_capacity,2)
        self.assertEqual(value.eligible_record_counts,(2,2,2))

    def test_repairer_interval_does_not_undo_actual_anchoring(self):
        window=RepairCapacityWindow(0,1,True,(record(1,".4"),))
        value=project_repair_capacity(declared_capacity=4,windows=(window,),repairer_interval=1,
            prior_hard_times=(("root:repairer",0),))
        self.assertEqual(value.anchored_record_counts,(1,))
        self.assertEqual(value.eligible_record_counts,(0,))
        self.assertEqual(value.effective_capacity,0)

    def test_unknown_and_zero_capacity_without_demonstrated_history(self):
        self.assertIsNone(project_repair_capacity(declared_capacity=4,windows=()).effective_capacity)
        self.assertIsNone(project_repair_capacity(declared_capacity=None,windows=()).effective_capacity)
        self.assertEqual(project_repair_capacity(declared_capacity=0,windows=()).effective_capacity,0)
        self.assertEqual(project_repair_capacity(declared_capacity=4,windows=(),accountable_roots=0).effective_capacity,0)

    def test_intervals_are_contiguous_and_record_anchors_unique(self):
        first=RepairCapacityWindow(0,1,True,(record(1,".4"),))
        second=RepairCapacityWindow(2,3,True,(record(2,"2.4"),))
        with self.assertRaises(ValidationError):project_repair_capacity(declared_capacity=4,windows=(first,second))
        with self.assertRaises(ValidationError):project_repair_capacity(declared_capacity=4,windows=(replace(first,records=(record(1,".4"),record(1,".5"))),))
        invalid=replace(first,records=(record(1,".4",verified=False),))
        self.assertEqual(project_repair_capacity(declared_capacity=4,windows=(invalid,)).effective_capacity,0)

    def test_only_backlogged_windows_bound_demonstrated_capacity(self):
        windows=(RepairCapacityWindow(0,1,False,()),RepairCapacityWindow(1,2,True,(record(1,"1.4"),)))
        self.assertEqual(project_repair_capacity(declared_capacity=4,windows=windows).demonstrated_capacity,1)
