"""Exact directional federation arithmetic, without imported risk or shares."""
from decimal import Decimal
from fractions import Fraction
import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.imported_standing import derive_federation_factor,calculate_imported_standing


CEILINGS=dict(generation=100,ial=95,trajectory=100,adversity=100)


class ImportedStandingTests(unittest.TestCase):
    def standing(self,base=85,**kwargs):
        factor=derive_federation_factor(signed_factor="0.8",receiver_signed=True,**kwargs)
        return calculate_imported_standing(exportable_base=base,factor=factor,source_zone="zone-a",
            receiving_zone="zone-b",ceilings=CEILINGS,root_available=True)

    def test_fd17_and_fd20_use_one_factor_on_exportable_base(self):
        value=self.standing()
        self.assertEqual(value.base_trust,68)
        self.assertEqual(value.raw_base,68)
        self.assertFalse(hasattr(value,"por_share"))
        self.assertFalse(hasattr(value,"peer_share"))
        self.assertEqual(self.standing(80,class_ceiling="0.7").base_trust,56)
        reverse=derive_federation_factor(signed_factor="0.6",receiver_signed=True)
        other=calculate_imported_standing(exportable_base=85,factor=reverse,source_zone="zone-b",
            receiving_zone="zone-a",ceilings=CEILINGS,root_available=True)
        self.assertEqual(other.base_trust,51)

    def test_fd19_and_fd21_no_unsigned_factor_or_widening(self):
        absent=derive_federation_factor(signed_factor="0.8",receiver_signed=False)
        self.assertIsNone(absent.applied_factor)
        excessive=derive_federation_factor(signed_factor="1.25",receiver_signed=True)
        self.assertTrue(excessive.clause_void)
        self.assertIsNone(excessive.applied_factor)
        lowered=derive_federation_factor(signed_factor="0.8",receiver_signed=True,lowered_factor="1.3",declared_floor="0.9")
        self.assertEqual(lowered.applied_factor,Fraction(4,5))
        self.assertFalse(lowered.floor_valid)
        capped=derive_federation_factor(signed_factor="0.8",receiver_signed=True,class_ceiling="0.7",lowered_factor="0.2",declared_floor="0.4")
        self.assertEqual(capped.applied_factor,Fraction(2,5))

    def test_receiver_ceilings_and_missing_root_remain_independent(self):
        factor=derive_federation_factor(signed_factor=1,receiver_signed=True)
        value=calculate_imported_standing(exportable_base=100,factor=factor,source_zone="zone-a",receiving_zone="zone-b",
            ceilings={**CEILINGS,"repair_reentry":60},root_available=False)
        self.assertEqual(value.base_trust,60)
        self.assertEqual(dict(value.ceilings)["external_root_missing"],70)

    def test_receiver_core_calculates_its_own_risk(self):
        from tests.unit.core.test_v3_native_core_projection import soul,FACTORS
        from kinetic_trust_library.v3.evidence_state import assess_required_factor
        from kinetic_trust_library.v3.core_projection import project_native_core
        factors=tuple(assess_required_factor(factor=name,required_signals=("local",),populated_signals={"local":0},
            measured_stress="0.05") for name in FACTORS)
        result=project_native_core(soul("clear"),standing=self.standing(),factors=factors,
            weights=dict.fromkeys(FACTORS,"0.2"),demand=40)
        self.assertEqual(result.capacity.measured_effective_trust,Decimal("64.6"))
        veto=project_native_core(soul("veto"),standing=self.standing(),factors=object(),weights=object(),demand=40)
        self.assertIsNone(veto.capacity)

    def test_invalid_receiver_context_or_policy_does_not_derive_standing(self):
        factor=derive_federation_factor(signed_factor=1,receiver_signed=True)
        for changes in (dict(receiving_zone="zone-a"),dict(root_available=1),dict(ceilings={}),dict(exportable_base=101)):
            args=dict(exportable_base=80,factor=factor,source_zone="zone-a",receiving_zone="zone-b",ceilings=CEILINGS,root_available=True)
            with self.assertRaises(ValidationError):calculate_imported_standing(**{**args,**changes})


if __name__=="__main__":unittest.main()
