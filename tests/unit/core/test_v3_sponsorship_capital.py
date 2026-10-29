"""Identity reserve accounting retains ancestral liability after closure."""
from dataclasses import replace
from fractions import Fraction
import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.sponsorship_capital import BondCapital,project_bond_capital,project_sponsor_capital


def bond(**kw):
    return BondCapital(**{**dict(bond_id="bond:1",stake_amount=20,intrinsic_base=0,depth=1,opened_at=100,expires_at=200),**kw})


class SponsorshipCapitalTests(unittest.TestCase):
    def test_exact_taper_reaches_a_positive_permanent_floor(self):
        self.assertEqual(project_bond_capital(bond(intrinsic_base=60),now=150).effective_reserve,5)
        at_floor=project_bond_capital(bond(intrinsic_base=72),now=150)
        self.assertEqual(at_floor.effective_reserve,2)
        self.assertEqual(at_floor.phase,"active")
        matured=project_bond_capital(bond(intrinsic_base=80),now=150)
        self.assertEqual(matured.effective_reserve,2)
        self.assertEqual(matured.phase,"residual")
        after_loss=project_bond_capital(bond(intrinsic_base=20,previously_closed=True),now=150)
        self.assertEqual(after_loss.effective_reserve,2)
        expired=project_bond_capital(bond(),now=10000)
        self.assertEqual(expired.effective_reserve,2)
        self.assertEqual(expired.retained_liability,2)

    def test_termination_without_cause_and_unresolved_expiry_do_not_release_capital(self):
        active=project_bond_capital(bond(without_cause_terminated=True),now=150)
        self.assertEqual(active.effective_reserve,20)
        self.assertTrue(active.nonrenewable)
        pending=project_bond_capital(bond(for_cause_state="pending"),now=200)
        self.assertEqual(pending.effective_reserve,2)
        self.assertTrue(pending.unresolved_lapse)
        for state in ("rejected","misattestation"):
            self.assertEqual(project_bond_capital(bond(for_cause_state=state),now=200).effective_reserve,2)
        released=project_bond_capital(bond(for_cause_state="sustained"),now=150)
        self.assertEqual(released.effective_reserve,0)
        self.assertEqual(released.phase,"released")

    def test_transferred_residual_keeps_its_current_value(self):
        inherited=bond(depth=2,transferred_residual=2)
        projected=project_bond_capital(inherited,now=500)
        self.assertEqual(projected.effective_reserve,2)  # Not recomputed as 0.2 at the receiving depth.
        self.assertEqual(projected.retained_liability,2)

    def test_fd24_complete_home_reserve_and_overcommit_are_visible(self):
        existing=bond(bond_id="existing",stake_amount=20)
        new=bond(bond_id="new",stake_amount=15)
        result=project_sponsor_capital(sponsor_base=90,bonds=(existing,new),now=150)
        self.assertEqual(result.available_base,55)
        self.assertEqual(result.total_reserved,35)
        mature=replace(existing,intrinsic_base=80)
        retained=project_sponsor_capital(sponsor_base=90,bonds=(mature,new),now=150)
        self.assertEqual(retained.available_base,73)
        over=project_sponsor_capital(sponsor_base=30,bonds=(existing,new),now=150)
        self.assertTrue(over.overcommitted)
        self.assertEqual(over.available_base,0)

    def test_duplicate_future_or_malformed_liability_is_rejected(self):
        with self.assertRaises(ValidationError):project_sponsor_capital(sponsor_base=90,bonds=(bond(),bond()),now=150)
        for b in (bond(depth=0),bond(transferred_residual=0),bond(for_cause_state="forgiven"),bond(without_cause_terminated=1)):
            with self.assertRaises(ValidationError):project_bond_capital(b,now=150)
        with self.assertRaises(ValidationError):project_bond_capital(bond(),now=99)


if __name__=="__main__":unittest.main()
