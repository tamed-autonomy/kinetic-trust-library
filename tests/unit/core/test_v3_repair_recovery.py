import unittest
from kinetic_trust_library.v3.repair_recovery import RecoveryWindow, project_recovery
from kinetic_trust_library.errors import ValidationError


class RepairRecoveryTests(unittest.TestCase):
    def project(self, windows, previous="debt-growth", **kw):
        return project_recovery(previous_tier=previous, windows=windows,
            criticality=2, recovery_windows=3, recovery_margin="0.1",
            stock_target=1, amendment_rate_limit="0.1",
            nonattendance_rate_limit="0.1", **kw)

    def test_br33_requires_the_whole_recovery_predicate(self):
        first=RecoveryWindow("0.95",3,"1.2","0.1",0)
        good=RecoveryWindow("0.85",1,0,0,0)
        self.assertEqual(self.project((first,)).tier,"debt-growth")
        result=self.project((first,good,good,good))
        self.assertEqual(result.tier,"reserve-gone")
        self.assertTrue(result.recovered)
        self.assertTrue(result.rule_repair_required)
        for bad in (RecoveryWindow("0.9",1,0,0,0), RecoveryWindow("0.85",2,0,0,0),
                    RecoveryWindow("0.85",1,1,0,0), RecoveryWindow("0.85",1,0,"0.1",0),
                    RecoveryWindow("0.85",1,0,0,"0.1"),
                    RecoveryWindow(None,1,0,0,0)):
            self.assertEqual(self.project((good,bad,good)).tier,"debt-growth")

    def test_crisis_needs_sustained_measure_and_never_authorizes_emergency(self):
        high=RecoveryWindow(2,5,1,0,0)
        self.assertEqual(self.project((high,high),previous="normal").tier,"debt-growth")
        result=self.project((high,high,high),previous="normal",crisis_invariants_preserved=False)
        self.assertEqual(result.tier,"crisis")
        self.assertTrue(result.consequential_hosting_forbidden)
        self.assertTrue(result.rule_repair_required)
        self.assertFalse(result.emergency_authorized)
        quiet=RecoveryWindow("0.1",0,0,0,0)
        self.assertTrue(self.project((quiet,),previous="normal",
            crisis_invariants_preserved=False).consequential_hosting_forbidden)

    def test_quiet_or_unknown_does_not_discharge_a_prior_crisis(self):
        good=RecoveryWindow("0.4",0,0,0,0)
        self.assertEqual(self.project((good,),previous="crisis").tier,"crisis")
        self.assertEqual(self.project((good,good,good),previous="crisis").tier,"normal")
        unknown=RecoveryWindow(None,0,None,0,0)
        result=self.project((unknown,),previous="normal")
        self.assertFalse(result.measurement_complete)
        self.assertEqual(result.tier,"normal")

    def test_malformed_evidence_is_rejected(self):
        for windows in ((), [], (object(),), (RecoveryWindow(True,0,0,0,0),),
                        (RecoveryWindow(0,-1,0,0,0),)):
            with self.assertRaises(ValidationError):
                self.project(windows)


if __name__ == "__main__":
    unittest.main()
