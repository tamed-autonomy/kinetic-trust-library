"""Federation §6.5 routing is evidence delivery, never foreign closure."""
import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.federation_records import plan_federation_delivery


def destination(zone, **changes):
    value=dict(zone=zone,agreement_applicable=True,standing_admitted=False,
               bond_ever_opened=False,attestation_admitted=False,
               breach_previously_delivered=False,sovereignty_enforced=True)
    value.update(changes)
    return value


class FederationRecordsTests(unittest.TestCase):
    def plan(self, kind="breach", profile="software", **changes):
        args=dict(kind=kind,subject_profile=profile,breach_anchor="breach-1",
                  reconciliation_anchor=None,destinations=(
                      destination("b",standing_admitted=True),
                      destination("c",bond_ever_opened=True),destination("d")))
        args.update(changes)
        return plan_federation_delivery(**args)

    def test_exposure_reaches_only_covered_subject_zones(self):
        for kind in ("breach","withdrawal-for-cause"):
            result=self.plan(kind)
            self.assertEqual(result.required_destinations,("b","c"))
            self.assertEqual(result.disposition,"exposure")
            self.assertFalse(result.closes_receiver_exposure)
            self.assertEqual(result.notification_payload,())

    def test_notification_uses_actual_breach_delivery_not_new_coverage(self):
        for profile in ("software","person"):
            result=self.plan("reconciliation-anchored",profile,
                reconciliation_anchor="repair-1",destinations=(
                    destination("b",breach_previously_delivered=True),
                    destination("c",standing_admitted=True)))
            self.assertEqual(result.required_destinations,("b",))
            self.assertEqual(result.notification_payload,(("breach_anchor","breach-1"),
                                            ("reconciliation_anchor","repair-1")))
            self.assertFalse(result.closes_receiver_exposure)

    def test_veto_delta_and_person_reconciliation_deliver_nothing(self):
        for kind in ("silent-veto","soul-veto","delta","reconciliation-record"):
            for profile in ("software","person"):
                result=self.plan(kind,profile)
                self.assertEqual(result.required_destinations,())
                self.assertEqual(result.notification_payload,())

    def test_unenforced_constraint_retains_obligation_without_leaking(self):
        result=self.plan(destinations=(destination("b",standing_admitted=True,
                                                  sovereignty_enforced=False),))
        self.assertEqual(result.required_destinations,("b",))
        self.assertEqual(result.permitted_destinations,())
        self.assertEqual(result.blocked_destinations,("b",))

    def test_same_terms_require_applicable_agreement(self):
        result=self.plan("reconciliation-anchored",reconciliation_anchor="repair-1",
            destinations=(destination("b",breach_previously_delivered=True,
                                      agreement_applicable=False),))
        self.assertEqual(result.required_destinations,())

    def test_closed_shapes_and_anchor_identity(self):
        for args in (dict(kind="positive"),dict(subject_profile="unknown"),
                     dict(breach_anchor=""),dict(reconciliation_anchor="unexpected"),
                     dict(kind="reconciliation-anchored",reconciliation_anchor="breach-1"),
                     dict(destinations=(destination("b"),destination("b"))),
                     dict(destinations=(destination("b",standing_admitted=1),)),
                     dict(destinations=(dict(destination("b"),secret="private"),))):
            with self.subTest(args=args),self.assertRaises(ValidationError):self.plan(**args)
