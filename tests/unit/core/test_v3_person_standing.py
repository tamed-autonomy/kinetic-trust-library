"""Person standing is zone-scoped evidence, never human capacity or rank."""
import unittest
import json
import hashlib
from pathlib import Path
from decimal import Decimal
from kinetic_trust_library.errors import ValidationError


def acts():
    return tuple(dict(id="act:"+str(i),subject="person:acct:z1:0417",zone="zone:blue",
        kind=kind,under_stress=kind in ("approval","veto_clear"),anchor="signature:"+str(i),occurred_at=100+i)
        for i,kind in enumerate(("bond_posted","attestation_issued","approval","veto_clear","decision_contested")))


class PersonStandingTests(unittest.TestCase):
    def test_exact_published_source_and_composition_cases(self):
        raw=(Path(__file__).parents[3]/"spec/proposals/person-standing-v1.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),"c2fa8debf133e883f6fabf3ed62a464251608d461d7853e1f72a988547bd9217")
        cases={c["id"]:c for c in json.loads(raw)["vectors"]}
        source=cases["PS01-signed-acts-compose"]
        given=source["given"];expected=source["expect"]
        r=self.compose(por_contribution=given["PoR_contribution"],terminator_standing=given["terminator"]["standing"],
            ceilings={c["ceiling"]:c["value"] for c in given["applicable_ceilings"]})
        self.assertEqual(r.base_trust,expected["E_base"]);self.assertEqual(r.raw_base,expected["E_raw"])
        self.assertEqual(r.root_term,expected["root_term"])
        for name in ("PS05-transfer-by-agreement","PS06-agreement-admits-at-zero","PS07-no-agreement-no-transfer","PS08-ceiling-binds"):
            from kinetic_trust_library.v3.person_standing import calculate_imported_person_standing
            g=cases[name]["given"];a=g["agreement"];e=cases[name]["expect"]
            r=calculate_imported_person_standing(subject=g["subject"],source_zone=g.get("from_zone","zone-blue-z1"),
                receiving_zone=g["to_zone"],exportable_base=g["E_base_external"],agreement_exists=a["exists"],
                receiver_signed=a["exists"],person_factor=a.get("person_trust_factor"),zone_ceiling=a.get("zone_mass_ceiling",100))
            self.assertEqual(r.transferred,e["transferred"]);self.assertEqual(r.base_trust,e["E_base_zone"])

    def compose(self,**kw):
        from kinetic_trust_library.v3.person_standing import calculate_person_standing
        args=dict(subject="person:acct:z1:0417",zone="zone:blue",signed_acts=acts(),por_contribution=42,
            terminator_standing=80,ceilings={"ial":95},zone_risk=Decimal("0.25"),evaluated_at=200)
        return calculate_person_standing(**dict(args,**kw))

    def test_published_ps01_and_ps12_allocation(self):
        r=self.compose()
        self.assertEqual(r.root_term,24);self.assertEqual(r.raw_base,66)
        self.assertEqual(r.base_trust,66);self.assertEqual(r.effective_trust,Decimal("49.5"))
        self.assertFalse(r.action_permitted)
        self.assertEqual(r.subject,"person:acct:z1:0417");self.assertEqual(r.zone,"zone:blue")

    def test_no_software_defaults_or_observed_behavior_inputs(self):
        for field in ("generation","lineage","mass_ceiling","mitosis","behavioral_risk_score"):
            with self.subTest(field=field),self.assertRaises(ValidationError):
                self.compose(ceilings={field:50})
        a=list(acts());a[0]=dict(a[0],kind="login_timing_profile")
        with self.assertRaises(ValidationError):self.compose(signed_acts=tuple(a))

    def test_resilience_needs_actual_signed_stress_acts(self):
        quiet=tuple(dict(a,under_stress=False) for a in acts())
        with self.assertRaises(ValidationError):self.compose(signed_acts=quiet)
        self.assertEqual(self.compose(signed_acts=quiet,por_contribution=0).base_trust,24)

    def test_subject_zone_anchor_and_time_bindings(self):
        for patch in (dict(subject="person:other"),dict(zone="zone:other"),dict(anchor=""),dict(occurred_at=201),dict(under_stress=1)):
            a=list(acts());a[0]=dict(a[0],**patch)
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.compose(signed_acts=tuple(a))
        with self.assertRaises(ValidationError):self.compose(signed_acts=acts()+acts()[:1])
        with self.assertRaises(ValidationError):self.compose(subject="agent:3gen:a")

    def test_declared_ceilings_only_and_no_root_credit(self):
        self.assertEqual(self.compose(ceilings={"ial":40}).base_trust,40)
        self.assertEqual(self.compose(terminator_standing=0,por_contribution=70,ceilings={}).base_trust,70)
        with self.assertRaises(ValidationError):self.compose(por_contribution=71)

    def test_published_person_directional_import(self):
        from kinetic_trust_library.v3.person_standing import calculate_imported_person_standing
        def imported(**kw):
            args=dict(subject="person:acct:z1:0417",source_zone="zone:blue",receiving_zone="zone:partner",
                exportable_base=66,agreement_exists=True,receiver_signed=True,person_factor=Decimal("0.5"),zone_ceiling=40)
            return calculate_imported_person_standing(**dict(args,**kw))
        self.assertEqual(imported().base_trust,33)
        self.assertEqual(imported(person_factor=1).base_trust,40)
        self.assertEqual(imported(person_factor=0).base_trust,0)
        self.assertTrue(imported(person_factor=0).transferred)
        self.assertFalse(imported(agreement_exists=False,receiver_signed=False,person_factor=None).transferred)
        self.assertEqual(imported(agreement_exists=False,receiver_signed=False,person_factor=None).base_trust,0)
        self.assertFalse(imported(receiver_signed=False).transferred)
        with self.assertRaises(ValidationError):imported(person_factor=Decimal("1.1"))
