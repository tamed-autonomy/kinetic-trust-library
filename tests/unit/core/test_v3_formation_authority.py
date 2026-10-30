import unittest

from kinetic_trust_library.v3.formation_authority import project_formation_authority
from kinetic_trust_library.errors import ValidationError


class FormationAuthorityTests(unittest.TestCase):
    def evaluate(self, record=None, **changes):
        args=dict(subject="agent:a",relation_id="relation:a",consequence_class="Relational",
            principal="person:a",claimant="person:b",template_digest="sha256:"+"a"*64,
            grant_issued_at=20,evaluated_at=30,formation=record)
        args.update(changes)
        return project_formation_authority(**args)

    def record(self):
        return dict(subject="agent:a",relation_id="relation:a",consequence_class="Relational",
            template_digest="sha256:"+"a"*64,counterparty="person:b",registered_at=10,
            formed_at=15,countersigned_at=15,witness_anchor="audit:formation",
            countersignature_anchor="audit:signature",objection_at=None)

    def test_witnessed_counterparty_has_relation_specific_direct_authority(self):
        r=self.evaluate(self.record())
        self.assertTrue(r.direct_revocation);self.assertFalse(r.suspend_required)
        self.assertFalse(r.action_permitted)

    def test_unwitnessed_claim_requires_contest_identity_siting_and_human(self):
        r=self.evaluate()
        self.assertFalse(r.direct_revocation);self.assertTrue(r.suspend_required)
        self.assertTrue(r.human_classification_required);self.assertTrue(r.identity_assurance_required)

    def test_principal_can_revoke_without_counterparty_witness(self):
        r=self.evaluate(claimant="person:a")
        self.assertTrue(r.direct_revocation)

    def test_wrong_claimant_or_class_has_no_direct_counterparty_authority(self):
        for changes in (dict(claimant="person:c"),dict(consequence_class="Coordination")):
            with self.subTest(changes=changes):
                if "consequence_class" in changes:
                    record=self.record();record.update(changes)
                else:record=self.record()
                self.assertFalse(self.evaluate(record,**changes).direct_revocation)

    def test_formation_objection_suspends_minting(self):
        record=self.record();record["objection_at"]=15
        r=self.evaluate(record)
        self.assertTrue(r.minting_suspended);self.assertFalse(r.direct_revocation)
        self.assertTrue(r.human_classification_required)

    def test_hb_02_004_declined_logistics_signature_suspends_minting(self):
        import json
        from pathlib import Path
        source=json.loads((Path(__file__).parents[3]/'spec/proposals/hand-back-v1.json').read_text())
        case=next(c for c in source['vectors'] if c['id']=='HB-02-004')
        self.assertIn('declines to countersign',case['given']['template_submission'])
        record=self.record();record.update(consequence_class='Logistics',objection_at=15,
            countersigned_at=None,countersignature_anchor=None)
        for issued in (None,20):
            r=self.evaluate(record,consequence_class='Logistics',grant_issued_at=issued)
            with self.subTest(issued=issued):
                self.assertTrue(r.minting_suspended);self.assertTrue(r.human_classification_required)
                self.assertFalse(r.direct_revocation);self.assertFalse(r.action_permitted)
                self.assertEqual(r.formation_state,'pending-objection')
        self.assertTrue(self.evaluate(record,consequence_class='Logistics',claimant='person:a').direct_revocation)
        self.assertFalse(self.evaluate(record,consequence_class='Logistics',claimant='person:a',grant_issued_at=None).direct_revocation)

    def test_pending_objection_never_establishes_counterparty_revocation(self):
        record=self.record();record.update(objection_at=15,countersigned_at=None,countersignature_anchor=None)
        r=self.evaluate(record)
        self.assertFalse(r.direct_revocation);self.assertTrue(r.suspend_required)
        self.assertEqual(r.formation_state,'pending-objection')
        for patch in (dict(countersigned_at=15),dict(countersignature_anchor='audit:signature'),
                      dict(objection_at=None),dict(objection_at=14),dict(objection_at=31),
                      dict(witness_anchor=''),dict(registered_at=16)):
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.evaluate(dict(record,**patch))
        with self.assertRaises(ValidationError):self.evaluate(self.record(),grant_issued_at=None)
        with self.assertRaises(ValidationError):self.evaluate(grant_issued_at=None)

    def test_facts_cannot_be_rebound_or_backfilled_after_grant(self):
        for changes in (dict(subject="agent:b"),dict(relation_id="relation:b"),
                        dict(template_digest="sha256:"+"b"*64),dict(countersigned_at=21),
                        dict(registered_at=16),dict(witness_anchor=""),dict(formed_at=True)):
            record=self.record();record.update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValidationError):self.evaluate(record)
