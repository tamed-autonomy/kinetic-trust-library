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

    def test_facts_cannot_be_rebound_or_backfilled_after_grant(self):
        for changes in (dict(subject="agent:b"),dict(relation_id="relation:b"),
                        dict(template_digest="sha256:"+"b"*64),dict(countersigned_at=21),
                        dict(registered_at=16),dict(witness_anchor=""),dict(formed_at=True)):
            record=self.record();record.update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValidationError):self.evaluate(record)
