import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.management import project_management_history, unmanaged_response


def event(kind,index):
    return dict(kind=kind,anchor="audit:event:"+str(index),sequence=index,occurred_at=index*10,
        authority="authority:a",hand_back_digest=None if kind=="admitted" else "sha256:"+"a"*64)


class ManagementTests(unittest.TestCase):
    def project(self,history,**changes):
        args=dict(history=history,declared_regime="unmanaged",event_count=len(history),
            ledger_head_sequence=9,evaluated_at=100)
        args.update(changes);return project_management_history(**args)

    def test_no_history_is_unknown_not_adversary_or_formerly_managed(self):
        r=self.project([])
        self.assertEqual(r.regime,"unmanaged");self.assertFalse(r.ever_managed)
        self.assertFalse(r.action_permitted)

    def test_demotion_retains_admission_and_final_hand_back(self):
        r=self.project([event("admitted",1),event("demoted",2)])
        self.assertEqual(r.regime,"unmanaged");self.assertTrue(r.ever_managed)
        self.assertEqual(r.final_hand_back_digest,"sha256:"+"a"*64)

    def test_contest_cannot_restore_managed_status(self):
        history=[event("admitted",1),event("demoted",2)]
        with self.assertRaises(ValidationError):self.project(history,declared_regime="managed")
        with self.assertRaises(ValidationError):self.project(history+[dict(event("admitted",3),kind="contest")])

    def test_only_explicit_new_admission_restores_management(self):
        r=self.project([event("admitted",1),event("demoted",2),event("admitted",3)],declared_regime="managed")
        self.assertEqual(r.regime,"managed");self.assertTrue(r.ever_managed)
        self.assertEqual(len(r.demotion_digests),1)

    def test_incomplete_or_invalid_order_and_orphan_demotion_are_rejected(self):
        for history,changes in (([event("demoted",1)],{}),
                ([event("admitted",1),event("admitted",2)],{}),
                ([event("admitted",1),dict(event("demoted",2),hand_back_digest=None)],{}),
                ([event("admitted",1),dict(event("demoted",2),sequence=1)],{}),
                ([event("admitted",1),event("demoted",2)],dict(event_count=3)),
                ([event("admitted",1),dict(event("demoted",2),occurred_at=101)],{})):
            with self.subTest(history=history),self.assertRaises(ValidationError):self.project(history,**changes)

    def test_unmanaged_credential_variants_have_identical_public_denial(self):
        results=[unmanaged_response(hostile_facing=False,wire_silence=False,admission=False,
            admission_endpoint="channel:admission",credential_bytes=credential)
            for credential in (None,b"expired",b"malformed",b"nearly-valid")]
        self.assertTrue(all(r==results[0] for r in results))
        self.assertEqual(results[0].status,401)
        self.assertEqual(results[0].body_bytes,b'{"admission_endpoint":"channel:admission"}')
        self.assertEqual(results[0].code,"NO_TRUST_RELATION")

    def test_silence_requires_declaration_and_admission_stays_articulate(self):
        with self.assertRaises(ValidationError):unmanaged_response(hostile_facing=False,wire_silence=True,
            admission=False,admission_endpoint="channel:admission")
        silent=unmanaged_response(hostile_facing=True,wire_silence=True,admission=False,admission_endpoint="channel:admission")
        self.assertIsNone(silent.status);self.assertIsNone(silent.body_bytes)
        petition=unmanaged_response(hostile_facing=True,wire_silence=True,admission=True,admission_endpoint="channel:admission")
        self.assertEqual(petition.status,401);self.assertIn(b"channel:admission",petition.body_bytes)
