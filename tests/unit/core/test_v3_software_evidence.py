from dataclasses import replace
from importlib.util import find_spec
import unittest
from kinetic_trust_library.errors import ValidationError
from tests.unit.core._v3_software_fixture import evidence_fixture


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class SoftwareEvidenceTests(unittest.TestCase):
    def evaluate(self,f,previous=None):return f["v"].evaluate(actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True,previous_assessment=previous)

    def test_complete_current_scope_original_evidence_and_heads_are_retained(self):
        f=evidence_fixture();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertEqual(r.expires_at,1001)
        self.assertEqual(r.inputs_expires_at,1004)
        self.assertTrue(r.repair_path_verified);self.assertTrue(r.supervision_available)
        self.assertFalse(r.action_permitted);self.assertEqual(r.undefined_classes,())
        self.assertEqual(r.consumption_epoch,1)

    def test_original_observation_deadline_does_not_refresh_with_proof(self):
        for patch in (dict(observed_at=995),dict(observed_at=1001)):
            f=evidence_fixture();f["records"][0].update(patch);f["refresh"]()
            self.assertFalse(self.evaluate(f).valid)
        f=evidence_fixture();f["originals"][0]=b"substituted original source evidence"
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_scope_source_sequence_health_and_checkpoint_are_independent(self):
        f=evidence_fixture();f["records"][0]["scope"]=dict(f["records"][0]["scope"],target_revision="revision:other");f["refresh"]()
        with self.assertRaises(ValidationError):self.evaluate(f)
        f=evidence_fixture();f["records"][0]["sequence"]=0
        with self.assertRaises(ValidationError):self.evaluate(f)
        f=evidence_fixture();f["heads"]["resource_pressure"]["status"]="unavailable";f["refresh"]()
        self.assertFalse(self.evaluate(f).valid)
        f=evidence_fixture();f["state"]["continuity_checkpoint"]["anchor"]=""
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_current_unresolved_hold_survives_until_bound_authority_resolution(self):
        f=evidence_fixture()
        f["state"]["restriction_history"]=[dict(kind="impose",anchor="hold:1",sequence=1,occurred_at=990,authority="authority:software-hold",cause_anchor="cause:1")]
        f["refresh"]();old=self.evaluate(f);self.assertFalse(old.valid);self.assertEqual(old.unresolved_restrictions,("hold:1",))
        f["state"]["restriction_history"].append(dict(kind="resolve",anchor="resolution:1",sequence=2,occurred_at=999,
            authority="authority:software-hold",restriction_anchor="hold:1",cause_anchor="cause:1"))
        f["state"]["state_revision"]=2;f["refresh"]()
        self.assertTrue(self.evaluate(f,old).valid)
        f["state"]["restriction_history"]=[];f["state"]["state_revision"]=3;f["refresh"]()
        with self.assertRaises(ValidationError):self.evaluate(f,old)

    def test_rollback_and_rewritten_observation_under_same_head_cannot_recover(self):
        f=evidence_fixture();old=self.evaluate(f)
        f["records"][0]["observed_at"]=998;f["refresh"]()
        with self.assertRaises(ValidationError):self.evaluate(f,old)
        f=evidence_fixture();old=self.evaluate(f);f["state"]["consumption_epoch"]=0;f["refresh"]()
        with self.assertRaises(ValidationError):self.evaluate(f,old)

    def test_current_unknown_numeric_condition_needs_declared_conservative_pair(self):
        f=evidence_fixture();f["records"][0]["value"]=None;f["state"]["assessment"]["capacityKnown"]=False;f["refresh"]()
        r=self.evaluate(f);self.assertTrue(r.valid);self.assertEqual(r.undefined_classes,("resource_pressure",))
        f["state"]["assessment"]["capacityKnown"]=True
        self.assertFalse(self.evaluate(f).valid)

    def test_retained_source_sequence_gap_cannot_be_treated_as_current(self):
        f=evidence_fixture();old=self.evaluate(f)
        f["records"][0]["sequence"]=3;f["heads"]["resource_pressure"]["sequence"]=3
        f["state"]["state_revision"]=2;f["refresh"]()
        with self.assertRaisesRegex(ValidationError,"gap"):self.evaluate(f,old)

    def test_estimate_cannot_replace_control_latency_or_current_invalidation_status(self):
        for kind in ("control_latency","invalidation"):
            f=evidence_fixture();index=next(i for i,r in enumerate(f["records"]) if r["kind"]==kind)
            f["records"][index]["value"]=None;f["state"]["assessment"]["capacityKnown"]=False;f["refresh"]()
            with self.subTest(kind=kind):self.assertFalse(self.evaluate(f).valid)

    def test_authority_resolution_must_preserve_original_cause_and_role(self):
        for patch in (dict(cause_anchor="cause:other"),dict(authority="authority:agent")):
            f=evidence_fixture();f["state"]["restriction_history"]=[
                dict(kind="impose",anchor="hold:a",sequence=1,occurred_at=990,authority="authority:software-hold",cause_anchor="cause:a"),
                dict(kind="resolve",anchor="resolve:a",sequence=2,occurred_at=999,authority="authority:software-hold",cause_anchor="cause:a",restriction_anchor="hold:a")]
            f["state"]["restriction_history"][1].update(patch);f["refresh"]()
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.evaluate(f)

    def test_actual_source_outage_and_unhealthy_clock_never_supply_empty_state(self):
        f=evidence_fixture()
        with self.assertRaises(ValidationError):f["v"].evaluate(actual_operation=f["op"],evaluated_at=1000,clock_healthy=False)
        class Offline:
            def resolve(self,**kwargs):raise OSError("protected state unavailable")
        f["v"]=replace(f["v"],context_source=Offline())
        with self.assertRaises(OSError):self.evaluate(f)
