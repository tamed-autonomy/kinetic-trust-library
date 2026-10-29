"""Modeled installed authority for current one-link federation admission."""
from dataclasses import replace
from importlib.util import find_spec
from fractions import Fraction
import unittest


def fixture():
    import rfc8785
    from kinetic_trust_library.v3.federation import InstalledFederationVerifier,AuthenticatedFederationContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    op=dict(subject="urn:subject:x",actor="urn:agent:x",audience="urn:service:b",operation="urn:action:read",
        resource="urn:resource:r",parameters={},request_id="request:1",replay_domain="urn:domain:b")
    deployment=dict(id="urn:test:deployment")
    profile=dict(id="urn:test:federation",version=1,receiving_zone="zone-b",formula="minimum-applicable-directional-terms-v1",
        enforcement_classes={"blue":dict(rank=2,factor_ceiling="0.7"),"cyan":dict(rank=1,factor_ceiling="0.5")},
        subject_profiles=["software"],lowering_policies=["decay","liveness"])
    direction=dict(from_zone="zone-a",to_zone="zone-b",signed_by="zone-b",factor="0.8",
        factors_by_action_class={},factors_by_substrate_profile={},lowering_policies=["decay"],floor=0,lowest_enforcement_class="cyan")
    agreement=dict(id="agreement:ab",version=1,starts_at=800,expires_at=1100,
        parties=[dict(zone_id=z,terminator="authority:"+z,signing_authority="key:"+z) for z in ("zone-a","zone-b")],
        signed_by=["zone-a","zone-b"],directions=[direction],
        data_handling=dict(attestation_types=["behavior","passage"],trajectories=True,persons=None,cross_zone_sponsorship=True,breach_records="exposure"),
        sovereignty_enforced={"zone-a":["consent"],"zone-b":["consent"]},
        dispute_route=dict(route="urn:review:ab",deadline_seconds=60),incident_notification_seconds=60,leaving_notice_seconds=60,
        severance_causes=["security-breach"],clauses=[])
    attestation=dict(subject=op["actor"],subject_profile="software",from_zone="zone-a",to_zone="zone-b",kind="behavior",
        attested_at=899,expires_at=1050,link_count=1,earned_in_zone="zone-a",attested_base=85,exportable_base=80,
        signatures=[dict(zone_id="zone-a",registry_verified=True,witnessed=True)],signed_act=False,current_valid=True,
        payload_digest="sha256:"+"a"*64)
    state=dict(deployment_digest=_digest(deployment,"sha256"),profile_digest=_digest(profile,"sha256"),
        operation_digest=digest_demand_operation(op,algorithm="sha256"),checked_at=1000,expires_at=1007,
        admission_id="admission:1",ingress_at=900,subject=op["actor"],subject_profile="software",from_zone="zone-a",to_zone="zone-b",
        enforcement_class="blue",action_class="read",substrate_profile="software",receiver_accepting=True,
        required_sovereignty=["consent"],lowered_factors=[],agreement=agreement,attestation=attestation)
    calls=[]
    class Source:
        def resolve(self,**kw):
            calls.append(kw)
            return AuthenticatedFederationContext(rfc8785.dumps(state),b"modeled-current-agreement/signatures/registry/exportable-standing/admission")
    verifier=InstalledFederationVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),Source(),"sha256")
    return verifier,state,op,profile,calls


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema")),"install v3-proofs")
class FederationTests(unittest.TestCase):
    def evaluate(self,v,op):return v.evaluate(actual_operation=op,evaluated_at=1000,clock_healthy=True)

    def test_current_direction_exportable_operand_and_complete_binding(self):
        from kinetic_trust_library.errors import ValidationError
        v,state,op,profile,calls=fixture();result=self.evaluate(v,op)
        self.assertTrue(result.admitted)
        self.assertEqual(result.factor.applied_factor,Fraction(7,10))
        self.assertEqual(result.exportable_base,80)  # Neither total 85 nor foreign R/E_trust.
        self.assertEqual(result.derive_standing(ceilings=dict(generation=100,ial=95,trajectory=100,adversity=100),root_available=True).base_trust,56)
        self.assertEqual(result.expires_at,1007)
        state["checked_at"]=1001
        newer=v.evaluate(actual_operation=op,evaluated_at=1001,clock_healthy=True)
        self.assertEqual(result.frame_digest,newer.frame_digest)
        state["checked_at"]=1000
        state["operation_digest"]="sha256:"+"0"*64
        with self.assertRaises(ValidationError):self.evaluate(v,op)
        self.assertNotIn("candidate",calls[0])

    def test_admission_time_version_and_earliest_expiry_cannot_be_extended(self):
        v,state,op,profile,calls=fixture()
        state["expires_at"]=1200
        self.assertEqual(self.evaluate(v,op).expires_at,1050)
        state["agreement"]["expires_at"]=1020
        self.assertEqual(self.evaluate(v,op).expires_at,1020)
        state["agreement"].update(version=2,starts_at=950)
        self.assertFalse(self.evaluate(v,op).admitted)  # A later version is not the old ingress's authority.
        state.update(ingress_at=960,admission_id="admission:2")
        self.assertTrue(self.evaluate(v,op).admitted)
        state["agreement"]["dispute_route"]["deadline_seconds"]=0
        self.assertTrue(self.evaluate(v,op).admitted)  # An immediate deadline is still declared.

    def test_unsigned_expired_severed_or_relayed_import_is_unavailable(self):
        changes=(lambda s:s["agreement"]["directions"][0].update(signed_by="zone-a"),
            lambda s:s["agreement"].update(expires_at=999),lambda s:s.update(receiver_accepting=False),
            lambda s:s["attestation"].update(link_count=2),lambda s:s["attestation"].update(earned_in_zone="zone-c"),
            lambda s:s["attestation"]["signatures"][0].update(registry_verified=False),
            lambda s:s["attestation"]["signatures"][0].update(witnessed=False),
            lambda s:s["attestation"].update(current_valid=False),
            lambda s:s["attestation"].update(exportable_base=90),
            lambda s:s.update(required_sovereignty=["unsupported"]),
            lambda s:s["agreement"]["parties"][1].update(terminator=None))
        for change in changes:
            v,state,op,profile,calls=fixture();change(state)
            result=self.evaluate(v,op)
            self.assertFalse(result.admitted)
            self.assertIsNone(result.exportable_base)

    def test_scoped_terms_and_declared_lowering_never_create_a_second_factor(self):
        v,state,op,profile,calls=fixture();term=state["agreement"]["directions"][0]
        term["factors_by_action_class"]={"read":"0.6"};term["factors_by_substrate_profile"]={"software":"0.5"}
        state["lowered_factors"]=[dict(policy="decay",factor="0.4")]
        value=self.evaluate(v,op)
        self.assertEqual(value.factor.applied_factor,Fraction(2,5))
        state["lowered_factors"][0]["policy"]="undeclared"
        self.assertFalse(self.evaluate(v,op).admitted)
        state["lowered_factors"]=[];term["factors_by_action_class"]={"read":"1.2"}
        self.assertFalse(self.evaluate(v,op).admitted)

    def test_void_veto_clause_does_not_void_an_otherwise_valid_agreement(self):
        v,state,op,profile,calls=fixture()
        state["agreement"]["clauses"]=[dict(id="clause:override",effect="override-veto")]
        result=self.evaluate(v,op)
        self.assertTrue(result.admitted)
        self.assertEqual(result.void_clauses,("clause:override",))
        self.assertFalse(hasattr(result,"authorized"))

    def test_unwitnessed_cosignature_adds_no_credit_and_person_route_is_explicitly_unsupported(self):
        import rfc8785
        from kinetic_trust_library.errors import ValidationError
        v,state,op,profile,calls=fixture()
        state["attestation"]["signatures"].append(dict(zone_id="zone-c",registry_verified=True,witnessed=False))
        self.assertEqual(self.evaluate(v,op).exportable_base,80)
        state["subject_profile"]="person";state["attestation"]["subject_profile"]="person"
        self.assertFalse(self.evaluate(v,op).admitted)
        profile["subject_profiles"]=["person"]
        with self.assertRaises(ValidationError):replace(v,profile_bytes=rfc8785.dumps(profile))


if __name__=="__main__":unittest.main()
