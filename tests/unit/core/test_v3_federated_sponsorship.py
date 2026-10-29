"""Current cross-zone bond evidence with historical opening kept distinct."""
from dataclasses import asdict
from fractions import Fraction
from importlib.util import find_spec
import unittest


def fixture(subject=None,receiving_zone="zone-b",now=1000):
    import rfc8785
    import hashlib
    from kinetic_trust_library.v3.federated_sponsorship import InstalledFederatedSponsorshipVerifier,AuthenticatedFederatedSponsorshipContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.sponsorship_capital import BondCapital
    from tests.unit.core.test_v3_federation import fixture as federation_fixture
    fed,state,op,fed_profile,_=federation_fixture()
    fed_profile["enforcement_classes"]["blue"]["factor_ceiling"]=1
    subset={key:state[key] for key in ("subject","subject_profile","from_zone","to_zone","enforcement_class","action_class",
        "substrate_profile","receiver_accepting","required_sovereignty","lowered_factors","agreement","attestation","ingress_at")}
    subset["attestation"].update(attested_base=90,exportable_base=90)
    import copy
    opening_admission=copy.deepcopy(subset);current_admission=copy.deepcopy(subset)
    body=dict(id="bond:new",kind="sponsorship_bond",issuer=op["actor"],subject="urn:agent:new",start_time=900,end_time=1100,
        terminator=dict(kind="employer",reference="urn:test:accountable"),root_person="person:root:1",chain_length=2,
        inputs=dict(sponsor_e_base=90,stake_percentage=20))
    profile=dict(id="urn:test:cross-zone-bond",version=1,receiving_zone="zone-b",formula="home-reserve-and-receiver-measure-v1",
        federation_profile_digest=_digest(fed_profile,"sha256"),sponsor_admission_floor=50,root_binding="credit-digest-ceiling-v1")
    context=dict(subject=body["subject"],subject_profile="software",generation=0,lineage="sponsored",hop_bound=4,receiving_zone="zone-b",
        deployment_digest=_digest(dict(id="urn:test:deployment"),"sha256"),
        federated_sponsorship_profile_digest=_digest(profile,"sha256"))
    instrument=b"modeled-complete-signed-bond"
    legacy=asdict(BondCapital("bond:legacy",20,0,1,800,1200))
    current=asdict(BondCapital("bond:new",18,12,1,900,1100))
    state=dict(deployment_digest=context["deployment_digest"],profile_digest=context["federated_sponsorship_profile_digest"],
        context_digest=_digest(context,"sha256"),instrument_digest="sha256:"+hashlib.sha256(instrument).hexdigest(),body_digest=_digest(body,"sha256"),
        checked_at=1000,expires_at=1007,receiving_zone="zone-b",home_zone="zone-a",root="root:sponsor",sponsor=body["issuer"],
        subject=body["subject"],bond_id=body["id"],opened_at=900,
        opening=dict(home_base=90,commitments=[copy.deepcopy(legacy)],repair_zones=[],sponsor_admission=opening_admission,
            sponsor_otherwise_admissible=True,home_recorded=True,receiving_anchor_verified=True),
        current=dict(home_base=90,commitments=[legacy,current],sponsor_admission=current_admission,
            sponsor_otherwise_admissible=True,home_recorded=True,receiving_anchor_verified=True,subject_intrinsic_base=12,
            severance_at=None,lent_withdrawn=False))
    if subject is not None:body["subject"]=state["subject"]=context["subject"]=subject
    if receiving_zone!="zone-b":
        mapping={"zone-b":receiving_zone}
        if receiving_zone=="zone-a":mapping["zone-a"]="zone-home"
        def zone(value):
            if type(value) is dict:return {mapping.get(key,key):zone(item) for key,item in value.items()}
            if type(value) is list:return [zone(item) for item in value]
            return mapping.get(value,value)
        profile=zone(profile);fed_profile=zone(fed_profile);state=zone(state);context=zone(context)
    shift=now-1000
    state["checked_at"]+=shift;state["expires_at"]+=shift;state["opened_at"]+=shift
    body["start_time"]+=shift;body["end_time"]+=shift
    for part in ("opening","current"):
        for item in state[part]["commitments"]:item["opened_at"]+=shift;item["expires_at"]+=shift
        admission=state[part]["sponsor_admission"];admission["ingress_at"]+=shift
        admission["agreement"]["starts_at"]+=shift;admission["agreement"]["expires_at"]+=shift
        admission["attestation"]["attested_at"]+=shift;admission["attestation"]["expires_at"]+=shift
    profile["federation_profile_digest"]=_digest(fed_profile,"sha256")
    state["profile_digest"]=context["federated_sponsorship_profile_digest"]=_digest(profile,"sha256")
    state["context_digest"]=_digest(context,"sha256");state["body_digest"]=_digest(body,"sha256")
    class Source:
        def resolve(self,**kw):return AuthenticatedFederatedSponsorshipContext(rfc8785.dumps(state),rfc8785.dumps(body),
            b"modeled-complete-opening/current-home-capital/all-zone-breach/registry/bond-anchor")
    v=InstalledFederatedSponsorshipVerifier(fed.deployment_profile_bytes,rfc8785.dumps(profile),rfc8785.dumps(fed_profile),Source(),"sha256")
    return v,state,body,instrument,rfc8785.dumps(context)


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema")),"install v3-proofs")
class FederatedSponsorshipTests(unittest.TestCase):
    def evaluate(self,v,instrument,context):return v.evaluate(instrument,context_bytes=context,evaluated_at=1000,clock_healthy=True)

    def test_home_reserve_receiver_measure_and_collateral_are_distinct(self):
        v,state,body,instrument,context=fixture();result=self.evaluate(v,instrument,context)
        self.assertTrue(result.opening_valid)
        self.assertTrue(result.active)
        self.assertEqual(result.sponsor_measure,72)
        self.assertEqual(result.home_capital.available_base,Fraction(547,10))  # 90 - 20 - 18*(1-12/80).
        self.assertEqual(result.receiver_collateral,Fraction(36,5))
        self.assertEqual(result.root_sponsor_basis,72)
        self.assertEqual(result.subject_intrinsic_base,12)
        state["opening"]["sponsor_admission"]["attestation"].update(attested_base=95,exportable_base=95)
        state["current"]["home_base"]=95
        state["current"]["sponsor_admission"]["attestation"].update(attested_base=95,exportable_base=95)
        self.assertEqual(self.evaluate(v,instrument,context).root_sponsor_basis,72)  # Original home base was 90, not the older attestation's 95.

    def test_bad_opening_records_or_capital_never_create_valid_birth(self):
        changes=(lambda s:s["opening"].update(home_recorded=False),lambda s:s["opening"].update(receiving_anchor_verified=False),
            lambda s:s["opening"].update(sponsor_otherwise_admissible=False),
            lambda s:s["opening"]["commitments"][0].update(stake_amount=80),
            lambda s:s["opening"]["sponsor_admission"]["agreement"]["data_handling"].update(cross_zone_sponsorship=False))
        for change in changes:
            v,state,body,instrument,context=fixture();change(state)
            result=self.evaluate(v,instrument,context)
            self.assertFalse(result.opening_valid)
            self.assertFalse(result.active)

    def test_current_withdrawal_or_severance_keeps_birth_earned_standing_and_residual(self):
        v,state,body,instrument,context=fixture()
        state["current"]["lent_withdrawn"]=True
        result=self.evaluate(v,instrument,context)
        self.assertTrue(result.opening_valid);self.assertFalse(result.active)
        self.assertEqual(result.subject_intrinsic_base,12)
        state["current"].update(lent_withdrawn=False,severance_at=999)
        result=self.evaluate(v,instrument,context)
        self.assertTrue(result.opening_valid);self.assertFalse(result.active)
        self.assertEqual(dict(result.home_capital.bonds)["bond:new"].effective_reserve,Fraction(9,5))
        self.assertEqual(result.ends_at,999)
        v,state,body,instrument,context=fixture()
        state["current"]["subject_intrinsic_base"]=80
        state["current"]["commitments"][1]["intrinsic_base"]=80
        matured=self.evaluate(v,instrument,context)
        self.assertTrue(matured.opening_valid);self.assertFalse(matured.active)
        self.assertEqual(matured.subject_intrinsic_base,80)
        self.assertEqual(dict(matured.home_capital.bonds)["bond:new"].effective_reserve,Fraction(9,5))

    def test_current_record_loss_or_admission_failure_does_not_rewrite_opening(self):
        for change in (lambda s:s["current"].update(home_recorded=False),
                       lambda s:s["current"]["sponsor_admission"].update(receiver_accepting=False)):
            v,state,body,instrument,context=fixture();change(state)
            result=self.evaluate(v,instrument,context)
            self.assertTrue(result.opening_valid);self.assertFalse(result.active)

    def test_unknown_agreements_and_current_rebasing_cannot_create_credit(self):
        v,state,body,instrument,context=fixture()
        state["opening"]["sponsor_admission"]["agreement"]=None
        state["current"]["sponsor_admission"]["agreement"]=None
        result=self.evaluate(v,instrument,context)
        self.assertFalse(result.opening_valid);self.assertFalse(result.active)
        v,state,body,instrument,context=fixture()
        state["current"]["sponsor_admission"]["agreement"].update(id="agreement:unrelated",expires_at=880,starts_at=800)
        result=self.evaluate(v,instrument,context)
        self.assertTrue(result.opening_valid);self.assertFalse(result.active)
        self.assertEqual(result.ends_at,1100)

    def test_any_breach_zone_blocks_opening_and_instrument_scope_cannot_be_substituted(self):
        from kinetic_trust_library.v3.installed_repair import HARD_ENTRIES
        from kinetic_trust_library.errors import ValidationError
        v,state,body,instrument,context=fixture()
        policy=dict(id="urn:test:opening-repair",version=1,aggregate_count_limit=1,
            entry_classes={key:dict(hard=True,count_limit=1,declared_capacity=2) for key in HARD_ENTRIES})
        state["opening"]["repair_zones"]=[dict(zone_id="zone-c",root=state["root"],profile=policy,
            counts={key:2 if key=="misattestation" else 0 for key in HARD_ENTRIES},blocked_classes=[],aggregate_blocked=False,hard_blocked=False)]
        self.assertFalse(self.evaluate(v,instrument,context).opening_valid)
        with self.assertRaises(ValidationError):self.evaluate(v,instrument+b"substitution",context)

    def test_agreement_end_caps_credit_and_clock_crossing_updates_the_semantic_frame(self):
        v,state,body,instrument,context=fixture()
        for part in ("opening","current"):
            state[part]["sponsor_admission"]["agreement"]["expires_at"]=1005
        active=self.evaluate(v,instrument,context)
        self.assertTrue(active.active);self.assertEqual(active.expires_at,1005)
        state.update(checked_at=1006,expires_at=1013)
        ended=v.evaluate(instrument,context_bytes=context,evaluated_at=1006,clock_healthy=True)
        self.assertTrue(ended.opening_valid);self.assertFalse(ended.active)
        self.assertEqual(dict(ended.home_capital.bonds)["bond:new"].effective_reserve,Fraction(9,5))
        self.assertNotEqual(active.frame_digest,ended.frame_digest)

    def test_foreign_root_requires_selected_policy_and_whole_standing_ceiling(self):
        import rfc8785
        import json
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        from kinetic_trust_library.v3.native_proof_profile import RootProofBinding
        v,state,body,instrument,context=fixture()
        class Adapter:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone="zone-a")
        policy=InstalledRootVerifier(Adapter(),"sha256",federated_sponsorship_verifier=v)
        result=policy.evaluate(instrument,context_bytes=context,evaluated_at=1000)
        self.assertEqual(result.score,Fraction(144,5))
        self.assertTrue(result.federated_sponsorship.active)
        roots=select_assessed_roots((result,),context_bytes=context,evaluated_at=1000,algorithm="sha256")
        claims=dict(sub=body["subject"],exp=1007,ktp=dict(zone="zone-b",subject_kind="software_agent",generation=0,lineage="sponsored",
            sponsor=body["issuer"],root_instrument=json.loads(result.projection_bytes),e_base=70,
            applicable_ceilings=[dict(ceiling="federated_sponsor",value=72),dict(ceiling=result.federated_sponsorship.credit_ceiling_name,value=72)]))
        binding=RootProofBinding(roots,"zone-b")
        self.assertTrue(binding(rfc8785.dumps(claims),1000))
        for cap in claims["ktp"]["applicable_ceilings"]:cap["value"]=1
        claims["ktp"]["e_base"]=1
        state["current"]["home_base"]=80
        state["current"]["sponsor_admission"]["attestation"].update(attested_base=80,exportable_base=80)
        refreshed=policy.evaluate(instrument,context_bytes=context,evaluated_at=1000)
        selected=select_assessed_roots((refreshed,),context_bytes=context,evaluated_at=1000,algorithm="sha256")
        self.assertFalse(RootProofBinding(selected,"zone-b")(rfc8785.dumps(claims),1000))
        for cap in claims["ktp"]["applicable_ceilings"]:cap["value"]=72
        claims["ktp"]["e_base"]=73
        self.assertFalse(binding(rfc8785.dumps(claims),1000))
        claims["ktp"]["e_base"]=70;claims["ktp"]["applicable_ceilings"]=[]
        self.assertFalse(binding(rfc8785.dumps(claims),1000))
        missing=InstalledRootVerifier(Adapter(),"sha256").evaluate(instrument,context_bytes=context,evaluated_at=1000)
        self.assertEqual(missing.score,0)

    def test_installed_standing_applies_sponsor_ceiling_to_the_whole_base(self):
        import json
        import rfc8785
        from dataclasses import replace
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier,AuthenticatedStandingEvidence
        from tests.unit.core.test_v3_federation import fixture as federation_fixture
        v,state,body,instrument,context_bytes=fixture();context=json.loads(context_bytes)
        deployment=json.loads(v.deployment_profile_bytes);deployment.update(peer_share=0,external_root=dict(hop_bound=4))
        profile=json.loads(v.profile_bytes);profile["sponsor_admission_floor"]=10
        state["deployment_digest"]=context["deployment_digest"]=_digest(deployment,"sha256")
        state["profile_digest"]=context["federated_sponsorship_profile_digest"]=_digest(profile,"sha256")
        context_bytes=rfc8785.dumps(context);state["context_digest"]=_digest(context,"sha256")
        for part in ("opening","current"):
            state[part]["sponsor_admission"]["agreement"]["directions"][0]["factor"]="0.2"
        v=replace(v,deployment_profile_bytes=rfc8785.dumps(deployment),profile_bytes=rfc8785.dumps(profile))
        class Root:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone="zone-a")
        assessed=InstalledRootVerifier(Root(),"sha256",federated_sponsorship_verifier=v).evaluate(instrument,context_bytes=context_bytes,evaluated_at=1000)
        roots=select_assessed_roots((assessed,),context_bytes=context_bytes,evaluated_at=1000,algorithm="sha256")
        _,_,operation,_,_=federation_fixture();operation["actor"]=body["subject"]
        standing_body=dict(subject=body["subject"],generation=0,identity_assurance_level=3,trajectory_length=20000,
            por_contribution=70,peer_score=0,maximum_adversity_friction="0.9",crisis_exposure=True,additional_ceilings={})
        class Standing:
            def verify(self,*args,**kwargs):return AuthenticatedStandingEvidence(rfc8785.dumps(standing_body))
        verifier=InstalledStandingVerifier(v.deployment_profile_bytes,Standing(),"sha256")
        result=verifier.evaluate(b"modeled-local-standing",roots=roots,actual_operation=operation,evaluated_at=1000)
        self.assertEqual(result.base.base_trust,18)
        self.assertEqual(dict(result.base.ceilings)["federated_sponsor"],18)
        self.assertTrue(any(name.startswith("federated_sponsor_credit.") for name,_ in result.base.ceilings))
        standing_body["additional_ceilings"]["federated_sponsor"]=100
        from kinetic_trust_library.errors import ValidationError
        with self.assertRaises(ValidationError):verifier.evaluate(b"same",roots=roots,actual_operation=operation,evaluated_at=1000)


if __name__=="__main__":unittest.main()
