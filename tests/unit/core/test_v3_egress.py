"""Fresh native egress proofs; disclosure/measurement services are modeled."""
from importlib.util import find_spec
from dataclasses import replace
import json,base64
from pathlib import Path
import unittest

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.egress import InstalledEgressProjector,AuthenticatedEgressEvidence,minimize_confidential_exit_summary

HAS_EXTRAS=all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography"))


def fixture():
    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier,AuthenticatedSoulResponse
    from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier,AuthenticatedEnvironmentEvidence
    from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier,AuthenticatedStandingEvidence
    from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.installed_demand import InstalledDemandVerifier
    from kinetic_trust_library.v3.demand_classification import InstalledDemandClassifier
    from kinetic_trust_library.v3.core_projection import NativeCoreContext,project_classified_native_core
    from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource
    from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
    from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
    from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle,RootProofBinding
    from kinetic_trust_library.v3.enclosure import InstalledEnclosureVerifier,AuthenticatedEnclosureEvidence
    from kinetic_trust_library.v3._readiness_crypto import digest_bytes
    from tests.unit.core.test_v3_ingress import fixture as ingress_fixture
    from tests.unit.core.test_v3_installed_demand_verifier import FixtureAdapter
    root=Path(__file__).parents[3]
    vectors=json.loads((root/"spec/proposals/demand-supplier-v1.json").read_text())
    profile,operation=vectors["deployment_profile"],vectors["operation"]
    operation=dict(operation,actor="agent:guarantor:7gen:optimized:a1b2c3d4")
    raw=rfc8785.dumps(profile)
    roots=select_assessed_roots((),context_bytes=rfc8785.dumps(dict(subject=operation["actor"],subject_profile="software",generation=7,
        lineage="guarantor",hop_bound=profile["external_root"]["hop_bound"],deployment_digest=_digest(profile,"sha256"))),evaluated_at=1030,algorithm="sha256")
    class Soul:
        def query(self,*,required_frameworks,**kwargs):return tuple(AuthenticatedSoulResponse(f,"clear",b"modeled-clear") for f in required_frameworks)
    class Environment:
        def verify(self,*args,**kwargs):return AuthenticatedEnvironmentEvidence(rfc8785.dumps({"factors":{
            name:dict(signals=dict.fromkeys(config["signals"],0),measured_stress=.4) for name,config in profile["risk_factors"].items()}}))
    class Standing:
        def verify(self,*args,**kwargs):return AuthenticatedStandingEvidence(rfc8785.dumps(dict(subject=operation["actor"],generation=7,
            identity_assurance_level=3,trajectory_length=20000,por_contribution=70,peer_score=0,maximum_adversity_friction=.9,crisis_exposure=True,additional_ceilings={})))
    soul=InstalledSoulVerifier(raw,Soul(),"sha256").evaluate(actual_operation=operation,evaluated_at=1030)
    environment=InstalledEnvironmentVerifier(raw,Environment(),"sha256").evaluate(b"modeled-enclosure-environment",actual_operation=operation,evaluated_at=1030)
    standing=InstalledStandingVerifier(raw,Standing(),"sha256").evaluate(b"modeled-standing",roots=roots,actual_operation=operation,evaluated_at=1030)
    verified=InstalledDemandVerifier(raw,rfc8785.dumps(vectors["supplier_profile_payload"]),rfc8785.dumps(vectors["verification_profile_payload"]),
        FixtureAdapter(vectors,vectors["context"]),"sha256").evaluate(next(c for c in vectors["cases"] if c["id"]=="valid-value")["jws"].encode(),
            actual_operation=operation,evaluated_at=1030,clock_healthy=True)
    class Classifier:
        def classify(self,*args,criticality,**kwargs):return 10+criticality*10
    demand=InstalledDemandClassifier(raw,Classifier(),"sha256",rfc8785.dumps(dict(id="urn:test:classifier",version="test",unit="urn:ktp:unit:action-risk-points",formula="10+10*c"))).classify(
        verified,actual_operation=operation,evaluated_at=1030)
    enc_profile=dict(id="urn:test:outer-enclosure",version=1,formula="reference-floor-v1",zone_id="zone-1",depth=1,reach="0.5",attenuation_per_class_step="0.5",overlap_policy_id="urn:test:overlap")
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    enc_body=dict(deployment_digest=_digest(profile,"sha256"),operation_digest=digest_demand_operation(operation,algorithm="sha256"),profile_digest=_digest(enc_profile,"sha256"),
        checked_at=1030,zone_id="zone-1",depth=1,topology_epoch=5,zone_class="cyan",enclosure_class="green",enclosure_zone="zone-0",registry_reach="0.5",
        signed_enclosure_risk="0.1",gateway_risk="0.1",expires_at=1040)
    class Enclosure:
        def resolve(self,**kwargs):return AuthenticatedEnclosureEvidence(rfc8785.dumps(enc_body),b"modeled-current-outer-topology")
    enclosure=InstalledEnclosureVerifier(raw,rfc8785.dumps(enc_profile),Enclosure(),"sha256").evaluate(actual_operation=operation,evaluated_at=1030,clock_healthy=True)
    context=NativeCoreContext(raw,rfc8785.dumps(operation),1030,"sha256",rfc8785.dumps(enc_profile))
    core=project_classified_native_core(soul,standing=standing,environment=environment,context=context,demand=demand,enclosure=enclosure)
    inner_ingress,outer_ingress=ingress_fixture(2,evaluated_at=1030),ingress_fixture(1,evaluated_at=1030)
    metadata=dict(iss="https://outer.example.com",aud=operation["audience"],jti="fresh-egress",exp=1037,zone="zone-1",advancement_floor=0,ingress_path=outer_ingress["receipts"])
    outward=NativeCoreClaimsSource(core,standing,context,rfc8785.dumps(metadata))
    proof_vectors=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
    original=json.loads(base64.urlsafe_b64decode(next(c for c in proof_vectors["cases"] if c["id"]=="clear")["jws"].split(".")[1]+"=="))
    original.update(iat=1030,exp=1040)
    original["ktp"].update(subject_kind="software_agent",zone="zone-2",r=.31,e_trust=41.4,ingress_path=inner_ingress["receipts"],
        root_instrument=dict(kind="none",status="none",reason="missing"))
    keys={k["kid"]:dict(k,zone="zone-2",not_before=1000,not_after=1100) for k in proof_vectors["keys"]}
    incoming_context=dict(proof_vectors["context"],zone="zone-2",receiving_zone="zone-2",subject_kind="software_agent",ring_depth=2)
    incoming_verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps(keys),rfc8785.dumps(incoming_context),("EdDSA",),
        RootProofBinding(roots,"zone-2"),ingress_policy=inner_ingress["verifier"])
    class Input:
        def produce(self,**kwargs):return rfc8785.dumps(original)
    class Signer:
        def sign(self,message,**kwargs):return Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(message)
    incoming=InstalledProofIssuer(Input(),Signer(),incoming_verifier,"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
    outer_keys={name:dict(key,zone="zone-1",issuer="https://outer.example.com") for name,key in keys.items()}
    outer_context=dict(incoming_context,zone="zone-1",receiving_zone="zone-1",issuer="https://outer.example.com",audience=operation["audience"],ring_depth=1,required_ceilings={})
    outer_verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps(outer_keys),rfc8785.dumps(outer_context),("EdDSA",),
        RootProofBinding(roots,"zone-1"),ingress_policy=outer_ingress["verifier"])
    policy=dict(id="urn:test:disclosure",version=1,mode="fresh-enclosure-proof-v1",subject=operation["actor"],source_zone="zone-2",
        measurement_zone="zone-1",audience=operation["audience"],digest_algorithm="sha256")
    state=dict(profile_digest=_digest(policy,"sha256"),incoming_proof_digest=digest_bytes(incoming.compact.encode(),2),
        outward_claims_digest=digest_bytes(outward.produce(evaluated_at=1030),2),checked_at=1030,topology_epoch=5,
        ancestry=["zone-0","zone-1","zone-2"],expires_at=1039)
    calls=[]
    class Disclosure:
        def resolve(self,**kwargs):
            calls.append(kwargs)
            return AuthenticatedEgressEvidence(rfc8785.dumps(state),b"modeled-approved-whole-payload/current-departure/disclosure")
    projector=InstalledEgressProjector(rfc8785.dumps(policy),Disclosure(),incoming_verifier,outward)
    return dict(projector=projector,incoming=incoming,outward=outward,outer_verifier=outer_verifier,signer=Signer(),state=state,calls=calls,
        policy=policy,original=original,enc_body=enc_body)


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class EgressTests(unittest.TestCase):
    def test_known_veto_invalid_input_and_unhealthy_clock_cannot_be_cleared(self):
        import rfc8785
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        from kinetic_trust_library.v3._readiness_crypto import digest_bytes
        f=fixture()
        with self.assertRaises(ValidationError):f["projector"].evaluate(f["incoming"].compact,evaluated_at=1030,clock_healthy=False)
        with self.assertRaises(ValidationError):f["projector"].evaluate("invalid",evaluated_at=1030,clock_healthy=True)
        self.assertEqual(f["calls"],[])
        f["original"]["ktp"].update(gate_state="veto",soul=dict(soul=1,constraint_type="ocap",authority="urn:test:veto-authority"))
        class Veto:
            def produce(self,**kwargs):return rfc8785.dumps(f["original"])
        incoming=InstalledProofIssuer(Veto(),f["signer"],f["projector"].incoming_verifier,"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        self.assertEqual(incoming.verification.reason,"TP_VETO")
        f["state"]["incoming_proof_digest"]=digest_bytes(incoming.compact.encode(),2)
        with self.assertRaisesRegex(ValidationError,"known input veto"):
            f["projector"].evaluate(incoming.compact,evaluated_at=1030,clock_healthy=True)

    def test_nested_enclosure_cannot_be_replaced_with_flat_core_even_when_scores_match(self):
        from kinetic_trust_library.v3.core_projection import project_classified_native_core
        f=fixture();outward=f["outward"];core=outward.core
        context=replace(outward.context,enclosure_profile_bytes=None)
        flat=project_classified_native_core(core.soul_assessment,standing=core.standing_assessment,environment=core.environment_assessment,
            context=context,demand=core.classified_demand)
        flat_source=replace(outward,core=flat,context=context)
        self.assertEqual(flat_source.produce(evaluated_at=1030),outward.produce(evaluated_at=1030))
        with self.assertRaisesRegex(ValidationError,"enclosure"):
            replace(f["projector"],outward_claim_source=flat_source).evaluate(f["incoming"].compact,evaluated_at=1030,clock_healthy=True)

    def test_fresh_enclosure_proof_signed_and_original_unchanged(self):
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        f=fixture();before=f["incoming"].compact
        projected=f["projector"].evaluate(before,evaluated_at=1030,clock_healthy=True)
        issued=InstalledProofIssuer(projected,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        body=json.loads(issued.payload_bytes)
        self.assertEqual(issued.verification.reason,"TP_CLEAR")
        self.assertEqual((body["ktp"]["r"],body["ktp"]["e_trust"]),(.4,42))
        self.assertEqual([r["zone_id"] for r in body["ktp"]["ingress_path"]],["zone-0"])
        self.assertNotIn("de_dt",body["ktp"]);self.assertNotIn("sigma",body["ktp"])
        self.assertEqual(f["incoming"].compact,before)
        self.assertNotEqual(issued.compact,before)
        self.assertNotIn("incoming_compact",f["calls"][0])
        self.assertIs(projected.outward_core,f["outward"].core)

    def test_stale_misbound_or_unapproved_output_fails(self):
        for field,value in (("checked_at",1029),("topology_epoch",6),("outward_claims_digest","sha256:"+"0"*64),
                            ("incoming_proof_digest","sha256:"+"0"*64),("expires_at",1036),("ancestry",["wrong","zone-1","zone-2"])):
            f=fixture();f["state"][field]=value
            with self.subTest(field=field),self.assertRaises(ValidationError):
                f["projector"].evaluate(f["incoming"].compact,evaluated_at=1030,clock_healthy=True)

    def test_minimal_exit_summary_omits_statistics_and_unknown_fields(self):
        import rfc8785
        original=dict(actions_total=10,actions_allowed=8,actions_vetoed=2,soul_vetoes=1,attestations_earned=3,
            min_e_trust=10,max_e_trust=70,avg_e_trust=42,tier_history=["operator"],r=.4,veto_rate=.2,unknown={"hidden":.4})
        raw=rfc8785.dumps(original)
        result=json.loads(minimize_confidential_exit_summary(raw))
        self.assertEqual(set(result),{"actions_total","actions_allowed","actions_vetoed","soul_vetoes","attestations_earned"})
        self.assertEqual(json.loads(raw),original)
        with self.assertRaises(ValidationError):minimize_confidential_exit_summary(rfc8785.dumps(dict(actions_total=True)))
