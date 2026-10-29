"""A real installed-input Core evaluation feeds native signed proof issuance."""
import json
import unittest
from decimal import Decimal
from importlib.util import find_spec
from pathlib import Path
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource, _wire_number


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785", "jsonschema", "cryptography")), "install v3-proofs")
class CoreClaimsTests(unittest.TestCase):
    def test_native_bundle_uses_v3_risk_id_without_rewriting_proposal_snapshot(self):
        from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle
        schemas=[json.loads(raw) for raw in native_schema_bundle().schemas]
        new_id="https://kinetic-trust-protocol.net/specs/schemas/v3/risk-factors.json"
        self.assertIn(new_id,{s["$id"] for s in schemas})
        context=schemas[0]["$defs"]["ktpClaims"]["properties"]["context"]
        self.assertEqual(context["anyOf"][0]["$ref"],new_id)
        original=json.loads((Path(__file__).parents[3]/"src/kinetic_trust_library/v3/schemas/trust-proof-composed-v3.json").read_text())
        self.assertIn("/v2/",original["$defs"]["ktpClaims"]["properties"]["context"]["anyOf"][0]["$ref"])

    def test_wire_conversion_preserves_value_or_requires_precision_profile(self):
        self.assertEqual(_wire_number(Decimal("0.1")),.1)
        self.assertEqual(_wire_number(Decimal("52.5")),52.5)
        for value in ("0.1234567890123456789012345678901234", "1e-6143", "9007199254740992"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                _wire_number(Decimal(value))

    def test_classified_core_to_signed_proof_and_unknown_measurements(self):
        import base64
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier, AuthenticatedSoulResponse
        from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier, AuthenticatedEnvironmentEvidence
        from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier, AuthenticatedStandingEvidence
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.installed_demand import InstalledDemandVerifier
        from kinetic_trust_library.v3.demand_classification import InstalledDemandClassifier
        from kinetic_trust_library.v3.core_projection import NativeCoreContext, project_classified_native_core
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
        from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle, RootProofBinding
        from tests.unit.core.test_v3_installed_demand_verifier import FixtureAdapter
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())
        profile,operation=vectors["deployment_profile"],vectors["operation"]
        operation={**operation,"actor":"agent:guarantor:7gen:optimized:a1b2c3d4"}
        raw=rfc8785.dumps(profile)
        class Soul:
            state="clear"
            def query(self, *, required_frameworks, **kwargs):
                return tuple(AuthenticatedSoulResponse(f,self.state,b"fixture-authenticated",
                    rfc8785.dumps(dict(soul=1,constraint_type="ocap",authority="urn:ktp:authority:fixture")) if self.state=="veto" else None)
                    for f in required_frameworks)
        soul_adapter=Soul()
        class Environment:
            absent=False
            def verify(self,*args,**kwargs):
                return AuthenticatedEnvironmentEvidence(rfc8785.dumps({"factors":{
                    name:{"signals":{} if self.absent else dict.fromkeys(config["signals"],0),"measured_stress":.25}
                    for name,config in profile["risk_factors"].items()}}))
        environment_adapter=Environment()
        roots=select_assessed_roots((),context_bytes=rfc8785.dumps(dict(subject=operation["actor"],subject_profile="software",
            generation=7,lineage="guarantor",hop_bound=profile["external_root"]["hop_bound"],deployment_digest=_digest(profile,"sha256"))),
            evaluated_at=1030,algorithm="sha256")
        class Standing:
            def verify(self,*args,**kwargs):
                return AuthenticatedStandingEvidence(rfc8785.dumps(dict(subject=operation["actor"],generation=7,
                    identity_assurance_level=3,trajectory_length=20000,por_contribution=70,peer_score=0,
                    maximum_adversity_friction=.9,crisis_exposure=True,additional_ceilings={})))
        standing=InstalledStandingVerifier(raw,Standing(),"sha256").evaluate(b"standing",roots=roots,actual_operation=operation,evaluated_at=1030)
        demand_verifier=InstalledDemandVerifier(raw,rfc8785.dumps(vectors["supplier_profile_payload"]),
            rfc8785.dumps(vectors["verification_profile_payload"]),FixtureAdapter(vectors,vectors["context"]),"sha256")
        case=next(c for c in vectors["cases"] if c["id"]=="valid-value")
        assessed=demand_verifier.evaluate(case["jws"].encode(),actual_operation=operation,evaluated_at=1030,clock_healthy=True)
        class Classifier:
            def classify(self,operation_bytes,*,criticality,classifier_profile_bytes): return 10+criticality*10
        classifier_profile=rfc8785.dumps(dict(id="urn:ktp:classifier:core-test",version="test-v1",unit="ktp-action-risk-points",formula="10 + 10 * moment_criticality"))
        demand=InstalledDemandClassifier(raw,Classifier(),"sha256",classifier_profile).classify(assessed,actual_operation=operation,evaluated_at=1030)
        context=NativeCoreContext(raw,rfc8785.dumps(operation),1030,"sha256")
        metadata=rfc8785.dumps(dict(iss="https://oracle.example.com",aud=operation["audience"],jti="native-core-proof",exp=1040,zone="zone:alpha",advancement_floor=0))
        private=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        key=dict(kid="native-test",alg="EdDSA",kty="OKP",crv="Ed25519",issuer="https://oracle.example.com",zone="zone:alpha",
            role="trust-proof-oracle",revoked=False,not_before=1000,not_after=1100,
            x=base64.urlsafe_b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).rstrip(b"=").decode())
        verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({key["kid"]:key}),rfc8785.dumps(dict(
            issuer=key["issuer"],audience=operation["audience"],zone="zone:alpha",subject=operation["actor"],subject_kind="software_agent",
            required_ceilings={},ring_depth=0)),("EdDSA",),RootProofBinding(roots,"zone:alpha"))
        class Signer:
            def sign(self,signing_input,**kwargs): return private.sign(signing_input)
        for soul_state,absent,expected in (("clear",False,"TP_CLEAR"),("clear",True,"TP_UNDETERMINED"),("veto",False,"TP_VETO"),("unanswered",False,"TP_UNDETERMINED")):
            with self.subTest(soul=soul_state,absent=absent):
                soul_adapter.state=soul_state
                environment_adapter.absent=absent
                soul=InstalledSoulVerifier(raw,soul_adapter,"sha256").evaluate(actual_operation=operation,evaluated_at=1030)
                environment=InstalledEnvironmentVerifier(raw,environment_adapter,"sha256").evaluate(b"environment",actual_operation=operation,evaluated_at=1030)
                core=project_classified_native_core(soul,standing=standing,environment=environment,context=context,demand=demand)
                source=NativeCoreClaimsSource(core,standing,context,metadata)
                issued=InstalledProofIssuer(source,Signer(),verifier,"EdDSA",key["kid"]).issue(now=1030,clock_healthy=True)
                self.assertEqual(issued.verification.reason,expected)
                claims=json.loads(issued.payload_bytes)["ktp"]
                self.assertEqual(claims["root_instrument"],dict(kind="none",status="none",reason="missing"))
                self.assertEqual(claims["e_trust"],52.5 if expected=="TP_CLEAR" else None)
                if absent: self.assertIsNone(claims["r"])
                from kinetic_trust_library.v3.native_geometry import NativeGeometrySource, AuthenticatedGeometryAuthority
                from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier
                geometry_profile=rfc8785.dumps(dict(id="urn:ktp:profile:native-geometry-test",release="unreleased-v3.0.0",
                    evaluator="urn:ktp:evaluator:test",core_deployment_digest=_digest(profile,"sha256"),
                    numeric_convention="exact-decimal-boundaries-binary64-margin-v1",constraint_policy="retain-grant-and-prior-v1",
                    input_order="layer-then-name-v1",sources=dict(soul="urn:ktp:source:soul",core="urn:ktp:source:core",environment="urn:ktp:source:environment",
                    demand="urn:ktp:source:demand",authority="urn:ktp:source:authority"),magnitudes={"max_calls":{"unit":"calls","direction":"maximum"}},
                    thresholds=dict(veto=0,assisted_floor=.05,metacognitive_floor=.1,allow=.2)))
                class Authority:
                    prior="stable"
                    prior_state="observed"
                    grant_state="observed"
                    calls=0
                    def verify(self,**kwargs):
                        self.calls+=1
                        prior=(dict(state="observed",supervision=self.prior,ceilings={"max_calls":8}) if self.prior_state=="observed" else dict(state=self.prior_state))
                        grant=(dict(state="observed",ceilings={"max_calls":10}) if self.grant_state=="observed" else dict(state=self.grant_state))
                        return AuthenticatedGeometryAuthority(rfc8785.dumps(dict(prior=prior,grant=grant)),b"fixture-authenticated-grant-and-prior")
                authority=Authority()
                geometry=NativeGeometrySource(source,demand,issued.compact,verifier,geometry_profile,authority,"native-decision",True)
                raw_body=geometry.produce(evaluated_at=1030)
                body=json.loads(raw_body)
                self.assertEqual(InstalledGeometryVerifier(geometry,verifier,"sha256").verify(raw_body,evaluated_at=1030).reason,"DG_VALID")
                self.assertEqual(body["result"]["supervision"],"stable" if expected=="TP_CLEAR" else "silent_veto")
                self.assertEqual(body["gates"]["binding"],"passed")
                if expected=="TP_CLEAR":
                    self.assertEqual(body["capacity"]["E"],52.5)
                    self.assertEqual(body["result"]["tightenedConstraints"]["ceilings"],[{"magnitude":"max_calls","max":8}])
                    authority.prior="regulated"
                    regulated=json.loads(geometry.produce(evaluated_at=1030))
                    self.assertEqual(regulated["result"]["supervision"],"regulated")
                    authority.prior="silent_veto"
                    veto=json.loads(geometry.produce(evaluated_at=1030))
                    self.assertEqual(veto["gates"]["prior"],"failed")
                    self.assertNotIn("capacity",veto)
                    self.assertNotIn("margin",veto)
                    authority.prior="stable"
                    for missing in ("prior", "grant"):
                        setattr(authority,missing+"_state","absent")
                        unavailable=json.loads(geometry.produce(evaluated_at=1030))
                        self.assertEqual(unavailable["result"]["supervision"],"silent_veto")
                        self.assertNotIn("capacity",unavailable)
                        self.assertIn(dict(input="prior_supervision" if missing=="prior" else "grant",layer="term",state="absent"),unavailable["undefined_inputs"])
                        setattr(authority,missing+"_state","observed")
                    for value,capacity_gate,has_margin in ((52.5,"passed",True),(60,"failed",False)):
                        class FixedClassifier:
                            def classify(self,*args,**kwargs): return value
                        fixed_profile=rfc8785.dumps(dict(id="urn:ktp:classifier:fixed-test",version="test-v1",unit="ktp-action-risk-points",formula=str(value)))
                        fixed=InstalledDemandClassifier(raw,FixedClassifier(),"sha256",fixed_profile).classify(assessed,actual_operation=operation,evaluated_at=1030)
                        fixed_core=project_classified_native_core(soul,standing=standing,environment=environment,context=context,demand=fixed)
                        fixed_source=NativeCoreClaimsSource(fixed_core,standing,context,metadata)
                        stopped=json.loads(NativeGeometrySource(fixed_source,fixed,issued.compact,verifier,geometry_profile,authority,"boundary",True).produce(evaluated_at=1030))
                        self.assertEqual(stopped["gates"]["capacity"],capacity_gate)
                        self.assertEqual("margin" in stopped,has_margin)
                        self.assertEqual(stopped["result"]["supervision"],"silent_veto")
                    calls=authority.calls
                    rejected=json.loads(NativeGeometrySource(source,demand,"bad.proof.bytes",verifier,geometry_profile,authority,"rejected",True).produce(evaluated_at=1030))
                    self.assertEqual(rejected["gates"]["binding"],"failed")
                    self.assertIsNone(rejected["association"])
                    self.assertEqual(authority.calls,calls)
                else:
                    self.assertNotIn("capacity",body)
                    self.assertNotIn("margin",body)
                    if soul_state!="clear": self.assertEqual(authority.calls,0)
                if expected == "TP_CLEAR":
                    from kinetic_trust_library.v3.request_association import InstalledRequestAssociationVerifier
                    from kinetic_trust_library.v3.request_binding import digest_canonical_request, digest_complete_proof
                    request_bytes=geometry.request_bytes
                    request=json.loads(request_bytes)
                    association=rfc8785.dumps(dict(version="request-proof-association-v1",
                        request_digest=digest_canonical_request(request,algorithm="sha256"),
                        proof_digest=digest_complete_proof(issued.compact,algorithm="sha256"),proof_jti="native-core-proof"))
                    class Invocation:
                        def reconstruct(self,evidence,*,evaluated_at): return request_bytes
                    class Replay:
                        def reserve(self,**kwargs): return "RB_BOUND"
                    bound=InstalledRequestAssociationVerifier(Invocation(),verifier,Replay(),"sha256").verify(
                        request_bytes,association,issued.compact,invocation_evidence=b"fixture-verified-delegation",now=1030,clock_healthy=True)
                    self.assertEqual(bound.reason,"RB_BOUND")
                    self.assertNotEqual(request["subject"],request["actor"])
                    from kinetic_trust_library.v3.geometry_carrier import InstalledGeometryCarrierVerifier
                    from kinetic_trust_library.v3.geometry_issuance import InstalledGeometryCarrierIssuer
                    from kinetic_trust_library.v3.carrier_association import AssociationGeometryCarrier
                    evaluator=json.loads(geometry_profile)["evaluator"]
                    carrier_key={**key,"kid":"native-carrier-test","role":"decision-geometry-evaluator",
                        "issuer":evaluator,"audience":operation["audience"],"curve":"Ed25519"}
                    carrier_context=rfc8785.dumps(dict(identity=dict(evaluator=evaluator,audience=operation["audience"],evaluated_at=1030),
                        request=request,proof=issued.compact,profile_expires_at=1040,supporting_expiries=[1038]))
                    carrier_verifier=InstalledGeometryCarrierVerifier(rfc8785.dumps({carrier_key["kid"]:carrier_key}),carrier_context,
                        InstalledGeometryVerifier(geometry,verifier,"sha256"),("EdDSA",))
                    carrier=InstalledGeometryCarrierIssuer(geometry,Signer(),carrier_verifier,"EdDSA",carrier_key["kid"]).issue(
                        now=1030,clock_healthy=True)
                    protected=InstalledRequestAssociationVerifier(Invocation(),verifier,Replay(),"sha256",True,
                        AssociationGeometryCarrier(carrier.compact,carrier_verifier)).verify(request_bytes,association,issued.compact,
                        invocation_evidence=b"fixture-verified-delegation",now=1030,clock_healthy=True)
                    self.assertEqual(protected.reason,"RB_BOUND")
                    self.assertEqual(json.loads(protected.carrier_binding.canonical_geometry_bytes),body)
                    missing_units=rfc8785.dumps({**json.loads(geometry_profile),"magnitudes":["max_calls"]})
                    with self.assertRaises(ValidationError):
                        NativeGeometrySource(source,demand,issued.compact,verifier,missing_units,authority,"missing-units",True)
                    wrong_metadata=rfc8785.dumps({**json.loads(metadata),"aud":"urn:other-audience"})
                    with self.assertRaisesRegex(ValidationError,"audience"):
                        NativeCoreClaimsSource(core,standing,context,wrong_metadata)
                with self.assertRaises(ValidationError): source.produce(evaluated_at=1031)


if __name__ == "__main__": unittest.main()
