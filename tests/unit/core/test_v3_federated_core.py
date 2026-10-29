"""Real native signed proof from a selected imported-standing route."""
import json
import unittest
from dataclasses import replace
from importlib.util import find_spec
from decimal import Decimal


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","cryptography","jsonschema")),"install v3-proofs")
class FederatedCoreTests(unittest.TestCase):
    def test_imported_route_preserves_local_core_and_admission_bound_claims(self):
        import rfc8785
        from kinetic_trust_library.errors import ValidationError
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.installed_standing import InstalledStandingVerifier,AuthenticatedStandingEvidence
        from kinetic_trust_library.v3.imported_standing import NativeImportedStanding
        from kinetic_trust_library.v3.core_projection import project_classified_native_core
        from kinetic_trust_library.v3.core_claims import NativeCoreClaimsSource
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        from tests.unit.core.test_v3_egress import fixture as core_fixture
        from tests.unit.core.test_v3_federation import fixture as fed_fixture
        f=core_fixture();original=f["outward"]
        operation=json.loads(original.context.operation_bytes)
        policy,state,op,profile,_=fed_fixture(operation,json.loads(original.context.deployment_profile_bytes),1030,"zone-1")
        profile["standing_binding"]="admission-digest-ceiling-v1"
        state["profile_digest"]=_digest(profile,"sha256");policy=replace(policy,profile_bytes=rfc8785.dumps(profile))
        standing_body=json.loads(original.standing.authenticated_body_bytes)
        del standing_body["por_contribution"];del standing_body["peer_score"]
        class Standing:
            def verify(self,*args,**kwargs):return AuthenticatedStandingEvidence(rfc8785.dumps(standing_body))
        verifier=InstalledStandingVerifier(original.context.deployment_profile_bytes,Standing(),"sha256",federation_verifier=policy)
        standing=verifier.evaluate(b"modeled-local-identity-and-ceilings",roots=original.standing.roots,actual_operation=operation,evaluated_at=1030)
        self.assertIs(type(standing.base),NativeImportedStanding)
        self.assertEqual(standing.base.base_trust,56)
        self.assertEqual(len([name for name,_ in standing.base.ceilings if name.startswith("federation_ingress.")]),1)
        context=replace(original.context,federation_profile_bytes=policy.profile_bytes)
        def core(ctx):return project_classified_native_core(original.core.soul_assessment,standing=standing,
            environment=original.core.environment_assessment,context=ctx,demand=original.core.classified_demand,enclosure=original.core.enclosure_assessment)
        result=core(context)
        self.assertEqual(result.capacity.measured_effective_trust,Decimal("33.6"))
        claims=NativeCoreClaimsSource(result,standing,context,original.assertion_metadata_bytes)
        proof=InstalledProofIssuer(claims,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        self.assertEqual(json.loads(proof.payload_bytes)["ktp"]["e_base"],56)
        self.assertEqual(json.loads(proof.payload_bytes)["ktp"]["peer_share"],json.loads(context.deployment_profile_bytes)["peer_share"])
        with self.assertRaisesRegex(ValidationError,"federation"):core(original.context)
        metadata=json.loads(original.assertion_metadata_bytes);metadata["exp"]=1038
        with self.assertRaisesRegex(ValidationError,"federation"):
            replace(claims,assertion_metadata_bytes=rfc8785.dumps(metadata))
        standing_body["additional_ceilings"]["federation_ingress.counterfeit"]=100
        with self.assertRaisesRegex(ValidationError,"ceilings"):
            verifier.evaluate(b"same-local-evidence",roots=original.standing.roots,actual_operation=operation,evaluated_at=1030)
        standing_body["additional_ceilings"]={}
        from kinetic_trust_library.v3.native_geometry import NativeGeometrySource,AuthenticatedGeometryAuthority
        evaluation=dict(id="urn:test:fed-geometry",release="unreleased-v3.0.0",evaluator="urn:test:evaluator",
            core_deployment_digest=_digest(json.loads(context.deployment_profile_bytes),"sha256"),input_order="layer-then-name-v1",
            numeric_convention="exact-decimal-boundaries-binary64-margin-v1",constraint_policy="retain-grant-and-prior-v1",
            sources={name:"urn:test:source:"+name for name in ("soul","core","environment","demand","authority")},
            magnitudes={"max_calls":{"unit":"calls","direction":"maximum"}},thresholds=dict(veto=0,assisted_floor=.05,metacognitive_floor=.1,allow=.2),
            federation_profile_digest=standing.federation.profile_digest)
        class Authority:
            def verify(self,**kwargs):return AuthenticatedGeometryAuthority(rfc8785.dumps(dict(prior=dict(state="observed",supervision="stable",ceilings={}),
                grant=dict(state="observed",ceilings={"max_calls":8}))),b"modeled-current-grant")
        geometry=NativeGeometrySource(claims,result.classified_demand,proof.compact,f["outer_verifier"],rfc8785.dumps(evaluation),Authority(),"federation-geometry",True)
        body=json.loads(geometry.produce(evaluated_at=1030))
        self.assertEqual(next(item for item in body["inputs"] if item["name"]=="federation")["value"],standing.federation.geometry_value())
        state["checked_at"]=1031
        refreshed=policy.evaluate(actual_operation=operation,evaluated_at=1031,clock_healthy=True)
        self.assertEqual(refreshed.standing_ceiling_name,standing.federation.standing_ceiling_name)
        state["checked_at"]=1030
        evaluation.pop("federation_profile_digest")
        with self.assertRaisesRegex(ValidationError,"federation"):replace(geometry,evaluation_profile_bytes=rfc8785.dumps(evaluation))
        state["receiver_accepting"]=False
        with self.assertRaisesRegex(ValidationError,"FEDERATION"):
            verifier.evaluate(b"same-local-evidence",roots=original.standing.roots,actual_operation=operation,evaluated_at=1030)
