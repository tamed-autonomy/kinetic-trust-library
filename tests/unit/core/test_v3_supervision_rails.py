"""Rail ownership/release semantics; signatures are tested separately below."""
from dataclasses import replace
from importlib.util import find_spec
import unittest
import json
from kinetic_trust_library.errors import ValidationError

from kinetic_trust_library.v3.supervision_rails import (
    RailScope,RailIncrement,RailRelease,project_supervision_rails,
)


def scope():
    return RailScope("evaluation-1","urn:agent:1","sha256:"+"1"*64,"test-possession",
                     "sha256:"+"2"*64,"sha256:"+"3"*64,"zone:alpha",5)


def hold(rail="normative",increment="hold-1",before="stable",after="regulated",frame=None):
    return RailIncrement(frame or scope(),increment,rail,"urn:issuer:"+rail,before,after)


def release(rail="normative",target="stable",frame=None,increment="hold-1",identifier="release-1"):
    return RailRelease(frame or scope(),identifier,increment,rail,"urn:issuer:"+rail,target)


class RailProjectionTests(unittest.TestCase):
    def test_release_own_increment_and_preserve_other_rail(self):
        result=project_supervision_rails(scope(),"stable",(hold(),),(release(),))
        self.assertEqual(result.supervision,"stable")
        self.assertTrue(result.release_outcomes[0].requested_level_permitted)
        other=hold("prudence","other",after="assisted")
        result=project_supervision_rails(scope(),"stable",(hold(),other),(release(),))
        self.assertEqual(result.supervision,"assisted")

    def test_below_floor_request_only_releases_to_environment_floor(self):
        result=project_supervision_rails(scope(),"assisted",(hold(before="assisted"),),(release(),))
        self.assertEqual(result.supervision,"assisted")
        self.assertTrue(result.release_outcomes[0].applied)
        self.assertFalse(result.release_outcomes[0].requested_level_permitted)

    def test_other_party_action_actor_and_evaluation_do_not_release(self):
        for changed in (replace(release(),issuer="urn:other"),release("prudence"),
                        release(frame=replace(scope(),actor="urn:agent:2")),
                        release(frame=replace(scope(),action_digest="sha256:"+"4"*64)),
                        release(frame=replace(scope(),evaluation_id="evaluation-2"))):
            with self.subTest(changed=changed):
                result=project_supervision_rails(scope(),"stable",(hold(),),(changed,))
                self.assertEqual(result.supervision,"regulated")
                self.assertFalse(result.release_outcomes[0].applied)

    def test_releases_cannot_raise_or_clear_existing_veto(self):
        result=project_supervision_rails(scope(),"silent_veto",(hold(),),(release(),))
        self.assertEqual(result.supervision,"silent_veto")
        result=project_supervision_rails(scope(),"stable",(hold(),),(release(target="silent_veto"),))
        self.assertEqual(result.supervision,"regulated")
        self.assertFalse(result.release_outcomes[0].applied)

    def test_next_evaluation_starts_from_fresh_hold(self):
        next_scope=replace(scope(),evaluation_id="evaluation-2")
        result=project_supervision_rails(next_scope,"stable",(hold(frame=next_scope),),(release(),))
        self.assertEqual(result.supervision,"regulated")

    def test_multiple_releases_are_order_independent(self):
        a,b=release(target="assisted"),release(identifier="release-2")
        first=project_supervision_rails(scope(),"stable",(hold(),),(a,b))
        second=project_supervision_rails(scope(),"stable",(hold(),),(b,a))
        self.assertEqual(first.supervision,second.supervision)
        self.assertEqual(first.supervision,"stable")


@unittest.skipUnless(all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class InstalledRailTests(unittest.TestCase):
    def test_real_signature_source_inventory_and_scope(self):
        from kinetic_trust_library.v3.supervision_rails import InstalledSupervisionRailVerifier,AuthenticatedRailContext,AuthenticatedRailPayload
        from tests.unit.core.test_v3_egress import fixture
        from kinetic_trust_library.v3 import _readiness_crypto as c
        from kinetic_trust_library.v3.demand_operation import digest_demand_operation
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.exceptions import InvalidSignature
        from dataclasses import asdict
        f=fixture();claims=f["outward"];context=claims.context
        external={"$id":"urn:test:rail-schema","type":"object"}
        profile=dict(id="urn:test:rails",version=1,external_schema_id=external["$id"],external_schema_digest=c.digest(external,2),
            signature_profile_id="urn:unsafe-test:rails-ed25519",digest_algorithm="sha256",rail_authorities={"normative":"urn:issuer:normative","prudence":"urn:issuer:prudence"})
        evaluation=dict(id="urn:test:rail-geometry",release="unreleased-v3.0.0",evaluator="urn:test:rail-evaluator",
            core_deployment_digest=c.digest(json.loads(context.deployment_profile_bytes),2),input_order="layer-then-name-v1",
            numeric_convention="exact-decimal-boundaries-binary64-margin-v1",constraint_policy="retain-grant-and-prior-v1",
            sources={name:"urn:test:source:"+name for name in ("soul","core","environment","demand","authority")},
            magnitudes={"max_calls":{"unit":"calls","direction":"maximum"}},
            thresholds=dict(veto=0,assisted_floor=.05,metacognitive_floor=.1,allow=.2),supervision_rail_profile_digest=c.digest(profile,2))
        frame=replace(scope(),evaluation_id="rail-geometry",actor=json.loads(context.operation_bytes)["actor"],zone_id="zone-1")
        private=Ed25519PrivateKey.from_private_bytes(bytes([51])*32)
        event=dict(kind="increment",scope=asdict(frame),increment_id="hold-1",rail_id="normative",issuer="urn:issuer:normative",
            from_supervision="stable",to_supervision="regulated",iat=1029,exp=1036)
        change=dict(kind="release",scope=asdict(frame),release_id="release-1",increment_id="hold-1",rail_id="normative",issuer="urn:issuer:normative",
            to_supervision="stable",iat=1029,exp=1035)
        def sign(body):
            message=(c.b64(c.canonical(dict(alg="EdDSA",kid="rail-key",typ="ktp-rail-test-v1")))+"."+c.b64(c.canonical(body))).encode()
            return message+b"."+c.b64(private.sign(message)).encode()
        hold_token=sign(event)
        state=dict(profile_digest=c.digest(profile,2),deployment_digest=c.digest(json.loads(context.deployment_profile_bytes),2),
            operation_digest=digest_demand_operation(json.loads(context.operation_bytes),algorithm="sha256"),
            evaluation_profile_digest=c.digest(evaluation,2),checked_at=1030,scope=asdict(frame),
            active_increment_digests={"hold-1":c.digest_bytes(hold_token,2)},expires_at=1037)
        calls=[]
        class Source:
            def resolve(self,**kwargs):
                calls.append(kwargs)
                return AuthenticatedRailContext(c.canonical(state),b"modeled-complete-current-increment-inventory")
        class Adapter:
            def verify(self,raw,**kwargs):
                header,body,sig=raw.decode().split(".")
                if c.unb64(header)!=c.canonical(dict(alg="EdDSA",kid="rail-key",typ="ktp-rail-test-v1")):raise ValueError("header")
                try:private.public_key().verify(c.unb64(sig),(header+"."+body).encode())
                except InvalidSignature as error:raise ValueError("signature") from error
                payload=c.unb64(body)
                return AuthenticatedRailPayload(payload,"urn:issuer:normative","rail-key",b"real-fixture-signature/modeled-role")
        verifier=InstalledSupervisionRailVerifier(c.canonical(profile),c.canonical(external),Source(),Adapter())
        def evaluate(increments=(hold_token,),releases=()):
            return verifier.evaluate(claims,c.canonical(evaluation),increments,releases,evaluated_at=1030,clock_healthy=True)
        held=evaluate()
        self.assertEqual(held.projection.supervision,"regulated")
        released=evaluate(releases=(sign(change),))
        self.assertEqual(released.projection.supervision,"stable")
        self.assertEqual(released.expires_at,1035)
        self.assertEqual(released.increment_tokens,(hold_token,))
        self.assertNotIn("increment_tokens",calls[0])
        with self.assertRaises(ValidationError):evaluate(increments=())
        self.assertEqual(evaluate(releases=(b"invalid",)).projection.supervision,"regulated")
        from kinetic_trust_library.v3.native_geometry import NativeGeometrySource,AuthenticatedGeometryAuthority
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer
        proof=InstalledProofIssuer(claims,f["signer"],f["outer_verifier"],"EdDSA","TEST-ed25519").issue(now=1030,clock_healthy=True)
        class Authority:
            def verify(self,**kwargs):return AuthenticatedGeometryAuthority(c.canonical(dict(
                prior=dict(state="observed",supervision="stable",ceilings={}),
                grant=dict(state="observed",ceilings={"max_calls":8}))),b"modeled-nonreleasable-prior/grant")
        geometry=NativeGeometrySource(claims,claims.core.classified_demand,proof.compact,f["outer_verifier"],c.canonical(evaluation),Authority(),"rail-geometry",True,
            supervision_rails=held)
        held_body=json.loads(geometry.produce(evaluated_at=1030))
        released_body=json.loads(replace(geometry,supervision_rails=released).produce(evaluated_at=1030))
        self.assertEqual(held_body["result"]["supervision"],"regulated")
        self.assertEqual(released_body["result"]["supervision"],"stable")
        self.assertEqual(held_body["capacity"],released_body["capacity"])
        self.assertEqual(held_body["result"]["tightenedConstraints"],released_body["result"]["tightenedConstraints"])
        from kinetic_trust_library.v3.geometry_carrier import InstalledGeometryCarrierVerifier
        from kinetic_trust_library.v3.geometry_issuance import InstalledGeometryCarrierIssuer
        from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier
        released_geometry=replace(geometry,supervision_rails=released)
        key=json.loads(f["outer_verifier"].trusted_keys_bytes)["TEST-ed25519"]
        carrier_key={**key,"kid":"rail-carrier","role":"decision-geometry-evaluator",
            "issuer":evaluation["evaluator"],"audience":json.loads(context.operation_bytes)["audience"],"curve":"Ed25519"}
        carrier_context=c.canonical(dict(identity=dict(evaluator=evaluation["evaluator"],
            audience=carrier_key["audience"],evaluated_at=1030),request=json.loads(released_geometry.request_bytes),
            proof=proof.compact,profile_expires_at=1037,supporting_expiries=[]))
        carrier_verifier=InstalledGeometryCarrierVerifier(c.canonical({"rail-carrier":carrier_key}),carrier_context,
            InstalledGeometryVerifier(released_geometry,f["outer_verifier"],"sha256"),("EdDSA",))
        carrier=InstalledGeometryCarrierIssuer(released_geometry,f["signer"],carrier_verifier,"EdDSA","rail-carrier").issue(
            now=1030,clock_healthy=True)
        self.assertEqual(json.loads(carrier.payload_bytes)["expires_at"],1035)
        self.assertEqual(carrier.verification.reason,"DG_CARRIER_VALID")
        with self.assertRaisesRegex(ValidationError,"rail"):replace(geometry,supervision_rails=None)
        with self.assertRaisesRegex(ValidationError,"rail"):replace(released_geometry,decision_id="another-evaluation")
        change["scope"]["evaluation_id"]="next-evaluation"
        self.assertEqual(evaluate(releases=(sign(change),)).projection.supervision,"regulated")
