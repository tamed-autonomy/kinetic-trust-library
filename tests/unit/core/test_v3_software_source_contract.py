import hashlib
import json
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
import unittest


@unittest.skipUnless(all(find_spec(n) for n in ('rfc8785','jsonschema','cryptography')),'install v3-proofs')
class RevisedSoftwareSourceTests(unittest.TestCase):
    def suite(self):
        return json.loads((Path(__file__).parents[3]/'spec/proposals/software-substrate-execution-v1.json').read_bytes())

    def test_source_signature_binding_subchecks_use_real_runtime_verifiers(self):
        import rfc8785
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from kinetic_trust_library._jws_encoding import _decode_segment
        from kinetic_trust_library.v3.native_issuance import _segment
        from kinetic_trust_library.v3.software_decision_signature import InstalledSoftwareDecisionSignatureVerifier
        from kinetic_trust_library.v3.trust_proof_signature import trust_proof_signature_valid
        suite=self.suite();numbers=load_pem_public_key(suite['fixturePublicKeyPem'].encode()).public_numbers()
        public=dict(alg='ES256',kty='EC',crv='P-256',x=_segment(numbers.x.to_bytes(32,'big')),y=_segment(numbers.y.to_bytes(32,'big')))
        cases=[c for c in suite['vectors'] if c.get('stage')=='signature_binding']
        self.assertEqual(len(cases),5)
        for case in cases:
            with self.subTest(case=case['id']):
                inputs=case['request']['softwareContext']['cryptographicInputs'];compact=inputs['signedDecision']
                body=json.loads(_decode_segment(compact.split('.')[1],name='source payload'))
                key=dict(public,kid='fixture-only',subject=body['issuer_id'],zone_id='zone:source-fixture',
                    purpose='ktp-software-substrate-decision-v1',not_before=0,not_after=1000,revoked=False)
                profile=dict(id='signature:source-fixture',version=1,zone='zone:source-fixture',
                    formula='software-decision-es256-ed25519-v1',execution_profile_digest=body['request_binding']['execution_profile_digest'],
                    policy_digest=body['request_binding']['policy_digest'],issuer_ids=[body['issuer_id']],algorithms=['ES256'])
                verifier=InstalledSoftwareDecisionSignatureVerifier(rfc8785.dumps({'fixture-only':key}),rfc8785.dumps(profile))
                verified=verifier.verify(rfc8785.dumps(dict(body,signature=compact)),now=100,clock_healthy=True)
                actual=dict(proofSignatureValid=trust_proof_signature_valid(inputs['ordinaryProof'],algorithm='ES256',trusted_key=public),
                    decisionSignatureValid=verified.verified)
                if verified.verified:
                    actual['requestBindingMatches']=body['request_binding']==inputs['actualRequestBinding'] and body['request_digest']=='sha256:'+hashlib.sha256(rfc8785.dumps(inputs['actualRequestBinding'])).hexdigest()
                    actual['proofDigestMatches']=body['proof_digest']=='sha256:'+hashlib.sha256(inputs['ordinaryProof'].encode('ascii')).hexdigest()
                self.assertEqual(actual,case['expect']['cryptographicChecks'])
                self.assertFalse(verified.complete_consumption_verified);self.assertFalse(verified.action_permitted)
                # The source's ordinary proof is an opaque crypto fixture,
                # deliberately outside the real ordinary authorization schema.
                proof=json.loads(_decode_segment(inputs['ordinaryProof'].split('.')[1],name='opaque source proof'))
                self.assertNotIn('ktp',proof)

    def test_source_freshness_predicates_through_installed_evidence(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        from tests.unit.core._v3_software_fixture import evidence_fixture
        cases=[c for c in self.suite()['vectors'] if c.get('stage')=='observation_freshness']
        self.assertEqual(len(cases),3)
        for case in cases:
            with self.subTest(case=case['id']):
                context=case['request']['softwareContext']
                for name in ('nowMs','observedAtMs','maxAgeMs'):self.assertEqual(context[name]%1000,0)
                f=evidence_fixture(now=context['nowMs']//1000)
                for declaration in f['profile']['sources']:declaration['max_age_seconds']=context['maxAgeMs']//1000
                for record in f['records']:
                    record['observed_at']=context['observedAtMs']//1000;record['max_age_seconds']=context['maxAgeMs']//1000
                f['state']['profile_digest']=_digest(f['profile'],'sha256')
                f['v']=replace(f['v'],profile_bytes=rfc8785.dumps(f['profile']));f['refresh']()
                result=f['v'].evaluate(actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)
                self.assertEqual(result.valid,case['expect']['observationFresh'])
                if not result.valid:self.assertTrue(result.undefined_classes)
                self.assertFalse(result.action_permitted)
