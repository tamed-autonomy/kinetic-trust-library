from copy import deepcopy
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
import json
import unittest
from kinetic_trust_library.errors import ValidationError,ProofFormatError


def fixture(state='withheld'):
    import hashlib,rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from kinetic_trust_library.v3.native_issuance import _segment
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from kinetic_trust_library.v3.consequential_evidence import AuthenticatedConsequentialEvidenceContext,InstalledConsequentialEvidenceVerifier
    from tests.unit.core._v3_software_fixture import evidence_fixture
    from tests.unit.core.test_v3_software_decision_signature import fixture as software_fixture
    f=evidence_fixture();_,_,_,decision,software_sign=software_fixture()
    decision.update(request_binding=f['state']['request_binding'],request_digest=_digest(f['state']['request_binding'],'sha256'))
    signed_decision=software_sign()
    p=dict(id='evidence:installed',version=1,zone='zone:software',formula='consequential-evidence-v1',
        protected_path='path:complete',recovery_boundary='recovery:actual',max_observation_age_seconds=10,
        sources={'source:observer':['withheld','dispatched','effect_confirmed','no_effect','unknown']},
        issuer_ids=['issuer:evidence'],algorithms=['EdDSA','ES256'])
    original=b'authenticated original observation from installed source'
    observation=dict(source_id='source:observer',interval_start=100,interval_end=101,provenance_digest='sha256:'+hashlib.sha256(original).hexdigest())
    marker=None
    if state=='withheld':observation['protected_path_coverage']=p['protected_path']
    if state!='unknown':marker=dict(kind={'withheld':'non_dispatch','dispatched':'dispatch','effect_confirmed':'effect','no_effect':'no_effect'}[state],value='marker:actual')
    body=dict(artifact_type='ktp-consequential-action-evidence-v1',request_id=f['op']['request_id'],
        operation_fingerprint_digest=decision['request_digest'],consumption_decision_digest=_digest(json.loads(signed_decision),'sha256'),
        enforcement_destination=decision['request_binding']['enforcement_destination'],reservation_reference='reservation:effect',
        reservation_digest=_digest({'reservation':'actual'},'sha256'),evidence_state=state,observation=observation)
    if marker is not None:body['target_marker']=marker
    private=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    key=dict(kid='key:evidence',subject='issuer:evidence',zone_id=p['zone'],purpose=body['artifact_type'],alg='EdDSA',kty='OKP',crv='Ed25519',
        x=_segment(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)),not_before=90,not_after=200,revoked=False,source_ids=['source:observer'])
    keys={key['kid']:key}
    source=dict(profile_digest=_digest(p,'sha256'),operation_digest=digest_demand_operation(f['op'],algorithm='sha256'),checked_at=102,expires_at=105,
        recovery_boundary=p['recovery_boundary'],request_binding=decision['request_binding'],required_interval=dict(start=100,end=101),
        reservation=dict(reference=body['reservation_reference'],digest=body['reservation_digest']),recorder_evidence_digest=None,
        observed=dict(evidence_state=state,observation=deepcopy(observation),target_marker=deepcopy(marker)))
    class Source:
        def resolve(self,**kwargs):return AuthenticatedConsequentialEvidenceContext(rfc8785.dumps(source),rfc8785.dumps(keys),original)
    v=InstalledConsequentialEvidenceVerifier(rfc8785.dumps(p),Source(),'sha256')
    def sign(typ=body['artifact_type']):
        unsigned=rfc8785.dumps({k:v for k,v in body.items() if k!='signature'})
        message=(_segment(rfc8785.dumps(dict(alg='EdDSA',kid=key['kid'],typ=typ)))+'.'+_segment(unsigned)).encode()
        body['signature']=message.decode()+'.'+_segment(private.sign(message))
        return rfc8785.dumps(body)
    return dict(v=v,p=p,source=source,key=key,keys=keys,body=body,sign=sign,decision=signed_decision,op=f['op'])


@unittest.skipUnless(all(find_spec(n) for n in ('rfc8785','jsonschema','cryptography')),'install v3-proofs')
class ConsequentialEvidenceTests(unittest.TestCase):
    def evaluate(self,f):
        return f['v'].evaluate(f['sign'](),actual_operation=f['op'],consumption_decision_bytes=f['decision'],evaluated_at=102,clock_healthy=True)

    def test_all_24_exact_published_shape_cases(self):
        import rfc8785
        from kinetic_trust_library.v3.consequential_evidence_shape import consequential_evidence_validator,parse_consequential_evidence
        suite=json.loads((Path(__file__).parents[3]/'spec/proposals/consequential-action-execution-v1.json').read_bytes())
        self.assertEqual(len(suite['schemaVectors']),24)
        for case in suite['schemaVectors']:
            value=deepcopy(suite['schemaFixture'])
            for mutation in case.get('mutations',[case['mutation']] if 'mutation' in case else []):
                parent=value
                for part in mutation['path'][:-1]:parent=parent[part]
                if mutation['operation']=='remove':del parent[mutation['path'][-1]]
                else:parent[mutation['path'][-1]]=mutation['value']
            with self.subTest(case=case['id']):
                self.assertEqual(consequential_evidence_validator().is_valid(value),case['expect']['schemaValid'])
                if case['expect']['schemaValid']:self.assertEqual(parse_consequential_evidence(rfc8785.dumps(value)),value)

    def test_only_authenticated_non_dispatch_can_release_a_reservation(self):
        for state in ('withheld','dispatched','effect_confirmed','no_effect','unknown'):
            f=fixture(state);r=self.evaluate(f)
            self.assertTrue(r.verified);self.assertEqual(r.evidence_state,state)
            self.assertEqual(r.reservation_release_candidate,state=='withheld')
            self.assertFalse(r.action_permitted)

    def test_signature_cannot_authenticate_substituted_scope_or_observation(self):
        for mutate in (lambda f:f['body'].update(enforcement_destination='destination:other'),
            lambda f:f['body'].update(request_id='request:other'),lambda f:f['body'].update(consumption_decision_digest='sha256:'+'0'*64),
            lambda f:f['body']['observation'].update(protected_path_coverage='path:partial'),
            lambda f:f['body']['observation'].update(interval_end=103),lambda f:f['source'].update(recovery_boundary='recovery:other')):
            f=fixture();mutate(f)
            with self.subTest(mutate=mutate),self.assertRaises(ValidationError):self.evaluate(f)
        f=fixture();f['key']['revoked']=True
        self.assertFalse(self.evaluate(f).verified)
        f=fixture();raw=f['sign']('ktp-software-substrate-decision-v1')
        self.assertFalse(f['v'].evaluate(raw,actual_operation=f['op'],consumption_decision_bytes=f['decision'],evaluated_at=102,clock_healthy=True).verified)

    def test_strict_canonical_control_tokens_and_unknown_source_are_rejected(self):
        from kinetic_trust_library.v3.consequential_evidence_shape import parse_consequential_evidence
        f=fixture();raw=f['sign']()
        for malformed in (raw+b'\n',raw.replace(b'"interval_end":101',b'"interval_end":101.0'),raw.replace(b'"interval_end":101',b'"interval_end":101,"interval_end":101')):
            with self.assertRaises((ValidationError,ProofFormatError)):parse_consequential_evidence(malformed)
        f['source']['checked_at']=101
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_es256_and_payload_header_mutations(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric import ec,utils
        from cryptography.hazmat.primitives import hashes
        from kinetic_trust_library.v3.native_issuance import _segment
        from kinetic_trust_library.v3._readiness_crypto import ORDERS
        f=fixture();private=ec.derive_private_key(11,ec.SECP256R1());public=private.public_key().public_numbers()
        f['key'].update(alg='ES256',kty='EC',crv='P-256',x=_segment(public.x.to_bytes(32,'big')),y=_segment(public.y.to_bytes(32,'big')))
        def signed(header_extra=None,alter_payload=False):
            payload={k:v for k,v in f['body'].items() if k!='signature'}
            if alter_payload:payload['request_id']='request:changed-in-JWS'
            header=dict(alg='ES256',kid=f['key']['kid'],typ='ktp-consequential-action-evidence-v1')
            header.update(header_extra or {})
            message=(_segment(rfc8785.dumps(header))+'.'+_segment(rfc8785.dumps(payload))).encode()
            r,s=utils.decode_dss_signature(private.sign(message,ec.ECDSA(hashes.SHA256())))
            s=min(s,ORDERS['ES256']-s)
            f['body']['signature']=message.decode()+'.'+_segment(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
            return rfc8785.dumps(f['body'])
        def verify(raw):return f['v'].evaluate(raw,actual_operation=f['op'],consumption_decision_bytes=f['decision'],evaluated_at=102,clock_healthy=True)
        self.assertTrue(verify(signed()).verified)
        self.assertFalse(verify(signed({'extra':'not-permitted'})).verified)
        self.assertFalse(verify(signed(alter_payload=True)).verified)
        f['key']['source_ids']=[];self.assertFalse(verify(signed()).verified)

    def test_freshness_equality_and_incomplete_protected_interval_never_release(self):
        for mutate in (lambda f:f['source'].update(required_interval=dict(start=99,end=101)),
                       lambda f:f['source'].update(required_interval=dict(start=100,end=102))):
            f=fixture();mutate(f)
            with self.assertRaises(ValidationError):self.evaluate(f)
        f=fixture();f['source'].update(checked_at=111,expires_at=115)
        with self.assertRaises(ValidationError):f['v'].evaluate(f['sign'](),actual_operation=f['op'],consumption_decision_bytes=f['decision'],evaluated_at=111,clock_healthy=True)

    def test_verified_evidence_cannot_outlive_current_signing_key(self):
        f=fixture();f['key']['not_after']=103
        result=self.evaluate(f);self.assertTrue(result.verified);self.assertEqual(result.expires_at,103)
