"""Exact registered limited context, with real fixture decryption at Source."""
import copy,json,unittest
from dataclasses import replace
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError


def fixture():
    import rfc8785,hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from tests.unit.core.test_v3_hand_back import fixture as primary_fixture
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from kinetic_trust_library.v3.counterparty_hand_back import InstalledCounterpartyHandBackVerifier,AuthenticatedCounterpartyContext
    hb,hs,wire,op,_,now,_=primary_fixture();t=hs['template']
    profile=dict(id='counterparty:test',version=1,zone='zone-a',formula='registered-counterparty-limited-context-v1',
        hand_back_profile_digest=_digest(json.loads(hb.profile_bytes),'sha256'),registry='registry:redaction')
    policy=dict(id='redaction:1',version=1,registered_at=t['registered_at'],template_id=t['id'],template_version=t['version'],
        subject=op['actor'],consequence_class=hs['consequence_class'],reason_class_source='hand-back.reason',
        delegator=dict(principal=t['recipient']['principal'],endpoint=t['recipient']['endpoint'],key_id=t['recipient']['key_id'],
            tier='full',sections=['action','lease_history','environment_attestations','work_product']),
        counterparty=dict(principal='person:counterparty',endpoint='channel:counterparty',key_id='key:counterparty',tier='counterparty',
            sections=['action','reason_class','attestation_references']),attestation_reference_rule='all-primary-environment-attestations')
    t['redaction_policy_digest']=_digest(policy,'sha256');hs['lease']['template_digest']=_digest(t,'sha256')
    hs['bundle']['redaction_policy_digest']=t['redaction_policy_digest']
    h=lambda b:'sha256:'+hashlib.sha256(b).hexdigest()
    full=dict(action=wire['action'],lease_history=['lease:1'],environment_attestations=['attestation:1','attestation:2'],
        work_product='PRIVATE DRAFT MUST NEVER BE IN THE LIMITED BUNDLE')
    key=AESGCM.generate_key(bit_length=256);nonce=b'primaryNonce'
    primary_cipher=nonce+AESGCM(key).encrypt(nonce,rfc8785.dumps(full),b'fixture full context')
    hs['bundle']['ciphertext_digest']=h(primary_cipher);wire['context']['ciphertext_digest']=h(primary_cipher)
    class Primary:
        def resolve(self,**kwargs):
            actual=json.loads(AESGCM(key).decrypt(primary_cipher[:12],primary_cipher[12:],b'fixture full context'))
            assert actual==full
            from kinetic_trust_library.v3.hand_back import AuthenticatedHandBackContext
            return AuthenticatedHandBackContext(rfc8785.dumps(hs),primary_cipher,b'authenticated primary registry and decrypted full context')
    hb=replace(hb,context_source=Primary())
    limited=dict(action=wire['action'],reason_class=wire['reason'],attestation_references=['attestation:1','attestation:2'])
    secondary_key=AESGCM.generate_key(bit_length=256);secondary_nonce=b'limitedNonce'
    state=dict(deployment_digest=_digest(json.loads(hb.deployment_profile_bytes),'sha256'),profile_digest=_digest(profile,'sha256'),
        operation_digest=digest_demand_operation(op,algorithm='sha256'),
        primary_hand_back_digest=_digest(wire,'sha256'),primary_ciphertext_digest=h(primary_cipher),template_digest=_digest(t,'sha256'),
        policy_digest=_digest(policy,'sha256'),checked_at=now,expires_at=now+5,zone='zone-a',registry='registry:redaction',
        registration_anchor='audit:redaction:1',registration_epoch=1,registration_revision=1,registration_status='active',
        primary_attestation_references=full['environment_attestations'],agent_can_read=False,
        recipient_endpoint='channel:counterparty',recipient_key_id='key:counterparty',recipient_principal='person:counterparty',
        counterparty_ciphertext_digest=None,limited_projection_digest=None)
    output={}
    def refresh():
        projection=rfc8785.dumps(limited)
        cipher=secondary_nonce+AESGCM(secondary_key).encrypt(secondary_nonce,projection,b'fixture counterparty limited context')
        output.update(cipher=cipher,projection=projection)
        state['counterparty_ciphertext_digest']=h(cipher);state['limited_projection_digest']=h(projection)
    refresh()
    class Source:
        def resolve(self,**kwargs):
            actual=AESGCM(secondary_key).decrypt(output['cipher'][:12],output['cipher'][12:],b'fixture counterparty limited context')
            assert actual==output['projection']
            return AuthenticatedCounterpartyContext(rfc8785.dumps(state),rfc8785.dumps(policy),output['cipher'],actual,b'authenticated original redaction policy/content/registry/custody')
    v=InstalledCounterpartyHandBackVerifier(hb,rfc8785.dumps(profile),Source())
    return dict(v=v,hb=hb,hs=hs,wire=wire,op=op,now=now,policy=policy,state=state,limited=limited,output=output,refresh=refresh)


@unittest.skipUnless(all(find_spec(n) for n in ('rfc8785','jsonschema','cryptography')),'install v3-proofs')
class CounterpartyHandBackTests(unittest.TestCase):
    def evaluate(self,f):
        import rfc8785
        primary=f['hb'].evaluate(rfc8785.dumps(f['wire']),actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)
        self.assertTrue(primary.valid,primary.reason)
        return f['v'].evaluate(rfc8785.dumps(f['wire']),actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)

    def test_hb_11_003_full_primary_and_limited_counterparty(self):
        from pathlib import Path
        suite=json.loads((Path(__file__).parents[3]/'spec/proposals/hand-back-v1.json').read_text())
        case=next(c for c in suite['vectors'] if c['id']=='HB-11-003')
        self.assertIn('never',case['expect']['counterparty_receives'])
        f=fixture();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertTrue(r.primary.valid);self.assertFalse(r.action_permitted)
        self.assertTrue(r.delivery_required);self.assertEqual(r.expires_at,f['now']+5)
        self.assertEqual(r.recipient_endpoint,'channel:counterparty');self.assertEqual(r.recipient_key_id,'key:counterparty')
        self.assertEqual(r.ciphertext_bytes,f['output']['cipher'])
        self.assertNotIn(b'PRIVATE DRAFT',r.ciphertext_bytes)
        with self.assertRaises(TypeError):type(r)()

    def test_actual_projection_cannot_expose_drafts_or_change_scope(self):
        f=fixture()
        for patch in (dict(work_product='draft'),dict(reason_class='some other explanation'),dict(action='action:other'),
                      dict(attestation_references=['attestation:2']),dict(attestation_references=[]),
                      dict(attestation_references=['attestation:1','attestation:1'])):
            original=copy.deepcopy(f['limited']);f['limited'].update(patch);f['refresh']()
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.evaluate(f)
            f['limited'].clear();f['limited'].update(original);f['refresh']()

    def test_exact_primary_policy_ciphertext_and_current_registration(self):
        f=fixture()
        for field,value in (('primary_ciphertext_digest','sha256:'+'0'*64),('primary_hand_back_digest','sha256:'+'0'*64),
                            ('counterparty_ciphertext_digest','sha256:'+'0'*64),('limited_projection_digest','sha256:'+'0'*64),
                            ('agent_can_read',True),('recipient_endpoint','channel:other'),('recipient_key_id','key:other'),
                            ('recipient_principal','person:other'),('registration_status','revoked'),('registration_epoch',True),
                            ('checked_at',f['now']-1),('expires_at',f['now'])):
            original=f['state'][field];f['state'][field]=value
            with self.subTest(field=field),self.assertRaises(ValidationError):self.evaluate(f)
            f['state'][field]=original
        f['state']['primary_attestation_references']=['attestation:2']
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_actual_operation_is_snapshotted_before_either_source(self):
        import rfc8785
        f=fixture();original=rfc8785.dumps(f['op']);base=f['hb'].context_source
        class MutatingPrimary:
            def resolve(self,**kwargs):
                f['op']['resource']='resource:changed-during-source'
                return base.resolve(**kwargs)
        f['v']=replace(f['v'],hand_back_verifier=replace(f['hb'],context_source=MutatingPrimary()))
        r=self.evaluate(f)
        self.assertEqual(r.operation_bytes,original)

    def test_registration_must_precede_grant_and_keep_registered_recipient(self):
        import rfc8785
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture()
        for patch in (dict(registered_at=f['now']),dict(reason_class_source='numeric diagnostics'),dict(template_id='another'),
                      dict(counterparty=dict(f['policy']['counterparty'],key_id='key:delegator'))):
            original=copy.deepcopy(f['policy']);f['policy'].update(patch)
            # Rebind fixture digests so rejection tests the semantic constraint,
            # rather than succeeding only because the policy hash is stale.
            f['hs']['template']['redaction_policy_digest']=_digest(f['policy'],'sha256')
            f['hs']['bundle']['redaction_policy_digest']=f['hs']['template']['redaction_policy_digest']
            td=_digest(f['hs']['template'],'sha256');f['hs']['lease']['template_digest']=td
            f['state'].update(policy_digest=_digest(f['policy'],'sha256'),template_digest=td)
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.evaluate(f)
            f['policy'].clear();f['policy'].update(original)
