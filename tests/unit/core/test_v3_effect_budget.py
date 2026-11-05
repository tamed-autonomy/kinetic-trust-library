from copy import deepcopy
from importlib.util import find_spec
import json
import unittest
from kinetic_trust_library.errors import ValidationError


def fixture(operation=None,decision_bytes=None,evidence_verifier=None,zone=None):
    import rfc8785
    from tests.unit.core.test_v3_consequential_evidence import fixture as evidence_fixture
    from kinetic_trust_library.v3.effect_budget import InstalledEffectBudgetVerifier,AuthenticatedEffectBudgetContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    e=evidence_fixture();op=operation or e['op'];decision_bytes=decision_bytes or e['decision'];decision=json.loads(decision_bytes)
    if zone is not None and evidence_verifier is None:
        from dataclasses import replace
        e['p']['zone']=zone;e['key']['zone_id']=zone;e['source']['profile_digest']=_digest(e['p'],'sha256')
        e['v']=replace(e['v'],profile_bytes=rfc8785.dumps(e['p']))
    p=dict(id='budget:installed',version=1,zone=zone or 'zone:software',formula='cumulative-effect-budget-v1',scope='scope:all-replicas',
        units='unit:maximum-effects',maximum=10,registry='registry:effect-budget',replay_domain=op['replay_domain'],
        retention_seconds=120,longest_recovery_seconds=120,recovery_boundary='recovery:actual',
        target_contract_digest=_digest({'contract':'pinned-tested-conditional-target'},'sha256'),conditional_commit=True,
        checkpoint_seconds=1,safe_transition='transition:bounded-stop',abandon_after_seconds=30,
        observer_profile_digest=_digest(json.loads((evidence_verifier or e['v']).profile_bytes),'sha256'),
        recorder_required=True,accounting_period='cumulative',reset_conditions='none',charge_expiry='none')
    s=dict(profile_digest=_digest(p,'sha256'),operation_digest=digest_demand_operation(op,algorithm='sha256'),
        request_binding=decision['request_binding'],checked_at=102,expires_at=105,epoch=1,revision=1,checkpoint_anchor='audit:budget:1',
        recovery_boundary=p['recovery_boundary'],registry=p['registry'],scope=p['scope'],units=p['units'],maximum=p['maximum'],
        ledger=[],requested_units=3,reservation_units=3,recorder_available=True,target_revision='revision:target:a')
    class Source:
        def resolve(self,**kwargs):return AuthenticatedEffectBudgetContext(rfc8785.dumps(s),b'authenticated complete durable inventory across every scoped actor/resource/replica')
    v=InstalledEffectBudgetVerifier(rfc8785.dumps(p),Source(),evidence_verifier or e['v'],'sha256')
    def entry(request_id='other-request',status='held',state='unknown',units=6):
        binding=deepcopy(decision['request_binding']);binding['request_id']=request_id
        return dict(request_id=request_id,request_binding=binding,fingerprint_digest=_digest(binding,'sha256'),
            attempt=1,created_at=100,reservation_reference=e['body']['reservation_reference'] if request_id==op['request_id'] else 'reservation:other',
            reservation_digest=e['body']['reservation_digest'],units=units,reservation_status=status,evidence_state=state,
            decision_digests=[_digest(json.loads(decision_bytes),'sha256')],last_evidence_digest=_digest(json.loads(e['sign']()),'sha256') if status=='released' else None,
            protected_interval=dict(start=100,end=101))
    return dict(v=v,p=p,s=s,e=e,op=op,decision=decision_bytes,entry=entry)


@unittest.skipUnless(all(find_spec(n) for n in ('rfc8785','jsonschema','cryptography')),'install v3-proofs')
class EffectBudgetTests(unittest.TestCase):
    def evaluate(self,f,previous=None,non_dispatch=None):
        return f['v'].evaluate(f['decision'],actual_operation=f['op'],target_revision='revision:target:a',evaluated_at=102,
            clock_healthy=True,previous_assessment=previous,non_dispatch=non_dispatch)

    def test_shared_remainder_is_additional_restriction_never_capacity(self):
        f=fixture();f['s']['ledger']=[f['entry']()]
        r=self.evaluate(f);self.assertTrue(r.budget_eligible);self.assertEqual(r.remaining_units,4)
        self.assertEqual(json.loads(r.commit_conditions_bytes)['reservation_units'],3);self.assertFalse(r.action_permitted)
        f['s'].update(requested_units=6,reservation_units=6)
        r=self.evaluate(f);self.assertFalse(r.budget_eligible);self.assertEqual(r.reason,'EFFECT_BUDGET_INSUFFICIENT')

    def test_unknown_dispatch_no_effect_and_renewal_cannot_authorize_retry(self):
        for state in ('unknown','dispatched','effect_confirmed','no_effect'):
            f=fixture();f['s']['ledger']=[f['entry'](f['op']['request_id'],state=state)]
            with self.subTest(state=state):
                r=self.evaluate(f);self.assertFalse(r.budget_eligible);self.assertEqual(r.reason,'EFFECT_REPLAY_UNRESOLVED')
                self.assertEqual(r.remaining_units,4)

    def test_same_identity_changed_canonical_body_is_collision(self):
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture();old=f['entry'](f['op']['request_id']);old['request_binding']['parameters_digest']='sha256:'+'1'*64
        old['fingerprint_digest']=_digest(old['request_binding'],'sha256');f['s']['ledger']=[old]
        r=self.evaluate(f);self.assertFalse(r.budget_eligible);self.assertEqual(r.reason,'EFFECT_IDENTITY_COLLISION')

    def test_retry_needs_fresh_sealed_non_dispatch_and_preserves_attempt_history(self):
        f=fixture();e=f['e'];f['s']['ledger']=[f['entry'](f['op']['request_id'],status='released',state='withheld')]
        self.assertFalse(self.evaluate(f).budget_eligible)
        observed=e['v'].evaluate(e['sign'](),actual_operation=e['op'],consumption_decision_bytes=e['decision'],evaluated_at=102,clock_healthy=True)
        r=self.evaluate(f,non_dispatch=observed);self.assertTrue(r.budget_eligible)
        self.assertEqual(json.loads(r.commit_conditions_bytes)['next_attempt'],2)
        self.assertEqual(len(json.loads(r.source_state_bytes)['ledger']),1)

    def test_protected_inventory_cannot_rollback_or_erase_held_reservations(self):
        f=fixture();f['s']['ledger']=[f['entry']()];old=self.evaluate(f)
        f['s']['ledger']=[];f['s']['epoch']=2;f['s']['revision']=2
        with self.assertRaises(ValidationError):self.evaluate(f,old)
        f=fixture();old=self.evaluate(f);f['s']['ledger']=[f['entry']()]
        with self.assertRaises(ValidationError):self.evaluate(f,old)

    def test_current_target_recorder_expiry_and_reservation_are_independent(self):
        for patch in (dict(target_revision='revision:other'),dict(recorder_available=False),dict(requested_units=4,reservation_units=3)):
            f=fixture();f['s'].update(patch)
            with self.subTest(patch=patch):self.assertFalse(self.evaluate(f).budget_eligible)
        f=fixture();f['s']['expires_at']=102
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_no_effect_and_deadline_cannot_be_rewritten_as_a_release(self):
        for state in ('unknown','dispatched','effect_confirmed','no_effect'):
            f=fixture();entry=f['entry'](status='released',state=state);f['s']['ledger']=[entry]
            with self.subTest(state=state),self.assertRaises(ValidationError):self.evaluate(f)
        f=fixture();f['s']['ledger']=[f['entry']()]
        f['s']['ledger'][0]['created_at']=1
        f['s']['ledger'][0]['protected_interval']['start']=1
        # Being older than the declared abandonment bound does not free it.
        self.assertEqual(self.evaluate(f).remaining_units,4)

    def test_exact_published_budget_numeric_cases(self):
        from pathlib import Path
        suite=json.loads((Path(__file__).parents[3]/'spec/proposals/consequential-action-execution-v1.json').read_bytes())
        for case in suite['vectors']:
            if case['id'] not in ('E08','E27'):continue
            c=case['request'];f=fixture()
            f['s']['ledger']=[f['entry'](units=c['firstReservation'])]
            f['s'].update(requested_units=c['secondRequested'],reservation_units=c.get('secondConservativeReservation',c['secondRequested']))
            r=self.evaluate(f)
            with self.subTest(case=case['id']):
                if case['id']=='E08':
                    self.assertFalse(r.budget_eligible);self.assertLessEqual(r.remaining_units,case['expect']['remainingBudgetUnitsAtMost'])
                else:
                    self.assertEqual(r.budget_eligible,case['expect']['secondBudgetEligible'])
                    self.assertEqual(r.remaining_units,case['expect']['remainingBudgetUnits'])
                    self.assertNotIn('environmentalCapacity',json.loads(r.commit_conditions_bytes))
                    self.assertNotIn('result',json.loads(r.commit_conditions_bytes))

    def test_retry_conditions_cannot_outlive_verified_non_dispatch(self):
        import rfc8785
        from dataclasses import replace
        from kinetic_trust_library.v3.demand_supplier import _digest
        f=fixture();e=f['e'];e['source']['expires_at']=103
        f['s']['ledger']=[f['entry'](f['op']['request_id'],status='released',state='withheld')]
        f['p']['checkpoint_seconds']=10
        f['s']['profile_digest']=_digest(f['p'],'sha256')
        f['v']=replace(f['v'],profile_bytes=rfc8785.dumps(f['p']))
        observed=e['v'].evaluate(e['sign'](),actual_operation=e['op'],consumption_decision_bytes=e['decision'],evaluated_at=102,clock_healthy=True)
        result=self.evaluate(f,non_dispatch=observed)
        self.assertTrue(result.budget_eligible);self.assertEqual(result.expires_at,103)
        self.assertEqual(json.loads(result.commit_conditions_bytes)['expires_at'],103)

    def test_native_api_exposes_optional_effect_and_release_verifiers(self):
        from kinetic_trust_library.v3 import api
        for name in ('InstalledConsequentialEvidenceVerifier','ConsequentialEvidenceAssessment',
                     'InstalledEffectBudgetVerifier','EffectBudgetAssessment',
                     'InstalledConsequentialReleaseVerifier','ConsequentialReleaseAssessment'):
            with self.subTest(name=name):self.assertIn(name,api.__all__);self.assertIsNotNone(getattr(api,name))
