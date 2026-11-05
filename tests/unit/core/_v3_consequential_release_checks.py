"""Exercise release through the real current native/software checkpoint graph."""
def check_consequential_release(test,checkpoint,current,raw,operation,readiness):
    import json,rfc8785
    from kinetic_trust_library.v3.consequential_release import InstalledConsequentialReleaseVerifier
    from kinetic_trust_library.v3.demand_supplier import _digest
    from tests.unit.core.test_v3_effect_budget import fixture
    f=fixture(operation,raw,zone=json.loads(checkpoint.profile_bytes)['zone'])
    f['s'].update(checked_at=1001,expires_at=1005)
    p=dict(id='release:installed',version=1,formula='native-software-effect-release-v1',
        checkpoint_profile_digest=_digest(json.loads(checkpoint.profile_bytes),'sha256'),
        budget_profile_digest=_digest(f['p'],'sha256'))
    v=InstalledConsequentialReleaseVerifier(checkpoint,f['v'],rfc8785.dumps(p))
    def evaluate(previous=current):return v.evaluate(raw,previous,actual_operation=operation,
        invocation_evidence=b'fixture-actual-invocation',evaluated_at=1001,clock_healthy=True)
    good=evaluate();test.assertTrue(good.conditional_release,good.reason);test.assertFalse(good.action_permitted)
    conditions=json.loads(good.commit_conditions_bytes)
    test.assertEqual(conditions['effect_budget']['request_id'],operation['request_id'])
    test.assertTrue(conditions['effect_budget']['atomic_compare_reserve_and_commit_required'])
    test.assertEqual(conditions['software'],json.loads(good.checkpoint.commit_conditions_bytes))
    test.assertEqual(good.checkpoint.consumption.decision_bytes,raw)
    test.assertFalse(good.commit_time_authorization_guarantee)
    test.assertEqual(good.evidence_state,'unknown');test.assertTrue(good.observation_record_required)
    readiness['readiness_epoch']+=1
    denied=evaluate(good);test.assertFalse(denied.conditional_release);test.assertIsNone(denied.commit_conditions_bytes)
    test.assertEqual(denied.evidence_state,'unknown');test.assertTrue(denied.observation_record_required)
    readiness['readiness_epoch']-=1
    f['s']['recorder_available']=False
    test.assertFalse(evaluate(denied).conditional_release)
    f['s']['recorder_available']=True
    f['s']['target_revision']='revision:substituted'
    test.assertFalse(evaluate(good).conditional_release)
    f['s']['target_revision']='revision:target:a'
    entry=f['entry'](operation['request_id']);f['s']['ledger']=[entry]
    f['s'].update(revision=2,checkpoint_anchor='audit:budget:2')
    replay=evaluate(good);test.assertFalse(replay.conditional_release);test.assertEqual(replay.reason,'EFFECT_REPLAY_UNRESOLVED')
    # A different transport token/proof cannot erase the protected entry.
    f['s']['ledger']=[];f['s'].update(revision=3,checkpoint_anchor='audit:budget:3')
    from kinetic_trust_library.errors import ValidationError
    with test.assertRaises(ValidationError):evaluate(replay)
