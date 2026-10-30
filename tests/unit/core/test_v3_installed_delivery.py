from importlib.util import find_spec
import unittest

HAS_EXTRAS=all(find_spec(n) for n in ("rfc8785","cryptography","jsonschema"))


def fixture():
    import json,rfc8785
    from tests.unit.core.test_v3_hand_back import fixture as base
    from tests.unit.core.test_v3_delivery_effort import terms
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.installed_delivery import InstalledHandBackDeliveryVerifier,AuthenticatedDeliveryContext
    hb,hs,wire,op,_,now,_=base();recipient=hs["template"]["recipient"]
    p=dict(id="delivery:policy",version=1,zone="zone-a",formula="anchored-retry-and-escalation-v1",
        ledger_owner="authority:delivery-audit",append_protocol="append:delivery",
        hand_back_profile_digest=_digest(json.loads(hb.profile_bytes),"sha256"),capacity_freshness_seconds=2,
        classes={kind:dict(**terms(),primary_route="route:primary",escalation_routes=["route:backup","route:backup"])
                 for kind in ("Logistics","Coordination","Relational")})
    digest=_digest(wire,"sha256");cipher=wire["context"]["ciphertext_digest"]
    routes=[dict(ref=ref,endpoint=recipient["endpoint"],principal=recipient["principal"],sealed_to=recipient["key_id"],
        channel=channel,registered_at=now-90,anchor="sha256:"+str(i)*64)
        for i,(ref,channel) in enumerate((("route:primary",recipient["channel"]),("route:backup","protected:backup")),start=3)]
    s=dict(deployment_digest=hs["deployment_digest"],profile_digest=_digest(p,"sha256"),operation_digest=hs["operation_digest"],
        hand_back_digest=digest,subject=op["actor"],zone="zone-a",checked_at=now,expires_at=now+7,
        queue_id="queue:delivery",queue_anchor="sha256:"+"f"*64,history_start=now,ledger_head=dict(anchor="sha256:"+"a"*64,sequence=100),
        ledger_owner=p["ledger_owner"],append_protocol=p["append_protocol"],
        declaration=dict(anchor="sha256:"+"d"*64,profile_digest=_digest(p,"sha256"),declared_at=now-80,
            template_digest=hs["lease"]["template_digest"],lease_id=hs["lease"]["id"],routes=routes),
        capacity_binding=dict(id="capacity:declared",principal=recipient["principal"],declared_at=now-90,anchor="sha256:"+"e"*64),
        escrow=dict(anchor="sha256:"+"b"*64,stored_at=now,hand_back_digest=digest,ciphertext_digest=cipher,sealed_to=recipient["key_id"]),
        attempts=[],attempt_count=0,escalations=[],escalation_count=0,capacity_records={},receipt_bindings={},acknowledgment=None)
    class Source:
        def resolve(self,**kw):return AuthenticatedDeliveryContext(rfc8785.dumps(s),b"modeled grant-time declaration/sealed durable escrow/actual complete attempt and receipt history")
    return InstalledHandBackDeliveryVerifier(hb,rfc8785.dumps(p),Source()),s,hs,wire,op,now


def evaluate(args):
    import rfc8785
    v,s,hs,wire,op,now=args
    return v.evaluate(rfc8785.dumps(wire),actual_operation=op,evaluated_at=now,clock_healthy=True)


def add_attempt(args,index=1,*,at=None,accepted=False,capacity="available"):
    from tests.unit.core.test_v3_delivery_effort import attempt
    _,s,hs,wire,_,now=args;at=now if at is None else at
    recipient=hs["template" if "template" in hs else "fallback"]["recipient"]
    a=attempt(index,at,reachable=accepted,capacity=capacity,accepted=accepted);a["message_digest"]=s["hand_back_digest"]
    s["attempts"].append(a);s["attempt_count"]+=1
    s["capacity_records"][a["capacity_anchor"]]=dict(binding="capacity:declared",principal=recipient["principal"],
        capacity=capacity,observed_at=at)
    if accepted:
        s["receipt_bindings"][a["receipt"]["anchor"]]=dict(hand_back_digest=s["hand_back_digest"],attempt_anchor=a["anchor"],
            endpoint=recipient["endpoint"],principal=recipient["principal"],sealed_to=wire["context"]["sealed_to"],
            ciphertext_digest=wire["context"]["ciphertext_digest"])
    return a


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class InstalledDeliveryTests(unittest.TestCase):
    def test_valid_parked_original_remains_constructible_without_reachability(self):
        r=evaluate(fixture());self.assertTrue(r.hand_back.valid);self.assertTrue(r.projection.attempt_due)
        self.assertFalse(r.action_permitted)

    def test_missing_escrow_reports_work_without_invalidating_original_stop(self):
        args=fixture();args[1]["escrow"]=None;r=evaluate(args)
        self.assertTrue(r.hand_back.valid);self.assertTrue(r.projection.escrow_required);self.assertFalse(r.effort_current)

    def test_delivery_advances_by_actual_receipt_without_rewriting_original_wire(self):
        args=fixture();add_attempt(args,accepted=True);r=evaluate(args)
        self.assertEqual(r.hand_back.delivery_state,"parked");self.assertEqual(r.projection.delivery_state,"delivered")
        self.assertFalse(r.action_permitted)

    def test_foreign_receipt_or_wrong_sealed_escrow_is_rejected(self):
        from kinetic_trust_library.errors import ValidationError
        args=fixture();a=add_attempt(args,accepted=True)
        args[1]["receipt_bindings"][a["receipt"]["anchor"]]["endpoint"]="channel:attacker"
        with self.assertRaises(ValidationError):evaluate(args)
        args=fixture();args[1]["escrow"]["ciphertext_digest"]="sha256:"+"0"*64
        with self.assertRaises(ValidationError):evaluate(args)
        import rfc8785
        self.assertTrue(args[0].hand_back_verifier.evaluate(rfc8785.dumps(args[3]),actual_operation=args[4],evaluated_at=args[5],clock_healthy=True).valid)

    def test_late_declaration_and_truncated_attempt_history_are_rejected(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["declaration"].update(declared_at=s["checked_at"]),lambda s:s.update(attempt_count=1)):
            args=fixture();change(args[1])
            with self.subTest(change=change),self.assertRaises(ValidationError):evaluate(args)

    def test_saturated_capacity_is_recorded_as_parked_and_never_clear(self):
        args=fixture();add_attempt(args,capacity="exhausted");r=evaluate(args)
        self.assertEqual(r.projection.delivery_state,"parked");self.assertTrue(r.projection.capacity_exhaustion_anchors)
        self.assertFalse(r.action_permitted)
        self.assertTrue(r.capacity_pressure_record_required)
        self.assertEqual(r.capacity_pressure_hand_back_digest,args[1]["hand_back_digest"])

    def test_original_capacity_records_and_declared_channels_cannot_be_substituted(self):
        from kinetic_trust_library.errors import ValidationError
        args=fixture();a=add_attempt(args)
        args[1]["capacity_records"][a["capacity_anchor"]]["principal"]="person:other"
        with self.assertRaises(ValidationError):evaluate(args)
        args=fixture();args[1]["declaration"]["routes"][1]["sealed_to"]="key:attacker"
        with self.assertRaises(ValidationError):evaluate(args)

    def test_delivery_source_failure_is_not_an_empty_successful_queue(self):
        from dataclasses import replace
        args=list(fixture())
        class Source:
            def resolve(self,**kw):raise RuntimeError("delivery audit unavailable")
        args[0]=replace(args[0],context_source=Source())
        with self.assertRaisesRegex(RuntimeError,"audit unavailable"):evaluate(args)

    def test_optional_escrow_after_immediate_delivery_is_not_a_missed_parking_obligation(self):
        args=list(fixture());add_attempt(args,accepted=True)
        args[5]+=3;args[1].update(checked_at=args[5],expires_at=args[5]+7)
        args[2].update(checked_at=args[5],expires_at=args[5]+7)
        args[1]["escrow"]["stored_at"]=args[5]
        r=evaluate(args);self.assertTrue(r.effort_current);self.assertFalse(r.late_escrow_record_required)

    def test_history_cannot_omit_attempts_already_attested_by_the_original_record(self):
        from kinetic_trust_library.errors import ValidationError
        from kinetic_trust_library.v3.demand_supplier import _digest
        args=fixture();args[2]["delivery"]["attempts"]=args[3]["delivery"]["attempts"]=1
        digest=_digest(args[3],"sha256");args[1]["hand_back_digest"]=args[1]["escrow"]["hand_back_digest"]=digest
        with self.assertRaises(ValidationError):evaluate(args)
