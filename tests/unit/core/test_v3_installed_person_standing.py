from kinetic_trust_library.v3.demand_supplier import _digest
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError


def fixture(deployment=None):
    import rfc8785
    from kinetic_trust_library.v3.installed_person_standing import InstalledPersonStandingVerifier,AuthenticatedPersonStandingContext
    from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
    from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from tests.unit.core.test_v3_person_standing import acts
    subject="person:acct:z1:0417";now=1800000004
    dp=deployment if deployment is not None else {"external_root":{"hop_bound":4},"peer_share":0}
    p=dict(id="person-standing:a",version=1,zone="zone:blue",formula="signed-act-strongest-root-person-standing-v1",
        contribution_policy="policy:signed-stress-assessment",trajectory_ceiling_policy="policy:provisional-person-trajectory")
    op=dict(subject="subject:a",actor=subject,audience="service:a",operation="action:review",resource="resource:a",
        parameters={},request_id="request:a",replay_domain="replay:a")
    body=json.loads((Path(__file__).parents[3]/"spec/proposals/external-root-v1.json").read_text())["instruments"]["attestation"]["body"]
    body.update(subject=subject,root_person=subject)
    class RootSource:
        def verify(self,evidence,**kwargs):
            import hashlib
            facts=dict(instrument_digest="sha256:"+hashlib.sha256(evidence).hexdigest(),context_digest=_digest(json.loads(kwargs["context_bytes"]),"sha256"),subject=subject,terminator=body["terminator"],
                standing=80,anchor="audit:institution",as_of=now,expires_at=body["end_time"])
            return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone="zone:blue",person_standing_bytes=rfc8785.dumps(facts))
    context=rfc8785.dumps(dict(subject=subject,subject_profile="person",hop_bound=4,receiving_zone="zone:blue",deployment_digest=_digest(dp,"sha256")))
    root=InstalledRootVerifier(RootSource(),"sha256").evaluate(b"modeled authenticated person attestation",context_bytes=context,evaluated_at=now)
    roots=select_assessed_roots((root,),context_bytes=context,evaluated_at=now,algorithm="sha256")
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),operation_digest=digest_demand_operation(op,algorithm="sha256"),
        subject=subject,zone="zone:blue",checked_at=now,expires_at=now+5,
        signed_acts=list(acts()),por_contribution=42,zone_risk=0.25,ceilings={"ial":95,"trajectory":100},
        contribution_policy=p["contribution_policy"],trajectory_ceiling_policy=p["trajectory_ceiling_policy"],
        ledger_head="audit:person-ledger",root_digest=json.loads(root.projection_bytes).get("attestation_digest"),
        terminator=dict(identity=body["terminator"],standing=80,anchor="audit:institution",as_of=now,expires_at=now+3))
    class Source:
        def resolve(self,**kwargs):return AuthenticatedPersonStandingContext(rfc8785.dumps(state),b"modeled signed acts, complete ledger and institutional standing")
    v=InstalledPersonStandingVerifier(rfc8785.dumps(dp),rfc8785.dumps(p),Source(),"sha256")
    return dict(v=v,state=state,roots=roots,op=op,now=now,profile=p,dp=dp)


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class InstalledPersonStandingTests(unittest.TestCase):
    def test_current_root_institution_and_signed_acts(self):
        f=fixture();r=f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        self.assertEqual(r.standing.base_trust,66);self.assertEqual(str(r.standing.effective_trust),"49.5")
        self.assertEqual(r.expires_at,f["now"]+3);self.assertFalse(r.action_permitted)
        self.assertIs(r.roots,f["roots"])

    def test_wrong_current_scope_institution_or_policy_is_rejected(self):
        for field,value in (("subject","person:other"),("zone","zone:other"),("contribution_policy","policy:other"),
                ("root_digest","sha256:"+"0"*64),("trajectory_ceiling_policy","policy:other"),("expires_at",1800000004)):
            f=fixture();f["state"][field]=value
            with self.subTest(field=field),self.assertRaises(ValidationError):
                f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        f=fixture();f["state"]["terminator"]["identity"]={"kind":"board","id":"org:other"}
        with self.assertRaises(ValidationError):f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)

    def test_unhealthy_clock_or_source_outage_never_becomes_standing(self):
        f=fixture()
        with self.assertRaises(ValidationError):f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=False)
        from dataclasses import replace
        class Offline:
            def resolve(self,**kwargs):raise OSError("ledger offline")
        v=replace(f["v"],context_source=Offline())
        with self.assertRaises(OSError):v.evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)

    def test_no_current_root_removes_institutional_credit(self):
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        f=fixture()
        roots=select_assessed_roots((),context_bytes=f["roots"].context_bytes,evaluated_at=f["now"],algorithm="sha256")
        with self.assertRaises(ValidationError):f["v"].evaluate(roots=roots,actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        f["state"].update(root_digest=None,terminator=None)
        r=f["v"].evaluate(roots=roots,actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        self.assertEqual(r.standing.root_term,0);self.assertEqual(r.standing.base_trust,42)
        self.assertFalse(r.action_permitted)

    def test_closed_ledger_and_expiry_bounds(self):
        f=fixture();f["state"]["signed_acts"][0]["observed_behavior"]="positive"
        with self.assertRaises(ValidationError):f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        f=fixture();f["state"]["terminator"]["expires_at"]=f["now"]+100
        f["state"]["expires_at"]=f["now"]+100
        r=f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        self.assertEqual(r.expires_at,1800000010)
        f["state"]["ceilings"].pop("trajectory")
        with self.assertRaises(ValidationError):f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)

    def test_factless_person_instrument_cannot_reuse_software_ranking(self):
        import rfc8785
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        f=fixture();old=f["roots"].selected
        body=json.loads(old.authenticated_body_bytes);body["id"]="attestation:second-person"
        class Source:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone="zone:blue")
        other=InstalledRootVerifier(Source(),"sha256").evaluate(b"second authenticated person instrument",
            context_bytes=f["roots"].context_bytes,evaluated_at=f["now"])
        roots=select_assessed_roots((old,other),context_bytes=f["roots"].context_bytes,evaluated_at=f["now"],algorithm="sha256")
        self.assertEqual(other.score,0)
        self.assertEqual(json.loads(other.projection_bytes)["kind"],"none")
        self.assertIs(roots.selected,old)
        self.assertEqual(f["v"].evaluate(roots=roots,actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True).standing.base_trust,66)

    def test_person_concurrent_roots_use_institution_not_exposure(self):
        import rfc8785,hashlib
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        f=fixture();base=json.loads(f['roots'].selected.authenticated_body_bytes)
        cases=json.loads((Path(__file__).parents[3]/'spec/proposals/person-standing-v1.json').read_bytes())['vectors']
        case=next(c for c in cases if c['id']=='PS13-concurrent-instruments-strongest-single')
        f['state']['por_contribution']=case['given']['PoR_contribution']
        scores=[i['terminator']['standing'] for i in case['given']['root_instruments']]

        def assess(label,standing,exposure,expires=None):
            body=json.loads(json.dumps(base));body['id']='attestation:'+label
            body['terminator']['reference']='org:'+label
            body['inputs'].update(declared_exposure=exposure,anchored_capacity=100)
            raw=('complete signed instrument '+label).encode()
            facts=dict(instrument_digest='sha256:'+hashlib.sha256(raw).hexdigest(),context_digest=_digest(json.loads(f['roots'].context_bytes),'sha256'),subject=body['subject'],terminator=body['terminator'],
                standing=standing,as_of=f['now'],expires_at=expires or f['now']+2,anchor='audit:institution:'+label)
            class Source:
                def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone='zone:blue',person_standing_bytes=rfc8785.dumps(facts))
            result=InstalledRootVerifier(Source(),'sha256').evaluate(raw,context_bytes=f['roots'].context_bytes,evaluated_at=f['now'])
            return result,facts
        weaker,_=assess('high-exposure',scores[0],100)
        stronger,facts=assess('low-exposure',scores[1],1)
        for candidates in ((weaker,stronger),(stronger,weaker)):
            roots=select_assessed_roots(candidates,context_bytes=f['roots'].context_bytes,evaluated_at=f['now'],algorithm='sha256')
            self.assertIs(roots.selected,stronger)
            f['state'].update(root_digest=facts['instrument_digest'],terminator={k:facts[k] for k in ('standing','anchor','as_of','expires_at')})
            f['state']['terminator']['identity']=facts['terminator']
            result=f['v'].evaluate(roots=roots,actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)
            self.assertEqual(stronger.score,case['expect']['Root_score'])
            self.assertEqual(result.standing.root_term,case['expect']['root_term']);self.assertEqual(result.standing.base_trust,case['expect']['E_base'])
            self.assertEqual(result.expires_at,f['now']+2);self.assertFalse(result.action_permitted)
            from kinetic_trust_library.v3.native_proof_profile import RootProofBinding
            bound=RootProofBinding(roots,"zone:blue")
            payload=dict(sub=f['op']['actor'],exp=f['now']+3,ktp=dict(zone="zone:blue",subject_kind="person",root_instrument=json.loads(stronger.projection_bytes)))
            self.assertFalse(bound(rfc8785.dumps(payload),f['now']))
        tied,_=assess('tie',90,99)
        expected=min((tied,stronger),key=lambda c:hashlib.sha256(c.complete_instrument_bytes).hexdigest())
        for ordered in ((tied,stronger),(stronger,tied)):
            self.assertIs(select_assessed_roots(ordered,context_bytes=f['roots'].context_bytes,evaluated_at=f['now'],algorithm='sha256').selected,expected)
        # Every competing current score must remain fresh, including a weaker one.
        fleeting,_=assess('expires-first',80,100,expires=f['now']+1)
        roots=select_assessed_roots((stronger,fleeting),context_bytes=f['roots'].context_bytes,evaluated_at=f['now'],algorithm='sha256')
        result=f['v'].evaluate(roots=roots,actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)
        self.assertEqual(result.expires_at,f['now']+1)
        f['state']['terminator']['standing']=100
        with self.assertRaises(ValidationError):f['v'].evaluate(roots=roots,actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)

    def test_person_scoring_facts_must_bind_the_actual_current_instrument(self):
        import rfc8785,hashlib
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        f=fixture();body=f['roots'].selected.authenticated_body_bytes;raw=b'complete signed person root'
        facts=dict(instrument_digest='sha256:'+hashlib.sha256(raw).hexdigest(),context_digest=_digest(json.loads(f['roots'].context_bytes),'sha256'),subject=f['op']['actor'],
            terminator=json.loads(body)['terminator'],standing=90,as_of=f['now'],expires_at=f['now']+1,anchor='audit:institution')
        class Source:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(body,(),issuer_zone='zone:blue',person_standing_bytes=rfc8785.dumps(facts))
        def evaluate():return InstalledRootVerifier(Source(),'sha256').evaluate(raw,context_bytes=f['roots'].context_bytes,evaluated_at=f['now'])
        self.assertEqual(evaluate().score,90)
        for field,value in [('instrument_digest','sha256:'+'0'*64),('context_digest','sha256:'+'0'*64),('subject','person:other'),('terminator',dict(kind='board',reference='org:other')),
            ('as_of',f['now']-1),('expires_at',f['now']),('standing',True),('standing',101),('anchor','')]:
            before=facts[field];facts[field]=value
            with self.subTest(field=field):self.assertEqual(evaluate().score,0)
            facts[field]=before

    def test_current_zero_standing_person_root_is_not_missing(self):
        import rfc8785,hashlib
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        from kinetic_trust_library.v3.native_proof_profile import RootProofBinding
        f=fixture();body=f['roots'].selected.authenticated_body_bytes;raw=b'current person instrument zero institutional standing'
        facts=dict(instrument_digest='sha256:'+hashlib.sha256(raw).hexdigest(),context_digest=_digest(json.loads(f['roots'].context_bytes),'sha256'),
            subject=f['op']['actor'],terminator=json.loads(body)['terminator'],standing=0,as_of=f['now'],expires_at=f['now']+2,anchor='audit:zero-institution')
        class Source:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(body,(),issuer_zone='zone:blue',person_standing_bytes=rfc8785.dumps(facts))
        root=InstalledRootVerifier(Source(),'sha256').evaluate(raw,context_bytes=f['roots'].context_bytes,evaluated_at=f['now'])
        self.assertEqual(json.loads(root.projection_bytes)['kind'],'external_attestation');self.assertEqual(root.score,0)
        roots=select_assessed_roots((root,),context_bytes=f['roots'].context_bytes,evaluated_at=f['now'],algorithm='sha256')
        self.assertIs(roots.selected,root)
        f['state'].update(root_digest=facts['instrument_digest'],terminator=dict(identity=facts['terminator'],standing=0,
            anchor=facts['anchor'],as_of=f['now'],expires_at=f['now']+2))
        result=f['v'].evaluate(roots=roots,actual_operation=f['op'],evaluated_at=f['now'],clock_healthy=True)
        self.assertEqual(result.standing.root_term,0);self.assertEqual(result.standing.base_trust,42)
        binding=RootProofBinding(roots,'zone:blue')
        self.assertTrue(binding(rfc8785.dumps(dict(sub=f['op']['actor'],exp=f['now']+1,ktp=dict(zone='zone:blue',subject_kind='person',root_instrument=json.loads(root.projection_bytes)))),f['now']))
