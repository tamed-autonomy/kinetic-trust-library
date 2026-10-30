import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError


def fixture():
    import rfc8785
    from kinetic_trust_library.v3.installed_person_standing import InstalledPersonStandingVerifier,AuthenticatedPersonStandingContext
    from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
    from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from tests.unit.core.test_v3_person_standing import acts
    subject="person:acct:z1:0417";now=1800000004
    dp={"external_root":{"hop_bound":4},"peer_share":0}
    p=dict(id="person-standing:a",version=1,zone="zone:blue",formula="signed-act-single-root-person-standing-v1",
        contribution_policy="policy:signed-stress-assessment",trajectory_ceiling_policy="policy:provisional-person-trajectory")
    op=dict(subject="subject:a",actor=subject,audience="service:a",operation="action:review",resource="resource:a",
        parameters={},request_id="request:a",replay_domain="replay:a")
    body=json.loads((Path(__file__).parents[3]/"spec/proposals/external-root-v1.json").read_text())["instruments"]["attestation"]["body"]
    body.update(subject=subject,root_person=subject)
    class RootSource:
        def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone="zone:blue")
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

    def test_multiple_root_instruments_do_not_reuse_software_ranking(self):
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
        with self.assertRaisesRegex(ValidationError,"multiple current Root"):
            f["v"].evaluate(roots=roots,actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
