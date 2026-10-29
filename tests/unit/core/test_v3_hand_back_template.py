from dataclasses import replace
from importlib.util import find_spec
import unittest


def fixture(operation=None,deployment=None,now=None,zone="zone-a"):
    import rfc8785,json
    from copy import deepcopy
    from tests.unit.core.test_v3_hand_back import fixture as hand_back_fixture
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from kinetic_trust_library.v3.hand_back_template import InstalledHandBackTemplateVerifier,AuthenticatedTemplateContext
    hb,hs,w,old_op,_,old_now,stamp=hand_back_fixture()
    op=old_op if operation is None else operation
    dp=json.loads(hb.deployment_profile_bytes) if deployment is None else deployment
    now=old_now if now is None else now;shift=now-old_now
    p=json.loads(hb.profile_bytes);p.update(zone=zone,formula="registered-template-and-sealed-context-v2")
    hs.update(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(p,"sha256"),
        operation_digest=digest_demand_operation(op,algorithm="sha256"),subject=op["actor"],zone=zone,
        action_id=op["operation"],checked_at=now,expires_at=now+7,sovereign_authority=None)
    w.update(action=op["operation"],issued_at=stamp(now),reissue_not_before=stamp(now+10))
    hs.update(issued_at=w["issued_at"],reissue_not_before=w["reissue_not_before"])
    t=hs["template"];t.update(subject=op["actor"],registered_at=t["registered_at"]+shift)
    t["repair"]["subject"]=op["actor"]
    contest=t["recourse"];contest["independent_of"]=[op["actor"],hs["operator"],*hs["operator_affiliates"],*hs["measurers"]]
    t["recourse"]=dict(system=contest,principal=deepcopy(contest),
        sovereign=[dict(kind="closed_by_authority",ref="sovereign:protocol",authority="community:a",protocol="protocol:refusal")],
        undetermined=dict(kind="undetermined",ref="registry:consulted",registry="registry:authorities"))
    hs["lease"].update(subject=op["actor"],issued_at=hs["lease"]["issued_at"]+shift,template_digest=_digest(t,"sha256"))
    hb=replace(hb,deployment_profile_bytes=rfc8785.dumps(dp),profile_bytes=rfc8785.dumps(p))
    state={key:hs[key] for key in ("deployment_digest","profile_digest","operation_digest","subject","subject_profile","zone",
        "consequence_class","delegator","operator","operator_affiliates","measurers","template","checked_at","expires_at")}
    state.update(registration_status="registered",required_sovereign_authorities=["community:a"])
    class Source:
        def resolve(self,**kw):return AuthenticatedTemplateContext(rfc8785.dumps(state),b"modeled actual original registered template/current authority/endpoint/recourse status")
    verifier=InstalledHandBackTemplateVerifier(hb,Source())
    return verifier,state,hs,w,op,now,p


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class TemplateTests(unittest.TestCase):
    def evaluate(self,v,s,op,now):
        from kinetic_trust_library.v3.demand_supplier import _digest
        return v.evaluate(template_digest=_digest(s["template"],"sha256"),actual_operation=op,evaluated_at=now,clock_healthy=True)

    def test_exact_original_template_is_immutable_current_and_has_all_return_paths(self):
        v,s,hs,w,op,now,_=fixture();r=self.evaluate(v,s,op,now)
        self.assertEqual(r.subject,op["actor"]);self.assertEqual(r.registered_at,now-100)
        self.assertEqual(r.consequence_class,"Coordination");self.assertEqual(r.expires_at,now+7)
        self.assertTrue(r.source_evidence_bytes)
        with self.assertRaises(TypeError):type(r)()

    def test_missing_repair_route_independent_contest_or_sovereign_route_is_not_a_template(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["template"].pop("repair"),
                       lambda s:s["template"]["recourse"].pop("principal"),
                       lambda s:s["template"]["recourse"]["system"].update(owner="affiliate:a"),
                       lambda s:s["template"]["recourse"].update(sovereign=[]),
                       lambda s:s["template"]["recipient"].update(principal="other"),
                       lambda s:s.update(registration_status="withdrawn")):
            v,s,hs,w,op,now,_=fixture();change(s)
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(v,s,op,now)

    def test_sovereign_stop_selects_registered_branch_without_rewriting_grant(self):
        v,s,hs,w,op,now,_=fixture()
        hb=v.hand_back_verifier
        before=hs["lease"]["template_digest"]
        hs.update(reason="exceeded_soul",stop_origin="sovereign",sovereign_authority="community:a");w["reason"]="exceeded_soul"
        w["recourse"]=dict(kind="closed_by_authority",ref="sovereign:protocol")
        self.assertTrue(hb.evaluate(__import__('rfc8785').dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True).valid)
        self.assertEqual(hs["lease"]["template_digest"],before)
        hs["sovereign_authority"]="community:unregistered"
        self.assertFalse(hb.evaluate(__import__('rfc8785').dumps(w),actual_operation=op,evaluated_at=now,clock_healthy=True).valid)

    def test_person_template_owns_its_recipient_without_a_software_delegator(self):
        v,s,hs,w,op,now,_=fixture();s["subject_profile"]="person"
        s["template"]["recipient"]["principal"]=op["actor"]
        self.assertEqual(self.evaluate(v,s,op,now).principal,op["actor"])
