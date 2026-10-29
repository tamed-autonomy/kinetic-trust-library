"""Bond opening uses the root's authenticated lineage inventory at that time."""
import json
import unittest
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


def fixture():
    import rfc8785
    from kinetic_trust_library.v3.sponsorship_repair import InstalledSponsorshipRepairVerifier,AuthenticatedSponsorshipContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    from kinetic_trust_library.v3._readiness_crypto import digest_bytes
    from kinetic_trust_library.v3.installed_repair import HARD_ENTRIES
    profile=dict(id="urn:test:sponsorship-repair",version=1,aggregate_count_limit=1,
        entry_classes={name:dict(hard=True,count_limit=1,declared_capacity=4) for name in HARD_ENTRIES})
    dp=dict(profile_id="sponsorship-test",version=1)
    body=json.loads((Path(__file__).parents[3]/"spec/proposals/external-root-v1.json").read_text())["instruments"]["bond"]["body"]
    raw=b"modeled-complete-authenticated-bond-envelope"
    context=dict(subject=body["subject"],subject_profile="software",generation=0,lineage="sponsored",hop_bound=4,
        deployment_digest=_digest(dp,"sha256"),sponsorship_repair_profile_digest=_digest(profile,"sha256"))
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(profile,"sha256"),context_digest=_digest(context,"sha256"),
        instrument_digest=digest_bytes(raw,2),body_digest=_digest(body,"sha256"),root=body["issuer"],subject=body["subject"],bond_id=body["id"],
        opened_at=1800000000,checked_at=1800000004,expires_at=1800000007,zone_id="zone:alpha",opening_anchor_verified=True,
        counts={name:0 for name in profile["entry_classes"]},blocked_classes=[],aggregate_blocked=False,hard_blocked=False)
    class Source:
        def resolve(self,**kwargs):return AuthenticatedSponsorshipContext(rfc8785.dumps(state),rfc8785.dumps(body),b"modeled-bond-anchor/complete-root-lineage-counts-at-opening")
    verifier=InstalledSponsorshipRepairVerifier(rfc8785.dumps(dp),rfc8785.dumps(profile),Source(),"sha256","zone:alpha")
    return verifier,state,context,raw,body,profile


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class SponsorshipRepairTests(unittest.TestCase):
    def evaluate(self,v,context,raw,now=1800000004):
        import rfc8785
        return v.evaluate(raw,context_bytes=rfc8785.dumps(context),evaluated_at=now,clock_healthy=True)

    def test_root_lineage_limit_and_recovery_hysteresis(self):
        v,state,context,raw,body,profile=fixture()
        name="act-outside-decision"
        state["counts"][name]=2
        self.assertFalse(self.evaluate(v,context,raw).eligible)
        state["counts"][name]=1
        self.assertTrue(self.evaluate(v,context,raw).eligible)
        state["blocked_classes"]=[name]
        self.assertFalse(self.evaluate(v,context,raw).eligible)
        state["counts"][name]=0
        self.assertTrue(self.evaluate(v,context,raw).eligible)
        state["blocked_classes"]=[]
        state["counts"].update({"act-outside-decision":1,"misattestation":1})
        self.assertFalse(self.evaluate(v,context,raw).eligible)
        state["counts"]["misattestation"]=0
        state["hard_blocked"]=True
        self.assertFalse(self.evaluate(v,context,raw).eligible)

    def test_profile_bounds_and_opening_binding(self):
        import rfc8785
        v,state,context,raw,body,profile=fixture()
        for patch in (dict(count_limit=2),dict(count_limit=1,declared_capacity=0),dict(hard=False)):
            changed=json.loads(rfc8785.dumps(profile));changed["entry_classes"]["misattestation"].update(patch)
            with self.assertRaises(ValidationError):replace(v,profile_bytes=rfc8785.dumps(changed))
        for patch in (dict(subject="another-subject"),dict(root="another-root"),dict(opening_anchor_verified=False),
                      dict(opened_at=1800000001),dict(checked_at=1800000003)):
            original=dict(state);state.update(patch)
            with self.assertRaises(ValidationError):self.evaluate(v,context,raw)
            state.clear();state.update(original)

    def test_current_root_credit_consumes_selected_opening_assessment(self):
        import rfc8785
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier,AuthenticatedRootInstrument
        v,state,context,raw,body,profile=fixture()
        class Adapter:
            def verify(self,*args,**kwargs):return AuthenticatedRootInstrument(rfc8785.dumps(body),(),issuer_zone="zone:alpha")
        root=InstalledRootVerifier(Adapter(),"sha256",sponsorship_repair_verifier=v)
        allowed=root.evaluate(raw,context_bytes=rfc8785.dumps(context),evaluated_at=1800000004)
        self.assertGreater(allowed.score,0)
        self.assertTrue(allowed.sponsorship_repair.eligible)
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        from kinetic_trust_library.v3.native_proof_profile import RootProofBinding
        roots=select_assessed_roots((allowed,),context_bytes=rfc8785.dumps(context),evaluated_at=1800000004,algorithm="sha256")
        claims=dict(sub=body["subject"],exp=1800000007,ktp=dict(zone="zone:alpha",subject_kind="software_agent",generation=0,
            lineage="sponsored",sponsor=body["issuer"],root_instrument=json.loads(allowed.projection_bytes)))
        binding=RootProofBinding(roots,"zone:alpha")
        self.assertTrue(binding(rfc8785.dumps(claims),1800000004))
        claims["exp"]=1800000008
        self.assertFalse(binding(rfc8785.dumps(claims),1800000004))
        state["counts"]["act-outside-decision"]=2
        denied=root.evaluate(raw,context_bytes=rfc8785.dumps(context),evaluated_at=1800000004)
        self.assertEqual(denied.score,0)
        self.assertFalse(denied.sponsorship_repair.eligible)
        self.assertEqual(json.loads(denied.projection_bytes)["kind"],"none")
        missing=replace(root,sponsorship_repair_verifier=None).evaluate(raw,context_bytes=rfc8785.dumps(context),evaluated_at=1800000004)
        self.assertEqual(missing.score,0)
        class Broken:
            def resolve(self,**kwargs):raise ValueError("opening registry unavailable")
        broken=replace(root,sponsorship_repair_verifier=replace(v,context_source=Broken()))
        with self.assertRaisesRegex(ValueError,"opening registry unavailable"):
            broken.evaluate(raw,context_bytes=rfc8785.dumps(context),evaluated_at=1800000004)
        # Historical opening remains a separate prerequisite after active bond expiry.
        state["counts"]["act-outside-decision"]=0;state.update(checked_at=1800000020,expires_at=1800000027)
        historical=self.evaluate(v,context,raw,1800000020)
        self.assertTrue(historical.eligible)
        self.assertEqual(historical.opened_at,1800000000)
