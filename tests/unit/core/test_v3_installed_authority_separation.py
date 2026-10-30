from importlib.util import find_spec
from dataclasses import replace
import unittest


def fixture(operation=None,deployment=None,zone="zone-a",evidence_digest=None,lease_authority="authority:a",now=1000):
    import rfc8785
    from tests.unit.core.test_v3_authority_separation import facts
    from kinetic_trust_library.v3.installed_authority_separation import InstalledAuthoritySeparationVerifier,AuthenticatedAuthoritySeparationContext
    from kinetic_trust_library.v3.demand_operation import digest_demand_operation
    from kinetic_trust_library.v3.demand_supplier import _digest
    op=operation or dict(subject="subject:a",actor="agent:a",audience="service:a",operation="action:write",resource="resource:a",
        parameters={},request_id="request:1",replay_domain="domain:a")
    dp=deployment or dict(id="deployment:a");evidence_digest=evidence_digest or "sha256:"+"a"*64
    profile=dict(id="separation:a",version=1,zone=zone,formula="audited-key-and-measurer-separation-v1",
        lease_authority=lease_authority,zone_class="blue",quorum_members=["measurer:a","measurer:b"],quorum_k=2,
        single_measurer_limit=None,maximum_audit_age_seconds=100,accepted_auditors=["auditor:a"])
    inventory=facts()
    state=dict(deployment_digest=_digest(dp,"sha256"),profile_digest=_digest(profile,"sha256"),operation_digest=digest_demand_operation(op,algorithm="sha256"),
        decision_digest=evidence_digest,subject=op["actor"],zone=zone,lease_authority=lease_authority,
        checked_at=now,expires_at=now+7,inventory=inventory,
        audit=dict(anchor="audit:architecture",auditor="auditor:a",observed_at=now-10,profile_digest=_digest(profile,"sha256"),inventory_digest=None),
        attestations=[dict(anchor="audit:attestation:"+str(i),measurer=m,key_id=k,decision_digest=evidence_digest)
            for i,(m,k) in enumerate((("measurer:a","key:measure-a"),("measurer:b","key:measure-b")))])
    def refresh():state["audit"]["inventory_digest"]=_digest({k:v for k,v in inventory.items() if k!="used_measurers"},"sha256")
    refresh()
    class Source:
        def resolve(self,**kw):return AuthenticatedAuthoritySeparationContext(rfc8785.dumps(state),b"modeled actual signed architectural audit and counted environment attestations")
    v=InstalledAuthoritySeparationVerifier(rfc8785.dumps(dp),rfc8785.dumps(profile),Source(),"sha256")
    return dict(v=v,s=state,op=op,dp=dp,profile=profile,evidence=evidence_digest,now=now,refresh=refresh)


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class InstalledAuthoritySeparationTests(unittest.TestCase):
    def evaluate(self,f):
        return f["v"].evaluate(decision_digest=f["evidence"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)

    def test_current_audit_and_used_attestations_bound_to_decision(self):
        f=fixture();r=self.evaluate(f)
        self.assertTrue(r.valid);self.assertFalse(r.action_permitted);self.assertEqual(r.expires_at,f["now"]+7)

    def test_audit_inventory_or_current_decision_cannot_be_substituted(self):
        from kinetic_trust_library.errors import ValidationError
        for change in (lambda s:s["inventory"]["lease_constructor_processes"].append("process:helper"),
                       lambda s:s["attestations"][0].update(decision_digest="sha256:"+"b"*64),
                       lambda s:s["attestations"].pop(),lambda s:s["audit"].update(observed_at=0),
                       lambda s:s["attestations"][0].update(key_id="key:measure-b")):
            f=fixture();change(f["s"])
            with self.subTest(change=change),self.assertRaises(ValidationError):self.evaluate(f)

    def test_actual_audited_agent_key_access_blocks_clearance_prerequisite(self):
        f=fixture();f["s"]["inventory"]["key_custody"][0]["processes"].append("process:helper");f["refresh"]()
        r=self.evaluate(f);self.assertFalse(r.valid);self.assertEqual(r.reason,"AGENT_HOLDS_ACCEPTED_KEY")

    def test_source_failure_is_not_a_clean_audit(self):
        from kinetic_trust_library.errors import ValidationError
        f=fixture()
        class Broken:
            def resolve(self,**kw):raise ValidationError("audit Source unavailable")
        f["v"]=replace(f["v"],context_source=Broken())
        with self.assertRaisesRegex(ValidationError,"Source unavailable"):self.evaluate(f)
