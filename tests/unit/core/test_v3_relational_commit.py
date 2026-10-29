"""Modeled authority state; actual atomic storage/effects remain Service-owned."""
from importlib.util import find_spec
import unittest

HAS_EXTRAS=all(find_spec(n) for n in ("rfc8785","cryptography","jsonschema"))


def fixture(decision_fixture=None):
    import json,rfc8785
    from tests.unit.core.test_v3_relational_decision import fixture as decision
    from kinetic_trust_library.v3.relational_commit import InstalledRelationalCommitVerifier,AuthenticatedRelationalCommitContext
    from kinetic_trust_library.v3.demand_supplier import _digest
    f=decision() if decision_fixture is None else decision_fixture
    dv=f["v"];lease=f["lease"];now=f["now"]
    p=dict(id="commit:1",version=1,zone=json.loads(dv.profile_bytes)["zone"],formula="conditional-single-use-commit-v1",
        decision_profile_digest=_digest(json.loads(dv.profile_bytes),"sha256"),authority=lease["issuer"],
        nonce_namespace="nonce-registry:relational",commit_protocol="compare-nonce-epoch-fences-with-effect-v1",max_contract_age_seconds=5)
    authority=dict(id=p["authority"],protocol=p["commit_protocol"],nonce_namespace=p["nonce_namespace"],registry_anchor="sha256:"+"5"*64,
        registered_at=800,withdrawn_at=None,revision=2)
    nonce=dict(lease_id=lease["id"],lease_digest=_digest(lease,"sha256"),nonce=lease["nonce"],subject=lease["subject"],
        grant_epoch=5,registered_at=lease["issued_at"],consumed_at=None,revoked_at=None,revision=7,record_anchor="sha256:"+"6"*64)
    s=dict(deployment_digest=f["s"]["deployment_digest"],profile_digest=_digest(p,"sha256"),operation_digest=f["s"]["operation_digest"],
        subject=lease["subject"],zone=p["zone"],checked_at=now,expires_at=now+7,authority=authority,nonce=nonce,
        current_grant_epoch=5,topology_epoch=5,ledger_head=f["rs"]["ledger_head"],fences=[])
    anchors=dict(grant=f["rs"]["grant"]["record_anchor"],nonce=nonce["record_anchor"],human_decision=f["s"]["decision"]["anchor"],
        template=lease["template_digest"],native_evidence=f["s"]["evidence_digest"],adverse_stop=f["rs"]["ledger_head"]["anchor"],authority=authority["registry_anchor"])
    s["fences"]=[dict(name=name,anchor=anchor,revision=10+i) for i,(name,anchor) in enumerate(anchors.items())]
    class Source:
        def resolve(self,**kw):return AuthenticatedRelationalCommitContext(rfc8785.dumps(s),b"modeled registered authority/actual nonce revision/protected source fences")
    v=InstalledRelationalCommitVerifier(dv,rfc8785.dumps(p),Source())
    return dict(f=f,v=v,s=s,p=p)


def evaluate(c):
    import rfc8785
    f=c["f"]
    return c["v"].evaluate(f["f"]["sign"](),rfc8785.dumps(f["lease"]),evidence_digest=f["s"]["evidence_digest"],
        actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)


@unittest.skipUnless(HAS_EXTRAS,"install v3-proofs")
class RelationalCommitTests(unittest.TestCase):
    def test_contract_preserves_exact_authority_nonce_current_fences_and_shortest_expiry(self):
        import json
        c=fixture();r=evaluate(c)
        self.assertTrue(r.conditional_commit);self.assertFalse(r.action_permitted);self.assertEqual(r.expires_at,1005)
        b=json.loads(r.contract_bytes)
        self.assertEqual(b["nonce"],c["f"]["lease"]["nonce"])
        self.assertEqual(b["fences"],sorted(c["s"]["fences"],key=lambda f:f["name"]))

    def test_consumed_revoked_or_changed_epoch_never_constructs_contract(self):
        for change in (lambda s:s["nonce"].update(consumed_at=999),lambda s:s["nonce"].update(revoked_at=999),
                       lambda s:s.update(current_grant_epoch=6),lambda s:s["authority"].update(withdrawn_at=999)):
            c=fixture();change(c["s"])
            with self.subTest(change=change):self.assertFalse(evaluate(c).conditional_commit)

    def test_wrong_nonce_owner_grant_or_fence_is_not_eligible(self):
        for change in (lambda s:s["nonce"].update(nonce="other"),lambda s:s["authority"].update(id="other"),
                       lambda s:s["fences"].pop(),lambda s:s["fences"][0].update(anchor="sha256:"+"0"*64)):
            c=fixture();change(c["s"])
            with self.subTest(change=change):self.assertFalse(evaluate(c).conditional_commit)

    def test_same_contract_can_pass_only_one_serialized_modeled_authority_commit(self):
        import rfc8785
        from threading import Lock
        from concurrent.futures import ThreadPoolExecutor
        from kinetic_trust_library.v3.relational_commit import check_relational_commit
        c=fixture();r=evaluate(c);lock=Lock();effects=[]
        def commit():
            with lock:
                c["s"]["checked_at"]=1001
                checked=check_relational_commit(r,rfc8785.dumps(c["s"]),actual_operation=c["f"]["op"],committed_at=1001,clock_healthy=True)
                if not checked.conditions_match:return False
                c["s"]["nonce"]["consumed_at"]=1001;c["s"]["nonce"]["revision"]+=1
                effects.append("one modeled effect")
                return True
        with ThreadPoolExecutor(max_workers=2) as executor:results=list(executor.map(lambda _:commit(),range(2)))
        self.assertEqual(sum(results),1);self.assertEqual(len(effects),1)

    def test_actual_changes_between_evaluation_and_commit_are_rejected(self):
        import rfc8785
        from kinetic_trust_library.v3.relational_commit import check_relational_commit
        for change in (lambda s:s.update(current_grant_epoch=6),lambda s:s.update(topology_epoch=6),
                       lambda s:s["ledger_head"].update(sequence=101),lambda s:s["fences"][0].update(revision=99),
                       lambda s:s["authority"].update(revision=3),lambda s:s["nonce"].update(revision=8)):
            c=fixture();r=evaluate(c);change(c["s"]);c["s"]["checked_at"]=1001
            with self.subTest(change=change):
                self.assertFalse(check_relational_commit(r,rfc8785.dumps(c["s"]),actual_operation=c["f"]["op"],committed_at=1001,clock_healthy=True).conditions_match)

    def test_expired_contract_or_unhealthy_commit_clock_fails_closed(self):
        import rfc8785
        from kinetic_trust_library.v3.relational_commit import check_relational_commit
        c=fixture();r=evaluate(c)
        for at,healthy in ((1005,True),(1001,False),(999,True)):
            self.assertFalse(check_relational_commit(r,rfc8785.dumps(c["s"]),actual_operation=c["f"]["op"],committed_at=at,clock_healthy=healthy).conditions_match)

    def test_wire_contract_is_not_authority_and_cached_frame_is_not_current(self):
        import rfc8785
        from kinetic_trust_library.errors import ValidationError
        from kinetic_trust_library.v3.relational_commit import check_relational_commit
        c=fixture();r=evaluate(c)
        with self.assertRaises(ValidationError):
            check_relational_commit(r.contract_bytes,rfc8785.dumps(c["s"]),actual_operation=c["f"]["op"],committed_at=1001,clock_healthy=True)
        self.assertFalse(check_relational_commit(r,rfc8785.dumps(c["s"]),actual_operation=c["f"]["op"],committed_at=1001,clock_healthy=True).conditions_match)
        c["s"]["checked_at"]=1001
        op=dict(c["f"]["op"],resource="resource:other")
        self.assertFalse(check_relational_commit(r,rfc8785.dumps(c["s"]),actual_operation=op,committed_at=1001,clock_healthy=True).conditions_match)

    def test_not_after_can_only_shorten_contract_and_is_enforced_at_commit(self):
        import rfc8785
        from kinetic_trust_library.v3.relational_commit import check_relational_commit
        c=fixture();f=c["f"]
        r=c["v"].evaluate(f["f"]["sign"](),rfc8785.dumps(f["lease"]),evidence_digest=f["s"]["evidence_digest"],
            actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True,not_after=1002)
        self.assertEqual(r.expires_at,1002)
        c["s"]["checked_at"]=1002
        self.assertFalse(check_relational_commit(r,rfc8785.dumps(c["s"]),actual_operation=f["op"],committed_at=1002,clock_healthy=True).conditions_match)
