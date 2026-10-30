import json
import hashlib
import unittest
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


class ClaimSubstrateTests(unittest.TestCase):
    def test_all_exact_published_substrate_cases(self):
        from kinetic_trust_library.v3.claim_substrate import assess_claim_substrate
        raw=(Path(__file__).parents[3]/"spec/proposals/claims-substrate-v1.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),"694cdc069c69ffb748f2eb0d2d62688afdeaaba4667cfc527b96c609278ab892")
        for case in json.loads(raw)["vectors"]:
            given=case["given"]
            profiles=tuple(tuple(s.rsplit(" ",1)) for s in given.get("profilesInSet",[]))
            r=assess_claim_substrate(given["claim"],profiles_in_set=profiles)
            with self.subTest(case=case["id"]):
                self.assertEqual(r.accepted,case["expect"]["accepted"])
                self.assertFalse(r.evidence_verified);self.assertFalse(r.runtime_conformance_established)
                self.assertEqual(r.level,given["claim"]["level"])
                if r.accepted:self.assertEqual(" ".join(r.specified_test_ids_run_under),case["expect"]["specifiedTestIdsRunUnder"])

    def test_exact_version_no_candidate_override_and_no_execution_enablement(self):
        from kinetic_trust_library.v3.claim_substrate import assess_claim_substrate
        claim=dict(product="library",version="unreleased",level="Basic",status="tested",substrateProfile={"id":"software-substrate-execution","version":"1.0"})
        self.assertFalse(assess_claim_substrate(claim,profiles_in_set=(("software-substrate-execution","2.0"),)).accepted)
        r=assess_claim_substrate(dict(claim,profilesInSet=["software-substrate-execution 1.0"]),profiles_in_set=())
        self.assertFalse(r.accepted)
        claim["substrateProfile"]["version"]="1.0 "
        self.assertFalse(assess_claim_substrate(claim,profiles_in_set=(("software-substrate-execution","1.0"),)).accepted)

    def test_inventory_is_independently_installed_immutable_and_unambiguous(self):
        from kinetic_trust_library.v3.claim_substrate import assess_claim_substrate
        for inventory in ([('a','1')],(('a','1'),('a','1')),(('a',1),)):
            with self.subTest(inventory=inventory),self.assertRaises(ValidationError):assess_claim_substrate({},profiles_in_set=inventory)

    def test_malformed_claim_does_not_establish_a_profile(self):
        from kinetic_trust_library.v3.claim_substrate import assess_claim_substrate
        for candidate in (None,{},dict(level="Basic",substrateProfile={"id":"x","version":"1"})):
            r=assess_claim_substrate(candidate,profiles_in_set=(("x","1"),))
            self.assertFalse(r.accepted);self.assertFalse(r.runtime_conformance_established)
