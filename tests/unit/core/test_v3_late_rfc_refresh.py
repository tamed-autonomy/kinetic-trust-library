from importlib.util import find_spec
import json
from pathlib import Path
import unittest
from kinetic_trust_library.errors import ValidationError


@unittest.skipUnless(find_spec("rfc8785") and find_spec("jsonschema"),"install v3-proofs")
class LateRFCRefreshTests(unittest.TestCase):
    def test_canonical_request_uses_the_refreshed_unit_without_old_alias(self):
        from kinetic_trust_library.v3.request_binding import canonical_request_bytes
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/request-binding-v1.json").read_text())
        request=json.loads(vectors["cases"][0]["steps"][0]["request_json"])
        request["demand"]["unit"]="urn:ktp:unit:action-risk-points"
        self.assertTrue(canonical_request_bytes(request))
        request["demand"]["unit"]="ktp-action-risk-points"
        with self.assertRaises(ValidationError):canonical_request_bytes(request)

    def test_zero_limit_reopens_sponsorship_after_reconciliation(self):
        from kinetic_trust_library.v3.sponsorship_repair import sponsorship_counts_eligible,_profile
        from tests.unit.core.test_v3_sponsorship_repair import fixture
        import rfc8785
        _,s,_,_,_,profile=fixture()
        profile["aggregate_count_limit"]=0
        for entry in profile["entry_classes"].values():entry["count_limit"]=0
        profile=_profile(rfc8785.dumps(profile));name=next(iter(s["counts"]))
        s["counts"][name]=1
        self.assertFalse(sponsorship_counts_eligible(profile,s["counts"],[name],True,True))
        s["counts"][name]=0
        self.assertTrue(sponsorship_counts_eligible(profile,s["counts"],[name],True,True))
