"""Observed primary-source snapshot hashes and native schema closure."""
import hashlib
import json
from importlib.resources import files
from pathlib import Path
import unittest


ROOT=Path(__file__).resolve().parents[3]
V3_RISK="https://kinetic-trust-protocol.net/specs/schemas/v3/risk-factors.json"


class RFCRefreshTests(unittest.TestCase):
    def test_observed_rfc_snapshots_match_their_recorded_primary_source_hashes(self):
        manifest=json.loads((ROOT/"spec/proposals/rfc-refresh-2026-10-29.json").read_text())
        self.assertEqual(manifest["status"],"provisional-untagged")
        observed=set()
        for entry in manifest["snapshots"]:
            path=entry["path"]
            with self.subTest(path=path):
                self.assertNotIn(path,observed);observed.add(path)
                self.assertRegex(entry["source_commit"],r"^[0-9a-f]{40}$")
                if path.startswith("src/kinetic_trust_library/v3/"):
                    raw=files("kinetic_trust_library.v3").joinpath(path.split("/v3/",1)[1]).read_bytes()
                else:raw=(ROOT/path).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(),entry["sha256"])
        self.assertEqual(len(observed),18)

    def test_native_proof_and_record_reference_the_native_risk_schema_directly(self):
        base=files("kinetic_trust_library.v3").joinpath("schemas")
        self.assertEqual(base.joinpath("trust-proof-v3.json").read_bytes(),base.joinpath("trust-proof-composed-v3.json").read_bytes())
        for name in ("trust-proof-v3.json","trust-proof-composed-v3.json"):
            schema=json.loads(base.joinpath(name).read_text())
            self.assertEqual(schema["$defs"]["ktpClaims"]["properties"]["context"]["anyOf"][0]["$ref"],V3_RISK)
        record=json.loads(base.joinpath("transaction-record-v3.json").read_text())
        self.assertEqual(record["$defs"]["oracleAttestation"]["properties"]["risk_factors"]["$ref"],V3_RISK)
        for obsolete in ("risk-factors-v2.json","risk-factors-composed-v3.json"):
            self.assertFalse(base.joinpath(obsolete).is_file())

    def test_prior_schema_reference_and_six_factor_legacy_remain_archived(self):
        archive=ROOT/"spec/proposals/archive/2026-10-29-pre-refresh"
        old=json.loads((archive/"trust-proof-composed-v3.json").read_text())
        self.assertIn("/v2/",old["$defs"]["ktpClaims"]["properties"]["context"]["anyOf"][0]["$ref"])
        frozen=json.loads((ROOT/"spec/v2.1.0/schemas/risk-factors.json").read_text())
        prior=json.loads((archive/"risk-factors-v2.json").read_text())
        self.assertEqual(prior,frozen)
        self.assertIn("moment_criticality",frozen["required"])
