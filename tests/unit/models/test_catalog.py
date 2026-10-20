import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType

from kinetic_trust_library._catalog import (
    ALIASES,
    CATALOG,
    ENVELOPE_ELIGIBILITY,
    validate_signal_id,
    validate_signal_subset,
)
from tools.compile_catalog import (
    CatalogCompileError,
    build_catalogue,
    compile_catalog,
    parse_json_bytes,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SPEC_ROOT = REPOSITORY_ROOT / "spec/v2.1.0"
CATALOG_MODULE = REPOSITORY_ROOT / "src/kinetic_trust_library/_catalog.py"
CATALOG_TOOL = REPOSITORY_ROOT / "tools/compile_catalog.py"
EXPECTED_DIGESTS = {
    "catalog/body.json": "ba2a9bebcdf5e2d276714605384594594c8e58a1e9913efd164f294d4b88ae9d",
    "catalog/index.json": "fc7d5d08d870d6ff45231f871f858f4d8f95240a1e5b43b43b06c22554102736",
    "catalog/information.json": "40575732b38b7e28f2f2b36849fbaf1dae603bfa40b19d56772692e2596ab925",
    "catalog/meta.json": "98eafb50ab50c2bfdec0ff63acde2f4e25287c91e872db04d4a34180cd6eb403",
    "catalog/relational.json": "4e65ba4a894b67ddeca7e1672ca1f55f680a84e5ecbece077c6b570d2c6cfd5c",
    "catalog/soul.json": "c08c0247a3670dd65b423e3dafc9cf3f4e6b258db0d05d17b45a135f2735b6dd",
    "catalog/time.json": "3f1af85df393cfba9e775d1e7c057e925c5f2f7c720c4cd2e05f50e6acab6b84",
    "catalog/world.json": "3604705de9a8af97a3001ad38ca3047a3c0d4bd838863b40f96ba2e3e9dab6e2",
    "conformance/aggregation-empty-window-v1.json": "8b3403ed7889f6b3d708d2e75f7cb8b9b700e75aaa00959ef46bf6d2d35aaa73",
    "conformance/ros2-reference-v0.1.json": "fbb11fefe441c10154c5bf99bd88b63d79a6885b5b1f3a70852f83d325a8b024",
    "schemas/deployment-profile.json": "c0087dc3662b8ef1988f7d612a779ca38f2b771454a45fc33abaaed6f2ebb3f2",
    "schemas/risk-factors.json": "a2f497489b94e727398278794389e6fbae0a44c851f19a1e5d1daafc1daa16e0",
    "schemas/sensor-config.json": "a9f70585fc9ba85334f972dc8dbccb9dfa0446cb18ce3d8b79cadf5d59f3ad22",
    "schemas/soul-constraint.json": "94dae2a47bab45ea324e11df43d3030c4850a78e72846f46ab60a9b1399f8fd5",
    "schemas/sponsorship-bond.json": "2718d44a473370caaf9d278f6514bd1e5ba111f3e00ff6bff2a72739c6a5025e",
    "schemas/transaction-record.json": "d0649fd4d7c77eb85243b37f115b48adf145cbcfd4d8b43cff912d8014fc0f12",
    "schemas/trust-proof.json": "41d5dd2506893094d41e21193cf95eed396dc99b8d32d7264f50ea1a7972d4e0",
}


class CatalogTests(unittest.TestCase):
    def test_pinned_catalogue_has_exact_identity(self):
        manifest = json.loads((SPEC_ROOT / "upstream.json").read_text())
        self.assertEqual(manifest["tag"], "v2.1.0")
        self.assertEqual(
            manifest["commit"], "15520035267546e1035aad7beea0cc3cf9ef8f2c"
        )
        path = SPEC_ROOT / "catalog/index.json"
        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            "fc7d5d08d870d6ff45231f871f858f4d8f95240a1e5b43b43b06c22554102736",
        )
        self.assertEqual(len(CATALOG), 1644)

    def test_all_official_artifacts_have_exact_pinned_digests(self):
        self.assertEqual(
            {
                path: hashlib.sha256((SPEC_ROOT / path).read_bytes()).hexdigest()
                for path in EXPECTED_DIGESTS
            },
            EXPECTED_DIGESTS,
        )

    def test_catalogue_exposes_owned_signal_alias_and_envelope_facts(self):
        signal = CATALOG["world.optical.illuminance"]
        self.assertEqual(signal.domain, "world")
        self.assertEqual(signal.group, "optical")
        self.assertEqual(signal.observation_class, "D")
        self.assertEqual(signal.value_type, "float")
        self.assertEqual(signal.value_range, "0-200000 lx")
        self.assertIsInstance(CATALOG, MappingProxyType)
        self.assertIsInstance(ALIASES, MappingProxyType)
        self.assertEqual(
            ALIASES["clock_offset"],
            frozenset(
                {
                    "time.sync.clock_offset",
                    "body.clock.offset_magnitude",
                    "world.network.time_sync_error",
                }
            ),
        )
        self.assertEqual(ENVELOPE_ELIGIBILITY[signal.signal_id], "D")
        with self.assertRaises((AttributeError, TypeError)):
            signal.name = "changed"
        with self.assertRaises(TypeError):
            CATALOG[signal.signal_id] = signal

    def test_signal_subset_rejects_duplicates_and_alias_double_counting(self):
        values = (
            "world.optical.illuminance",
            "world.weather.air_temperature",
        )
        self.assertEqual(validate_signal_subset(values), values)
        for invalid in (
            (values[0], values[0]),
            ("time.sync.clock_offset", "body.clock.offset_magnitude"),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_signal_subset(invalid)

    def test_collision_members_may_coexist_and_are_not_duplicate_aliases(self):
        collision = (
            "relational.communication.delivery_latency",
            "information.integrity.delivery_latency",
        )
        self.assertEqual(validate_signal_subset(collision), collision)
        self.assertTrue(
            all(
                not frozenset(collision).issubset(members)
                for members in ALIASES.values()
            )
        )

    def test_unknown_signal_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_signal_id("world.fake.missing")


class CatalogCompilerTests(unittest.TestCase):
    def _documents(self):
        index = json.loads((SPEC_ROOT / "catalog/index.json").read_text())
        domains = [
            json.loads((SPEC_ROOT / f"catalog/{domain}.json").read_text())
            for domain in index["domains"]
        ]
        return index, domains

    def test_compiler_reproduces_the_checked_in_module(self):
        self.assertEqual(
            compile_catalog(SPEC_ROOT).encode("utf-8"),
            CATALOG_MODULE.read_bytes(),
        )

    def test_check_rejects_crlf_generated_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            copied_spec = repository / "spec/v2.1.0"
            copied_tool = repository / "tools/compile_catalog.py"
            copied_output = repository / "src/kinetic_trust_library/_catalog.py"
            shutil.copytree(SPEC_ROOT, copied_spec)
            copied_tool.parent.mkdir(parents=True)
            copied_output.parent.mkdir(parents=True)
            shutil.copy2(CATALOG_TOOL, copied_tool)
            generated = CATALOG_MODULE.read_bytes()
            copied_output.write_bytes(generated.replace(b"\n", b"\r\n"))

            completed = subprocess.run(
                [sys.executable, str(copied_tool), "--check"],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 1)
            self.assertIn("generated catalogue is stale", completed.stderr)

    def test_compiler_rejects_manifest_digest_forgery(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied_root = Path(temporary) / "v2.1.0"
            shutil.copytree(SPEC_ROOT, copied_root)
            manifest_path = copied_root / "upstream.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["artifacts"][0]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(CatalogCompileError, "independent pin"):
                compile_catalog(copied_root)

    def test_compiler_rejects_tampered_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied_root = Path(temporary) / "v2.1.0"
            shutil.copytree(SPEC_ROOT, copied_root)
            body_path = copied_root / "catalog/body.json"
            body_path.write_bytes(body_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(CatalogCompileError, "digest mismatch"):
                compile_catalog(copied_root)

    def test_parser_rejects_duplicate_object_keys(self):
        with self.assertRaisesRegex(CatalogCompileError, "duplicate JSON key"):
            parse_json_bytes(b'{"count": 1, "count": 2}', path="duplicate.json")

    def test_compiler_rejects_duplicate_signal_ids(self):
        index, domains = self._documents()
        duplicate = deepcopy(domains[0]["groups"][0]["signals"][0])
        domains[0]["groups"][0]["signals"].append(duplicate)
        with self.assertRaisesRegex(CatalogCompileError, "duplicate signal ID"):
            build_catalogue(index, domains)

    def test_compiler_rejects_unknown_and_repeated_alias_members(self):
        index, domains = self._documents()
        for mutation in ("unknown", "repeated"):
            invalid_index = deepcopy(index)
            if mutation == "unknown":
                invalid_index["alias_sets"][0]["aliases"][0] = "world.fake.missing"
            else:
                invalid_index["alias_sets"][1]["aliases"][0] = invalid_index[
                    "alias_sets"
                ][0]["aliases"][0]
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(CatalogCompileError),
            ):
                build_catalogue(invalid_index, domains)

    def test_compiler_rejects_malformed_observation_class_declarations(self):
        index, domains = self._documents()
        domains[0]["groups"][0]["class"] = "X"
        with self.assertRaisesRegex(CatalogCompileError, "observation class"):
            build_catalogue(index, domains)

    def test_compiler_rejects_malformed_descriptive_fields(self):
        for field, target in (
            ("index comment", ("index", "$comment")),
            ("domain comment", ("domain", "$comment")),
            ("domain title", ("domain", "title")),
            ("alias quantity", ("alias", "quantity")),
            ("alias note", ("alias", "note")),
            ("alias unit_action", ("alias", "unit_action")),
        ):
            index, domains = self._documents()
            owner, key = target
            if owner == "index":
                index[key] = []
            elif owner == "domain":
                domains[0][key] = []
            else:
                index["alias_sets"][0][key] = []
            with self.subTest(field=field), self.assertRaises(CatalogCompileError):
                build_catalogue(index, domains)

    def test_compiler_controls_malformed_signal_field_errors(self):
        for field in ("type", "range", "class", "zero_one", "p"):
            index, domains = self._documents()
            domains[0]["groups"][0]["signals"][0][field] = []
            with self.subTest(field=field), self.assertRaises(CatalogCompileError):
                build_catalogue(index, domains)
