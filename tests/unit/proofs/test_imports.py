"""Optional Trust Proof adapter import-isolation tests."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import kinetic_trust_library

from kinetic_trust_library.errors import CryptoConfigurationError


_PROJECT_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_DIRECTORY = Path(kinetic_trust_library.__file__).resolve().parent
SOURCE_DIRECTORY = _PROJECT_ROOT / "src"


def _child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["KTP_EXPECTED_PACKAGE_DIRECTORY"] = str(PACKAGE_DIRECTORY)
    if PACKAGE_DIRECTORY.is_relative_to(SOURCE_DIRECTORY):
        environment["PYTHONPATH"] = str(SOURCE_DIRECTORY)
    else:
        environment.pop("PYTHONPATH", None)
    return environment


def _run_guarded_base_import_subprocess() -> subprocess.CompletedProcess[str]:
    script = textwrap.dedent(
        """
        import importlib.abc
        import sys


        class RejectCryptography(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "cryptography" or fullname.startswith("cryptography."):
                    raise AssertionError(f"base import requested optional backend: {fullname}")
                return None


        sys.meta_path.insert(0, RejectCryptography())

        import kinetic_trust_library
        import os
        from pathlib import Path

        expected = Path(os.environ["KTP_EXPECTED_PACKAGE_DIRECTORY"]).resolve()
        actual = Path(kinetic_trust_library.__file__).resolve().parent
        assert actual == expected, (actual, expected)
        import kinetic_trust_library.models
        import kinetic_trust_library.protocols
        import kinetic_trust_library.proofs
        import kinetic_trust_library.adapters
        import kinetic_trust_library.adapters.cryptography

        loaded = sorted(
            name
            for name in sys.modules
            if name == "cryptography" or name.startswith("cryptography.")
        )
        if loaded:
            raise AssertionError(f"optional backend was loaded: {loaded}")
        """
    )
    with tempfile.TemporaryDirectory() as temporary:
        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=temporary,
            env=_child_environment(),
            capture_output=True,
            text=True,
            check=False,
        )


class BaseImportIsolationTests(unittest.TestCase):
    def test_base_and_adapter_namespace_never_request_cryptography(self):
        completed = _run_guarded_base_import_subprocess()

        self.assertEqual(completed.returncode, 0, completed.stderr)


class OptionalAdapterLoadingTests(unittest.TestCase):
    @staticmethod
    def _public_entry_calls(adapter):
        return (
            lambda: adapter.cryptography_proof_crypto(),
            lambda: adapter.async_cryptography_proof_crypto(),
            lambda: adapter.ES256LocalSigner(object(), object()),
            lambda: adapter.AsyncES256LocalSigner(object(), object()),
            lambda: adapter.Ed25519LocalSigner(object(), object()),
            lambda: adapter.AsyncEd25519LocalSigner(object(), object()),
            lambda: adapter.es256_public_key_bytes(object()),
            lambda: adapter.ed25519_public_key_bytes(object()),
        )

    def test_public_adapter_surface_is_exact_and_backend_neutral(self):
        adapter = importlib.import_module("kinetic_trust_library.adapters.cryptography")
        expected = {
            "AsyncES256LocalSigner",
            "AsyncEd25519LocalSigner",
            "ES256LocalSigner",
            "Ed25519LocalSigner",
            "async_cryptography_proof_crypto",
            "cryptography_proof_crypto",
            "ed25519_public_key_bytes",
            "es256_public_key_bytes",
        }

        self.assertEqual(set(adapter.__all__), expected)

    def test_factory_maps_only_the_missing_external_package_to_configuration(self):
        adapter = importlib.import_module("kinetic_trust_library.adapters.cryptography")
        self.assertTrue(hasattr(adapter, "cryptography_proof_crypto"))

        missing = ModuleNotFoundError(
            "No module named 'cryptography'",
            name="cryptography",
        )
        for call in self._public_entry_calls(adapter):
            with (
                self.subTest(call=call),
                patch.object(
                    adapter,
                    "_import_cryptography_modules",
                    side_effect=missing,
                ),
                self.assertRaises(CryptoConfigurationError) as raised,
            ):
                call()

            self.assertIn("kinetic-trust-library[cryptography]", str(raised.exception))
            self.assertIs(raised.exception.__cause__, missing)

    def test_adapter_import_defect_is_not_mislabeled_as_missing_dependency(self):
        adapter = importlib.import_module("kinetic_trust_library.adapters.cryptography")
        self.assertTrue(hasattr(adapter, "cryptography_proof_crypto"))

        defect = ModuleNotFoundError(
            "No module named 'adapter_internal_dependency'",
            name="adapter_internal_dependency",
        )
        for call in self._public_entry_calls(adapter):
            with (
                self.subTest(call=call),
                patch.object(
                    adapter,
                    "_import_cryptography_modules",
                    side_effect=defect,
                ),
                self.assertRaises(ModuleNotFoundError) as raised,
            ):
                call()

            self.assertIs(raised.exception, defect)


if __name__ == "__main__":
    unittest.main()
