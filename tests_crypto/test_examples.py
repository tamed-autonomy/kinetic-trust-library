from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CryptoExampleSmokeTests(unittest.TestCase):
    def test_trust_proof_issue_and_verify_under_optimized_python(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [
                sys.executable,
                "-O",
                str(ROOT / "examples" / "04_trust_proof_issue_and_verify.py"),
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        for marker in (
            "verified=true",
            "proof_id=proof-example-1",
            "issuer=https://oracle.example",
            "subject=agent:independent:3gen:example-line:example-agent",
            "key_id=example-ed25519-key",
            "E_base=",
            "risk=",
            "E_trust=",
            "capacity_relation=above_capacity",
            "within_capacity=False",
            "envelope_margin=",
            "envelope_supervision=",
            "authorization_performed=false",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, completed.stdout)

    def test_proof_binding_checks_reject_mismatches_under_optimized_python(self) -> None:
        script = textwrap.dedent("""\
            from datetime import timedelta
            from pathlib import Path
            import runpy
            import sys
            from unittest.mock import patch
            from kinetic_trust_library.proofs import TrustProofs

            field = sys.argv[1]
            method = "issue" if field == "expires_at" else "verify"
            original = getattr(TrustProofs, method)

            def mismatched_result(self, *args, **kwargs):
                result = original(self, *args, **kwargs)
                if field == "expires_at":
                    object.__setattr__(result, field, result.expires_at + timedelta(seconds=1))
                    return result
                value = (
                    "other-decision"
                    if field == "decision_id"
                    else result.claims.issued_at + timedelta(seconds=1)
                )
                object.__setattr__(result.claims, field, value)
                return result

            sys.path.insert(0, str(Path("examples").resolve()))
            with patch.object(TrustProofs, method, mismatched_result):
                runpy.run_path("examples/04_trust_proof_issue_and_verify.py", run_name="__main__")
            """)
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for field, message in (
            ("decision_id", "verified proof decision ID does not match the evaluation"),
            ("issued_at", "verified proof issued-at does not match the evaluation cutoff"),
            ("expires_at", "issued proof exceeds the requested lifetime"),
        ):
            with self.subTest(field=field):
                completed = subprocess.run(
                    [sys.executable, "-O", "-c", script, field],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0, msg=completed.stdout)
                self.assertIn(f"RuntimeError: {message}", completed.stderr)
                self.assertNotIn("verified=true", completed.stdout)
