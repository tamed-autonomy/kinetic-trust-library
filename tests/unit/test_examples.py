from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]


def run_example(name: str) -> str:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples" / name)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"{name} failed with {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


class ExampleSmokeTests(unittest.TestCase):
    def test_observations_from_application_apis(self) -> None:
        output = run_example("03_observations_from_application_apis.py")
        for marker in (
            "result_type=EvaluationBundle",
            "selected_compute_observation=api:compute:new",
            "unavailable_alarm_reason=source_unavailable",
            "published_index_observation=api:index:2026-07",
            "capacity_relation=",
            "within_capacity=",
            "envelope_margin=",
            "envelope_supervision=",
            "network_calls=0",
            "action_executed=false",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, output)

    def test_fail_closed_evaluation_outcomes(self) -> None:
        output = run_example("02_fail_closed_evaluation_outcomes.py")
        for marker in (
            "case=clear",
            "case=soul_veto",
            "case=soul_undetermined",
            "downstream_present=false",
            "core_capacity=unevaluated",
            "capacity_relation=",
            "within_capacity=",
            "envelope_margin=",
            "envelope_supervision=silent_veto",
            "case=missing_evidence",
            "undefined_inputs=",
            "case=rejected_request",
            "failed_stage=evidence",
            "case=application_failure",
            "library_called=false",
            "ktp_result=false",
            "action_executed=false",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, output)

    def test_core_and_envelope_evaluation(self) -> None:
        output = run_example("01_core_and_envelope_evaluation.py")
        for marker in (
            "result_type=EvaluationBundle",
            "risk=",
            "E_base=",
            "E_trust=",
            "tier=",
            "capacity_relation=above_capacity",
            "within_capacity=False",
            "envelope_capacity=",
            "envelope_margin=",
            "envelope_supervision=",
            "action_executed=false",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, output)
