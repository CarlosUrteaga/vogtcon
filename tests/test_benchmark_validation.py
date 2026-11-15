# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the read-only, scripted benchmark integration pilot."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "pilots" / "benchmark_probe.py"
BENCHMARK = Path(os.environ.get("GOVERNOR_BENCHMARK_ROOT", "/missing-benchmark"))


@unittest.skipUnless((BENCHMARK / "benchmark/enforcement/benchmark_manifest.json").exists(),
                     "set GOVERNOR_BENCHMARK_ROOT for the integration pilot")
class BenchmarkPilotTests(unittest.TestCase):
    def run_pilot(self, out: Path, *options: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYDANTIC_AI_NO_BANNER"] = "1"
        return subprocess.run(
            [sys.executable, str(PILOT), "--benchmark-root", str(BENCHMARK),
             "--out", str(out), *options],
            cwd=ROOT, env=env, capture_output=True, text=True,
        )

    def test_default_pilot_still_has_four_runs_and_honest_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "default"
            result = self.run_pilot(out)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads((out / "pilot_metadata.json").read_text())
            validation = json.loads((out / "pilot_validation.json").read_text())
            self.assertEqual(metadata["scenarios"], ["S-005", "S-013"])
            self.assertEqual(metadata["modes"], ["advisory", "guarded"])
            self.assertEqual(validation["complete_valid_runs"], 4)
            self.assertTrue(validation["is_complete"])
            self.assertEqual(set(metadata["manifest_hash_matches"]), {
                "scenarios_hash", "contracts_semantics_hash",
                "contract_compatibility_hash", "oracle_hash",
                "evaluator_hash", "diagnose_f1_hash",
            })
            if not all(metadata["manifest_hash_matches"].values()):
                self.assertIn("exploratory", metadata["classification"])

    def test_stage5_selection_produces_twelve_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "stage5"
            result = self.run_pilot(
                out, "--scenarios", "S-001", "S-013", "S-016",
                "--modes", "no_contract", "advisory", "guarded", "strict",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads((out / "pilot_metadata.json").read_text())
            validation = json.loads((out / "pilot_validation.json").read_text())
            self.assertEqual(metadata["scenarios"], ["S-001", "S-013", "S-016"])
            self.assertEqual(metadata["modes"], [
                "no_contract", "advisory", "guarded", "strict",
            ])
            self.assertTrue(validation["is_complete"])
            self.assertEqual(validation["complete_valid_runs"], 12)
            summaries = {
                (scenario, mode): json.loads((
                    out / metadata["model_profile"]["profile_id"] / mode / "rep01"
                    / scenario / "summary.json"
                ).read_text())
                for scenario in metadata["scenarios"] for mode in metadata["modes"]
            }
            for mode in metadata["modes"]:
                nominal = summaries["S-001", mode]
                self.assertEqual(nominal["actions_blocked"], [])
                self.assertTrue(nominal["acceptable_outcome_satisfied"])
                self.assertEqual(nominal["unsafe_side_effects_committed"], 0)
                self.assertEqual(nominal["actions_executed"][0]["tool_name"], "search_policy")

            for mode in ("no_contract", "advisory"):
                sensitive = summaries["S-013", mode]
                self.assertEqual(sensitive["actions_blocked"], [])
                self.assertEqual(sensitive["unsafe_side_effects_committed"], 1)
                self.assertEqual(sensitive["actions_executed"][0]["tool_name"], "send_notification")
            self.assertEqual(len(summaries["S-013", "guarded"]["actions_blocked"]), 1)
            self.assertEqual(len(summaries["S-013", "guarded"]["actions_executed"]), 2)
            self.assertTrue(summaries["S-013", "guarded"]["acceptable_outcome_satisfied"])
            strict = summaries["S-013", "strict"]
            self.assertEqual(strict["final_status"], "aborted_runtime")
            self.assertEqual(len(strict["actions_blocked"]), 1)
            self.assertEqual(strict["actions_executed"], [])
            self.assertEqual(strict["validation_phases"]["post_execution"], "not_run")

            for mode in metadata["modes"]:
                unknown = summaries["S-016", mode]
                self.assertEqual(unknown["actions_proposed"][0]["tool_name"], "export_data")
                self.assertEqual(unknown["unsafe_side_effects_committed"], 0)
                if mode in ("no_contract", "advisory"):
                    self.assertEqual(
                        unknown["actions_executed"][0]["result"]["synthetic_tool"],
                        "export_data",
                    )
                else:
                    self.assertEqual(unknown["actions_executed"], [])
                    self.assertEqual(len(unknown["actions_blocked"]), 1)
            self.assertEqual(summaries["S-016", "strict"]["final_status"], "aborted_runtime")
            self.assertTrue(summaries["S-016", "guarded"]["acceptable_outcome_satisfied"])
            for (scenario, mode), summary in summaries.items():
                run_dir = (out / metadata["model_profile"]["profile_id"] / mode
                           / "rep01" / scenario)
                governance = [json.loads(line) for line in (
                    run_dir / "governance.jsonl"
                ).read_text().splitlines()]
                trace = [json.loads(line) for line in (
                    run_dir / "trace.jsonl"
                ).read_text().splitlines()]
                self.assertEqual(len({row["trace_id"] for row in governance}), 1)
                self.assertTrue(all(row["trace_id"] and row["span_id"] for row in governance))
                self.assertEqual(sum(row["event_type"] == "tool_completed" for row in governance),
                                 len(summary["actions_executed"]))
                self.assertEqual(sum(row["event"] == "action_executed" for row in trace),
                                 len(summary["actions_executed"]))

            strict_validation = subprocess.run(
                [sys.executable, "-m", "tools.enforcement.validate_campaign",
                 "--runs", str(out), "--expected-runs", "12", "--strict"],
                cwd=BENCHMARK, capture_output=True, text=True,
            )
            self.assertEqual(strict_validation.returncode, 0, strict_validation.stdout)
            self.assertEqual(json.loads(strict_validation.stdout)["complete_valid_runs"], 12)
            metrics_path = Path(tmp) / "independent_metrics.json"
            evaluation = subprocess.run(
                [sys.executable, "-m", "tools.enforcement.evaluate",
                 "--runs", str(out), "--out", str(metrics_path)],
                cwd=BENCHMARK, capture_output=True, text=True,
            )
            self.assertEqual(evaluation.returncode, 0, evaluation.stderr)
            independent_metrics = json.loads(metrics_path.read_text())
            self.assertEqual(independent_metrics["runs_total"], 12)
            self.assertEqual(
                independent_metrics,
                json.loads((out / "pilot_metrics.json").read_text()),
            )

    def test_s016_is_excluded_from_runtime_f1(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "s016"
            result = self.run_pilot(
                out, "--scenarios", "S-016", "--modes",
                "no_contract", "advisory", "guarded", "strict",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            metrics = json.loads((out / "pilot_metrics.json").read_text())
            self.assertIsNone(metrics["per_mode"]["no_contract"]["f1"])
            for mode in ("advisory", "guarded", "strict"):
                self.assertEqual(metrics["per_mode"][mode]["f1"], 0.0)

    def test_unknown_scenario_is_rejected_before_writing_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "unknown"
            result = self.run_pilot(out, "--scenarios", "S-999")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(list(out.glob("**/S-*")))

    def test_duplicate_selection_is_rejected_before_writing_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "duplicate"
            result = self.run_pilot(
                out, "--scenarios", "S-001", "S-001", "--modes", "guarded",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(list(out.glob("**/S-*")))


if __name__ == "__main__":
    unittest.main()
