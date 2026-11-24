# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Unit and integration tests for the vogtcon CLI."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from vogtcon.cli import (
    EXIT_EXPLAIN_INVALID_LOG,
    EXIT_EXPLAIN_RUN_NOT_FOUND,
    EXIT_EXPLAIN_SUCCESS,
    EXIT_EXPLAIN_USAGE_OR_IO,
    EXIT_INVALID,
    EXIT_UNSUPPORTED_RULES,
    EXIT_USAGE_OR_IO,
    EXIT_VALID,
    main,
)
from vogtcon.records import RunEvent


class TestCliValidate(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parent.parent
        self.notification_v1 = self.repo_root / "examples" / "notification_contract.yaml"
        self.notification_v2 = self.repo_root / "examples" / "notification_contract_v2.yaml"

    def run_cli(self, args: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(args)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_version(self) -> None:
        code, out, _ = self.run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("vogtcon", out)

    def test_validate_v1_contract_success(self) -> None:
        code, out, err = self.run_cli(["validate", str(self.notification_v1)])
        self.assertEqual(code, EXIT_VALID)
        self.assertIn("Contract is valid", out)
        self.assertIn("example.notification", out)
        self.assertIn("Schema Version: 1", out)
        self.assertEqual(err, "")

    def test_validate_v2_contract_success(self) -> None:
        code, out, err = self.run_cli(["validate", str(self.notification_v2)])
        self.assertEqual(code, EXIT_VALID)
        self.assertIn("Contract is valid", out)
        self.assertIn("example.notification", out)
        self.assertIn("Schema Version: 2", out)
        self.assertIn("(verified)", out)
        self.assertEqual(err, "")

    def test_validate_v2_fingerprint_mismatch(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(
                """schema_version: 2
contract_id: test.bad.fingerprint
approved_agent_configurations:
  - test-agent
declared_tools:
  - tool_a
response_schema:
  required_fields:
    - status
memory_policy: none
validation_phases:
  - pre_execution
  - runtime
  - post_execution
runtime_rules:
  - tool.declared_only
postconditions:
  - response.schema_complete
contract_fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
"""
            )
            bad_path = f.name

        try:
            code, out, err = self.run_cli(["validate", bad_path])
            self.assertEqual(code, EXIT_INVALID)
            self.assertIn("Contract validation failed", err)
            self.assertIn("Contract fingerprint mismatch", err)
        finally:
            Path(bad_path).unlink(missing_ok=True)

    def test_validate_unsupported_rules(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(
                """schema_version: 2
contract_id: test.custom.rule
approved_agent_configurations:
  - test-agent
declared_tools:
  - tool_a
response_schema:
  required_fields:
    - status
memory_policy: none
validation_phases:
  - pre_execution
  - runtime
  - post_execution
runtime_rules:
  - tool.declared_only
  - custom.unknown_rule
postconditions:
  - response.schema_complete
contract_fingerprint: sha256:0e44698dbc25559bacd44ac95f74fe4ad7bcbf1f3e2ed3a9f6cdb27ba556d6be
"""
            )
            custom_path = f.name

        try:
            code, out, err = self.run_cli(["validate", custom_path])
            self.assertEqual(code, EXIT_UNSUPPORTED_RULES)
            self.assertIn("Contract contains rules outside default catalog", err)
            self.assertIn("custom.unknown_rule", err)
        finally:
            Path(custom_path).unlink(missing_ok=True)

    def test_validate_nonexistent_file(self) -> None:
        code, out, err = self.run_cli(["validate", "/nonexistent/path/contract.yaml"])
        self.assertEqual(code, EXIT_USAGE_OR_IO)
        self.assertIn("Contract file not found", err)

    def test_validate_invalid_syntax(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("::invalid yaml content:: -- %%\n")
            invalid_path = f.name

        try:
            code, out, err = self.run_cli(["validate", invalid_path])
            self.assertEqual(code, EXIT_INVALID)
            self.assertIn("Contract validation failed", err)
        finally:
            Path(invalid_path).unlink(missing_ok=True)

    def test_validate_json_output(self) -> None:
        code, out, err = self.run_cli(["validate", str(self.notification_v2), "--json"])
        self.assertEqual(code, EXIT_VALID)
        self.assertEqual(err, "")
        data = json.loads(out)
        self.assertEqual(data["status"], "valid")
        self.assertEqual(data["contract_id"], "example.notification")
        self.assertEqual(data["schema_version"], 2)
        self.assertTrue(data["fingerprint"]["verified"])
        self.assertEqual(data["declared_tools"], ["send_notification"])
        self.assertIn("tool.declared_only", data["rules"]["runtime"])


class TestCliExplain(unittest.TestCase):
    def run_cli(self, args: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(args)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_explain_recovery_nominal_trace(self) -> None:
        events = [
            RunEvent(
                run_id="run-rec-1",
                sequence=1,
                contract_id="example.notification",
                mode="guarded",
                phase="pre_execution",
                event_type="decision",
                execution_status="not_started",
            ),
            RunEvent(
                run_id="run-rec-1",
                sequence=2,
                contract_id="example.notification",
                mode="guarded",
                phase="runtime",
                event_type="decision",
                action_index=1,
                tool_name="send_notification",
                decision="block",
                violation_rules=["sensitive_requires_approval"],
                execution_status="not_started",
            ),
            RunEvent(
                run_id="run-rec-1",
                sequence=3,
                contract_id="example.notification",
                mode="guarded",
                phase="runtime",
                event_type="decision",
                action_index=2,
                tool_name="send_notification",
                decision="allow",
                execution_status="not_started",
            ),
            RunEvent(
                run_id="run-rec-1",
                sequence=4,
                contract_id="example.notification",
                mode="guarded",
                phase="runtime",
                event_type="tool_completed",
                action_index=2,
                tool_name="send_notification",
                execution_status="completed",
            ),
            RunEvent(
                run_id="run-rec-1",
                sequence=5,
                contract_id="example.notification",
                mode="guarded",
                phase="post_execution",
                event_type="decision",
                execution_status="not_started",
            ),
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for ev in events:
                f.write(ev.model_dump_json() + "\n")
            log_path = f.name

        try:
            # Text output
            code, out, err = self.run_cli(["explain", log_path])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            self.assertIn("Run ID:    run-rec-1", out)
            self.assertIn("Integrity: complete", out)
            self.assertIn("Decision: BLOCK", out)
            self.assertIn("[RETRY]", out)
            self.assertIn("Proposed Actions:       2", out)
            self.assertIn("Blocked Actions:        1", out)
            self.assertIn("Allowed Actions:        1", out)
            self.assertIn("1 completed", out)
            self.assertEqual(err, "")

            # JSON output
            code, json_out, _ = self.run_cli(["explain", log_path, "--json"])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            data = json.loads(json_out)
            self.assertEqual(data["status"], "ok")
            self.assertEqual(len(data["runs"]), 1)
            run_data = data["runs"][0]
            self.assertEqual(run_data["trace_integrity"], "complete")
            self.assertEqual(run_data["summary"]["total_actions"], 2)
            self.assertEqual(run_data["summary"]["blocked_actions"], 1)
            self.assertEqual(run_data["summary"]["allowed_actions"], 1)
            self.assertEqual(run_data["summary"]["retried_actions"], 1)
            self.assertEqual(run_data["summary"]["completed_invocations"], 1)
            self.assertEqual(run_data["actions"][1]["is_retry"], True)
            self.assertEqual(run_data["actions"][1]["tool_outcome"], "completed")
        finally:
            Path(log_path).unlink(missing_ok=True)

    def test_explain_partial_trace(self) -> None:
        # Pre + runtime allow without tool_completed or post
        events = [
            RunEvent(
                run_id="part-1",
                sequence=1,
                contract_id="example.notification",
                mode="guarded",
                phase="pre_execution",
                event_type="decision",
                execution_status="not_started",
            ),
            RunEvent(
                run_id="part-1",
                sequence=2,
                contract_id="example.notification",
                mode="guarded",
                phase="runtime",
                event_type="decision",
                action_index=1,
                tool_name="send_notification",
                decision="allow",
                execution_status="not_started",
            ),
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for ev in events:
                f.write(ev.model_dump_json() + "\n")
            log_path = f.name

        try:
            code, out, err = self.run_cli(["explain", log_path])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            self.assertIn("Integrity: partial", out)
            self.assertIn("UNFINALIZED", out)
            self.assertIn("INDETERMINATE", out)

            code, json_out, _ = self.run_cli(["explain", log_path, "--json"])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            data = json.loads(json_out)
            run_data = data["runs"][0]
            self.assertEqual(run_data["trace_integrity"], "partial")
            self.assertEqual(run_data["summary"]["unfinalized_invocations"], 1)
            self.assertEqual(run_data["actions"][0]["tool_outcome"], "unfinalized")
        finally:
            Path(log_path).unlink(missing_ok=True)

    def test_explain_tool_error(self) -> None:
        events = [
            RunEvent(
                run_id="err-1",
                sequence=1,
                contract_id="example.notification",
                mode="guarded",
                phase="pre_execution",
                event_type="decision",
                execution_status="not_started",
            ),
            RunEvent(
                run_id="err-1",
                sequence=2,
                contract_id="example.notification",
                mode="guarded",
                phase="runtime",
                event_type="decision",
                action_index=1,
                tool_name="failing_tool",
                decision="allow",
                execution_status="not_started",
            ),
            RunEvent(
                run_id="err-1",
                sequence=3,
                contract_id="example.notification",
                mode="guarded",
                phase="runtime",
                event_type="tool_error",
                action_index=1,
                tool_name="failing_tool",
                execution_status="unknown",
            ),
            RunEvent(
                run_id="err-1",
                sequence=4,
                contract_id="example.notification",
                mode="guarded",
                phase="post_execution",
                event_type="decision",
                execution_status="not_started",
            ),
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for ev in events:
                f.write(ev.model_dump_json() + "\n")
            log_path = f.name

        try:
            code, out, _ = self.run_cli(["explain", log_path])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            self.assertIn("tool_error (execution failed with error)", out)

            code, json_out, _ = self.run_cli(["explain", log_path, "--json"])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            data = json.loads(json_out)
            run_data = data["runs"][0]
            self.assertEqual(run_data["summary"]["error_invocations"], 1)
            self.assertEqual(run_data["actions"][0]["tool_outcome"], "error")
        finally:
            Path(log_path).unlink(missing_ok=True)

    def test_explain_filter_by_run_id(self) -> None:
        events = [
            RunEvent(
                run_id="run-a",
                sequence=1,
                contract_id="c1",
                mode="guarded",
                phase="pre_execution",
                event_type="decision",
                execution_status="not_started",
            ),
            RunEvent(
                run_id="run-b",
                sequence=1,
                contract_id="c2",
                mode="guarded",
                phase="pre_execution",
                event_type="decision",
                execution_status="not_started",
            ),
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for ev in events:
                f.write(ev.model_dump_json() + "\n")
            log_path = f.name

        try:
            # Filter existing run-a
            code, out, _ = self.run_cli(["explain", log_path, "--run-id", "run-a"])
            self.assertEqual(code, EXIT_EXPLAIN_SUCCESS)
            self.assertIn("Run ID:    run-a", out)
            self.assertNotIn("Run ID:    run-b", out)

            # Filter non-existent run-c
            code, out, err = self.run_cli(["explain", log_path, "--run-id", "run-c"])
            self.assertEqual(code, EXIT_EXPLAIN_RUN_NOT_FOUND)
            self.assertIn("Run ID 'run-c' not found", err)
        finally:
            Path(log_path).unlink(missing_ok=True)

    def test_explain_invalid_log_format(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"arbitrary_benchmark_log": true, "message": "hello"}\n')
            bad_log = f.name

        try:
            code, out, err = self.run_cli(["explain", bad_log])
            self.assertEqual(code, EXIT_EXPLAIN_INVALID_LOG)
            self.assertIn("Invalid RunEvent schema: not a vogtcon decision log", err)
        finally:
            Path(bad_log).unlink(missing_ok=True)

    def test_explain_nonexistent_file(self) -> None:
        code, out, err = self.run_cli(["explain", "/nonexistent/log.jsonl"])
        self.assertEqual(code, EXIT_EXPLAIN_USAGE_OR_IO)
        self.assertIn("Log file not found", err)


if __name__ == "__main__":
    unittest.main()
