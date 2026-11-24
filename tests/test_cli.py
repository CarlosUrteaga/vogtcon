# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Unit and integration tests for the vogtcon CLI."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib.metadata import version
from pathlib import Path
from unittest.mock import patch

import yaml

from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    JsonlDecisionLog,
    RunEvent,
    WorkflowController,
)
from vogtcon.cli import (
    EXIT_INVALID,
    EXIT_UNSUPPORTED_RULES,
    EXIT_USAGE_OR_IO,
    EXIT_VALID,
    main,
)


class TestCliValidate(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parent.parent
        self.notification_v1 = self.repo_root / "examples" / "notification_contract.yaml"
        self.notification_v2 = self.repo_root / "examples" / "notification_contract_v2.yaml"
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.contract_path = Path(workspace.name) / "contract.yaml"

    def run_cli(self, args: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(args)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_version(self) -> None:
        self.assertEqual(self.run_cli(["--version"]), (0, f"vogtcon {version('vogtcon')}\n", ""))

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
            f.write("sample: [\n")
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
        result = json.loads(out)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["output_version"], 1)
        self.assertEqual(result["command"], "validate")
        self.assertEqual(result["path"], str(self.notification_v2))
        self.assertEqual(result["diagnostics"], [])
        data = result["data"]
        self.assertEqual(data["contract_id"], "example.notification")
        self.assertEqual(data["contract_version"], 2)
        self.assertIsNone(data["mode"])
        self.assertTrue(data["fingerprint"]["verified"])
        self.assertEqual(data["declared_tools"], ["send_notification"])
        self.assertIn("tool.declared_only", data["runtime_rules"])

    def test_formats_and_legacy_fingerprint(self) -> None:
        for fixture, contract_version in ((self.notification_v1, 1), (self.notification_v2, 2)):
            contract = yaml.safe_load(fixture.read_text(encoding="utf-8"))
            for dump in (yaml.safe_dump, json.dumps):
                with self.subTest(version=contract_version, format=dump.__name__):
                    self.contract_path.write_text(dump(contract), encoding="utf-8")
                    code, out, err = self.run_cli(["validate", str(self.contract_path), "--json"])
                    self.assertEqual((code, err), (0, ""))
                    data = json.loads(out)["data"]
                    self.assertEqual(data["contract_version"], contract_version)
                    self.assertEqual(data["mode"], contract.get("mode"))
                    self.assertEqual(data["fingerprint"], {
                        "value": contract["contract_fingerprint"],
                        "verified": contract_version == 2,
                    })
                    self.assertEqual(data["validation_phases"], contract["validation_phases"])

    def test_legacy_no_contract_preserves_not_enforced(self) -> None:
        contract = yaml.safe_load(self.notification_v1.read_text(encoding="utf-8"))
        contract.update(mode="no_contract", validation_phases="not_enforced")
        self.contract_path.write_text(json.dumps(contract), encoding="utf-8")
        code, out, err = self.run_cli(["validate", str(self.contract_path), "--json"])
        self.assertEqual((code, err), (0, ""))
        validation = json.loads(out)["data"]
        self.assertEqual(validation["validation_phases"], "not_enforced")
        self.assertFalse(validation["fingerprint"]["verified"])
        code, out, err = self.run_cli(["validate", str(self.contract_path)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("not_enforced", out)
        self.assertIn("not verified", out)

    def test_validation_failures_omit_raw_input(self) -> None:
        contract = yaml.safe_load(self.notification_v2.read_text(encoding="utf-8"))
        for overrides in (
            {"schema_version": 1}, {"schema_version": 3}, {"schema_version": 2.0},
            {"schema_version": "2"}, {"validation_phases": ["runtime"]},
            {"contract_fingerprint": "sha256:stale"},
            {"declared_tools": {"private-fixture-value": True}},
        ):
            with self.subTest(overrides=overrides):
                self.contract_path.write_text(json.dumps({**contract, **overrides}), encoding="utf-8")
                code, out, err = self.run_cli(["validate", str(self.contract_path), "--json"])
                self.assertEqual((code, err), (1, ""))
                result = json.loads(out)
                self.assertEqual(result["status"], "invalid_contract")
                self.assertIsNone(result["data"])
                self.assertEqual(result["diagnostics"][0]["code"], "invalid_contract")
                self.assertNotIn("private-fixture-value", out)

    def test_catalog_error_precedes_phases_and_fingerprint(self) -> None:
        contract = yaml.safe_load(self.notification_v2.read_text(encoding="utf-8"))
        contract.update(
            runtime_rules=["custom.z", "custom.a", "custom.z", "response.schema_complete"],
            postconditions=["custom.post"],
            validation_phases=["runtime"],
            contract_fingerprint="sha256:stale",
        )
        for field, ids in (
            ("runtime_rules", ["custom.a", "custom.z", "response.schema_complete"]),
            ("postconditions", ["custom.post"]),
        ):
            with self.subTest(field=field):
                self.contract_path.write_text(json.dumps(contract), encoding="utf-8")
                code, out, err = self.run_cli(["validate", str(self.contract_path), "--json"])
                self.assertEqual((code, err), (2, ""))
                result = json.loads(out)
                self.assertEqual(result["status"], "unsupported_rules")
                self.assertEqual(result["data"], {"field": field, "unsupported_ids": ids})
                self.assertEqual(result["diagnostics"][0]["code"], "unsupported_rule")
                self.assertNotIn("fingerprint", out)
                contract["runtime_rules"] = ["tool.declared_only"]

    def test_read_errors_use_json_diagnostics(self) -> None:
        for path in (self.contract_path, self.contract_path.parent):
            with self.subTest(path=path):
                code, out, err = self.run_cli(["validate", str(path), "--json"])
                self.assertEqual((code, err), (3, ""))
                result = json.loads(out)
                self.assertEqual(result["status"], "io_error")
                self.assertEqual(result["diagnostics"][0]["code"], "io_error")
        with patch("vogtcon.cli.load_contract", side_effect=PermissionError()):
            code, out, err = self.run_cli(["validate", str(self.notification_v1), "--json"])
        self.assertEqual((code, err), (3, ""))
        self.assertEqual(json.loads(out)["status"], "io_error")

    def test_stable_output_keeps_original_path_and_file_bytes(self) -> None:
        original = self.notification_v2.read_bytes()
        self.contract_path.write_bytes(original)
        path = f"{self.contract_path.parent}/./{self.contract_path.name}"
        args = ["validate", path, "--json"]
        first = self.run_cli(args)
        self.assertEqual(first, self.run_cli(args))
        self.assertEqual(first[0], 0)
        self.assertEqual(json.loads(first[1])["path"], path)
        self.assertEqual(self.contract_path.read_bytes(), original)

    def test_help_and_usage_exit_codes(self) -> None:
        for args in (["--help"], ["validate", "--help"]):
            with self.subTest(args=args):
                code, out, err = self.run_cli(args)
                self.assertEqual((code, err), (0, ""))
                self.assertIn("usage: vogtcon", out)
        for args in ([], ["validate"], ["validate", "--json"],
                     ["validate", str(self.notification_v2), "--unknown"]):
            with self.subTest(args=args):
                code, out, err = self.run_cli(args)
                self.assertEqual((code, out), (3, ""))
                self.assertIn("usage: vogtcon", err)


class TestCliExplain(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parent.parent
        self.notification_v2 = self.repo_root / "examples" / "notification_contract_v2.yaml"
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.log_path = Path(workspace.name) / "decisions.jsonl"

    def run_cli(self, args: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(args)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def _context(self, contract_fingerprint: str, *, approved: bool) -> ExecutionContext:
        return ExecutionContext(
            state={"approval_granted": approved},
            available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint=contract_fingerprint,
        )

    def _sensitive_proposal(self) -> ActionProposal:
        return ActionProposal(
            tool_name="send_notification",
            arguments={"message": "hi", "sensitive": True},
        )

    def test_explain_nominal_controller_trace_e1(self) -> None:
        recorder = JsonlDecisionLog(self.log_path)
        controller = WorkflowController.from_contract_path(
            self.notification_v2,
            "demo",
            policy=EnforcementPolicy(mode="guarded"),
            recorder=recorder,
        )
        fp = controller.contract.contract_fingerprint
        unapproved = self._context(fp, approved=False)
        approved = self._context(fp, approved=True)

        self.assertEqual(controller.begin(unapproved).violations, [])
        blocked = controller.execute(self._sensitive_proposal(), unapproved, lambda _p: "sent")
        self.assertFalse(blocked.executed)
        self.assertEqual(blocked.decision.decision, "block")

        allowed = controller.execute(self._sensitive_proposal(), approved, lambda _p: "sent")
        self.assertTrue(allowed.executed)
        self.assertEqual(allowed.decision.decision, "allow")
        self.assertEqual(controller.finish(approved, {"status": "sent"}).violations, [])

        original_bytes = self.log_path.read_bytes()

        # JSON output
        code, out, err = self.run_cli(["explain", str(self.log_path), "--run-id", "demo", "--json"])
        self.assertEqual((code, err), (0, ""))
        result = json.loads(out)
        self.assertEqual(result["output_version"], 1)
        self.assertEqual(result["command"], "explain")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["path"], str(self.log_path))
        self.assertEqual(result["diagnostics"], [])
        self.assertEqual(len(result["data"]["runs"]), 1)

        run = result["data"]["runs"][0]
        self.assertEqual(run["run_id"], "demo")
        self.assertEqual(run["contract_id"], "example.notification")
        self.assertEqual(run["mode"], "guarded")
        self.assertEqual(run["trace_integrity"], "complete")
        self.assertEqual(run["terminal"], "post_execution")
        self.assertEqual(run["pre_execution"], {"sequence": 1, "decision": None, "violation_rules": []})
        self.assertEqual(run["post_execution"], {"sequence": 5, "decision": None, "violation_rules": []})
        self.assertEqual(
            run["actions"],
            [
                {
                    "action_index": 1,
                    "tool_name": "send_notification",
                    "decision": "block",
                    "decision_sequence": 2,
                    "tool_event_sequence": None,
                    "violation_rules": ["sensitive_requires_approval"],
                    "prior_same_tool_block_action_index": None,
                    "tool_outcome": "prevented",
                    "effect_evidence": "prevented_by_recorded_decision",
                },
                {
                    "action_index": 2,
                    "tool_name": "send_notification",
                    "decision": "allow",
                    "decision_sequence": 3,
                    "tool_event_sequence": 4,
                    "violation_rules": [],
                    "prior_same_tool_block_action_index": 1,
                    "tool_outcome": "completed",
                    "effect_evidence": "not_verified",
                },
            ],
        )
        self.assertEqual(
            run["counts"],
            {"prevented": 1, "completed": 1, "error": 0, "unfinalized": 0, "unknown": 0},
        )

        # Human output
        code_txt, out_txt, err_txt = self.run_cli(["explain", str(self.log_path), "--run-id", "demo"])
        self.assertEqual((code_txt, err_txt), (0, ""))
        for token in (
            "demo",
            "guarded",
            "example.notification",
            "pre_execution",
            "send_notification",
            "block",
            "sensitive_requires_approval",
            "allow",
            "action 1",
            "tool_completed",
            "post_execution",
        ):
            self.assertIn(token, out_txt)
        self.assertNotIn("authorized by host", out_txt.lower())
        self.assertNotIn("recovered via retry", out_txt.lower())
        self.assertEqual(self.log_path.read_bytes(), original_bytes)

    def test_explain_advisory_allow_with_warning(self) -> None:
        recorder = JsonlDecisionLog(self.log_path)
        controller = WorkflowController.from_contract_path(
            self.notification_v2,
            "adv-run",
            policy=EnforcementPolicy(mode="advisory"),
            recorder=recorder,
        )
        unapproved = self._context(controller.contract.contract_fingerprint, approved=False)
        self.assertEqual(controller.begin(unapproved).violations, [])
        outcome = controller.execute(self._sensitive_proposal(), unapproved, lambda _p: "sent")
        self.assertTrue(outcome.executed)
        self.assertEqual(outcome.decision.decision, "allow_with_warning")
        controller.finish(unapproved, {"status": "sent"})

        code, out, err = self.run_cli(["explain", str(self.log_path), "--json"])
        self.assertEqual((code, err), (0, ""))
        run = json.loads(out)["data"]["runs"][0]
        self.assertEqual(run["trace_integrity"], "complete")
        self.assertEqual(run["terminal"], "post_execution")
        self.assertEqual(run["counts"]["completed"], 1)
        action = run["actions"][0]
        self.assertEqual(action["decision"], "allow_with_warning")
        self.assertEqual(action["violation_rules"], ["sensitive_requires_approval"])
        self.assertEqual(action["tool_outcome"], "completed")
        self.assertEqual(action["effect_evidence"], "not_verified")

    def test_explain_interleaved_runs_and_run_id_filter_e6(self) -> None:
        events = [
            RunEvent(
                run_id="run-alpha", sequence=1, contract_id="c1", mode="guarded",
                phase="pre_execution", event_type="decision",
            ),
            RunEvent(
                run_id="run-beta", sequence=1, contract_id="c2", mode="guarded",
                phase="pre_execution", event_type="decision",
            ),
            RunEvent(
                run_id="run-alpha", sequence=2, contract_id="c1", mode="guarded",
                phase="runtime", event_type="decision", action_index=1,
                tool_name="tool_a", decision="block", violation_rules=["rule.a"],
            ),
            RunEvent(
                run_id="run-beta", sequence=2, contract_id="c2", mode="guarded",
                phase="runtime", event_type="decision", action_index=1,
                tool_name="tool_b", decision="allow",
            ),
            RunEvent(
                run_id="run-alpha", sequence=3, contract_id="c1", mode="guarded",
                phase="post_execution", event_type="decision",
            ),
            RunEvent(
                run_id="run-beta", sequence=3, contract_id="c2", mode="guarded",
                phase="runtime", event_type="tool_completed", action_index=1,
                tool_name="tool_b", execution_status="completed",
            ),
            RunEvent(
                run_id="run-beta", sequence=4, contract_id="c2", mode="guarded",
                phase="post_execution", event_type="decision",
            ),
        ]
        self.log_path.write_text(
            "\n".join(ev.model_dump_json() for ev in events) + "\n",
            encoding="utf-8",
        )

        # Without --run-id: both runs in order of first appearance, no mixing
        code, out, err = self.run_cli(["explain", str(self.log_path), "--json"])
        self.assertEqual((code, err), (0, ""))
        runs = json.loads(out)["data"]["runs"]
        self.assertEqual([r["run_id"] for r in runs], ["run-alpha", "run-beta"])
        self.assertEqual(runs[0]["counts"]["prevented"], 1)
        self.assertEqual(runs[0]["counts"]["completed"], 0)
        self.assertEqual(runs[1]["counts"]["prevented"], 0)
        self.assertEqual(runs[1]["counts"]["completed"], 1)

        # With --run-id run-beta
        code, out, err = self.run_cli(["explain", str(self.log_path), "--run-id", "run-beta", "--json"])
        self.assertEqual((code, err), (0, ""))
        filtered_runs = json.loads(out)["data"]["runs"]
        self.assertEqual(len(filtered_runs), 1)
        self.assertEqual(filtered_runs[0]["run_id"], "run-beta")

        # With unknown --run-id (JSON & human)
        code, out, err = self.run_cli(["explain", str(self.log_path), "--run-id", "unknown-run", "--json"])
        self.assertEqual((code, err), (2, ""))
        res = json.loads(out)
        self.assertEqual(res["status"], "run_not_found")
        self.assertIsNone(res["data"])
        self.assertEqual(res["diagnostics"][0]["code"], "run_not_found")
        self.assertEqual(res["diagnostics"][0]["run_id"], "unknown-run")
        self.assertIsNone(res["diagnostics"][0]["line"])

        code_h, out_h, err_h = self.run_cli(["explain", str(self.log_path), "--run-id", "unknown-run"])
        self.assertEqual((code_h, out_h), (2, ""))
        self.assertIn("unknown-run", err_h)

        # Interleaved inconsistent run outside filter does not invalidate selected run
        broken_events = [
            RunEvent(
                run_id="run-broken", sequence=1, contract_id="c3", mode="guarded",
                phase="pre_execution", event_type="decision",
            ),
            RunEvent(
                run_id="run-broken", sequence=1, contract_id="c3", mode="guarded",
                phase="post_execution", event_type="decision",
            ),
        ]
        with self.log_path.open("a", encoding="utf-8") as fh:
            for ev in broken_events:
                fh.write(ev.model_dump_json() + "\n")

        code_f, out_f, err_f = self.run_cli(["explain", str(self.log_path), "--run-id", "run-alpha", "--json"])
        self.assertEqual((code_f, err_f), (0, ""))
        res_f = json.loads(out_f)
        self.assertEqual(res_f["status"], "ok")
        self.assertEqual([r["run_id"] for r in res_f["data"]["runs"]], ["run-alpha"])

    def test_explain_help_usage_io_and_determinism_g1(self) -> None:
        code, out, err = self.run_cli(["explain", "--help"])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("usage: vogtcon explain", out)

        for args in (
            ["explain"],
            ["explain", "--json"],
            ["explain", str(self.log_path), "--run-id"],
            ["explain", str(self.log_path), "--unknown"],
        ):
            with self.subTest(args=args):
                code, out, err = self.run_cli(args)
                self.assertEqual((code, out), (3, ""))
                self.assertIn("usage: vogtcon", err)

        # IO errors with --json
        for path in (self.log_path, self.log_path.parent):
            with self.subTest(path=path):
                code, out, err = self.run_cli(["explain", str(path), "--json"])
                self.assertEqual((code, err), (3, ""))
                res = json.loads(out)
                self.assertEqual(res["output_version"], 1)
                self.assertEqual(res["command"], "explain")
                self.assertEqual(res["status"], "io_error")
                self.assertIsNone(res["data"])
                self.assertEqual(res["diagnostics"][0]["code"], "io_error")

        self.log_path.write_text("", encoding="utf-8")
        real_open = Path.open

        def deny_log(path_self: Path, *args: object, **kwargs: object) -> object:
            if path_self == self.log_path:
                raise PermissionError("permission denied")
            return real_open(path_self, *args, **kwargs)  # type: ignore[arg-type]

        with patch.object(Path, "open", autospec=True, side_effect=deny_log):
            code, out, err = self.run_cli(["explain", str(self.log_path), "--json"])
        self.assertEqual((code, err), (3, ""))
        self.assertEqual(json.loads(out)["status"], "io_error")

        # Determinism and path preservation
        ev = RunEvent(
            run_id="det-1", sequence=1, contract_id="c1", mode="guarded",
            phase="pre_execution", event_type="decision",
        )
        raw = (ev.model_dump_json() + "\n").encode("utf-8")
        self.log_path.write_bytes(raw)
        dotted_path = f"{self.log_path.parent}/./{self.log_path.name}"
        first = self.run_cli(["explain", dotted_path, "--json"])
        self.assertEqual(first, self.run_cli(["explain", dotted_path, "--json"]))
        self.assertEqual(first[0], 0)
        self.assertEqual(json.loads(first[1])["path"], dotted_path)
        self.assertEqual(self.log_path.read_bytes(), raw)
