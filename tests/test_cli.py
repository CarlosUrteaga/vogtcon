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
