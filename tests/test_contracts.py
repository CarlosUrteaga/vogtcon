# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import yaml
from pydantic import ValidationError

from vogtcon import (
    ActionProposal, EnforcementPolicy, ExecutionContext, Governor,
    JsonlDecisionLog, WorkflowController, load_contract,
)
from vogtcon.models import ContractRulesV2


def example_contract():
    return {
        "contract_id": "example.guarded", "mode": "guarded",
        "approved_agent_configurations": ["sha256:agent", {"fingerprint": "sha256:agent"}],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["answer"]},
        "memory_policy": "allowed-scope-only",
        "validation_phases": ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": ["sensitive_requires_approval"],
        "postconditions": ["run_ledger.required"],
        "agent_feedback": {
            "advisory_warning_visibility": False, "guarded_denial_style": "minimal",
            "strict_replanning_after_violation": False,
        },
        "contract_fingerprint": "sha256:stored",
    }


def v2_contract():
    return {
        "schema_version": 2,
        "contract_id": "example.v2",
        "approved_agent_configurations": ["sha256:agent"],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["answer"]},
        "memory_policy": "none",
        "validation_phases": ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": ["sensitive_requires_approval"],
        "postconditions": ["run_ledger.required"],
        "metadata": {"owner": "sí"},
        "contract_fingerprint": "sha256:5a92de44c4a3d327a2ada6e67a5cb56be3264477313285900daaaf90457776fa",
    }


class ContractLoadingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "contract.yaml"

    def load(self, text):
        self.path.write_text(text, encoding="utf-8")
        return load_contract(self.path)

    def test_public_v2_example_loads(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "notification_contract_v2.yaml"
        document = load_contract(path)
        self.assertIsInstance(document.contract, ContractRulesV2)
        self.assertNotIn("mode", document.original)

    def test_v2_loads_json_and_yaml_without_mode(self):
        data = v2_contract()
        for content in (
            json.dumps(data),
            yaml.safe_dump(data),
            "# comment and spacing do not affect parsed identity\n\n" + yaml.safe_dump(data),
            json.dumps(dict(reversed(list(data.items())))),
        ):
            with self.subTest(format=content[:20]):
                document = self.load(content)
                self.assertIsInstance(document.contract, ContractRulesV2)
                self.assertEqual(document.original, data)
                self.assertNotIn("mode", document.original)

    def test_loaded_v2_contract_runs_with_external_policy_and_records_mode(self):
        contract = self.load(yaml.safe_dump(v2_contract())).contract
        log = JsonlDecisionLog(self.path.parent / "events.jsonl")
        controller = WorkflowController(
            Governor(), "run-v2", contract, log,
            policy=EnforcementPolicy(mode="guarded"),
        )
        context = ExecutionContext(
            state={}, available_tools=["send_notification"],
            observed_agent_fingerprint="sha256:agent",
            observed_contract_fingerprint=contract.contract_fingerprint,
        )
        self.assertEqual(controller.begin(context).violations, [])
        effects = []
        proposal = ActionProposal(
            tool_name="send_notification", arguments={"sensitive": True},
        )
        blocked = controller.execute(
            proposal, context, lambda _a: effects.append("sent"),
        )
        self.assertEqual(blocked.decision.decision, "block")
        self.assertEqual(effects, [])
        approved = context.model_copy(update={"state": {"approval_granted": True}})
        self.assertTrue(controller.execute(
            proposal, approved, lambda _a: effects.append("sent"),
        ).executed)
        self.assertEqual(controller.finish(approved, {"answer": "ok"}, {}).violations, [])
        self.assertEqual(effects, ["sent"])
        events = log.read()
        self.assertTrue(all(event.mode == "guarded" for event in events))
        self.assertEqual([event.action_index for event in events], [None, 1, 2, 2, None])

    def test_v2_rejects_bad_fingerprint_rules_and_phases(self):
        for key, value, message in (
            ("contract_fingerprint", "sha256:wrong", "fingerprint mismatch"),
            ("metadata", {"owner": "changed"}, "fingerprint mismatch"),
            ("runtime_rules", ["unknown.rule"], "Unsupported"),
            ("validation_phases", ["runtime"], "all three"),
        ):
            with self.subTest(key=key):
                data = v2_contract()
                data[key] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.load(json.dumps(data))

    def test_v2_rejects_enforcement_fields_and_unknown_version(self):
        for key, value in (("mode", "guarded"), ("agent_feedback", {})):
            with self.subTest(key=key):
                data = v2_contract()
                data[key] = value
                with self.assertRaises(ValidationError):
                    self.load(json.dumps(data))
        data = v2_contract()
        data["schema_version"] = 3
        with self.assertRaisesRegex(ValueError, "schema_version"):
            self.load(json.dumps(data))

    def test_json_and_yaml_preserve_data_and_source(self):
        data = example_contract()
        data["metadata"] = {"label": "sí", "values": [None, True, 1.5]}
        data["approved_agent_configurations"].append({"fingerprint": "sha256:agent", "note": "duplicate"})
        for text in (json.dumps(data), yaml.safe_dump(data)):
            with self.subTest(format=text[:1]):
                document = self.load(text)
                self.assertEqual(document.original, data)
                self.assertEqual(document.contract.contract_fingerprint, "sha256:stored")
                self.assertEqual(self.path.read_text(), text)
                document.original["metadata"]["label"] = "modified"
                self.assertEqual(document.original, data)

    def test_json_scalar_semantics_take_precedence(self):
        data = example_contract()
        data["metadata"] = {"scientific": 1e20, "label": "on"}
        self.assertEqual(self.load(json.dumps(data)).original, data)

    def test_nonobject_and_invalid_documents(self):
        for text in ("", "[]", "null", "42", "a: [", '{"broken":', "!!python/object/apply:os.system ['false']"):
            with self.subTest(text=text), self.assertRaises((ValueError, yaml.YAMLError)):
                self.load(text)

    def test_non_json_yaml_values_rejected(self):
        for extra in ("date: 2026-11-10", "binary: !!binary SGVsbG8=", "number: .nan", "number: .inf", "map: {1: value}"):
            with self.subTest(extra=extra), self.assertRaises((ValueError, TypeError)):
                self.load(yaml.safe_dump(example_contract()) + extra + "\n")

    def test_shape_errors_and_missing_file_propagate(self):
        with self.assertRaises(ValidationError):
            self.load("mode: guarded\n")
        with self.assertRaises(FileNotFoundError):
            load_contract(self.path.parent / "absent.yaml")

    def test_unknown_and_wrong_phase_rules_rejected_in_all_modes(self):
        for mode in ("no_contract", "advisory", "guarded", "strict"):
            for field, rule in (("runtime_rules", "unknown"), ("runtime_rules", "run_ledger.required"),
                                ("postconditions", "unknown"), ("postconditions", "tool.declared_only")):
                with self.subTest(mode=mode, field=field, rule=rule):
                    data = example_contract()
                    data["mode"] = mode
                    data[field] = [rule]
                    with self.assertRaisesRegex(ValueError, "Unsupported"):
                        self.load(json.dumps(data))

    def test_enforced_modes_require_all_phases(self):
        for mode in ("advisory", "guarded", "strict"):
            for phases in ("not_enforced", [], ["runtime"]):
                with self.subTest(mode=mode, phases=phases):
                    data = example_contract()
                    data.update(mode=mode, validation_phases=phases)
                    with self.assertRaisesRegex(ValueError, "all three"):
                        self.load(json.dumps(data))

    def test_no_contract_accepts_not_enforced(self):
        data = example_contract()
        data.update(mode="no_contract", validation_phases="not_enforced", runtime_rules=[], postconditions=[])
        self.assertEqual(self.load(json.dumps(data)).original, data)

    def test_all_original_benchmark_contracts_load_without_rewriting(self):
        root = os.environ.get("GOVERNOR_BENCHMARK_ROOT")
        if not root:
            self.skipTest("Set GOVERNOR_BENCHMARK_ROOT for read-only compatibility checks")
        for mode in ("no_contract", "advisory", "guarded", "strict"):
            path = Path(root) / "contracts" / "enforcement" / f"{mode}.yaml"
            with self.subTest(mode=mode):
                before = path.read_bytes()
                self.assertEqual(load_contract(path).original, json.loads(before))
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
