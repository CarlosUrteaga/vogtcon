# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import unittest
from copy import deepcopy
from pathlib import Path

from pydantic import ValidationError

from vogtcon import (
    ActionProposal,
    AgentContract,
    ContractDocument,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    GovernorInput,
    Violation,
)
from vogtcon.models import ContractRulesV2


def contract_data(mode: str = "guarded") -> dict:
    """Small in-memory example; never materialize or write benchmark fixtures."""
    return {
        "contract_id": f"enforcement.{mode}.v2",
        "mode": mode,
        "approved_agent_configurations": [
            "sha256:example-agent",
            {"fingerprint": "sha256:example-agent"},
        ],
        "declared_tools": ["*"] if mode == "no_contract" else ["send_notification"],
        "response_schema": {"required_fields": ["answer", "citations", "status"]},
        "memory_policy": "allowed-scope-only",
        "validation_phases": "not_enforced" if mode == "no_contract" else [
            "pre_execution", "runtime", "post_execution"
        ],
        "runtime_rules": [] if mode == "no_contract" else ["sensitive_requires_approval"],
        "postconditions": [] if mode == "no_contract" else ["run_ledger.required"],
        "agent_feedback": {
            "advisory_warning_visibility": False,
            "guarded_denial_style": "minimal",
            "strict_replanning_after_violation": False,
        },
        "contract_fingerprint": "sha256:example-contract",
    }


def v2_contract_data() -> dict:
    data = contract_data()
    del data["mode"]
    del data["agent_feedback"]
    data["schema_version"] = 2
    return data


def input_data(phase: str = "runtime") -> dict:
    data = {
        "run_id": "run-1",
        "contract": contract_data(),
        "phase": phase,
        "context": {"state": {"user_role": "employee"}, "available_tools": ["send_notification"]},
    }
    if phase == "runtime":
        data["action"] = {"tool_name": "send_notification", "arguments": {"sensitive": True}}
    elif phase == "pre_execution":
        data["context"].update(
            observed_agent_fingerprint="sha256:observed-agent",
            observed_contract_fingerprint="sha256:observed-contract",
        )
    elif phase == "post_execution":
        data["response"] = {}
    return data


class ContractModelTests(unittest.TestCase):
    def test_policy_binding_requires_v2_mode_and_rejects_v1_conflict(self):
        data = input_data()
        data["contract"] = v2_contract_data()
        data["contract"]["metadata"] = {}
        with self.assertRaisesRegex(ValidationError, "require an enforcement policy"):
            GovernorInput.model_validate(data)
        data["policy"] = {"mode": "advisory"}
        request = GovernorInput.model_validate(data)
        self.assertEqual(request.effective_mode, "advisory")
        self.assertEqual(request.contract.model_dump(), data["contract"])

        data["contract"] = contract_data("guarded")
        with self.assertRaisesRegex(ValidationError, "conflicts with legacy"):
            GovernorInput.model_validate(data)
        data["policy"] = {"mode": "guarded"}
        self.assertEqual(GovernorInput.model_validate(data).effective_mode, "guarded")

        data["policy"] = {"mode": "invalid"}
        with self.assertRaises(ValidationError):
            GovernorInput.model_validate(data)

    def test_legacy_request_dump_has_no_new_policy_field(self):
        request = GovernorInput.model_validate(input_data())
        self.assertNotIn("policy", request.model_dump())
        self.assertNotIn('"policy"', request.model_dump_json())

    def test_direct_input_cannot_reinterpret_malformed_v2_as_legacy(self):
        data = input_data()
        data["contract"]["schema_version"] = 2
        data["policy"] = {"mode": "guarded"}
        with self.assertRaises(ValidationError):
            GovernorInput.model_validate(data)
        legacy_with_version = AgentContract.model_validate(data["contract"])
        data["contract"] = legacy_with_version
        with self.assertRaisesRegex(ValidationError, "schema_version"):
            GovernorInput.model_validate(data)

    def test_v2_rules_have_no_enforcement_mode(self):
        data = v2_contract_data()
        data["metadata"] = {"owner": "example", "values": [None, True, 3]}
        model = ContractRulesV2.model_validate(data)
        self.assertEqual(data, model.model_dump())
        self.assertFalse(hasattr(model, "mode"))

    def test_v2_rejects_enforcement_fields_and_wrong_version(self):
        for key, value in (
            ("mode", "guarded"),
            ("agent_feedback", {"guarded_denial_style": "minimal"}),
            ("schema_version", 1),
            ("schema_version", "2"),
            ("schema_version", True),
            ("runtime_ruless", []),
        ):
            with self.subTest(key=key, value=value):
                data = v2_contract_data()
                data[key] = value
                with self.assertRaises(ValidationError):
                    ContractRulesV2.model_validate(data)

    def test_contract_document_dispatches_versions_and_preserves_original(self):
        legacy = contract_data()
        self.assertIsInstance(ContractDocument(legacy).contract, AgentContract)

        data = v2_contract_data()
        data["metadata"] = {"nested": ["original"]}
        document = ContractDocument(data)
        self.assertIsInstance(document.contract, ContractRulesV2)
        data["metadata"]["nested"].append("changed")
        document.contract.metadata["nested"].append("model")
        returned = document.original
        returned["metadata"]["nested"].append("returned")
        self.assertEqual(["original"], document.original["metadata"]["nested"])

    def test_contract_document_rejects_unsupported_versions(self):
        for version in (None, 1, 3, "2", 2.0, True):
            with self.subTest(version=version):
                data = v2_contract_data()
                data["schema_version"] = version
                with self.assertRaisesRegex(ValueError, "schema_version"):
                    ContractDocument(data)

    def test_existing_modes_and_alternative_shapes(self):
        for mode in ("no_contract", "advisory", "guarded", "strict"):
            with self.subTest(mode=mode):
                data = contract_data(mode)
                model = AgentContract.model_validate(data)
                self.assertEqual(data, model.model_dump())
                self.assertEqual(data, AgentContract.model_validate_json(json.dumps(data)).model_dump())

    def test_required_contract_fields_cannot_be_omitted(self):
        for key in contract_data():
            with self.subTest(key=key):
                data = contract_data()
                del data[key]
                with self.assertRaises(ValidationError):
                    AgentContract.model_validate(data)

    def test_contract_does_not_coerce_invalid_types(self):
        for key, value in (
            ("mode", "unknown"), ("contract_id", 123),
            ("declared_tools", "send_notification"),
            ("runtime_rules", ("sensitive_requires_approval",)),
            ("validation_phases", ["unknown"]),
            ("approved_agent_configurations", [{}]),
        ):
            with self.subTest(key=key, value=value):
                data = contract_data()
                data[key] = value
                with self.assertRaises(ValidationError):
                    AgentContract.model_validate(data)

    def test_feedback_boolean_is_not_coerced(self):
        for value in ("false", 0, None):
            with self.subTest(value=value):
                data = contract_data()
                data["agent_feedback"]["advisory_warning_visibility"] = value
                with self.assertRaises(ValidationError):
                    AgentContract.model_validate(data)

    def test_rule_resolution_is_not_schema_validation(self):
        data = contract_data()
        data["runtime_rules"] = ["future.rule"]
        self.assertEqual(["future.rule"], AgentContract.model_validate(data).runtime_rules)

    def test_contract_metadata_and_duplicates_are_preserved(self):
        data = contract_data()
        data["metadata"] = {"owner": "example", "values": [None, True, 3]}
        data["approved_agent_configurations"].append(deepcopy(data["approved_agent_configurations"][1]))
        data["response_schema"]["description"] = "legacy metadata"
        self.assertEqual(data, AgentContract.model_validate(data).model_dump())

    def test_original_snapshot_is_independent_of_input_model_and_returned_copy(self):
        data = contract_data()
        expected = deepcopy(data)
        document = ContractDocument(data)
        data["approved_agent_configurations"].clear()
        document.contract.approved_agent_configurations.clear()
        returned = document.original
        returned["approved_agent_configurations"].clear()
        self.assertEqual(expected, document.original)
        self.assertEqual("sha256:example-contract", document.original["contract_fingerprint"])

    def test_original_snapshot_preserves_key_order_and_omitted_keys(self):
        data = contract_data()
        data["extra_metadata"] = {"z": 1, "a": 2}
        document = ContractDocument(data)
        self.assertEqual(list(data), list(document.original))
        self.assertEqual(["z", "a"], list(document.original["extra_metadata"]))
        self.assertNotIn("schema_version", document.original)
        self.assertEqual(data, document.original)

    def test_invalid_contract_has_no_document_wrapper(self):
        with self.assertRaises(ValidationError):
            ContractDocument({"mode": "guarded"})


class EvaluationModelTests(unittest.TestCase):
    def test_required_evaluation_fields_cannot_be_omitted(self):
        for key in ("run_id", "contract", "phase", "context"):
            with self.subTest(key=key):
                data = input_data()
                del data[key]
                with self.assertRaises(ValidationError):
                    GovernorInput.model_validate(data)

    def test_all_evaluation_phases_have_valid_inputs(self):
        for phase in ("pre_execution", "runtime", "post_execution"):
            with self.subTest(phase=phase):
                model = GovernorInput.model_validate(input_data(phase))
                self.assertEqual(phase, model.phase)
                self.assertEqual(model, GovernorInput.model_validate_json(model.model_dump_json()))

    def test_runtime_requires_an_action(self):
        data = input_data()
        del data["action"]
        with self.assertRaises(ValidationError):
            GovernorInput.model_validate(data)

    def test_pre_execution_requires_observed_fingerprints(self):
        for key in ("observed_agent_fingerprint", "observed_contract_fingerprint"):
            with self.subTest(key=key):
                data = input_data("pre_execution")
                del data["context"][key]
                with self.assertRaises(ValidationError):
                    GovernorInput.model_validate(data)

    def test_tampered_fingerprint_is_evidence_not_a_schema_error(self):
        data = input_data("pre_execution")
        data["context"]["observed_agent_fingerprint"] = "sha256:tampered-agent-config-v2"
        self.assertEqual("sha256:tampered-agent-config-v2", GovernorInput.model_validate(data).context.observed_agent_fingerprint)

    def test_incomplete_response_and_ledgers_can_reach_the_evaluator(self):
        for ledger in (None, {}, {"run_id": "run-1"}):
            with self.subTest(ledger=ledger):
                data = input_data("post_execution")
                data["response"] = {"answer": "incomplete"}
                data["run_ledger"] = ledger
                result = GovernorInput.model_validate(data)
                self.assertEqual(ledger, result.run_ledger)
                self.assertEqual({"answer": "incomplete"}, result.response)

    def test_post_execution_requires_a_response_mapping(self):
        for value in (None, "answer", []):
            with self.subTest(value=value):
                data = input_data("post_execution")
                data["response"] = value
                with self.assertRaises(ValidationError):
                    GovernorInput.model_validate(data)

    def test_phase_payloads_cannot_be_mixed(self):
        for phase, key, value in (
            ("pre_execution", "action", {"tool_name": "send_notification"}),
            ("post_execution", "action", {"tool_name": "send_notification"}),
            ("runtime", "response", {}),
            ("runtime", "run_ledger", {}),
        ):
            with self.subTest(phase=phase, key=key):
                data = input_data(phase)
                data[key] = value
                with self.assertRaises(ValidationError):
                    GovernorInput.model_validate(data)

    def test_operation_fields_reject_typos(self):
        with self.assertRaises(ValidationError):
            ActionProposal(tool_name="send_notification", argumments={})
        with self.assertRaises(ValidationError):
            ExecutionContext(state={}, available_tools=[], user_role="admin")

    def test_iteration_is_a_positive_integer_without_coercion(self):
        for value in (True, "1", 0, -1, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    ActionProposal(tool_name="send_notification", iteration=value)

    def test_state_is_not_merged_with_agent_arguments(self):
        data = input_data()
        data["action"]["arguments"]["user_role"] = "admin"
        model = GovernorInput.model_validate(data)
        self.assertEqual("employee", model.context.state["user_role"])
        self.assertEqual("admin", model.action.arguments["user_role"])

    def test_payloads_are_json_values(self):
        for value in (object(), {1, 2}, float("nan"), float("inf")):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ValidationError):
                    ActionProposal(tool_name="send_notification", arguments={"value": value})

    def test_defaults_are_not_shared_between_instances(self):
        first = ActionProposal(tool_name="send_notification")
        second = ActionProposal(tool_name="send_notification")
        first.arguments["sensitive"] = True
        self.assertEqual({}, second.arguments)

    def test_fields_cannot_be_reassigned(self):
        action = ActionProposal(tool_name="send_notification")
        with self.assertRaises(ValidationError):
            action.tool_name = "approve_request"


class DecisionModelTests(unittest.TestCase):
    def test_preserves_all_historical_runtime_decision_names(self):
        for decision in ("allow", "allow_with_warning", "block", "abort"):
            with self.subTest(decision=decision):
                result = GovernanceDecision(phase="runtime", decision=decision, violations=[])
                self.assertEqual(decision, result.model_dump()["decision"])

    def test_no_implicit_allow(self):
        with self.assertRaises(ValidationError):
            GovernanceDecision(phase="runtime", violations=[])

    def test_unsupported_decisions_are_rejected(self):
        for decision in ("warn", "modify", "pause", "replan", "ALLOW", ""):
            with self.subTest(decision=decision):
                with self.assertRaises(ValidationError):
                    GovernanceDecision(phase="runtime", decision=decision, violations=[])

    def test_pre_and_post_results_do_not_reuse_tool_decisions(self):
        for phase in ("pre_execution", "post_execution"):
            with self.subTest(phase=phase):
                self.assertIsNone(GovernanceDecision(phase=phase, violations=[]).decision)
                with self.assertRaises(ValidationError):
                    GovernanceDecision(phase=phase, violations=[], decision="block")

    def test_violation_phase_must_match_the_result(self):
        with self.assertRaises(ValidationError):
            GovernanceDecision(phase="runtime", decision="block", violations=[
                Violation(rule="run_ledger.required", phase="post_execution")
            ])

    def test_advisory_decision_can_include_violations(self):
        result = GovernanceDecision(phase="runtime", decision="allow_with_warning", violations=[
            Violation(rule="sensitive_requires_approval", phase="runtime", action="send_notification")
        ])
        self.assertEqual("high", result.violations[0].severity)
        self.assertEqual(result, GovernanceDecision.model_validate_json(result.model_dump_json()))


class BenchmarkContractCompatibilityTests(unittest.TestCase):
    """Optional read-only integration; never import the benchmark test suite.

Set GOVERNOR_BENCHMARK_ROOT to a checkout to run these checks. Unit tests above
remain independent of that checkout and of any developer-specific path.
"""

    @classmethod
    def setUpClass(cls):
        root = os.environ.get("GOVERNOR_BENCHMARK_ROOT")
        if not root:
            raise unittest.SkipTest("set GOVERNOR_BENCHMARK_ROOT for read-only contract compatibility")
        cls.root = Path(root)

    def check_contract(self, mode):
        path = self.root / "contracts" / "enforcement" / f"{mode}.yaml"
        before = path.read_bytes()
        data = json.loads(before)
        document = ContractDocument(data)
        self.assertEqual(mode, document.contract.mode)
        self.assertEqual(data, document.original)
        self.assertEqual(data, document.contract.model_dump())
        self.assertEqual(len(data["approved_agent_configurations"]), len(document.contract.approved_agent_configurations))
        self.assertEqual(data["contract_fingerprint"], document.contract.contract_fingerprint)
        payload = {k: v for k, v in data.items() if k != "contract_fingerprint"}
        preserved = {k: v for k, v in document.original.items() if k != "contract_fingerprint"}
        def digest(value):
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            return "sha256:" + hashlib.sha256(encoded).hexdigest()

        self.assertEqual(digest(payload), digest(preserved))
        self.assertEqual(data["contract_fingerprint"], digest(preserved))
        self.assertEqual(before, path.read_bytes())

    def test_original_no_contract(self):
        self.check_contract("no_contract")

    def test_original_advisory(self):
        self.check_contract("advisory")

    def test_original_guarded(self):
        self.check_contract("guarded")

    def test_original_strict(self):
        self.check_contract("strict")


if __name__ == "__main__":
    unittest.main()
