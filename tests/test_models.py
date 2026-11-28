# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import unittest
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType

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
from vogtcon.models import (
    OPERATION_DIGEST_EXCLUDED_METADATA,
    OPERATION_IDENTITY_VERSION,
    ApprovalStateRecord,
    ApprovedAgentConfiguration,
    ContractRulesV2,
    ContractRulesV3,
    EffectRecord,
    HostApproval,
    HostFacts,
    PlannedEffect,
    ResponseSchema,
    RetrievedEvidence,
    RuleBinding,
    TrajectoryEntry,
    TrajectoryView,
    _parse_utc_timestamp,
)


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


def v3_contract_data() -> dict:
    return {
        "schema_version": 3,
        "contract_id": "enforcement.v3.example",
        "approved_agent_configurations": [
            "sha256:example-agent",
            {"fingerprint": "sha256:example-agent"},
        ],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["answer", "citations", "status"]},
        "memory_policy": "allowed-scope-only",
        "validation_phases": ["pre_execution", "runtime", "post_execution"],
        "rules": [
            {
                "instance_id": "declared-tools",
                "rule_type": "tool.declared_only",
                "phases": ["runtime"],
                "params": {},
            },
            {
                "instance_id": "response-complete",
                "rule_type": "response.schema_complete",
                "phases": ["post_execution"],
                "params": {},
            },
        ],
        "contract_fingerprint": "sha256:example-v3-contract",
        "metadata": {"owner": "example"},
    }


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
        for version in (None, 1, 4, "2", "3", 2.0, 3.0, True):
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


class HostFactsAndEffectTests(unittest.TestCase):
    def test_host_facts_and_planned_effect_defaults_and_deep_immutability(self):
        default_facts = HostFacts()
        self.assertIsInstance(default_facts.facts, MappingProxyType)
        self.assertEqual(default_facts.facts, {})
        with self.assertRaises(TypeError):
            default_facts.facts["role"] = "manager"

        default_effect = PlannedEffect(tool_name="send_notification")
        self.assertIsInstance(default_effect.parameters, MappingProxyType)
        self.assertIsInstance(default_effect.defaults, MappingProxyType)
        self.assertEqual(default_effect.parameters, {})
        self.assertEqual(default_effect.defaults, {})
        with self.assertRaises(TypeError):
            default_effect.parameters["channel"] = "email"
        with self.assertRaises(TypeError):
            default_effect.defaults["retries"] = 1

        caller_facts_input = {
            "role": "manager",
            "nested": {"dept": "finance", "scopes": ["read", {"level": 2}]},
        }
        caller_params_input = {
            "recipient": "ops@example.com",
            "targets": ["primary", {"backup": "audit@example.com"}],
        }
        caller_defaults_input = {
            "channel": "email",
            "headers": {"priority": "normal", "tags": ["v3"]},
        }

        facts = HostFacts(facts=caller_facts_input)
        effect = PlannedEffect(
            tool_name="send_notification",
            parameters=caller_params_input,
            defaults=caller_defaults_input,
        )
        initial_digest = effect.operation_digest()

        # Caller mutates original input dicts and nested dicts/lists after validation
        caller_facts_input["role"] = "admin"
        caller_facts_input["nested"]["dept"] = "tampered"
        caller_facts_input["nested"]["scopes"].append("write")
        caller_facts_input["nested"]["scopes"][1]["level"] = 99

        caller_params_input["recipient"] = "attacker@example.com"
        caller_params_input["targets"].append("injected")
        caller_params_input["targets"][1]["backup"] = "attacker@example.com"

        caller_defaults_input["channel"] = "sms"
        caller_defaults_input["headers"]["priority"] = "urgent"
        caller_defaults_input["headers"]["tags"].append("mutated")

        self.assertEqual(facts.facts["role"], "manager")
        self.assertEqual(facts.facts["nested"]["dept"], "finance")
        self.assertEqual(facts.facts["nested"]["scopes"], ("read", MappingProxyType({"level": 2})))
        self.assertEqual(effect.parameters["recipient"], "ops@example.com")
        self.assertEqual(
            effect.parameters["targets"],
            ("primary", MappingProxyType({"backup": "audit@example.com"})),
        )
        self.assertEqual(effect.defaults["channel"], "email")
        self.assertEqual(effect.defaults["headers"]["tags"], ("v3",))
        self.assertEqual(effect.operation_digest(), initial_digest)

        # Direct top-level and nested mutations on stored snapshots fail
        with self.assertRaises(TypeError):
            facts.facts["role"] = "admin"
        with self.assertRaises(TypeError):
            facts.facts["nested"]["dept"] = "tampered"
        with self.assertRaises(AttributeError):
            facts.facts["nested"]["scopes"].append("write")
        with self.assertRaises(TypeError):
            facts.facts["nested"]["scopes"][0] = "write"
        with self.assertRaises(TypeError):
            facts.facts["nested"]["scopes"][1]["level"] = 99

        with self.assertRaises(TypeError):
            effect.parameters["recipient"] = "attacker@example.com"
        with self.assertRaises(AttributeError):
            effect.parameters["targets"].append("injected")
        with self.assertRaises(TypeError):
            effect.parameters["targets"][1]["backup"] = "attacker@example.com"

        with self.assertRaises(TypeError):
            effect.defaults["channel"] = "sms"
        with self.assertRaises(TypeError):
            effect.defaults["headers"]["priority"] = "urgent"
        with self.assertRaises(AttributeError):
            effect.defaults["headers"]["tags"].append("mutated")

        self.assertEqual(effect.operation_digest(), initial_digest)

    def test_serialization_and_deepcopy_produce_native_json_structures(self):
        facts = HostFacts(facts={"nested": {"items": [1, {"ok": True}]}})
        effect = PlannedEffect(
            tool_name="send_notification",
            parameters={"targets": ["ops@example.com", {"cc": ["audit@example.com"]}]},
            defaults={"meta": {"retries": [1, 2]}},
        )
        for dumped in (facts.model_dump(), facts.model_dump(mode="json"), json.loads(facts.model_dump_json())):
            self.assertIs(type(dumped["facts"]), dict)
            self.assertIs(type(dumped["facts"]["nested"]), dict)
            self.assertIs(type(dumped["facts"]["nested"]["items"]), list)
            self.assertIs(type(dumped["facts"]["nested"]["items"][1]), dict)
            dumped["facts"]["nested"]["items"].append(99)

        self.assertEqual(len(facts.facts["nested"]["items"]), 2)

        for dumped in (effect.model_dump(), effect.model_dump(mode="json"), json.loads(effect.model_dump_json())):
            self.assertIs(type(dumped["parameters"]), dict)
            self.assertIs(type(dumped["parameters"]["targets"]), list)
            self.assertIs(type(dumped["parameters"]["targets"][1]), dict)
            self.assertIs(type(dumped["parameters"]["targets"][1]["cc"]), list)
            self.assertIs(type(dumped["defaults"]), dict)
            self.assertIs(type(dumped["defaults"]["meta"]["retries"]), list)

        self.assertEqual(deepcopy(facts), facts)
        self.assertEqual(facts.model_copy(deep=True), facts)
        updated_effect = effect.model_copy(
            update={"tool_name": "create_ticket", "parameters": {"nested": [1, 2]}},
            deep=True,
        )
        self.assertEqual(effect.tool_name, "send_notification")
        self.assertEqual(updated_effect.tool_name, "create_ticket")
        self.assertIsInstance(updated_effect.parameters, MappingProxyType)
        with self.assertRaises(AttributeError):
            updated_effect.parameters["nested"].append(3)

    def test_strict_typing_extra_forbid_and_frozen_assignment(self):
        for bad_facts in ([], "facts", 1, None):
            with self.subTest(bad_facts=bad_facts):
                with self.assertRaises(ValidationError):
                    HostFacts(facts=bad_facts)

        for bad_tool in ("", 123, None, True):
            with self.subTest(bad_tool=bad_tool):
                with self.assertRaises(ValidationError):
                    PlannedEffect(tool_name=bad_tool)

        for bad_map in ([], "params", 1, None):
            with self.subTest(bad_map=bad_map):
                with self.assertRaises(ValidationError):
                    PlannedEffect(tool_name="send_notification", parameters=bad_map)
                with self.assertRaises(ValidationError):
                    PlannedEffect(tool_name="send_notification", defaults=bad_map)

        facts = HostFacts(facts={"approved": True})
        with self.assertRaises(ValidationError):
            facts.facts = {}

        effect = PlannedEffect(tool_name="send_notification", parameters={"to": "ops@example.com"})
        with self.assertRaises(ValidationError):
            effect.tool_name = "other_tool"
        with self.assertRaises(ValidationError):
            effect.parameters = {}
        with self.assertRaises(ValidationError):
            effect.defaults = {}

    def test_rejects_action_proposal_and_context_fields(self):
        with self.assertRaises(ValidationError):
            HostFacts(facts={}, arguments={"sensitive": False})
        with self.assertRaises(ValidationError):
            HostFacts(facts={}, state={"user_role": "admin"})
        with self.assertRaises(ValidationError):
            PlannedEffect(tool_name="send_notification", arguments={"to": "a@example.com"})
        with self.assertRaises(ValidationError):
            PlannedEffect(tool_name="send_notification", iteration=1)

    def test_rejects_non_json_and_non_finite_numbers(self):
        for bad_value in (object(), {1, 2}, float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(bad_value)):
                with self.assertRaises(ValidationError):
                    HostFacts(facts={"bad": bad_value})
                with self.assertRaises(ValidationError):
                    PlannedEffect(tool_name="send_notification", parameters={"bad": bad_value})
                with self.assertRaises(ValidationError):
                    PlannedEffect(tool_name="send_notification", defaults={"bad": bad_value})


class OperationIdentityTests(unittest.TestCase):
    def test_version_and_excluded_metadata_enumeration(self):
        self.assertIs(type(OPERATION_IDENTITY_VERSION), int)
        self.assertEqual(OPERATION_IDENTITY_VERSION, 1)
        expected_excluded = (
            "run_id",
            "iteration",
            "policy_mode",
            "contract_fingerprint",
            "agent_fingerprint",
            "approval_id",
            "approver_id",
            "requester_id",
            "approval_issued_at",
            "approval_expires_at",
            "approval_scope",
            "trace_id",
            "span_id",
            "host_facts",
        )
        self.assertEqual(OPERATION_DIGEST_EXCLUDED_METADATA, expected_excluded)

        effect = PlannedEffect(
            tool_name="send_notification",
            parameters={"recipient": "ops@example.com"},
            defaults={"channel": "email"},
        )
        canonical = effect.canonical_operation()
        self.assertEqual(
            set(canonical.keys()),
            {"identity", "version", "tool_name", "parameters"},
        )
        self.assertEqual(canonical["identity"], "vogtcon.operation")
        self.assertEqual(canonical["version"], 1)
        for excluded_key in OPERATION_DIGEST_EXCLUDED_METADATA:
            self.assertNotIn(excluded_key, canonical)

    def test_effective_parameters_overlay_explicit_none_and_mutation_isolation(self):
        effect = PlannedEffect(
            tool_name="send_notification",
            defaults={
                "channel": "email",
                "cc": "audit@example.com",
                "options": {"retry": 3, "format": "plain"},
            },
            parameters={
                "cc": None,
                "options": {"format": "html"},
                "recipient": "user@example.com",
            },
        )
        effective = effect.effective_parameters
        self.assertEqual(
            effective,
            {
                "channel": "email",
                "cc": None,
                "options": {"format": "html"},
                "recipient": "user@example.com",
            },
        )
        effective["channel"] = "sms"
        effective["options"]["format"] = "markdown"
        self.assertEqual(effect.defaults["channel"], "email")
        self.assertEqual(effect.parameters["options"], {"format": "html"})
        self.assertEqual(effect.effective_parameters["channel"], "email")
        self.assertEqual(effect.effective_parameters["options"], {"format": "html"})

    def test_digest_format_determinism_key_order_and_default_equivalence(self):
        via_defaults = PlannedEffect(
            tool_name="send_notification",
            defaults={"channel": "email", "meta": {"b": 2, "a": "sí"}},
            parameters={"recipient": "ops@example.com"},
        )
        via_explicit = PlannedEffect(
            tool_name="send_notification",
            defaults={},
            parameters={"meta": {"a": "sí", "b": 2}, "recipient": "ops@example.com", "channel": "email"},
        )
        via_overridden_default = PlannedEffect(
            tool_name="send_notification",
            defaults={"channel": "sms", "recipient": "nobody@example.com"},
            parameters={"channel": "email", "recipient": "ops@example.com", "meta": {"a": "sí", "b": 2}},
        )
        digest = via_defaults.operation_digest()
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(digest, via_defaults.operation_digest())
        self.assertEqual(digest, via_explicit.operation_digest())
        self.assertEqual(digest, via_overridden_default.operation_digest())

    def test_digest_distinguishes_tool_values_none_and_json_types(self):
        base = PlannedEffect(
            tool_name="send_notification",
            parameters={"flag": 1},
            defaults={"channel": "email"},
        )
        different_tool = PlannedEffect(
            tool_name="create_ticket",
            parameters={"flag": 1},
            defaults={"channel": "email"},
        )
        explicit_none = PlannedEffect(
            tool_name="send_notification",
            parameters={"flag": 1, "channel": None},
            defaults={"channel": "email"},
        )
        self.assertNotEqual(base.operation_digest(), different_tool.operation_digest())
        self.assertNotEqual(base.operation_digest(), explicit_none.operation_digest())

        typed_digests = {
            repr(val): PlannedEffect(
                tool_name="send_notification",
                parameters={"value": val},
            ).operation_digest()
            for val in (1, True, "1", 1.0, 0, False, "0", 0.0, None)
        }
        self.assertEqual(len(set(typed_digests.values())), len(typed_digests))

    def test_digest_invariant_under_excluded_context_and_proposal_metadata(self):
        effect = PlannedEffect(
            tool_name="send_notification",
            parameters={"recipient": "ops@example.com"},
            defaults={"channel": "email"},
        )
        first = GovernorInput(
            run_id="run-alpha",
            contract=AgentContract.model_validate(contract_data("guarded")),
            phase="runtime",
            context=ExecutionContext(
                state={"user_role": "employee", "trace_id": "trace-1"},
                available_tools=["send_notification"],
                observed_agent_fingerprint="sha256:agent-a",
                observed_contract_fingerprint="sha256:contract-a",
            ),
            action=ActionProposal(
                tool_name="send_notification",
                arguments={"recipient": "attacker@example.com", "sensitive": False},
                iteration=1,
            ),
            host_facts=HostFacts(facts={"user_role": "employee", "approval_id": "app-1"}),
            planned_effect=effect,
        )
        second = GovernorInput(
            run_id="run-beta",
            contract=ContractRulesV2.model_validate(v2_contract_data()),
            phase="runtime",
            policy=EnforcementPolicy(mode="strict"),
            context=ExecutionContext(
                state={"user_role": "manager", "trace_id": "trace-2"},
                available_tools=["send_notification"],
                observed_agent_fingerprint="sha256:agent-b",
                observed_contract_fingerprint="sha256:contract-b",
            ),
            action=ActionProposal(
                tool_name="send_notification",
                arguments={"recipient": "different@example.com", "sensitive": True},
                iteration=9,
            ),
            host_facts=HostFacts(facts={"user_role": "manager", "approval_id": "app-2"}),
            planned_effect=effect,
        )
        assert first.planned_effect is not None and second.planned_effect is not None
        self.assertEqual(
            first.planned_effect.operation_digest(),
            second.planned_effect.operation_digest(),
        )


class ContractV3ModelTests(unittest.TestCase):
    def test_valid_v3_contract_and_defaults(self):
        data = v3_contract_data()
        model = ContractRulesV3.model_validate(data)
        self.assertEqual(model.model_dump(), data)
        self.assertEqual(
            ContractRulesV3.model_validate_json(json.dumps(data)).model_dump(),
            data,
        )
        self.assertFalse(hasattr(model, "mode"))
        self.assertFalse(hasattr(model, "agent_feedback"))
        self.assertFalse(hasattr(model, "runtime_rules"))
        self.assertFalse(hasattr(model, "postconditions"))

        minimal = deepcopy(data)
        minimal["rules"] = []
        del minimal["metadata"]
        minimal_model = ContractRulesV3.model_validate(minimal)
        self.assertEqual(minimal_model.rules, ())
        self.assertEqual(minimal_model.metadata, {})
        self.assertIsInstance(minimal_model.metadata, MappingProxyType)

        b1 = RuleBinding(instance_id="r1", rule_type="tool.declared_only", phases=["runtime"])
        b2 = RuleBinding(instance_id="r2", rule_type="tool.declared_only", phases=["runtime"])
        self.assertIsInstance(b1.params, MappingProxyType)
        self.assertEqual(b1.phases, ("runtime",))
        self.assertEqual(b2.params, {})
        with self.assertRaises(TypeError):
            b1.params["k"] = "v"

    def test_contract_document_dispatches_v3_and_preserves_original(self):
        data = v3_contract_data()
        del data["metadata"]
        del data["rules"][0]["params"]
        data["extra_check"] = None
        del data["extra_check"]
        expected = deepcopy(data)

        document = ContractDocument(data)
        self.assertIsInstance(document.contract, ContractRulesV3)
        data["declared_tools"].append("mutated")
        with self.assertRaises(AttributeError):
            document.contract.declared_tools.append("model_mutated")
        returned = document.original
        returned["declared_tools"].append("returned_mutated")

        self.assertEqual(document.original, expected)
        self.assertNotIn("metadata", document.original)
        self.assertNotIn("params", document.original["rules"][0])

    def test_v3_contract_and_rule_binding_are_deeply_immutable_and_serialize_to_native_json(
        self,
    ):
        raw_input = {
            "schema_version": 3,
            "contract_id": "enforcement.v3.immutable",
            "approved_agent_configurations": [
                "sha256:example-agent",
                {
                    "fingerprint": "sha256:example-agent-2",
                    "note": "approved",
                    "tags": ["prod", {"tier": 1}],
                },
            ],
            "declared_tools": ["send_notification", "transfer_funds"],
            "response_schema": {
                "required_fields": ["answer", "status"],
                "description": "strict response",
                "nested": {"formats": ["json", "text"]},
            },
            "memory_policy": "allowed-scope-only",
            "validation_phases": ["pre_execution", "runtime", "post_execution"],
            "rules": [
                {
                    "instance_id": "transfer-limit",
                    "rule_type": "transfer.max_amount",
                    "phases": ["runtime"],
                    "params": {
                        "max_amount": 500,
                        "nested": {"currencies": ["MXN", "USD"], "flags": {"strict": True}},
                    },
                }
            ],
            "contract_fingerprint": "sha256:example-v3-contract",
            "metadata": {
                "owner": "security",
                "audit": {"reviewers": ["alice", "bob"], "level": 3},
            },
        }
        expected_dump = deepcopy(raw_input)
        standalone_schema = ResponseSchema.model_validate(raw_input["response_schema"])
        standalone_cfg = ApprovedAgentConfiguration.model_validate(
            raw_input["approved_agent_configurations"][1]
        )

        contract = ContractRulesV3(
            schema_version=3,
            contract_id=raw_input["contract_id"],
            approved_agent_configurations=[
                raw_input["approved_agent_configurations"][0],
                standalone_cfg,
            ],
            declared_tools=raw_input["declared_tools"],
            response_schema=standalone_schema,
            memory_policy=raw_input["memory_policy"],
            validation_phases=raw_input["validation_phases"],
            rules=[RuleBinding.model_validate(raw_input["rules"][0])],
            contract_fingerprint=raw_input["contract_fingerprint"],
            metadata=raw_input["metadata"],
        )

        # Caller mutates raw inputs and standalone models after construction
        raw_input["declared_tools"].append("unapproved_tool")
        raw_input["validation_phases"].append("runtime")
        raw_input["rules"][0]["phases"].append("post_execution")
        raw_input["rules"][0]["params"]["max_amount"] = 999999
        raw_input["rules"][0]["params"]["nested"]["currencies"].append("EUR")
        raw_input["metadata"]["owner"] = "tampered"
        raw_input["metadata"]["audit"]["reviewers"].append("mallory")
        standalone_schema.required_fields.append("injected_field")
        standalone_schema.model_extra["description"] = "mutated"
        standalone_cfg.model_extra["note"] = "mutated"

        self.assertEqual(contract.model_dump(), expected_dump)
        self.assertEqual(contract.model_dump(mode="json"), expected_dump)
        self.assertEqual(json.loads(contract.model_dump_json()), expected_dump)
        self.assertIsInstance(contract.response_schema, ResponseSchema)
        self.assertIsInstance(
            contract.approved_agent_configurations[1], ApprovedAgentConfiguration
        )

        # Direct mutation attempts on every collection/mapping path fail
        with self.assertRaises(AttributeError):
            contract.declared_tools.append("unapproved_tool")  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            contract.validation_phases.append("runtime")  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            contract.rules.append(contract.rules[0])  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            contract.rules[0].phases.append("post_execution")  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            contract.rules[0].params["max_amount"] = 999999  # type: ignore[index]
        with self.assertRaises(TypeError):
            contract.rules[0].params["nested"]["flags"]["strict"] = False  # type: ignore[index]
        with self.assertRaises(AttributeError):
            contract.rules[0].params["nested"]["currencies"].append("EUR")  # type: ignore[union-attr]
        with self.assertRaises(AttributeError):
            contract.response_schema.required_fields.append("extra")  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            contract.response_schema.model_extra["description"] = "tampered"
        with self.assertRaises(AttributeError):
            contract.response_schema.model_extra["nested"]["formats"].append("xml")
        with self.assertRaises(AttributeError):
            contract.approved_agent_configurations.append("sha256:other")  # type: ignore[attr-defined]
        cfg_item = contract.approved_agent_configurations[1]
        assert isinstance(cfg_item, ApprovedAgentConfiguration)
        with self.assertRaises(TypeError):
            cfg_item.model_extra["note"] = "tampered"
        with self.assertRaises(AttributeError):
            cfg_item.model_extra["tags"].append("dev")
        with self.assertRaises(TypeError):
            cfg_item.model_extra["tags"][1]["tier"] = 99
        with self.assertRaises(TypeError):
            contract.metadata["owner"] = "attacker"  # type: ignore[index]
        with self.assertRaises(AttributeError):
            contract.metadata["audit"]["reviewers"].append("mallory")  # type: ignore[union-attr]

        # deepcopy and model_copy preserve deep immutability and native dumps
        self.assertEqual(deepcopy(contract), contract)
        self.assertEqual(contract.model_copy(deep=True), contract)
        updated = contract.model_copy(
            update={
                "declared_tools": ["only_tool"],
                "metadata": {"nested": ["a", "b"]},
            },
            deep=True,
        )
        self.assertEqual(updated.declared_tools, ("only_tool",))
        with self.assertRaises(AttributeError):
            updated.metadata["nested"].append("c")  # type: ignore[union-attr]
        self.assertIs(type(updated.model_dump()["declared_tools"]), list)
        self.assertIs(type(updated.model_dump()["metadata"]["nested"]), list)

    def test_v3_rejects_missing_rules_and_legacy_or_enforcement_fields(self):
        missing_rules = v3_contract_data()
        del missing_rules["rules"]
        with self.assertRaises(ValidationError):
            ContractRulesV3.model_validate(missing_rules)

        v2_as_v3 = v2_contract_data()
        v2_as_v3["schema_version"] = 3
        with self.assertRaises(ValidationError):
            ContractDocument(v2_as_v3)

        for key, value in (
            ("runtime_rules", ["tool.declared_only"]),
            ("postconditions", ["response.schema_complete"]),
            ("mode", "guarded"),
            ("agent_feedback", {"guarded_denial_style": "minimal"}),
            ("unexpected_field", True),
        ):
            with self.subTest(key=key):
                bad = v3_contract_data()
                bad[key] = value
                with self.assertRaises(ValidationError):
                    ContractRulesV3.model_validate(bad)
                with self.assertRaises(ValidationError):
                    ContractDocument(bad)

    def test_v3_rejects_non_int_or_wrong_schema_version(self):
        for bad_version in ("3", 3.0, True, False, 2, 1, None):
            with self.subTest(version=bad_version):
                bad = v3_contract_data()
                bad["schema_version"] = bad_version
                with self.assertRaises(ValidationError):
                    ContractRulesV3.model_validate(bad)

    def test_instance_id_pattern_length_and_uniqueness(self):
        for valid_id in ("a", "Rule_1.2:check-a", "a" * 128):
            with self.subTest(valid_id=len(valid_id)):
                binding = RuleBinding(
                    instance_id=valid_id,
                    rule_type="tool.declared_only",
                    phases=["runtime"],
                )
                self.assertEqual(binding.instance_id, valid_id)

        for invalid_id in (
            "",
            " ",
            " leading",
            "trailing ",
            "has space",
            "line\nbreak",
            "-starts-dash",
            ".starts-dot",
            "_starts-underscore",
            ":starts-colon",
            "bad/slash",
            "bad@char",
            "a" * 129,
        ):
            with self.subTest(invalid_id=repr(invalid_id)):
                with self.assertRaises(ValidationError):
                    RuleBinding(
                        instance_id=invalid_id,
                        rule_type="tool.declared_only",
                        phases=["runtime"],
                    )

        dup = v3_contract_data()
        dup["rules"].append(
            {
                "instance_id": "declared-tools",
                "rule_type": "response.schema_complete",
                "phases": ["post_execution"],
            }
        )
        with self.assertRaisesRegex(
            ValidationError,
            r"Duplicate rule instance_id\(s\): declared-tools",
        ):
            ContractRulesV3.model_validate(dup)

    def test_rule_binding_phases_and_strict_params(self):
        with self.assertRaisesRegex(ValidationError, "RuleBinding phases must be non-empty"):
            RuleBinding(instance_id="r1", rule_type="tool.declared_only", phases=[])

        with self.assertRaisesRegex(
            ValidationError, "RuleBinding phases must not contain duplicates"
        ):
            RuleBinding(
                instance_id="r1",
                rule_type="tool.declared_only",
                phases=["runtime", "runtime"],
            )

        for bad_phases in (["unknown"], "runtime", ("runtime",)):
            with self.subTest(bad_phases=bad_phases):
                with self.assertRaises(ValidationError):
                    RuleBinding(
                        instance_id="r1",
                        rule_type="tool.declared_only",
                        phases=bad_phases,
                    )

        for bad_params in ([], "x", 1, None, {"nan": float("nan")}, {"obj": object()}):
            with self.subTest(bad_params=repr(bad_params)):
                with self.assertRaises(ValidationError):
                    RuleBinding(
                        instance_id="r1",
                        rule_type="tool.declared_only",
                        phases=["runtime"],
                        params=bad_params,
                    )

        binding = RuleBinding(
            instance_id="r1",
            rule_type="custom.limit",
            phases=["runtime"],
            params={"count": 1, "flag": True, "label": "1", "ratio": 1.0, "opt": None},
        )
        self.assertIs(type(binding.params["count"]), int)
        self.assertIs(type(binding.params["flag"]), bool)
        self.assertIs(type(binding.params["label"]), str)
        self.assertIs(type(binding.params["ratio"]), float)
        self.assertIsNone(binding.params["opt"])


class SourceAgreementTests(unittest.TestCase):
    def test_legacy_request_dump_omits_unset_host_facts_and_planned_effect(self):
        for phase in ("pre_execution", "runtime", "post_execution"):
            with self.subTest(phase=phase):
                request = GovernorInput.model_validate(input_data(phase))
                dumped = request.model_dump()
                dumped_json = request.model_dump_json()
                self.assertNotIn("host_facts", dumped)
                self.assertNotIn("planned_effect", dumped)
                self.assertNotIn('"host_facts"', dumped_json)
                self.assertNotIn('"planned_effect"', dumped_json)

    def test_matching_and_disjoint_host_facts_succeed(self):
        data = input_data("runtime")
        data["context"]["state"] = {
            "user_role": "manager",
            "nested": {"b": [1, 2], "a": {"y": True, "x": "ok"}},
        }
        data["host_facts"] = {
            "facts": {
                "nested": {"a": {"x": "ok", "y": True}, "b": [1, 2]},
                "department": "finance",
            }
        }
        data["planned_effect"] = {
            "tool_name": "send_notification",
            "parameters": {"recipient": "normalized@example.com"},
            "defaults": {"channel": "email"},
        }
        request = GovernorInput.model_validate(data)
        self.assertEqual(request, GovernorInput.model_validate_json(request.model_dump_json()))
        self.assertEqual(deepcopy(request), request)
        for dumped in (request.model_dump(), request.model_dump(mode="json")):
            self.assertIs(type(dumped["context"]["state"]), dict)
            self.assertIs(type(dumped["context"]["state"]["nested"]["b"]), list)
            self.assertIs(type(dumped["host_facts"]["facts"]), dict)
            self.assertIs(type(dumped["host_facts"]["facts"]["nested"]["b"]), list)
            self.assertIs(type(dumped["planned_effect"]["parameters"]), dict)

        assert request.host_facts is not None
        with self.assertRaises(TypeError):
            request.context.state["user_role"] = "admin"
        with self.assertRaises(AttributeError):
            request.context.state["nested"]["b"].append(3)
        with self.assertRaises(TypeError):
            request.context.state["nested"]["a"]["x"] = "tampered"
        with self.assertRaises(TypeError):
            request.host_facts.facts["user_role"] = "admin"
        with self.assertRaises(AttributeError):
            request.host_facts.facts["nested"]["b"].append(3)
        with self.assertRaises(TypeError):
            request.host_facts.facts["nested"]["a"]["x"] = "tampered"

        nested_type_conflict = input_data("runtime")
        nested_type_conflict["context"]["state"] = {"nested_list": [1, True]}
        nested_type_conflict["host_facts"] = {"facts": {"nested_list": [1, 1]}}
        with self.assertRaisesRegex(
            ValidationError,
            r"host_facts conflicts with context\.state for key\(s\): nested_list",
        ):
            GovernorInput.model_validate(nested_type_conflict)

    def test_conflicting_host_facts_fail_naming_keys_without_leaking_values(self):
        secret_state = "SECRET_STATE_TOKEN_ALPHA_9001"
        secret_host = "SECRET_HOST_TOKEN_BETA_9002"
        data = input_data("runtime")
        data["context"]["state"] = {
            "z_token": secret_state,
            "a_role": "employee",
            "shared_ok": 42,
        }
        data["host_facts"] = {
            "facts": {
                "z_token": secret_host,
                "a_role": "admin",
                "shared_ok": 42,
            }
        }
        with self.assertRaises(ValidationError) as ctx:
            GovernorInput.model_validate(data)

        rendered = str(ctx.exception)
        messages = " | ".join(err["msg"] for err in ctx.exception.errors())
        self.assertIn(
            "host_facts conflicts with context.state for key(s): a_role, z_token",
            rendered,
        )
        self.assertNotIn(secret_state, rendered)
        self.assertNotIn(secret_host, rendered)
        self.assertNotIn(secret_state, messages)
        self.assertNotIn(secret_host, messages)

    def test_type_strict_conflicts_between_state_and_host_facts_fail(self):
        for state_val, host_val in (
            (True, 1),
            (False, 0),
            (1, 1.0),
            ("1", 1),
            (None, ""),
        ):
            with self.subTest(state_val=repr(state_val), host_val=repr(host_val)):
                data = input_data("runtime")
                data["context"]["state"] = {"flag": state_val}
                data["host_facts"] = {"facts": {"flag": host_val}}
                with self.assertRaisesRegex(
                    ValidationError,
                    r"host_facts conflicts with context\.state for key\(s\): flag",
                ):
                    GovernorInput.model_validate(data)

    def test_planned_effect_phase_boundaries_and_missing_action_order(self):
        for phase in ("pre_execution", "post_execution"):
            with self.subTest(phase=phase):
                data = input_data(phase)
                data["planned_effect"] = {"tool_name": "send_notification"}
                with self.assertRaisesRegex(
                    ValidationError,
                    "planned_effect is only accepted for runtime evaluation",
                ):
                    GovernorInput.model_validate(data)

        missing_action = input_data("runtime")
        del missing_action["action"]
        missing_action["planned_effect"] = {"tool_name": "send_notification"}
        with self.assertRaisesRegex(
            ValidationError,
            "runtime evaluation requires an action",
        ):
            GovernorInput.model_validate(missing_action)

    def test_planned_effect_tool_name_agreement_and_parameter_normalization(self):
        mismatch = input_data("runtime")
        mismatch["planned_effect"] = {"tool_name": "approve_request"}
        with self.assertRaisesRegex(
            ValidationError,
            r"planned_effect\.tool_name conflicts with action\.tool_name",
        ):
            GovernorInput.model_validate(mismatch)

        normalized = input_data("runtime")
        normalized["action"] = {
            "tool_name": "send_notification",
            "arguments": {"recipient": "  OPS@EXAMPLE.COM  ", "sensitive": False},
        }
        normalized["planned_effect"] = {
            "tool_name": "send_notification",
            "parameters": {"recipient": "ops@example.com", "sensitive": True},
            "defaults": {"channel": "email"},
        }
        request = GovernorInput.model_validate(normalized)
        assert request.planned_effect is not None and request.action is not None
        self.assertEqual(request.planned_effect.parameters["recipient"], "ops@example.com")
        self.assertEqual(request.action.arguments["recipient"], "  OPS@EXAMPLE.COM  ")

    def test_untrusted_action_arguments_do_not_conflict_with_or_alter_host_facts(self):
        data = input_data("runtime")
        data["context"]["state"] = {"user_role": "employee"}
        data["host_facts"] = {"facts": {"user_role": "employee", "approval_granted": False}}
        data["action"] = {
            "tool_name": "send_notification",
            "arguments": {"user_role": "admin", "approval_granted": True, "sensitive": False},
        }
        request = GovernorInput.model_validate(data)
        assert request.host_facts is not None
        self.assertEqual(request.host_facts.facts["user_role"], "employee")
        self.assertFalse(request.host_facts.facts["approval_granted"])

    def test_governor_input_accepts_v3_with_policy_and_rejects_missing_policy(self):
        v3_dict = v3_contract_data()
        v3_model = ContractRulesV3.model_validate(v3_dict)
        for candidate in (v3_model, v3_dict):
            with self.subTest(candidate=type(candidate).__name__):
                missing_policy = input_data("runtime")
                missing_policy["contract"] = candidate
                with self.assertRaisesRegex(
                    ValidationError,
                    "v3 contracts require an enforcement policy",
                ):
                    GovernorInput.model_validate(missing_policy)

                valid = input_data("runtime")
                valid["contract"] = candidate
                valid["policy"] = {"mode": "guarded"}
                request = GovernorInput.model_validate(valid)
                self.assertIsInstance(request.contract, ContractRulesV3)
                self.assertEqual(request.effective_mode, "guarded")

        malformed_v3 = input_data("runtime")
        malformed_v3["contract"] = {"schema_version": 3}
        malformed_v3["policy"] = {"mode": "guarded"}
        with self.assertRaises(ValidationError):
            GovernorInput.model_validate(malformed_v3)

        for unsupported in (4, "3", 3.0, True):
            with self.subTest(unsupported=repr(unsupported)):
                data = input_data("runtime")
                data["contract"] = {**v3_dict, "schema_version": unsupported}
                data["policy"] = {"mode": "guarded"}
                with self.assertRaisesRegex(
                    ValidationError,
                    "Unsupported contract schema_version",
                ):
                    GovernorInput.model_validate(data)

    def test_context_state_is_detached_and_frozen_with_host_facts_and_model_copy(self):
        caller_state = {
            "approval_granted": False,
            "nested": {"scope": "read", "items": [1, 2]},
        }
        caller_ctx = ExecutionContext(
            state=caller_state,
            available_tools=["send_notification"],
        )
        request = GovernorInput(
            run_id="run-ctx-freeze",
            contract=AgentContract.model_validate(contract_data("guarded")),
            phase="runtime",
            context=caller_ctx,
            action=ActionProposal(
                tool_name="send_notification",
                arguments={"sensitive": True},
            ),
            host_facts=HostFacts(facts={"approval_granted": False}),
        )

        # Standalone ExecutionContext remains mutable for legacy callers,
        # while request.context is detached and deeply frozen.
        caller_state["approval_granted"] = True
        caller_state["nested"]["scope"] = "write"
        caller_state["nested"]["items"].append(3)
        caller_ctx.state["extra"] = "legacy-mutable"

        self.assertIsInstance(request.context.state, MappingProxyType)
        self.assertFalse(request.context.state["approval_granted"])
        self.assertNotIn("extra", request.context.state)
        self.assertEqual(request.context.state["nested"]["scope"], "read")
        self.assertEqual(request.context.state["nested"]["items"], (1, 2))

        with self.assertRaises(TypeError):
            request.context.state["approval_granted"] = True
        with self.assertRaises(TypeError):
            request.context.state["nested"]["scope"] = "write"
        with self.assertRaises(AttributeError):
            request.context.state["nested"]["items"].append(99)

        for dumped in (
            request.model_dump(),
            request.model_dump(mode="json"),
            json.loads(request.model_dump_json()),
        ):
            self.assertIs(type(dumped["context"]["state"]), dict)
            self.assertIs(type(dumped["context"]["state"]["nested"]), dict)
            self.assertIs(type(dumped["context"]["state"]["nested"]["items"]), list)

        deep_copied = request.model_copy(update={"run_id": "run-ctx-freeze-2"}, deep=True)
        self.assertEqual(deep_copied.run_id, "run-ctx-freeze-2")
        self.assertIsInstance(deep_copied.context.state, MappingProxyType)

        with self.assertRaisesRegex(
            ValueError,
            r"host_facts conflicts with context\.state for key\(s\): approval_granted",
        ):
            request.model_copy(
                update={
                    "context": ExecutionContext(
                        state={"approval_granted": True},
                        available_tools=["send_notification"],
                    )
                }
            )

        # Legacy request without host_facts stays untouched unless host_facts is attached
        legacy_request = GovernorInput.model_validate(input_data("runtime"))
        self.assertIs(type(legacy_request.context.state), dict)
        promoted = legacy_request.model_copy(
            update={"host_facts": HostFacts(facts={"user_role": "employee"})}
        )
        self.assertIs(type(legacy_request.context.state), dict)
        self.assertIsInstance(promoted.context.state, MappingProxyType)


class EffectAndTrajectoryModelTests(unittest.TestCase):
    def _digest(self, suffix: str = "a") -> str:
        return "sha256:" + (suffix * 64)[:64]

    def test_effect_record_states_immutability_and_self_compensation_rejection(self):
        caller_meta = {"channel": "email", "nested": {"tags": ["urgent"]}}
        for status in ("reserved", "confirmed", "confirmed_absent", "uncertain"):
            with self.subTest(status=status):
                record = EffectRecord(
                    effect_id=f"eff-{status}",
                    run_id="run-1",
                    policy_scope="scope.alpha",
                    action_index=1,
                    tool_name="send_notification",
                    operation_digest=self._digest("a"),
                    status=status,
                    metadata=caller_meta,
                )
                self.assertEqual(record.status, status)
                self.assertIsInstance(record.metadata, MappingProxyType)

        record = EffectRecord(
            effect_id="eff-001",
            run_id="run-1",
            policy_scope="scope.alpha",
            action_index=1,
            tool_name="send_notification",
            operation_digest=self._digest("b"),
            status="confirmed",
            metadata=caller_meta,
        )
        caller_meta["channel"] = "sms"
        caller_meta["nested"]["tags"].append("mutated")
        self.assertEqual(record.metadata["channel"], "email")
        self.assertEqual(record.metadata["nested"]["tags"], ("urgent",))

        with self.assertRaises(TypeError):
            record.metadata["channel"] = "sms"
        with self.assertRaises(AttributeError):
            record.metadata["nested"]["tags"].append("x")

        for dumped in (
            record.model_dump(),
            record.model_dump(mode="json"),
            json.loads(record.model_dump_json()),
        ):
            self.assertIs(type(dumped["metadata"]), dict)
            self.assertIs(type(dumped["metadata"]["nested"]["tags"]), list)

        self.assertEqual(deepcopy(record), record)
        copied = record.model_copy(
            update={"metadata": {"updated": [1, 2]}}, deep=True
        )
        self.assertIsInstance(copied.metadata, MappingProxyType)
        with self.assertRaises(AttributeError):
            copied.metadata["updated"].append(3)

        with self.assertRaisesRegex(ValidationError, "Effect cannot compensate itself"):
            EffectRecord(
                effect_id="eff-001",
                run_id="run-1",
                tool_name="refund",
                operation_digest=self._digest("c"),
                status="confirmed",
                compensates_effect_id="eff-001",
            )
        with self.assertRaisesRegex(ValidationError, "Effect cannot compensate itself"):
            record.model_copy(update={"compensates_effect_id": "eff-001"})

        for bad_digest in ("md5:abc", "sha256:short", "sha256:" + "G" * 64, ""):
            with self.subTest(bad_digest=bad_digest):
                with self.assertRaises(ValidationError):
                    EffectRecord(
                        effect_id="eff-001",
                        run_id="run-1",
                        tool_name="send_notification",
                        operation_digest=bad_digest,
                        status="reserved",
                    )

    def test_trajectory_entry_kind_invariants_and_no_secret_leak_on_error(self):
        digest = self._digest("d")
        valid_entries = [
            TrajectoryEntry(
                sequence=1,
                kind="reserved",
                effect_id="eff-1",
                run_id="run-1",
                policy_scope="scope.a",
                action_index=1,
                tool_name="send_notification",
                operation_digest=digest,
                status="reserved",
            ),
            TrajectoryEntry(
                sequence=2,
                kind="observed",
                effect_id="eff-1",
                run_id="run-1",
                policy_scope="scope.a",
                action_index=1,
                tool_name="send_notification",
                operation_digest=digest,
                status="uncertain",
            ),
            TrajectoryEntry(
                sequence=3,
                kind="reconciled",
                effect_id="eff-1",
                run_id="run-1",
                policy_scope="scope.a",
                tool_name="send_notification",
                operation_digest=digest,
                status="confirmed",
                evidence_ref="audit-ticket-42",
            ),
            TrajectoryEntry(
                sequence=4,
                kind="compensated",
                effect_id="eff-2",
                run_id="run-1",
                policy_scope="scope.a",
                tool_name="revoke_notification",
                operation_digest=self._digest("e"),
                status="confirmed",
                compensates_effect_id="eff-1",
                evidence_ref="comp-ticket-9",
            ),
        ]
        self.assertEqual([e.sequence for e in valid_entries], [1, 2, 3, 4])

        invalid_cases = (
            {"kind": "reserved", "status": "confirmed"},
            {"kind": "reserved", "status": "reserved", "compensates_effect_id": "eff-0"},
            {"kind": "observed", "status": "reserved"},
            {"kind": "observed", "status": "confirmed", "compensates_effect_id": "eff-0"},
            {"kind": "reconciled", "status": "uncertain", "evidence_ref": "ev-1"},
            {"kind": "reconciled", "status": "confirmed", "evidence_ref": None},
            {
                "kind": "reconciled",
                "status": "confirmed",
                "evidence_ref": "ev-1",
                "compensates_effect_id": "eff-0",
            },
            {"kind": "compensated", "status": "uncertain", "compensates_effect_id": "eff-0"},
            {"kind": "compensated", "status": "confirmed", "compensates_effect_id": None},
            {"kind": "compensated", "status": "confirmed", "compensates_effect_id": "eff-1"},
            {"kind": "reserved", "status": "reserved", "sequence": 0},
            {"kind": "reserved", "status": "reserved", "sequence": True},
        )
        secret_sentinel = "SECRET_TRAJECTORY_PAYLOAD_9911"
        for overrides in invalid_cases:
            with self.subTest(overrides=overrides):
                payload = {
                    "sequence": 1,
                    "kind": "reserved",
                    "effect_id": "eff-1",
                    "run_id": "run-1",
                    "tool_name": "send_notification",
                    "operation_digest": digest,
                    "status": "reserved",
                    "metadata": {"secret": secret_sentinel},
                    **overrides,
                }
                with self.assertRaises(ValidationError) as ctx:
                    TrajectoryEntry.model_validate(payload)
                self.assertNotIn(secret_sentinel, str(ctx.exception))

    def test_trajectory_view_ordering_scope_suspension_and_deep_immutability(self):
        d1 = self._digest("1")
        d2 = self._digest("2")
        e1 = TrajectoryEntry(
            sequence=1,
            kind="reserved",
            effect_id="eff-1",
            run_id="run-1",
            policy_scope="scope.a",
            action_index=1,
            tool_name="send_notification",
            operation_digest=d1,
            status="reserved",
        )
        e2 = TrajectoryEntry(
            sequence=2,
            kind="observed",
            effect_id="eff-1",
            run_id="run-1",
            policy_scope="scope.a",
            action_index=1,
            tool_name="send_notification",
            operation_digest=d1,
            status="confirmed",
        )
        e3 = TrajectoryEntry(
            sequence=3,
            kind="observed",
            effect_id="eff-2",
            run_id="run-2",
            policy_scope="scope.a",
            action_index=1,
            tool_name="send_notification",
            operation_digest=d2,
            status="uncertain",
        )
        r1 = EffectRecord(
            effect_id="eff-1",
            run_id="run-1",
            policy_scope="scope.a",
            action_index=1,
            tool_name="send_notification",
            operation_digest=d1,
            status="confirmed",
        )
        r2 = EffectRecord(
            effect_id="eff-2",
            run_id="run-2",
            policy_scope="scope.a",
            action_index=1,
            tool_name="send_notification",
            operation_digest=d2,
            status="uncertain",
        )

        entries_list = [e1, e2, e3]
        effects_list = [r1, r2]
        view = TrajectoryView(
            policy_scope="scope.a",
            entries=entries_list,
            effects=effects_list,
            suspended=True,
            uncertain_effect_ids=("eff-2",),
        )
        entries_list.clear()
        effects_list.clear()
        self.assertEqual(len(view.entries), 3)
        self.assertEqual(len(view.effects), 2)
        self.assertIsInstance(view.entries, tuple)
        self.assertIsInstance(view.effects, tuple)
        self.assertIsInstance(view.uncertain_effect_ids, tuple)
        self.assertEqual(view.effect_by_id("eff-1"), r1)
        self.assertIsNone(view.effect_by_id("eff-missing"))
        self.assertEqual(view.effects_by_status("uncertain"), (r2,))
        self.assertEqual(view.effects_by_status("reserved"), ())

        with self.assertRaises(AttributeError):
            view.entries.append(e1)  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            view.effects.append(r1)  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            view.uncertain_effect_ids.append("eff-1")  # type: ignore[attr-defined]

        for dumped in (
            view.model_dump(),
            view.model_dump(mode="json"),
            json.loads(view.model_dump_json()),
        ):
            self.assertIs(type(dumped["entries"]), list)
            self.assertIs(type(dumped["effects"]), list)
            self.assertIs(type(dumped["uncertain_effect_ids"]), list)
        self.assertEqual(view, TrajectoryView.model_validate_json(view.model_dump_json()))
        self.assertEqual(deepcopy(view), view)

        # Invariant rejections
        with self.assertRaisesRegex(ValidationError, "must be suspended"):
            TrajectoryView(
                policy_scope="scope.a",
                entries=[e1, e2, e3],
                effects=[r1, r2],
                suspended=False,
                uncertain_effect_ids=["eff-2"],
            )
        with self.assertRaisesRegex(ValidationError, "must be suspended"):
            view.model_copy(update={"suspended": False})

        with self.assertRaisesRegex(ValidationError, "strictly increasing"):
            TrajectoryView(entries=[e2, e1])

        with self.assertRaisesRegex(ValidationError, "Duplicate effect_id"):
            TrajectoryView(effects=[r1, r1])

        with self.assertRaisesRegex(ValidationError, "must not contain duplicates"):
            TrajectoryView(
                effects=[r2],
                suspended=True,
                uncertain_effect_ids=["eff-2", "eff-2"],
            )

        with self.assertRaisesRegex(ValidationError, "must match uncertain effects"):
            TrajectoryView(effects=[r2], suspended=True, uncertain_effect_ids=[])

        wrong_scope_effect = r1.model_copy(update={"policy_scope": "scope.b"})
        with self.assertRaisesRegex(ValidationError, "does not match view policy_scope"):
            TrajectoryView(policy_scope="scope.a", effects=[wrong_scope_effect])

        wrong_scope_entry = e1.model_copy(update={"policy_scope": "scope.b"})
        with self.assertRaisesRegex(ValidationError, "does not match view policy_scope"):
            TrajectoryView(policy_scope="scope.a", entries=[wrong_scope_entry])


class GovernorInputV3AndTrajectoryTests(unittest.TestCase):
    def test_legacy_dumps_omit_policy_scope_trajectory_and_violation_rule_type(self):
        request = GovernorInput.model_validate(input_data("runtime"))
        dumped = request.model_dump()
        dumped_json = request.model_dump_json()
        self.assertNotIn("policy_scope", dumped)
        self.assertNotIn("trajectory", dumped)
        self.assertNotIn('"policy_scope"', dumped_json)
        self.assertNotIn('"trajectory"', dumped_json)

        legacy_violation = Violation(
            rule="tool.declared_only", phase="runtime", action="send_notification"
        )
        self.assertNotIn("rule_type", legacy_violation.model_dump())
        self.assertNotIn('"rule_type"', legacy_violation.model_dump_json())

        v3_violation = Violation(
            rule="declared-tools",
            rule_type="tool.declared_only",
            phase="runtime",
            action="send_notification",
        )
        self.assertEqual(v3_violation.model_dump()["rule_type"], "tool.declared_only")
        self.assertEqual(
            v3_violation, Violation.model_validate_json(v3_violation.model_dump_json())
        )

    def test_policy_scope_agreement_and_deeply_frozen_evaluation_views(self):
        view_a = TrajectoryView(policy_scope="scope.alpha")
        view_b = TrajectoryView(policy_scope="scope.beta")

        conflict = input_data("runtime")
        conflict["policy_scope"] = "scope.alpha"
        conflict["trajectory"] = view_b
        with self.assertRaisesRegex(
            ValidationError,
            r"trajectory\.policy_scope conflicts with policy_scope",
        ):
            GovernorInput.model_validate(conflict)

        # Agreeing scope + v3 contract freezes all four ExecutionContext container fields
        caller_tools = ["send_notification"]
        caller_props = {"summary": {"items": [1, 2]}}
        caller_outcomes = ["none"]
        caller_ctx = ExecutionContext(
            state={"nested": [1]},
            available_tools=caller_tools,
            final_properties=caller_props,
            forbidden_outcomes_triggered=caller_outcomes,
        )
        request = GovernorInput(
            run_id="run-v3-view",
            contract=ContractRulesV3.model_validate(v3_contract_data()),
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=caller_ctx,
            action=ActionProposal(tool_name="send_notification"),
            policy_scope="scope.alpha",
            trajectory=view_a,
        )

        # Standalone caller_ctx remains mutable; request.context is detached and deeply frozen
        caller_tools.append("extra_tool")
        caller_props["summary"]["items"].append(3)
        caller_outcomes.append("bad_outcome")

        self.assertEqual(request.context.available_tools, ("send_notification",))
        self.assertEqual(request.context.final_properties["summary"]["items"], (1, 2))
        self.assertEqual(request.context.forbidden_outcomes_triggered, ("none",))

        with self.assertRaises(TypeError):
            request.context.state["x"] = 1
        with self.assertRaises(AttributeError):
            request.context.available_tools.append("hack")  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            request.context.final_properties["x"] = 1
        with self.assertRaises(AttributeError):
            request.context.final_properties["summary"]["items"].append(9)
        with self.assertRaises(AttributeError):
            request.context.forbidden_outcomes_triggered.append("hack")  # type: ignore[attr-defined]

        for dumped in (
            request.model_dump(),
            request.model_dump(mode="json"),
            json.loads(request.model_dump_json()),
        ):
            self.assertIs(type(dumped["context"]["available_tools"]), list)
            self.assertIs(type(dumped["context"]["final_properties"]), dict)
            self.assertIs(type(dumped["context"]["forbidden_outcomes_triggered"]), list)

        self.assertEqual(
            request, GovernorInput.model_validate_json(request.model_dump_json())
        )
        self.assertEqual(request.model_copy(deep=True), request)
        with self.assertRaisesRegex(
            ValueError, r"trajectory\.policy_scope conflicts with policy_scope"
        ):
            request.model_copy(update={"trajectory": view_b})


class ApprovalAndEvidenceModelTests(unittest.TestCase):
    def _digest(self, seed: str = "a") -> str:
        return "sha256:" + (seed * 64)[:64]

    def test_utc_timestamp_parsing_and_no_secret_leak_in_traceback(self):
        import traceback

        dt_z = _parse_utc_timestamp("2026-11-27T10:30:00Z")
        dt_offset = _parse_utc_timestamp("2026-11-27T04:30:00-06:00")
        self.assertEqual(dt_z, dt_offset)

        sentinel = "SECRET_TS_PAYLOAD_T_8811"
        for bad_ts in (
            "2026-11-27",
            "2026-11-27 10:30:00Z",
            "2026-11-27T10:30:00",
            " 2026-11-27T10:30:00Z ",
            "2026-11-27t10:30:00Z",
            sentinel,
            "",
        ):
            with self.subTest(bad_ts=bad_ts):
                try:
                    _parse_utc_timestamp(bad_ts)
                    self.fail("Expected ValueError")
                except ValueError as err:
                    self.assertIsNone(err.__cause__)
                    self.assertNotIn(sentinel, str(err))
                    self.assertNotIn(sentinel, traceback.format_exc())

    def test_host_approval_immutability_window_authorities_and_no_secret_leak(self):
        caller_authorities = ["finance.approve", "ops.approve"]
        caller_meta = {"ticket": "INC-1", "nested": {"tags": ["p1"]}}
        approval = HostApproval(
            approval_id="app-001",
            operation_digest=self._digest("1"),
            requester_id="user:alice@example.com",
            approver_id="user:bob@example.com",
            approver_authorities=caller_authorities,
            policy_scope="scope.finance",
            issued_at="2026-11-27T10:00:00Z",
            expires_at="2026-11-27T08:00:00-03:00",  # 11:00Z > 10:00Z
            metadata=caller_meta,
        )
        caller_authorities.append("admin")
        caller_meta["nested"]["tags"].append("mutated")

        self.assertEqual(approval.approver_authorities, ("finance.approve", "ops.approve"))
        self.assertEqual(approval.metadata["nested"]["tags"], ("p1",))
        self.assertIsInstance(approval.approver_authorities, tuple)
        self.assertIsInstance(approval.metadata, MappingProxyType)

        # Empty approver_authorities is valid at schema level
        no_auth = approval.model_copy(update={"approver_authorities": ()})
        self.assertEqual(no_auth.approver_authorities, ())

        with self.assertRaises(AttributeError):
            approval.approver_authorities.append("admin")  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            approval.metadata["ticket"] = "INC-2"
        with self.assertRaises(AttributeError):
            approval.metadata["nested"]["tags"].append("p2")

        for dumped in (
            approval.model_dump(),
            approval.model_dump(mode="json"),
            json.loads(approval.model_dump_json()),
        ):
            self.assertIs(type(dumped["approver_authorities"]), list)
            self.assertIs(type(dumped["metadata"]), dict)
            self.assertIs(type(dumped["metadata"]["nested"]["tags"]), list)

        self.assertEqual(deepcopy(approval), approval)
        self.assertEqual(
            approval, HostApproval.model_validate_json(approval.model_dump_json())
        )

        # Equal or earlier expires_at (including timezone offset equivalence) rejected
        for bad_expires in (
            "2026-11-27T10:00:00Z",
            "2026-11-27T12:00:00+02:00",  # 10:00Z == issued_at
            "2026-11-27T09:59:59Z",
        ):
            with self.subTest(bad_expires=bad_expires):
                with self.assertRaisesRegex(
                    ValidationError, "expires_at must be strictly after issued_at"
                ):
                    approval.model_copy(update={"expires_at": bad_expires})

        # Duplicate authorities rejected
        with self.assertRaisesRegex(ValidationError, "must not contain duplicates"):
            approval.model_copy(update={"approver_authorities": ["ops", "ops"]})

        sentinel = "SECRET_APPROVAL_META_9988"
        with self.assertRaises(ValidationError) as ctx:
            HostApproval(
                approval_id="bad id!",
                operation_digest=self._digest("1"),
                requester_id="alice",
                approver_id="bob",
                policy_scope="scope.finance",
                issued_at="2026-11-27T10:00:00Z",
                expires_at="2026-11-27T11:00:00Z",
                metadata={"secret": sentinel},
            )
        self.assertNotIn(sentinel, str(ctx.exception))

    def test_retrieved_evidence_approval_state_and_trajectory_view_approvals(self):
        self.assertIn("relevance", RetrievedEvidence.__doc__ or "")
        ev_meta = {"chunk": [1, 2]}
        ev = RetrievedEvidence(
            evidence_id="doc:kb/policy-1",
            source="kb.internal",
            content_digest=self._digest("c"),
            retrieved_at="2026-11-27T10:00:00Z",
            metadata=ev_meta,
        )
        ev_meta["chunk"].append(3)
        self.assertEqual(ev.metadata["chunk"], (1, 2))
        with self.assertRaises(TypeError):
            ev.metadata["x"] = 1
        self.assertEqual(deepcopy(ev), ev)
        self.assertEqual(
            ev, RetrievedEvidence.model_validate_json(ev.model_dump_json())
        )

        # Stage 2 TrajectoryView without approvals omits 'approvals' key on dump
        empty_view = TrajectoryView(policy_scope="scope.a")
        self.assertEqual(empty_view.approvals, ())
        self.assertNotIn("approvals", empty_view.model_dump())
        self.assertNotIn('"approvals"', empty_view.model_dump_json())

        # EffectRecord & TrajectoryEntry omit approval_id when None, include when set
        eff_no_app = EffectRecord(
            effect_id="eff-1",
            run_id="run-1",
            policy_scope="scope.a",
            tool_name="send_notification",
            operation_digest=self._digest("1"),
            status="confirmed",
        )
        self.assertNotIn("approval_id", eff_no_app.model_dump())
        eff_with_app = eff_no_app.model_copy(update={"approval_id": "app-1"})
        self.assertEqual(eff_with_app.approval_id, "app-1")
        self.assertEqual(eff_with_app.model_dump()["approval_id"], "app-1")

        app_state = ApprovalStateRecord(
            approval_id="app-1",
            operation_digest=self._digest("1"),
            policy_scope="scope.a",
            status="consumed",
            effect_id="eff-1",
            single_use=True,
            retry_count=0,
        )
        view_with_app = TrajectoryView(
            policy_scope="scope.a",
            effects=[eff_with_app],
            approvals=[app_state],
        )
        self.assertEqual(view_with_app.approval_by_id("app-1"), app_state)
        self.assertIsNone(view_with_app.approval_by_id("app-missing"))
        self.assertIs(type(view_with_app.model_dump()["approvals"]), list)
        self.assertEqual(
            view_with_app,
            TrajectoryView.model_validate_json(view_with_app.model_dump_json()),
        )

        with self.assertRaisesRegex(ValidationError, "Duplicate approval_id"):
            TrajectoryView(
                policy_scope="scope.a", approvals=[app_state, app_state]
            )
        with self.assertRaisesRegex(
            ValidationError, "approval policy_scope does not match"
        ):
            TrajectoryView(
                policy_scope="scope.b", approvals=[app_state]
            )


class GovernorInputAuthorizationTests(unittest.TestCase):
    def _approval(self, approval_id: str = "app-1") -> HostApproval:
        return HostApproval(
            approval_id=approval_id,
            operation_digest="sha256:" + "a" * 64,
            requester_id="alice",
            approver_id="bob",
            approver_authorities=["ops.approve"],
            policy_scope="scope.ops",
            issued_at="2026-11-27T10:00:00Z",
            expires_at="2026-11-27T11:00:00Z",
        )

    def test_legacy_dump_omission_runtime_only_approval_and_strict_agreement(self):
        legacy = GovernorInput.model_validate(input_data("runtime"))
        dumped = legacy.model_dump()
        for key in ("requester_id", "evaluated_at", "approval", "retrieved_evidence"):
            self.assertNotIn(key, dumped)

        for phase in ("pre_execution", "post_execution"):
            with self.subTest(phase=phase):
                bad = input_data(phase)
                bad["approval"] = self._approval()
                with self.assertRaisesRegex(
                    ValidationError,
                    "approval is only accepted for runtime evaluation",
                ):
                    GovernorInput.model_validate(bad)

        secret_id = "SECRET_FOREIGN_APPROVAL_ID_4411"
        conflict_app = input_data("runtime")
        conflict_app["approval"] = self._approval("app-expected")
        conflict_app["host_facts"] = {"facts": {"approval_id": secret_id}}
        with self.assertRaises(ValidationError) as ctx_app:
            GovernorInput.model_validate(conflict_app)
        self.assertIn(
            "host_facts conflicts with approval for key: approval_id",
            str(ctx_app.exception),
        )
        self.assertNotIn(secret_id, str(ctx_app.exception))

        secret_req = "SECRET_REQUESTER_9922"
        conflict_req = input_data("runtime")
        conflict_req["requester_id"] = "alice"
        conflict_req["host_facts"] = {"facts": {"requester_id": secret_req}}
        with self.assertRaises(ValidationError) as ctx_req:
            GovernorInput.model_validate(conflict_req)
        self.assertIn(
            "host_facts conflicts with requester_id for key: requester_id",
            str(ctx_req.exception),
        )
        self.assertNotIn(secret_req, str(ctx_req.exception))

        ev_list = [RetrievedEvidence(evidence_id="ev-1", source="kb")]
        caller_ctx = ExecutionContext(
            state={"k": [1]}, available_tools=["send_notification"]
        )
        valid = GovernorInput(
            run_id="run-auth",
            contract=ContractRulesV3.model_validate(v3_contract_data()),
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=caller_ctx,
            action=ActionProposal(tool_name="send_notification"),
            requester_id="alice",
            evaluated_at="2026-11-27T10:05:00Z",
            approval=self._approval("app-1"),
            host_facts=HostFacts(
                facts={"approval_id": "app-1", "requester_id": "alice"}
            ),
            retrieved_evidence=ev_list,
        )
        ev_list.clear()
        assert valid.retrieved_evidence is not None
        self.assertEqual(len(valid.retrieved_evidence), 1)
        self.assertIsInstance(valid.retrieved_evidence, tuple)
        self.assertIsInstance(valid.context.state, MappingProxyType)
        self.assertIs(type(valid.model_dump()["retrieved_evidence"]), list)
        self.assertEqual(
            valid, GovernorInput.model_validate_json(valid.model_dump_json())
        )

        copied = valid.model_copy(
            update={
                "retrieved_evidence": [
                    RetrievedEvidence(evidence_id="ev-2", source="kb")
                ]
            }
        )
        self.assertIsInstance(copied.retrieved_evidence, tuple)


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


class PublicApiTests(unittest.TestCase):
    def test_v041_stage1_and_stage2_exports_are_available_and_listed_in_all(self):
        import vogtcon
        from vogtcon import contracts, effects, models, records, rules

        historical_exports = (
            "load_contract",
            "DeterministicEvaluator",
            "Governor",
            "GovernorEvaluator",
            "GovernedToolExecutor",
            "ToolExecutionOutcome",
            "WorkflowController",
            "RuleCatalog",
            "DEFAULT_RULE_CATALOG",
            "JsonlDecisionLog",
            "RunEvent",
            "RunRecorder",
            "TelemetryObserver",
            "ActionProposal",
            "AgentContract",
            "ContractDocument",
            "ContractRulesV2",
            "EnforcementPolicy",
            "ExecutionContext",
            "GovernanceDecision",
            "GovernorInput",
            "Violation",
        )
        stage1_exports = (
            "compute_v3_contract_fingerprint",
            "ContractRulesV3",
            "HostFacts",
            "OPERATION_DIGEST_EXCLUDED_METADATA",
            "OPERATION_IDENTITY_VERSION",
            "PlannedEffect",
            "RuleBinding",
            "DEFAULT_RULE_TYPES",
            "EmptyRuleParams",
            "RuleTypeSpec",
        )
        stage2_model_exports = (
            "EffectEventKind",
            "EffectId",
            "EffectRecord",
            "EffectStatus",
            "PolicyScopeId",
            "ReconciliationStatus",
            "TrajectoryEntry",
            "TrajectoryView",
        )
        stage2_effects_exports = (
            "CompensationRecord",
            "ConcurrencyError",
            "EffectGovernanceConfig",
            "EffectGovernanceError",
            "EffectObservationError",
            "EffectObserver",
            "EffectResolutionError",
            "EffectResolver",
            "EffectStore",
            "InMemoryEffectStore",
            "ObservationInput",
            "ObservedEffect",
            "ReconciliationError",
            "ReconciliationRecord",
            "ResolvedAction",
            "ScopeSuspendedError",
        )
        stage2_records_exports = (
            "RecordedEvent",
            "RunEventV2",
            "parse_run_event",
        )
        stage2_rules_exports = ("V3RuleHandler",)
        stage2_exports = (
            stage2_model_exports
            + stage2_effects_exports
            + stage2_records_exports
            + stage2_rules_exports
        )
        stage3_model_exports = (
            "ApprovalId",
            "ApprovalStateRecord",
            "ApprovalStatus",
            "ApprovalUsageStatus",
            "EvidenceId",
            "HostApproval",
            "PrincipalId",
            "RetrievedEvidence",
            "TimestampStr",
        )
        stage3_effects_exports = ("ApprovalReuseError",)
        stage3_rules_exports = (
            "BoundApprovalParams",
            "DestinationAllowlistParams",
            "RetrievedEvidenceParams",
        )
        stage3_exports = (
            stage3_model_exports
            + stage3_effects_exports
            + stage3_rules_exports
        )

        self.assertEqual(len(historical_exports), 22)
        self.assertEqual(len(stage1_exports), 10)
        self.assertEqual(len(stage2_exports), 28)
        self.assertEqual(len(stage3_exports), 13)
        self.assertEqual(len(vogtcon.__all__), 73)
        self.assertEqual(len(set(vogtcon.__all__)), 73)
        self.assertEqual(
            set(vogtcon.__all__),
            set(historical_exports)
            | set(stage1_exports)
            | set(stage2_exports)
            | set(stage3_exports),
        )

        for name in (
            historical_exports + stage1_exports + stage2_exports + stage3_exports
        ):
            with self.subTest(symbol=name):
                self.assertIn(name, vogtcon.__all__)
                self.assertTrue(hasattr(vogtcon, name))

        self.assertIs(
            vogtcon.compute_v3_contract_fingerprint,
            contracts.compute_v3_contract_fingerprint,
        )
        for name in (
            "ContractRulesV3",
            "HostFacts",
            "OPERATION_DIGEST_EXCLUDED_METADATA",
            "OPERATION_IDENTITY_VERSION",
            "PlannedEffect",
            "RuleBinding",
            *stage2_model_exports,
            *stage3_model_exports,
        ):
            self.assertIs(getattr(vogtcon, name), getattr(models, name))
        for name in (
            "DEFAULT_RULE_TYPES",
            "EmptyRuleParams",
            "RuleTypeSpec",
            *stage2_rules_exports,
            *stage3_rules_exports,
        ):
            self.assertIs(getattr(vogtcon, name), getattr(rules, name))
        for name in (*stage2_effects_exports, *stage3_effects_exports):
            self.assertIs(getattr(vogtcon, name), getattr(effects, name))
        for name in stage2_records_exports:
            self.assertIs(getattr(vogtcon, name), getattr(records, name))


if __name__ == "__main__":
    unittest.main()
