# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import tempfile
import traceback
import unittest
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vogtcon import (
    ActionProposal, EnforcementPolicy, ExecutionContext, Governor,
    JsonlDecisionLog, RuleCatalog, WorkflowController, load_contract,
)
from vogtcon.contracts import (
    _UnsupportedContractRules,
    compute_v3_contract_fingerprint,
    validate_contract_rules,
)
from vogtcon.models import ContractRulesV2, ContractRulesV3
from vogtcon.rules import EmptyRuleParams, RuleTypeSpec


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
        data["schema_version"] = 4
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


class _TransferLimitParams(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )

    max_amount: int = Field(ge=1)
    currency: str = "MXN"


class _TransferLimitParamsAltDefault(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )

    max_amount: int = Field(ge=1)
    currency: str = "USD"


def _make_custom_v3_catalog(params_model: type[BaseModel] = _TransferLimitParams) -> RuleCatalog:
    return RuleCatalog(
        rule_types={
            "transfer.max_amount": RuleTypeSpec(
                allowed_phases=frozenset({"runtime"}),
                params_model=params_model,
            )
        }
    )


def v3_contract(
    rules: list[dict[str, object]] | None = None,
    rule_catalog: RuleCatalog | None = None,
) -> dict[str, object]:
    data: dict[str, object] = {
        "schema_version": 3,
        "contract_id": "example.v3",
        "approved_agent_configurations": ["sha256:agent"],
        "declared_tools": ["send_notification", "transfer_funds"],
        "response_schema": {"required_fields": ["answer"]},
        "memory_policy": "none",
        "validation_phases": ["pre_execution", "runtime", "post_execution"],
        "rules": (
            rules
            if rules is not None
            else [
                {
                    "instance_id": "declared-tools",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                    "params": {},
                },
                {
                    "instance_id": "schema-complete",
                    "rule_type": "response.schema_complete",
                    "phases": ["post_execution"],
                    "params": {},
                },
            ]
        ),
        "metadata": {"owner": "sí"},
        "contract_fingerprint": "sha256:placeholder",
    }
    typed = ContractRulesV3.model_validate(data)
    data["contract_fingerprint"] = compute_v3_contract_fingerprint(
        typed, rule_catalog=rule_catalog
    )
    return data


class ContractV3LoadingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "contract_v3.yaml"

    def load(self, text: str, rule_catalog: RuleCatalog | None = None):
        self.path.write_text(text, encoding="utf-8")
        return load_contract(self.path, rule_catalog=rule_catalog)

    def test_v3_loads_json_and_yaml_with_default_and_custom_catalog(self):
        data = v3_contract()
        for content in (
            json.dumps(data),
            yaml.safe_dump(data),
            "# comment and spacing do not affect v3 identity\n\n" + yaml.safe_dump(data),
            json.dumps(dict(reversed(list(data.items())))),
        ):
            with self.subTest(format=content[:20]):
                document = self.load(content)
                self.assertIsInstance(document.contract, ContractRulesV3)
                self.assertEqual(document.original, data)
                document.original["metadata"]["owner"] = "mutated"
                self.assertEqual(document.original, data)

        catalog = _make_custom_v3_catalog()
        custom_data = v3_contract(
            rules=[
                {
                    "instance_id": "declared-tools",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "mxn-cap",
                    "rule_type": "transfer.max_amount",
                    "phases": ["runtime"],
                    "params": {"max_amount": 1000},
                },
            ],
            rule_catalog=catalog,
        )
        doc_custom = self.load(yaml.safe_dump(custom_data), rule_catalog=catalog)
        self.assertIsInstance(doc_custom.contract, ContractRulesV3)
        self.assertEqual(doc_custom.original, custom_data)

    def test_v3_rejects_unknown_rule_types_including_legacy_argument_and_benchmark_rules(
        self,
    ):
        for bad_rule in (
            "completely.unknown",
            "sensitive_requires_approval",
            "memory.scope_allowed",
            "ticket_requires_evidence",
            "authorization.role_required",
            "run_ledger.required",
            "run_ledger.complete",
            "forbidden.outcome_triggered",
        ):
            with self.subTest(bad_rule=bad_rule):
                data = v3_contract()
                data["rules"] = [
                    {
                        "instance_id": "bad-rule",
                        "rule_type": bad_rule,
                        "phases": ["runtime"],
                    }
                ]
                with self.assertRaises(_UnsupportedContractRules) as ctx:
                    self.load(json.dumps(data))
                self.assertEqual(ctx.exception.field, "rules")
                self.assertEqual(ctx.exception.ids, [bad_rule])

    def test_v3_rejects_disallowed_phase_for_rule_type(self):
        for rule_type, bad_phase in (
            ("tool.declared_only", "post_execution"),
            ("tool.declared_only", "pre_execution"),
            ("response.schema_complete", "runtime"),
        ):
            with self.subTest(rule_type=rule_type, bad_phase=bad_phase):
                data = v3_contract()
                data["rules"] = [
                    {
                        "instance_id": "wrong-phase",
                        "rule_type": rule_type,
                        "phases": [bad_phase],
                    }
                ]
                with self.assertRaisesRegex(
                    ValueError,
                    f"Rule instance 'wrong-phase' declares unsupported phase\\(s\\) for rule_type '{rule_type}'",
                ):
                    self.load(json.dumps(data))

    def test_v3_rejects_invalid_params_without_leaking_values(self):
        catalog = _make_custom_v3_catalog()
        self.assertIsNot(
            _TransferLimitParams.model_config.get("hide_input_in_errors"),
            True,
        )
        sentinel = "SECRET_PARAM_SENTINEL_XYZ"
        for bad_params in (
            {},  # missing required max_amount
            {"max_amount": sentinel},  # wrong type
            {"max_amount": 500, "extra_secret": sentinel},  # extra field
            {"max_amount": True},  # bool coercion rejected
            {"max_amount": 0},  # ge=1 rejected
        ):
            with self.subTest(bad_params=bad_params):
                data = v3_contract(rule_catalog=catalog)
                data["rules"] = [
                    {
                        "instance_id": "limit-check",
                        "rule_type": "transfer.max_amount",
                        "phases": ["runtime"],
                        "params": bad_params,
                    }
                ]
                typed = ContractRulesV3.model_validate(data)
                for call_name, fn in (
                    (
                        "validate_contract_rules",
                        lambda: validate_contract_rules(
                            typed, rule_catalog=catalog
                        ),
                    ),
                    (
                        "load_contract",
                        lambda: self.load(
                            json.dumps(data), rule_catalog=catalog
                        ),
                    ),
                ):
                    with self.subTest(call=call_name):
                        caught: ValueError | None = None
                        formatted_tb = ""
                        try:
                            fn()
                        except ValueError as exc:
                            caught = exc
                            formatted_tb = traceback.format_exc()
                        self.assertIsNotNone(caught)
                        assert caught is not None
                        self.assertIsNone(caught.__cause__)
                        self.assertTrue(caught.__suppress_context__)
                        message = str(caught)
                        self.assertIn(
                            "Invalid parameters for rule instance 'limit-check' (rule_type 'transfer.max_amount')",
                            message,
                        )
                        self.assertNotIn(sentinel, message)
                        self.assertNotIn(sentinel, formatted_tb)

    def test_v3_rejects_duplicate_instance_id_legacy_fields_and_incomplete_phases(self):
        dup_data = v3_contract()
        dup_data["rules"] = [
            {
                "instance_id": "dup-id",
                "rule_type": "tool.declared_only",
                "phases": ["runtime"],
            },
            {
                "instance_id": "dup-id",
                "rule_type": "response.schema_complete",
                "phases": ["post_execution"],
            },
        ]
        with self.assertRaisesRegex(ValidationError, "Duplicate rule instance_id"):
            self.load(json.dumps(dup_data))

        missing_rules = v3_contract()
        missing_rules.pop("rules")
        with self.assertRaises(ValidationError):
            self.load(json.dumps(missing_rules))

        for legacy_key, legacy_val in (
            ("runtime_rules", ["tool.declared_only"]),
            ("postconditions", ["response.schema_complete"]),
            ("mode", "guarded"),
            ("agent_feedback", {}),
        ):
            with self.subTest(legacy_key=legacy_key):
                bad = v3_contract()
                bad[legacy_key] = legacy_val
                with self.assertRaises(ValidationError):
                    self.load(json.dumps(bad))

        bad_phases = v3_contract()
        bad_phases["validation_phases"] = ["runtime", "post_execution"]
        with self.assertRaisesRegex(
            ValueError, "Enforced contracts require all three validation phases"
        ):
            self.load(json.dumps(bad_phases))

    def test_v3_validation_precedence(self):
        catalog = _make_custom_v3_catalog()

        # 1. Unknown rule_type precedes disallowed phase, invalid params, incomplete phases, and bad fingerprint
        data = v3_contract(rule_catalog=catalog)
        data["validation_phases"] = ["runtime"]
        data["contract_fingerprint"] = "sha256:wrong"
        data["rules"] = [
            {
                "instance_id": "bad-phase-and-params",
                "rule_type": "transfer.max_amount",
                "phases": ["post_execution"],
                "params": {"max_amount": "bad"},
            },
            {
                "instance_id": "unknown-type",
                "rule_type": "nonexistent.rule",
                "phases": ["runtime"],
            },
        ]
        with self.assertRaises(_UnsupportedContractRules) as ctx:
            self.load(json.dumps(data), rule_catalog=catalog)
        self.assertEqual(ctx.exception.field, "rules")
        self.assertEqual(ctx.exception.ids, ["nonexistent.rule"])

        # 2. Disallowed phase precedes invalid params, incomplete phases, and bad fingerprint
        data["rules"] = [
            {
                "instance_id": "bad-phase-and-params",
                "rule_type": "transfer.max_amount",
                "phases": ["post_execution"],
                "params": {"max_amount": "bad"},
            }
        ]
        with self.assertRaisesRegex(ValueError, "declares unsupported phase"):
            self.load(json.dumps(data), rule_catalog=catalog)

        # 3. Invalid params precede incomplete phases and bad fingerprint
        data["rules"] = [
            {
                "instance_id": "bad-params",
                "rule_type": "transfer.max_amount",
                "phases": ["runtime"],
                "params": {"max_amount": "bad"},
            }
        ]
        with self.assertRaisesRegex(ValueError, "Invalid parameters for rule instance"):
            self.load(json.dumps(data), rule_catalog=catalog)

        # 4. Incomplete validation_phases precedes bad fingerprint
        data["rules"] = [
            {
                "instance_id": "ok-params",
                "rule_type": "transfer.max_amount",
                "phases": ["runtime"],
                "params": {"max_amount": 100},
            }
        ]
        with self.assertRaisesRegex(
            ValueError, "Enforced contracts require all three validation phases"
        ):
            self.load(json.dumps(data), rule_catalog=catalog)


class ContractV3FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "contract_v3.yaml"

    def load(self, text: str, rule_catalog: RuleCatalog | None = None):
        self.path.write_text(text, encoding="utf-8")
        return load_contract(self.path, rule_catalog=rule_catalog)

    def test_v3_fingerprint_equivalence_with_omitted_vs_explicit_parameter_defaults(
        self,
    ):
        catalog = _make_custom_v3_catalog(_TransferLimitParams)
        omitted_data = v3_contract(
            rules=[
                {
                    "instance_id": "limit-1",
                    "rule_type": "transfer.max_amount",
                    "phases": ["runtime"],
                    "params": {"max_amount": 250},
                }
            ],
            rule_catalog=catalog,
        )
        explicit_data = v3_contract(
            rules=[
                {
                    "instance_id": "limit-1",
                    "rule_type": "transfer.max_amount",
                    "phases": ["runtime"],
                    "params": {"currency": "MXN", "max_amount": 250},
                }
            ],
            rule_catalog=catalog,
        )
        self.assertEqual(
            omitted_data["contract_fingerprint"],
            explicit_data["contract_fingerprint"],
        )

        # Changing the parameter default in a new catalog causes load-time mismatch
        alt_catalog = _make_custom_v3_catalog(_TransferLimitParamsAltDefault)
        with self.assertRaisesRegex(ValueError, "Contract fingerprint mismatch"):
            self.load(json.dumps(omitted_data), rule_catalog=alt_catalog)

    def test_v3_fingerprint_changes_on_any_normative_field_or_binding_change(self):
        catalog = _make_custom_v3_catalog()
        base_rules = [
            {
                "instance_id": "rule-a",
                "rule_type": "tool.declared_only",
                "phases": ["runtime"],
                "params": {},
            },
            {
                "instance_id": "rule-b",
                "rule_type": "transfer.max_amount",
                "phases": ["runtime"],
                "params": {"max_amount": 100},
            },
        ]
        base = v3_contract(rules=base_rules, rule_catalog=catalog)
        base_fp = base["contract_fingerprint"]

        mutations: list[tuple[str, dict[str, object]]] = []

        for field_name, new_value in (
            ("contract_id", "example.v3.changed"),
            ("declared_tools", ["send_notification"]),
            ("response_schema", {"required_fields": ["answer", "extra"]}),
            ("memory_policy", "strict"),
            ("approved_agent_configurations", ["sha256:other"]),
            ("metadata", {"owner": "other"}),
        ):
            mutated = json.loads(json.dumps(base))
            mutated[field_name] = new_value
            mutations.append((field_name, mutated))

        # Binding order change
        reordered = json.loads(json.dumps(base))
        reordered["rules"] = list(reversed(base_rules))
        mutations.append(("binding_order", reordered))

        # instance_id change
        changed_id = json.loads(json.dumps(base))
        changed_id["rules"][0]["instance_id"] = "rule-a-renamed"
        mutations.append(("instance_id", changed_id))

        # rule_type change
        changed_type = json.loads(json.dumps(base))
        changed_type["rules"][0] = {
            "instance_id": "rule-a",
            "rule_type": "response.schema_complete",
            "phases": ["post_execution"],
            "params": {},
        }
        mutations.append(("rule_type", changed_type))

        # param value change
        changed_param = json.loads(json.dumps(base))
        changed_param["rules"][1]["params"]["max_amount"] = 101
        mutations.append(("param_value", changed_param))

        multi_phase_catalog = RuleCatalog(
            rule_types={
                "multi.phase": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime", "post_execution"}),
                    params_model=EmptyRuleParams,
                )
            }
        )
        multi_base = v3_contract(
            rules=[
                {
                    "instance_id": "m1",
                    "rule_type": "multi.phase",
                    "phases": ["runtime"],
                }
            ],
            rule_catalog=multi_phase_catalog,
        )
        multi_mutated = json.loads(json.dumps(multi_base))
        multi_mutated["rules"][0]["phases"] = ["runtime", "post_execution"]
        self.assertNotEqual(
            compute_v3_contract_fingerprint(
                ContractRulesV3.model_validate(multi_mutated),
                rule_catalog=multi_phase_catalog,
            ),
            multi_base["contract_fingerprint"],
        )
        with self.assertRaisesRegex(ValueError, "Contract fingerprint mismatch"):
            self.load(json.dumps(multi_mutated), rule_catalog=multi_phase_catalog)

        for label, candidate in mutations:
            with self.subTest(mutation=label):
                new_fp = compute_v3_contract_fingerprint(
                    ContractRulesV3.model_validate(candidate),
                    rule_catalog=catalog,
                )
                self.assertNotEqual(new_fp, base_fp)
                with self.assertRaisesRegex(
                    ValueError, "Contract fingerprint mismatch"
                ):
                    self.load(json.dumps(candidate), rule_catalog=catalog)

    def test_compute_v3_contract_fingerprint_rejects_non_v3_and_invalid_contracts(self):
        v2_doc = ContractRulesV2.model_validate(v2_contract())
        with self.assertRaisesRegex(TypeError, "Expected a ContractRulesV3 instance"):
            compute_v3_contract_fingerprint(v2_doc)  # type: ignore[arg-type]

        invalid_v3 = ContractRulesV3.model_validate(
            {
                **v3_contract(),
                "rules": [
                    {
                        "instance_id": "unknown-rule",
                        "rule_type": "unknown.rule",
                        "phases": ["runtime"],
                    }
                ],
            }
        )
        with self.assertRaises(_UnsupportedContractRules):
            compute_v3_contract_fingerprint(invalid_v3)


class LegacyIdentityRegressionTests(unittest.TestCase):
    def test_pinned_v2_and_v1_fingerprints_remain_unchanged(self):
        example_path = (
            Path(__file__).resolve().parents[1]
            / "examples"
            / "notification_contract_v2.yaml"
        )
        example_doc = load_contract(example_path)
        self.assertEqual(
            example_doc.contract.contract_fingerprint,
            "sha256:ad61db75c5b4ba43868b51cf287180e7b79adf846a012611178ff6382c692cff",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            v2_path = Path(tmpdir) / "v2.json"
            v2_data = v2_contract()
            v2_path.write_text(json.dumps(v2_data), encoding="utf-8")
            v2_doc = load_contract(v2_path)
            self.assertEqual(
                v2_doc.contract.contract_fingerprint,
                "sha256:5a92de44c4a3d327a2ada6e67a5cb56be3264477313285900daaaf90457776fa",
            )

            v1_path = Path(tmpdir) / "v1.json"
            v1_data = example_contract()
            v1_data["contract_fingerprint"] = "arbitrary-unverified-v1-fingerprint"
            v1_path.write_text(json.dumps(v1_data), encoding="utf-8")
            v1_doc = load_contract(v1_path)
            self.assertEqual(
                v1_doc.contract.contract_fingerprint,
                "arbitrary-unverified-v1-fingerprint",
            )


if __name__ == "__main__":
    unittest.main()
