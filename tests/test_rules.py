# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vogtcon import (
    ActionProposal,
    DeterministicEvaluator,
    ExecutionContext,
    Governor,
    GovernorInput,
    RuleCatalog,
    Violation,
    load_contract,
)
from vogtcon.rules import (
    DEFAULT_POSTCONDITIONS,
    DEFAULT_RULE_CATALOG,
    DEFAULT_RULE_TYPES,
    DEFAULT_RUNTIME_RULES,
    POSTCONDITIONS,
    RUNTIME_RULES,
    BoundApprovalParams,
    DestinationAllowlistParams,
    EmptyRuleParams,
    RetrievedEvidenceParams,
    RuleTypeSpec,
)


def make_contract(
    mode="guarded",
    runtime_rules=None,
    postconditions=None,
    declared_tools=None,
):
    return {
        "contract_id": f"example.{mode}",
        "mode": mode,
        "approved_agent_configurations": ["agent-cfg"],
        "declared_tools": declared_tools if declared_tools is not None else ["search", "custom_action"],
        "response_schema": {"required_fields": ["status", "body"]},
        "memory_policy": "allowed-scope-only",
        "validation_phases": "not_enforced" if mode == "no_contract" else ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": list(runtime_rules) if runtime_rules is not None else list(RUNTIME_RULES),
        "postconditions": list(postconditions) if postconditions is not None else list(POSTCONDITIONS),
        "agent_feedback": {
            "advisory_warning_visibility": False,
            "guarded_denial_style": "minimal",
            "strict_replanning_after_violation": False,
        },
        "contract_fingerprint": "contract-fp",
    }


def make_request(
    phase="runtime",
    mode="guarded",
    contract=None,
    tool_name="search",
    arguments=None,
    state=None,
    response=None,
    run_ledger=None,
):
    data = {
        "run_id": "test-run",
        "contract": contract if contract is not None else make_contract(mode=mode),
        "phase": phase,
        "context": {
            "state": state if state is not None else {},
            "available_tools": ["search", "custom_action"],
            "observed_agent_fingerprint": "agent-cfg",
            "observed_contract_fingerprint": "contract-fp",
        },
    }
    if phase == "runtime":
        data["action"] = {"tool_name": tool_name, "arguments": arguments if arguments is not None else {}}
    elif phase == "post_execution":
        data["response"] = response if response is not None else {"status": "ok", "body": "done"}
        data["run_ledger"] = run_ledger if run_ledger is not None else {
            "run_id": "test-run", "scenario_id": "s1", "mode": mode, "contract_id": "c1",
            "provider": "p", "model_id": "m", "replication_id": "r", "actions": [], "artifacts": [],
        }
    return GovernorInput.model_validate(data)


class RuleCatalogTests(unittest.TestCase):
    def test_default_catalog_order_and_vocabulary(self):
        catalog = RuleCatalog()
        self.assertEqual(tuple(catalog.runtime_rules.keys()), RUNTIME_RULES)
        self.assertEqual(tuple(catalog.postconditions.keys()), POSTCONDITIONS)
        self.assertEqual(tuple(DEFAULT_RULE_CATALOG.runtime_rules.keys()), tuple(DEFAULT_RUNTIME_RULES.keys()))
        self.assertEqual(tuple(DEFAULT_RULE_CATALOG.postconditions.keys()), tuple(DEFAULT_POSTCONDITIONS.keys()))

    def test_builtin_rule_ids_cannot_be_shadowed(self):
        with self.assertRaisesRegex(ValueError, "Cannot replace built-in rule 'sensitive_requires_approval'"):
            RuleCatalog(runtime_rules={"sensitive_requires_approval": lambda _r: False})
        with self.assertRaisesRegex(ValueError, "Cannot replace built-in rule 'response.schema_complete'"):
            RuleCatalog(postconditions={"response.schema_complete": lambda _r: False})
        with self.assertRaises(TypeError):
            DEFAULT_RUNTIME_RULES["sensitive_requires_approval"] = lambda _r: False

    def test_custom_catalog_keeps_historical_rules_available(self):
        catalog = RuleCatalog(runtime_rules={"custom.flag": lambda _r: False})
        self.assertIn("sensitive_requires_approval", catalog.runtime_rules)
        self.assertIn("response.schema_complete", catalog.postconditions)

    def test_injected_positive_custom_runtime_and_post_rules(self):
        def check_no_danger_arg(req: GovernorInput) -> bool:
            assert req.action is not None
            return bool(req.action.arguments.get("danger", False))

        def check_body_not_empty(req: GovernorInput) -> bool:
            assert req.response is not None
            return req.response.get("body") == ""

        custom_catalog = RuleCatalog(
            runtime_rules={**DEFAULT_RUNTIME_RULES, "action.safe_parameters": check_no_danger_arg},
            postconditions={**DEFAULT_POSTCONDITIONS, "response.body_nonempty": check_body_not_empty},
        )
        evaluator = DeterministicEvaluator(rule_catalog=custom_catalog)

        contract = make_contract(
            runtime_rules=["action.safe_parameters"],
            postconditions=["response.body_nonempty"],
        )

        req_runtime_fail = make_request(
            phase="runtime", contract=contract, tool_name="custom_action", arguments={"danger": True}
        )
        decision = evaluator.evaluate(req_runtime_fail)
        self.assertEqual(decision.decision, "block")
        self.assertEqual([v.rule for v in decision.violations], ["action.safe_parameters"])
        self.assertEqual(decision.violations[0].action, "custom_action")

        req_runtime_pass = make_request(
            phase="runtime", contract=contract, tool_name="custom_action", arguments={"danger": False}
        )
        self.assertEqual(evaluator.evaluate(req_runtime_pass).decision, "allow")

        req_post_fail = make_request(
            phase="post_execution", contract=contract, response={"status": "ok", "body": ""}
        )
        post_decision = evaluator.evaluate(req_post_fail)
        self.assertEqual([v.rule for v in post_decision.violations], ["response.body_nonempty"])

    def test_custom_rule_returns_violation_object(self):
        def explicit_violation_rule(req: GovernorInput) -> Violation | None:
            assert req.action is not None
            if req.action.tool_name == "custom_action":
                return Violation(rule="custom.explicit", phase="runtime", severity="high", action="custom_action")
            return None

        catalog = RuleCatalog(runtime_rules={"custom.explicit": explicit_violation_rule})
        evaluator = DeterministicEvaluator(rule_catalog=catalog)
        contract = make_contract(runtime_rules=["custom.explicit"], postconditions=[])
        req = make_request(phase="runtime", contract=contract, tool_name="custom_action")
        decision = evaluator.evaluate(req)
        self.assertEqual(len(decision.violations), 1)
        self.assertEqual(decision.violations[0].rule, "custom.explicit")

    def test_invalid_rule_output_and_wrong_phase_raise_errors(self):
        def wrong_phase_rule(_req: GovernorInput):
            return Violation(rule="bad_phase", phase="post_execution")

        def invalid_type_rule(_req: GovernorInput):
            return "violated"

        catalog_bad_phase = RuleCatalog(runtime_rules={"bad_phase": wrong_phase_rule})
        evaluator_bad_phase = DeterministicEvaluator(rule_catalog=catalog_bad_phase)
        req1 = make_request(
            contract=make_contract(runtime_rules=["bad_phase"], postconditions=[]),
            tool_name="custom_action",
        )
        with self.assertRaisesRegex(ValueError, "expected 'runtime'"):
            evaluator_bad_phase.evaluate(req1)

        catalog_invalid = RuleCatalog(runtime_rules={"bad_type": invalid_type_rule})
        evaluator_invalid = DeterministicEvaluator(rule_catalog=catalog_invalid)
        req2 = make_request(
            contract=make_contract(runtime_rules=["bad_type"], postconditions=[]),
            tool_name="custom_action",
        )
        with self.assertRaisesRegex(ValueError, "invalid output of type"):
            evaluator_invalid.evaluate(req2)

        catalog_wrong_rule = RuleCatalog(
            runtime_rules={"selected.rule": lambda _req: Violation(rule="other.rule", phase="runtime")}
        )
        req3 = make_request(
            contract=make_contract(runtime_rules=["selected.rule"], postconditions=[]),
            tool_name="custom_action",
        )
        with self.assertRaisesRegex(ValueError, "produced violation for"):
            DeterministicEvaluator(rule_catalog=catalog_wrong_rule).evaluate(req3)

        catalog_wrong_action = RuleCatalog(
            runtime_rules={"selected.rule": lambda _req: Violation(
                rule="selected.rule", phase="runtime", action="other_tool"
            )}
        )
        with self.assertRaisesRegex(ValueError, "expected 'custom_action'"):
            DeterministicEvaluator(rule_catalog=catalog_wrong_action).evaluate(req3)

    def test_unknown_and_cross_phase_rules_fail_validation(self):
        catalog = RuleCatalog(
            runtime_rules={"custom.runtime": lambda _r: None},
            postconditions={"custom.post": lambda _r: None},
        )
        evaluator = DeterministicEvaluator(rule_catalog=catalog)

        req_cross = make_request(
            contract=make_contract(runtime_rules=["custom.post"], postconditions=[]),
            tool_name="search",
        )
        with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
            evaluator.evaluate(req_cross)

        for mode in ("no_contract", "guarded"):
            req_unknown = make_request(
                mode=mode,
                contract=make_contract(mode=mode, runtime_rules=["completely_unknown"], postconditions=[]),
                tool_name="search",
            )
            with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
                evaluator.evaluate(req_unknown)

    def test_no_contract_bypasses_violations_for_configured_custom_rules(self):
        catalog = RuleCatalog(runtime_rules={"custom.failing": lambda _r: True})
        evaluator = DeterministicEvaluator(rule_catalog=catalog)
        contract = make_contract(mode="no_contract", runtime_rules=["custom.failing"], postconditions=[])
        req = make_request(mode="no_contract", contract=contract, tool_name="search")
        decision = evaluator.evaluate(req)
        self.assertEqual(decision.violations, [])
        self.assertEqual(decision.decision, "allow")

    def test_duplicate_configured_rules_do_not_duplicate_violations(self):
        catalog = RuleCatalog(runtime_rules={"custom.always_fail": lambda _r: True})
        evaluator = DeterministicEvaluator(rule_catalog=catalog)
        contract = make_contract(
            runtime_rules=["custom.always_fail", "custom.always_fail"],
            postconditions=[],
        )
        req = make_request(contract=contract, tool_name="search")
        decision = evaluator.evaluate(req)
        self.assertEqual(len(decision.violations), 1)
        self.assertEqual(decision.violations[0].rule, "custom.always_fail")

    def test_load_contract_with_custom_catalog(self):
        catalog = RuleCatalog(
            runtime_rules={**DEFAULT_RUNTIME_RULES, "custom.declared": lambda _r: None},
            postconditions=DEFAULT_POSTCONDITIONS,
        )
        data = make_contract(runtime_rules=["custom.declared"], postconditions=["run_ledger.required"])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "contract.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
                load_contract(path)
            document = load_contract(path, rule_catalog=catalog)
            self.assertEqual(document.contract.runtime_rules, ["custom.declared"])

    def test_trusted_state_distinct_from_action_arguments(self):
        def check_tenant_state(req: GovernorInput) -> bool:
            assert req.action is not None
            return req.context.state.get("tenant_id") != "trusted_tenant"

        catalog = RuleCatalog(runtime_rules={"tenant.verified": check_tenant_state})
        evaluator = DeterministicEvaluator(rule_catalog=catalog)
        contract = make_contract(runtime_rules=["tenant.verified"], postconditions=[])

        spoofed_req = make_request(
            contract=contract,
            arguments={"tenant_id": "trusted_tenant"},
            state={},
        )
        self.assertEqual(evaluator.evaluate(spoofed_req).decision, "block")

        valid_req = make_request(
            contract=contract,
            arguments={"tenant_id": "arbitrary"},
            state={"tenant_id": "trusted_tenant"},
        )
        self.assertEqual(evaluator.evaluate(valid_req).decision, "allow")

    def test_governor_with_custom_catalog_and_mutual_exclusion(self):
        catalog = RuleCatalog(runtime_rules={"custom.flag": lambda _r: True})
        gov = Governor(rule_catalog=catalog)
        contract = make_contract(runtime_rules=["custom.flag"], postconditions=[])
        req = make_request(contract=contract)
        self.assertEqual(gov.evaluate(req).decision, "block")

        with self.assertRaisesRegex(ValueError, "Cannot specify both"):
            Governor(evaluator=DeterministicEvaluator(), rule_catalog=catalog)


class _StrictLimitParams(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )

    max_amount: int = Field(ge=1)
    currency: str = "MXN"
    channels: list[str] = Field(default_factory=lambda: ["email"])
    tags: dict[str, int] = Field(default_factory=dict)


class RuleTypeRegistryTests(unittest.TestCase):
    def test_default_rule_types_vocabulary_and_immutability(self):
        self.assertIsInstance(DEFAULT_RULE_TYPES, MappingProxyType)
        self.assertEqual(
            set(DEFAULT_RULE_TYPES.keys()),
            {
                "tool.declared_only",
                "response.schema_complete",
                "approval.bound_required",
                "destination.allowlist",
                "evidence.retrieved_required",
            },
        )
        expected_specs = (
            ("tool.declared_only", frozenset({"runtime"}), EmptyRuleParams),
            (
                "response.schema_complete",
                frozenset({"post_execution"}),
                EmptyRuleParams,
            ),
            (
                "approval.bound_required",
                frozenset({"runtime"}),
                BoundApprovalParams,
            ),
            (
                "destination.allowlist",
                frozenset({"runtime"}),
                DestinationAllowlistParams,
            ),
            (
                "evidence.retrieved_required",
                frozenset({"runtime"}),
                RetrievedEvidenceParams,
            ),
        )
        for rule_type, phases, model_cls in expected_specs:
            with self.subTest(rule_type=rule_type):
                spec = DEFAULT_RULE_TYPES[rule_type]
                self.assertEqual(spec.allowed_phases, phases)
                self.assertIs(spec.params_model, model_cls)
                self.assertTrue(callable(spec.handler))
        with self.assertRaises(TypeError):
            RuleTypeSpec(
                allowed_phases=frozenset({"runtime"}),
                params_model=EmptyRuleParams,
                handler="not_callable",  # type: ignore[arg-type]
            )
        with self.assertRaises(TypeError):
            DEFAULT_RULE_TYPES["custom.type"] = RuleTypeSpec(  # type: ignore[index]
                allowed_phases=frozenset({"runtime"})
            )

    def test_default_rule_types_excludes_argument_derived_and_benchmark_rules(self):
        excluded = (
            "sensitive_requires_approval",
            "memory.scope_allowed",
            "ticket_requires_evidence",
            "authorization.role_required",
            "run_ledger.required",
            "run_ledger.complete",
            "forbidden.outcome_triggered",
        )
        for rule_id in excluded:
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(rule_id, DEFAULT_RULE_TYPES)

    def test_rule_type_spec_validates_phases_and_strict_params_model(self):
        for bad_phases in (
            frozenset(),
            frozenset({"invalid_phase"}),  # type: ignore[arg-type]
            frozenset({"runtime", "unknown"}),  # type: ignore[arg-type]
            {"runtime"},  # type: ignore[arg-type]
            ["runtime"],  # type: ignore[arg-type]
        ):
            with self.subTest(bad_phases=bad_phases):
                with self.assertRaisesRegex(
                    ValueError, "non-empty frozenset of valid phases"
                ):
                    RuleTypeSpec(allowed_phases=bad_phases)

        for bad_model in (dict, object, "not_a_model", 123):
            with self.subTest(bad_model=bad_model):
                with self.assertRaisesRegex(
                    TypeError, "Pydantic BaseModel subclass"
                ):
                    RuleTypeSpec(
                        allowed_phases=frozenset({"runtime"}),
                        params_model=bad_model,  # type: ignore[arg-type]
                    )

        class NonStrictParams(BaseModel):
            model_config = ConfigDict(
                strict=False, extra="forbid", frozen=True, allow_inf_nan=False
            )

        class ExtraAllowParams(BaseModel):
            model_config = ConfigDict(
                strict=True, extra="allow", frozen=True, allow_inf_nan=False
            )

        class MutableParams(BaseModel):
            model_config = ConfigDict(
                strict=True, extra="forbid", frozen=False, allow_inf_nan=False
            )

        class NanAllowedParams(BaseModel):
            model_config = ConfigDict(
                strict=True, extra="forbid", frozen=True, allow_inf_nan=True
            )

        for model_cls in (
            NonStrictParams,
            ExtraAllowParams,
            MutableParams,
            NanAllowedParams,
        ):
            with self.subTest(model_cls=model_cls.__name__):
                with self.assertRaisesRegex(
                    ValueError,
                    "strict=True, extra='forbid', frozen=True, allow_inf_nan=False",
                ):
                    RuleTypeSpec(
                        allowed_phases=frozenset({"runtime"}),
                        params_model=model_cls,
                    )

    def test_catalog_accepts_custom_rule_types_and_protects_builtins_and_historical_ids(
        self,
    ):
        custom_spec = RuleTypeSpec(
            allowed_phases=frozenset({"runtime"}),
            params_model=_StrictLimitParams,
        )
        catalog = RuleCatalog(rule_types={"budget.limit": custom_spec})
        self.assertIn("tool.declared_only", catalog.rule_types)
        self.assertIn("response.schema_complete", catalog.rule_types)
        self.assertEqual(catalog.rule_types["budget.limit"], custom_spec)

        catalog_with_spread = RuleCatalog(
            rule_types={**DEFAULT_RULE_TYPES, "budget.limit": custom_spec}
        )
        self.assertEqual(catalog_with_spread.rule_types["budget.limit"], custom_spec)

        # Returned dict is a fresh copy
        mutated = catalog.rule_types
        mutated.pop("budget.limit")
        self.assertIn("budget.limit", catalog.rule_types)

        with self.assertRaisesRegex(
            ValueError, "Cannot replace built-in rule type 'tool.declared_only'"
        ):
            RuleCatalog(
                rule_types={
                    "tool.declared_only": RuleTypeSpec(
                        allowed_phases=frozenset({"post_execution"}),
                        params_model=EmptyRuleParams,
                    )
                }
            )
        with self.assertRaisesRegex(
            ValueError, "Cannot replace built-in rule type 'tool.declared_only'"
        ):
            RuleCatalog(
                rule_types={
                    "tool.declared_only": RuleTypeSpec(
                        allowed_phases=frozenset({"runtime"}),
                        params_model=EmptyRuleParams,
                        handler=lambda _req, _p: False,
                    )
                }
            )

        for historical_id in (
            "sensitive_requires_approval",
            "memory.scope_allowed",
            "ticket_requires_evidence",
            "authorization.role_required",
            "run_ledger.required",
            "run_ledger.complete",
            "forbidden.outcome_triggered",
        ):
            with self.subTest(historical_id=historical_id):
                with self.assertRaisesRegex(
                    ValueError,
                    f"Cannot shadow historical built-in rule '{historical_id}' as a v3 rule type",
                ):
                    RuleCatalog(rule_types={historical_id: custom_spec})

        with self.assertRaisesRegex(ValueError, "non-empty string"):
            RuleCatalog(rule_types={"": custom_spec})
        with self.assertRaisesRegex(TypeError, "must be a RuleTypeSpec"):
            RuleCatalog(rule_types={"budget.limit": "not_a_spec"})  # type: ignore[dict-item]

    def test_validate_rule_params_materializes_defaults_and_rejects_invalid_inputs(
        self,
    ):
        custom_spec = RuleTypeSpec(
            allowed_phases=frozenset({"runtime"}),
            params_model=_StrictLimitParams,
        )
        catalog = RuleCatalog(rule_types={"budget.limit": custom_spec})

        validated = catalog.validate_rule_params("budget.limit", {"max_amount": 500})
        self.assertEqual(
            validated.model_dump(mode="json"),
            {
                "max_amount": 500,
                "currency": "MXN",
                "channels": ["email"],
                "tags": {},
            },
        )

        from vogtcon.models import RuleBinding

        binding = RuleBinding(
            instance_id="b1",
            rule_type="budget.limit",
            phases=["runtime"],
            params={
                "max_amount": 500,
                "channels": ["email", "sms"],
                "tags": {"tier": 1},
            },
        )
        validated_from_frozen = catalog.validate_rule_params(
            "budget.limit", binding.params
        )
        self.assertEqual(
            validated_from_frozen.model_dump(mode="json"),
            {
                "max_amount": 500,
                "currency": "MXN",
                "channels": ["email", "sms"],
                "tags": {"tier": 1},
            },
        )

        empty_validated = catalog.validate_rule_params("tool.declared_only", {})
        self.assertEqual(empty_validated.model_dump(mode="json"), {})

        for bad_params in (
            {},  # missing required max_amount
            {"max_amount": "500"},  # string coercion forbidden
            {"max_amount": True},  # bool coercion forbidden
            {"max_amount": 0},  # violates ge=1
            {"max_amount": 100, "extra_field": 1},  # extra field forbidden
        ):
            with self.subTest(bad_params=bad_params):
                with self.assertRaises(ValidationError):
                    catalog.validate_rule_params("budget.limit", bad_params)

        with self.assertRaises(ValidationError):
            catalog.validate_rule_params("tool.declared_only", {"unexpected": True})

    def test_default_catalog_preserves_v1_v2_rules_and_order(self):
        catalog = RuleCatalog()
        self.assertEqual(tuple(catalog.runtime_rules.keys()), RUNTIME_RULES)
        self.assertEqual(tuple(catalog.postconditions.keys()), POSTCONDITIONS)
        self.assertEqual(
            set(catalog.rule_types.keys()), set(DEFAULT_RULE_TYPES.keys())
        )


class V3RuleEvaluationTests(unittest.TestCase):
    def _make_v3_contract(self, rules: list[dict], declared_tools: list[str] | None = None):
        from vogtcon.models import ContractRulesV3

        return ContractRulesV3.model_validate(
            {
                "schema_version": 3,
                "contract_id": "v3.eval.test",
                "approved_agent_configurations": ["sha256:agent"],
                "declared_tools": declared_tools if declared_tools is not None else ["send_notification"],
                "response_schema": {"required_fields": ["answer", "status"]},
                "memory_policy": "none",
                "validation_phases": ["pre_execution", "runtime", "post_execution"],
                "rules": rules,
                "contract_fingerprint": "sha256:" + "0" * 64,
            }
        )

    def test_builtin_v3_handlers_and_tool_declared_only_short_circuit(self):
        from vogtcon.models import EnforcementPolicy, PlannedEffect

        called_after_gate: list[str] = []
        catalog = RuleCatalog(
            rule_types={
                "custom.after_gate": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=lambda _req, _p: called_after_gate.append("ran") or True,
                )
            }
        )
        contract = self._make_v3_contract(
            [
                {
                    "instance_id": "gate-1",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "after-1",
                    "rule_type": "custom.after_gate",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "resp-1",
                    "rule_type": "response.schema_complete",
                    "phases": ["post_execution"],
                },
            ]
        )

        undeclared_req = GovernorInput(
            run_id="r1",
            contract=contract,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(state={}, available_tools=["undeclared_tool"]),
            action=ActionProposal(tool_name="undeclared_tool"),
            planned_effect=PlannedEffect(tool_name="undeclared_tool"),
        )
        violations = catalog.evaluate_v3(undeclared_req)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "gate-1")
        self.assertEqual(violations[0].rule_type, "tool.declared_only")
        self.assertEqual(violations[0].action, "undeclared_tool")
        self.assertEqual(called_after_gate, [])

        post_req = GovernorInput(
            run_id="r1",
            contract=contract,
            phase="post_execution",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(state={}, available_tools=["send_notification"]),
            response={"answer": "ok"},
        )
        post_violations = catalog.evaluate_v3(post_req)
        self.assertEqual(len(post_violations), 1)
        self.assertEqual(post_violations[0].rule, "resp-1")
        self.assertEqual(post_violations[0].rule_type, "response.schema_complete")
        self.assertIsNone(post_violations[0].action)

    def test_multiple_bindings_parameter_materialization_and_violation_coercion(self):
        from vogtcon.models import EnforcementPolicy, HostFacts, PlannedEffect

        seen_params: list[_StrictLimitParams] = []

        def check_limit(req: GovernorInput, params: BaseModel) -> bool:
            assert isinstance(params, _StrictLimitParams)
            seen_params.append(params)
            amount = req.host_facts.facts.get("amount", 0) if req.host_facts else 0
            return isinstance(amount, int) and amount > params.max_amount

        catalog = RuleCatalog(
            rule_types={
                "budget.limit": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=_StrictLimitParams,
                    handler=check_limit,
                ),
                "custom.direct_violation": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=lambda req, _p: Violation(
                        rule="direct-v",
                        phase=req.phase,
                        severity="critical",
                        action="send_notification",
                    ),
                ),
            }
        )
        contract = self._make_v3_contract(
            [
                {
                    "instance_id": "soft-cap",
                    "rule_type": "budget.limit",
                    "phases": ["runtime"],
                    "params": {"max_amount": 100},
                },
                {
                    "instance_id": "hard-cap",
                    "rule_type": "budget.limit",
                    "phases": ["runtime"],
                    "params": {"max_amount": 500, "currency": "USD"},
                },
                {
                    "instance_id": "direct-v",
                    "rule_type": "custom.direct_violation",
                    "phases": ["runtime"],
                },
            ]
        )
        req = GovernorInput(
            run_id="r-multi",
            contract=contract,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(state={}, available_tools=["send_notification"]),
            action=ActionProposal(tool_name="send_notification"),
            host_facts=HostFacts(facts={"amount": 250}),
            planned_effect=PlannedEffect(tool_name="send_notification"),
        )
        violations = catalog.evaluate_v3(req)
        self.assertEqual([v.rule for v in violations], ["soft-cap", "direct-v"])
        self.assertEqual(
            [v.rule_type for v in violations],
            ["budget.limit", "custom.direct_violation"],
        )
        self.assertEqual(violations[1].severity, "critical")
        self.assertEqual(seen_params[0].currency, "MXN")
        self.assertEqual(seen_params[1].currency, "USD")

        # Invalid Violation / return type coercion checks
        for bad_handler, expected_msg in (
            (
                lambda req, _p: Violation(
                    rule="wrong-id", phase=req.phase, action="send_notification"
                ),
                "produced violation for 'wrong-id'",
            ),
            (
                lambda req, _p: Violation(
                    rule="b1",
                    rule_type="wrong.type",
                    phase=req.phase,
                    action="send_notification",
                ),
                "expected 'custom.bad'",
            ),
            (lambda _req, _p: "invalid", "returned invalid output"),
        ):
            with self.subTest(expected_msg=expected_msg):
                bad_cat = RuleCatalog(
                    rule_types={
                        "custom.bad": RuleTypeSpec(
                            allowed_phases=frozenset({"runtime"}),
                            params_model=EmptyRuleParams,
                            handler=bad_handler,  # type: ignore[arg-type]
                        )
                    }
                )
                bad_contract = self._make_v3_contract(
                    [{"instance_id": "b1", "rule_type": "custom.bad", "phases": ["runtime"]}]
                )
                bad_req = req.model_copy(update={"contract": bad_contract})
                with self.assertRaisesRegex(ValueError, expected_msg):
                    bad_cat.evaluate_v3(bad_req)

    def test_validate_v3_handlers_fails_closed_even_for_post_only_schema_rule(self):
        from vogtcon.models import EnforcementPolicy

        schema_only_catalog = RuleCatalog(
            rule_types={
                "audit.schema_only": RuleTypeSpec(
                    allowed_phases=frozenset({"post_execution"}),
                    params_model=EmptyRuleParams,
                    handler=None,
                )
            }
        )
        contract = self._make_v3_contract(
            [
                {
                    "instance_id": "post-audit",
                    "rule_type": "audit.schema_only",
                    "phases": ["post_execution"],
                }
            ]
        )
        with self.assertRaisesRegex(
            ValueError,
            "Rule type 'audit.schema_only' has no evaluation handler configured",
        ):
            schema_only_catalog.validate_v3_handlers(contract)

        runtime_req = GovernorInput(
            run_id="r-missing-handler",
            contract=contract,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(state={}, available_tools=["send_notification"]),
            action=ActionProposal(tool_name="send_notification"),
        )
        with self.assertRaisesRegex(
            ValueError,
            "Rule type 'audit.schema_only' has no evaluation handler configured",
        ):
            schema_only_catalog.evaluate_v3(runtime_req)

        # Verify evaluate_v3 suppresses inner ValidationError traceback on bad params
        import traceback
        from vogtcon.models import RuleBinding

        secret_val = "SECRET_EVAL_PARAM_SENTINEL_7744"
        param_cat = RuleCatalog(
            rule_types={
                "budget.limit": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=_StrictLimitParams,
                    handler=lambda _r, _p: False,
                )
            }
        )
        tampered_binding = RuleBinding.model_construct(
            instance_id="bad-param-inst",
            rule_type="budget.limit",
            phases=("runtime",),
            params={"max_amount": secret_val},
        )
        tampered_contract = contract.model_copy()
        object.__setattr__(tampered_contract, "rules", (tampered_binding,))
        tampered_req = runtime_req.model_copy(update={"contract": tampered_contract})
        try:
            param_cat.evaluate_v3(tampered_req)
            self.fail("Expected ValueError for invalid params")
        except ValueError as err:
            self.assertIsNone(err.__cause__)
            self.assertTrue(err.__suppress_context__)
            self.assertNotIn(secret_val, str(err))
            self.assertNotIn(secret_val, traceback.format_exc())


class BoundApprovalRuleTests(unittest.TestCase):
    def _contract(self, params: dict | None = None):
        from vogtcon.models import ContractRulesV3

        rule_params = (
            params
            if params is not None
            else {
                "tools": ["send_notification"],
                "required_authorities": ["notif.approver"],
                "sensitivity_fact_key": "is_sensitive",
            }
        )
        return ContractRulesV3.model_validate(
            {
                "schema_version": 3,
                "contract_id": "v3.bound.approval",
                "approved_agent_configurations": ["agent-v3"],
                "declared_tools": ["send_notification", "search"],
                "response_schema": {"required_fields": ["status"]},
                "memory_policy": "none",
                "validation_phases": ["pre_execution", "runtime", "post_execution"],
                "rules": [
                    {
                        "instance_id": "bound-approval",
                        "rule_type": "approval.bound_required",
                        "phases": ["runtime"],
                        "params": rule_params,
                    }
                ],
                "contract_fingerprint": "sha256:" + "1" * 64,
            }
        )

    def test_bound_approval_parameter_validation_and_immutability(self):
        from copy import deepcopy

        p = BoundApprovalParams.model_validate(
            {
                "tools": ["send_notification"],
                "required_authorities": ["notif.approve", "sec.officer"],
            }
        )
        self.assertEqual(p.tools, ("send_notification",))
        self.assertEqual(p.required_authorities, ("notif.approve", "sec.officer"))
        self.assertEqual(p.authority_match, "any")
        self.assertFalse(p.allow_self_approval)
        self.assertTrue(p.require_single_use)
        self.assertFalse(p.allow_retry_after_confirmed_absent)
        self.assertEqual(deepcopy(p), p)
        self.assertEqual(p.model_copy(deep=True), p)
        with self.assertRaises(ValidationError):
            p.model_copy(update={"tools": []})

        for bad in (
            {"tools": [], "required_authorities": ["a"]},
            {"tools": ["t"], "required_authorities": []},
            {"tools": ["t", "t"], "required_authorities": ["a"]},
            {"tools": ["t"], "required_authorities": ["a", "a"]},
            {"tools": ["t"], "required_authorities": ["a"], "extra": 1},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    BoundApprovalParams.model_validate(bad)

    def test_bound_approval_checks_all_authorization_and_single_use_invariants(
        self,
    ):
        from vogtcon.models import (
            ApprovalStateRecord,
            EnforcementPolicy,
            ExecutionContext,
            HostApproval,
            HostFacts,
            PlannedEffect,
            TrajectoryView,
        )

        catalog = DEFAULT_RULE_CATALOG
        planned = PlannedEffect(
            tool_name="send_notification",
            parameters={"recipient": "ceo@example.com", "body": "Q4"},
        )
        digest = planned.operation_digest()
        base_approval = HostApproval(
            approval_id="app-100",
            operation_digest=digest,
            requester_id="agent-user",
            approver_id="mgr-user",
            approver_authorities=["notif.approver"],
            policy_scope="scope.notif",
            issued_at="2026-11-27T10:00:00Z",
            expires_at="2026-11-27T11:00:00Z",
        )
        empty_traj = TrajectoryView(policy_scope="scope.notif")

        def make_req(**overrides):
            kwargs = {
                "run_id": "r1",
                "contract": self._contract(),
                "phase": "runtime",
                "policy": EnforcementPolicy(mode="guarded"),
                "context": ExecutionContext(
                    state={}, available_tools=["send_notification", "search"]
                ),
                "action": ActionProposal(
                    tool_name="send_notification",
                    arguments={"is_sensitive": False, "approval_granted": True},
                ),
                "host_facts": HostFacts(facts={"is_sensitive": True}),
                "planned_effect": planned,
                "policy_scope": "scope.notif",
                "requester_id": "agent-user",
                "evaluated_at": "2026-11-27T10:30:00Z",
                "approval": base_approval,
                "trajectory": empty_traj,
            }
            kwargs.update(overrides)
            return GovernorInput(**kwargs)

        # 1. Valid approval passes
        self.assertEqual(catalog.evaluate_v3(make_req()), [])

        # 2. Non-governed tool passes without approval
        search_req = make_req(
            action=ActionProposal(tool_name="search"),
            planned_effect=PlannedEffect(tool_name="search"),
            approval=None,
        )
        self.assertEqual(catalog.evaluate_v3(search_req), [])

        # 3. Host-classified non-sensitive passes without approval
        self.assertEqual(
            catalog.evaluate_v3(
                make_req(
                    host_facts=HostFacts(facts={"is_sensitive": False}),
                    approval=None,
                )
            ),
            [],
        )

        # 4. Agent claiming sensitive=False in arguments while host_facts says True or is missing/non-bool fails closed (INV-04, INV-10)
        for bad_facts in (
            None,
            HostFacts(facts={}),
            HostFacts(facts={"is_sensitive": "false"}),
            HostFacts(facts={"is_sensitive": 0}),
            HostFacts(facts={"is_sensitive": True}),
        ):
            with self.subTest(bad_facts=bad_facts):
                v = catalog.evaluate_v3(
                    make_req(host_facts=bad_facts, approval=None)
                )
                self.assertEqual(len(v), 1)
                self.assertEqual(v[0].rule_type, "approval.bound_required")

        # 5. Missing planned_effect, requester_id, policy_scope, evaluated_at, or trajectory fails closed
        for missing_field in (
            "planned_effect",
            "requester_id",
            "policy_scope",
            "evaluated_at",
            "trajectory",
        ):
            with self.subTest(missing_field=missing_field):
                self.assertEqual(
                    len(catalog.evaluate_v3(make_req(**{missing_field: None}))),
                    1,
                )

        # Unscoped TrajectoryView(policy_scope=None) when request.policy_scope is set fails closed!
        self.assertEqual(
            len(
                catalog.evaluate_v3(
                    make_req(trajectory=TrajectoryView(policy_scope=None))
                )
            ),
            1,
        )

        # 6. Modified operation_digest (e.g. changed recipient or parameter) fails
        modified_effect = PlannedEffect(
            tool_name="send_notification",
            parameters={"recipient": "attacker@example.com", "body": "Q4"},
        )
        self.assertEqual(
            len(catalog.evaluate_v3(make_req(planned_effect=modified_effect))),
            1,
        )

        # 7. Foreign requester, wrong scope, revoked/expired status fail
        self.assertEqual(
            len(catalog.evaluate_v3(make_req(requester_id="other-user"))), 1
        )
        self.assertEqual(
            len(
                catalog.evaluate_v3(
                    make_req(
                        policy_scope="scope.other",
                        trajectory=TrajectoryView(policy_scope="scope.other"),
                    )
                )
            ),
            1,
        )
        for bad_status in ("revoked", "expired"):
            self.assertEqual(
                len(
                    catalog.evaluate_v3(
                        make_req(
                            approval=base_approval.model_copy(
                                update={"status": bad_status}
                            )
                        )
                    )
                ),
                1,
            )

        # 8. Self-approval: rejected by default; when allow_self_approval=True, STILL requires required_authorities!
        self_app_with_auth = base_approval.model_copy(
            update={"approver_id": "agent-user"}
        )
        self.assertEqual(
            len(catalog.evaluate_v3(make_req(approval=self_app_with_auth))), 1
        )
        allow_self_contract = self._contract(
            {
                "tools": ["send_notification"],
                "required_authorities": ["notif.approver", "sec.lead"],
                "authority_match": "all",
                "allow_self_approval": True,
            }
        )
        # Missing sec.lead authority -> rejected even with allow_self_approval=True
        self.assertEqual(
            len(
                catalog.evaluate_v3(
                    make_req(
                        contract=allow_self_contract,
                        approval=self_app_with_auth,
                    )
                )
            ),
            1,
        )
        # Empty authorities -> rejected
        self.assertEqual(
            len(
                catalog.evaluate_v3(
                    make_req(
                        contract=allow_self_contract,
                        approval=self_app_with_auth.model_copy(
                            update={"approver_authorities": []}
                        ),
                    )
                )
            ),
            1,
        )
        # Both authorities present -> allowed
        self.assertEqual(
            catalog.evaluate_v3(
                make_req(
                    contract=allow_self_contract,
                    approval=self_app_with_auth.model_copy(
                        update={
                            "approver_authorities": [
                                "notif.approver",
                                "sec.lead",
                            ]
                        }
                    ),
                )
            ),
            [],
        )

        # 9. Validity window boundaries & timezone offset equivalence (no wall-clock)
        # Exact issued_at is allowed; 1 second before is rejected; exact expires_at is rejected
        self.assertEqual(
            catalog.evaluate_v3(
                make_req(evaluated_at="2026-11-27T10:00:00Z")
            ),
            [],
        )
        self.assertEqual(
            catalog.evaluate_v3(
                make_req(evaluated_at="2026-11-27T04:30:00-06:00")
            ),
            [],
        )
        self.assertEqual(
            len(
                catalog.evaluate_v3(
                    make_req(evaluated_at="2026-11-27T09:59:59Z")
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                catalog.evaluate_v3(
                    make_req(evaluated_at="2026-11-27T11:00:00Z")
                )
            ),
            1,
        )

        # 10. Single-use trajectory states: reserved, consumed, locked_uncertain, released_absent
        for blocked_usage_status in ("reserved", "consumed", "locked_uncertain"):
            with self.subTest(usage_status=blocked_usage_status):
                traj = TrajectoryView(
                    policy_scope="scope.notif",
                    approvals=[
                        ApprovalStateRecord(
                            approval_id="app-100",
                            operation_digest=digest,
                            policy_scope="scope.notif",
                            status=blocked_usage_status,  # type: ignore[arg-type]
                            effect_id="eff-000001",
                        )
                    ],
                )
                self.assertEqual(
                    len(catalog.evaluate_v3(make_req(trajectory=traj))), 1
                )

        absent_traj = TrajectoryView(
            policy_scope="scope.notif",
            approvals=[
                ApprovalStateRecord(
                    approval_id="app-100",
                    operation_digest=digest,
                    policy_scope="scope.notif",
                    status="released_absent",
                    effect_id="eff-000001",
                )
            ],
        )
        # Disallowed when allow_retry_after_confirmed_absent=False
        self.assertEqual(
            len(catalog.evaluate_v3(make_req(trajectory=absent_traj))), 1
        )
        # Allowed when allow_retry_after_confirmed_absent=True for identical digest
        retry_contract = self._contract(
            {
                "tools": ["send_notification"],
                "required_authorities": ["notif.approver"],
                "allow_retry_after_confirmed_absent": True,
            }
        )
        self.assertEqual(
            catalog.evaluate_v3(
                make_req(contract=retry_contract, trajectory=absent_traj)
            ),
            [],
        )


class DestinationAllowlistRuleTests(unittest.TestCase):
    def test_destination_allowlist_reads_only_trusted_sources_and_blocks_spoofed_args(
        self,
    ):
        from vogtcon.models import (
            ContractRulesV3,
            EnforcementPolicy,
            ExecutionContext,
            HostFacts,
            PlannedEffect,
        )

        for bad_params in (
            {"tools": [], "allowed_destinations": ["ops@example.com"]},
            {"tools": ["send_notification"], "allowed_destinations": []},
            {"tools": ["send_notification"], "allowed_destinations": ["a", "a"]},
        ):
            with self.assertRaises(ValidationError):
                DestinationAllowlistParams.model_validate(bad_params)

        contract = ContractRulesV3.model_validate(
            {
                "schema_version": 3,
                "contract_id": "v3.dest",
                "approved_agent_configurations": ["agent-v3"],
                "declared_tools": ["send_notification"],
                "response_schema": {"required_fields": ["status"]},
                "memory_policy": "none",
                "validation_phases": ["pre_execution", "runtime", "post_execution"],
                "rules": [
                    {
                        "instance_id": "dest-effect",
                        "rule_type": "destination.allowlist",
                        "phases": ["runtime"],
                        "params": {
                            "tools": ["send_notification"],
                            "allowed_destinations": [
                                "ops@example.com",
                                "sec@example.com",
                            ],
                            "destination_param": "recipient",
                            "source": "planned_effect",
                        },
                    },
                    {
                        "instance_id": "dest-facts",
                        "rule_type": "destination.allowlist",
                        "phases": ["runtime"],
                        "params": {
                            "tools": ["send_notification"],
                            "allowed_destinations": ["internal.example.com"],
                            "destination_param": "resolved_domain",
                            "source": "host_facts",
                        },
                    },
                ],
                "contract_fingerprint": "sha256:" + "2" * 64,
            }
        )

        valid_req = GovernorInput(
            run_id="r-dest",
            contract=contract,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(
                state={}, available_tools=["send_notification"]
            ),
            action=ActionProposal(
                tool_name="send_notification",
                arguments={"recipient": "evil@attacker.org"},
            ),
            planned_effect=PlannedEffect(
                tool_name="send_notification",
                defaults={"recipient": "ops@example.com"},
            ),
            host_facts=HostFacts(
                facts={"resolved_domain": "internal.example.com"}
            ),
        )
        self.assertEqual(DEFAULT_RULE_CATALOG.evaluate_v3(valid_req), [])

        # Agent spoofs allowed recipient in ActionProposal.arguments while PlannedEffect has attacker destination (INV-04)
        spoofed_req = valid_req.model_copy(
            update={
                "action": ActionProposal(
                    tool_name="send_notification",
                    arguments={
                        "recipient": "ops@example.com",
                        "resolved_domain": "internal.example.com",
                    },
                ),
                "planned_effect": PlannedEffect(
                    tool_name="send_notification",
                    parameters={"recipient": "exfil@attacker.org"},
                ),
            }
        )
        v = DEFAULT_RULE_CATALOG.evaluate_v3(spoofed_req)
        self.assertEqual([item.rule for item in v], ["dest-effect"])

        # Missing or non-string destination fails closed
        missing_facts_req = valid_req.model_copy(update={"host_facts": None})
        self.assertEqual(
            [item.rule for item in DEFAULT_RULE_CATALOG.evaluate_v3(missing_facts_req)],
            ["dest-facts"],
        )


class RetrievedEvidenceRuleTests(unittest.TestCase):
    def test_retrieved_evidence_verifies_host_provenance_and_blocks_invented_claims(
        self,
    ):
        from vogtcon.models import (
            ContractRulesV3,
            EnforcementPolicy,
            ExecutionContext,
            PlannedEffect,
            RetrievedEvidence,
        )

        self.assertIn(
            "does NOT prove semantic relevance",
            RetrievedEvidenceParams.__doc__ or "",
        )
        for bad_params in (
            {"tools": []},
            {"tools": ["create_ticket"], "min_count": 0},
            {"tools": ["create_ticket"], "allowed_sources": []},
        ):
            with self.assertRaises(ValidationError):
                RetrievedEvidenceParams.model_validate(bad_params)

        contract = ContractRulesV3.model_validate(
            {
                "schema_version": 3,
                "contract_id": "v3.evidence",
                "approved_agent_configurations": ["agent-v3"],
                "declared_tools": ["create_ticket"],
                "response_schema": {"required_fields": ["status"]},
                "memory_policy": "none",
                "validation_phases": ["pre_execution", "runtime", "post_execution"],
                "rules": [
                    {
                        "instance_id": "ticket-evidence",
                        "rule_type": "evidence.retrieved_required",
                        "phases": ["runtime"],
                        "params": {
                            "tools": ["create_ticket"],
                            "min_count": 2,
                            "allowed_sources": ["kb.trusted", "logs.prod"],
                            "require_content_digest": True,
                            "claim_param": "evidence_ids",
                        },
                    }
                ],
                "contract_fingerprint": "sha256:" + "3" * 64,
            }
        )
        ev1 = RetrievedEvidence(
            evidence_id="ev-1",
            source="kb.trusted",
            content_digest="sha256:" + "a" * 64,
        )
        ev2 = RetrievedEvidence(
            evidence_id="ev-2",
            source="logs.prod",
            content_digest="sha256:" + "b" * 64,
        )

        valid_req = GovernorInput(
            run_id="r-ev",
            contract=contract,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(
                state={}, available_tools=["create_ticket"]
            ),
            action=ActionProposal(
                tool_name="create_ticket",
                arguments={"evidence_ids": ["invented-in-args"]},
            ),
            planned_effect=PlannedEffect(
                tool_name="create_ticket",
                parameters={"evidence_ids": ["ev-1", "ev-2"]},
            ),
            retrieved_evidence=[ev1, ev2],
        )
        self.assertEqual(DEFAULT_RULE_CATALOG.evaluate_v3(valid_req), [])

        # Invented evidence ID in claim_param fails closed
        invented_req = valid_req.model_copy(
            update={
                "planned_effect": PlannedEffect(
                    tool_name="create_ticket",
                    parameters={"evidence_ids": ["ev-1", "ev-999-invented"]},
                )
            }
        )
        self.assertEqual(
            len(DEFAULT_RULE_CATALOG.evaluate_v3(invented_req)), 1
        )

        # Duplicate claimed IDs below min_count unique IDs fails closed
        dup_claim_req = valid_req.model_copy(
            update={
                "planned_effect": PlannedEffect(
                    tool_name="create_ticket",
                    parameters={"evidence_ids": ["ev-1", "ev-1"]},
                )
            }
        )
        self.assertEqual(
            len(DEFAULT_RULE_CATALOG.evaluate_v3(dup_claim_req)), 1
        )

        # Evidence from disallowed source or missing content_digest fails closed
        untrusted_source = RetrievedEvidence(
            evidence_id="ev-2",
            source="untrusted.web",
            content_digest="sha256:" + "b" * 64,
        )
        no_digest = RetrievedEvidence(
            evidence_id="ev-2",
            source="logs.prod",
            content_digest=None,
        )
        for bad_ev in (untrusted_source, no_digest):
            self.assertEqual(
                len(
                    DEFAULT_RULE_CATALOG.evaluate_v3(
                        valid_req.model_copy(
                            update={"retrieved_evidence": [ev1, bad_ev]}
                        )
                    )
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
