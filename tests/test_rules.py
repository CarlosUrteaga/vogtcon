# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vogtcon import (
    DeterministicEvaluator,
    Governor,
    GovernorInput,
    RuleCatalog,
    Violation,
    load_contract,
)
from vogtcon.rules import (
    DEFAULT_POSTCONDITIONS,
    DEFAULT_RULE_CATALOG,
    DEFAULT_RUNTIME_RULES,
    POSTCONDITIONS,
    RUNTIME_RULES,
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


if __name__ == "__main__":
    unittest.main()
