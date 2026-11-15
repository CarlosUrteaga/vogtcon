# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
from pathlib import Path

from vogtcon import (
    ActionProposal,
    AgentContract,
    ContractRulesV2,
    EnforcementPolicy,
    ExecutionContext,
    GovernedToolExecutor,
    Governor,
    GovernorInput,
    GovernanceDecision,
    RuleCatalog,
    Violation,
    WorkflowController,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def contract(mode: str = "guarded") -> AgentContract:
    return AgentContract.model_validate({
        "contract_id": "test.notify", "mode": mode,
        "approved_agent_configurations": ["agent-v1"],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["status"]},
        "memory_policy": "none",
        "validation_phases": "not_enforced" if mode == "no_contract" else ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": ["tool.declared_only", "sensitive_requires_approval"],
        "postconditions": ["response.schema_complete"],
        "agent_feedback": {
            "advisory_warning_visibility": False,
            "guarded_denial_style": "minimal",
            "strict_replanning_after_violation": False,
        },
        "contract_fingerprint": "contract-v1",
    })


def v2_contract() -> ContractRulesV2:
    data = contract().model_dump()
    data.pop("mode")
    data.pop("agent_feedback")
    data["schema_version"] = 2
    return ContractRulesV2.model_validate(data)


def context(*, approval: bool = False, agent_fp: str = "agent-v1") -> ExecutionContext:
    return ExecutionContext.model_validate({
        "state": {"approval_granted": approval},
        "available_tools": ["send_notification"],
        "observed_agent_fingerprint": agent_fp,
        "observed_contract_fingerprint": "contract-v1",
    })


def action(*, sensitive: bool = True) -> ActionProposal:
    return ActionProposal(tool_name="send_notification", arguments={"sensitive": sensitive})


class ExecutorTests(unittest.TestCase):
    def test_gate_has_side_effect_only_for_allow_and_warning(self):
        for mode, expected, executed in (
            ("no_contract", "allow", True),
            ("advisory", "allow_with_warning", True),
            ("guarded", "block", False),
            ("strict", "abort", False),
        ):
            with self.subTest(mode=mode):
                calls = []
                request = GovernorInput(
                    run_id="run", contract=contract(mode), phase="runtime",
                    context=context(), action=action(),
                )
                outcome = GovernedToolExecutor(Governor()).execute(
                    request, lambda proposal: calls.append(proposal.tool_name) or "sent"
                )
                self.assertEqual(outcome.decision.decision, expected)
                self.assertEqual(outcome.executed, executed)
                self.assertEqual(calls, ["send_notification"] if executed else [])
                self.assertEqual(outcome.result, "sent" if executed else None)

    def test_evaluator_error_and_wrong_phase_never_call_tool(self):
        calls = []

        class BrokenEvaluator:
            def evaluate(self, _request):
                raise TimeoutError("judge timeout")

        gate = GovernedToolExecutor(Governor(evaluator=BrokenEvaluator()))
        runtime = GovernorInput(
            run_id="run", contract=contract(), phase="runtime",
            context=context(), action=action(),
        )
        with self.assertRaisesRegex(TimeoutError, "judge timeout"):
            gate.execute(runtime, lambda _proposal: calls.append("sent"))
        pre = GovernorInput(
            run_id="run", contract=contract(), phase="pre_execution", context=context()
        )
        with self.assertRaisesRegex(ValueError, "runtime action"):
            gate.execute(pre, lambda _proposal: calls.append("sent"))
        self.assertEqual(calls, [])

    def test_evaluator_cannot_mutate_executed_proposal_or_allow_violation(self):
        class MutatingEvaluator:
            def evaluate(self, request):
                request.action.arguments["sensitive"] = False
                return Governor().evaluate(request)

        request = GovernorInput(
            run_id="run", contract=contract(), phase="runtime",
            context=context(), action=action(),
        )
        seen = []
        with self.assertRaisesRegex(ValueError, "mutated the action"):
            GovernedToolExecutor(Governor(evaluator=MutatingEvaluator())).execute(
                request, lambda proposal: seen.append(proposal.arguments["sensitive"])
            )
        self.assertEqual(seen, [])
        self.assertEqual(request.action.arguments["sensitive"], True)

        class InconsistentEvaluator:
            def evaluate(self, request):
                real = Governor().evaluate(request)
                return real.model_copy(update={"decision": "allow"})

        with self.assertRaisesRegex(ValueError, "allowed a violating action"):
            GovernedToolExecutor(Governor(evaluator=InconsistentEvaluator())).execute(
                request, lambda _proposal: seen.append("sent")
            )
        self.assertEqual(seen, [])


class ControllerTests(unittest.TestCase):
    def test_factory_loads_v1_and_v2_with_the_same_gate(self):
        for filename, policy in (
            ("notification_contract.yaml", None),
            ("notification_contract_v2.yaml", EnforcementPolicy(mode="guarded")),
        ):
            with self.subTest(filename=filename):
                controller = WorkflowController.from_contract_path(
                    EXAMPLES / filename, "factory-run", policy=policy,
                )
                trusted = ExecutionContext(
                    state={"approval_granted": False},
                    available_tools=["send_notification"],
                    observed_agent_fingerprint="notification-agent-v1",
                    observed_contract_fingerprint=controller.contract.contract_fingerprint,
                )
                self.assertEqual(controller.begin(trusted).violations, [])
                effects = []
                outcome = controller.execute(
                    ActionProposal(
                        tool_name="send_notification",
                        arguments={"message": "hello", "sensitive": True},
                    ), trusted, lambda _proposal: effects.append("sent"),
                )
                self.assertEqual(outcome.decision.decision, "block")
                self.assertFalse(outcome.executed)
                self.assertEqual(effects, [])
                self.assertEqual(controller.finish(trusted, {"status": "blocked"}).violations, [])

    def test_factory_preserves_configuration_errors(self):
        with self.assertRaisesRegex(ValueError, "require an enforcement policy"):
            WorkflowController.from_contract_path(
                EXAMPLES / "notification_contract_v2.yaml", "run",
            )
        with self.assertRaisesRegex(ValueError, "conflicts with legacy"):
            WorkflowController.from_contract_path(
                EXAMPLES / "notification_contract.yaml", "run",
                policy=EnforcementPolicy(mode="advisory"),
            )
        with self.assertRaisesRegex(ValueError, "run_id must be nonempty"):
            WorkflowController.from_contract_path(
                EXAMPLES / "notification_contract_v2.yaml", "",
                policy=EnforcementPolicy(mode="guarded"),
            )
        with self.assertRaises(FileNotFoundError):
            WorkflowController.from_contract_path(
                EXAMPLES / "absent.yaml", "run",
                policy=EnforcementPolicy(mode="guarded"),
            )
        with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
            WorkflowController.from_contract_path(
                EXAMPLES / "custom_contract.yaml", "run",
                policy=EnforcementPolicy(mode="guarded"),
            )

    def test_factory_uses_custom_rule_for_loading_and_evaluation(self):
        catalog = RuleCatalog(runtime_rules={
            "note.public_requires_approval": lambda request: (
                request.action is not None
                and request.action.arguments.get("public") is True
                and request.context.state.get("approval_granted") is not True
            ),
        })
        controller = WorkflowController.from_contract_path(
            EXAMPLES / "custom_contract.yaml", "custom-rule",
            policy=EnforcementPolicy(mode="guarded"), rule_catalog=catalog,
        )
        trusted = ExecutionContext(
            state={"approval_granted": False}, available_tools=["save_note"],
            observed_agent_fingerprint="pydantic-note-agent-v1",
            observed_contract_fingerprint=controller.contract.contract_fingerprint,
        )
        self.assertEqual(controller.begin(trusted).violations, [])
        effects = []
        outcome = controller.execute(
            ActionProposal(tool_name="save_note", arguments={"text": "note", "public": True}),
            trusted, lambda _proposal: effects.append("saved"),
        )
        self.assertEqual(outcome.decision.decision, "block")
        self.assertEqual(
            [violation.rule for violation in outcome.decision.violations],
            ["note.public_requires_approval"],
        )
        self.assertEqual(effects, [])

    def test_v2_requires_policy_and_legacy_rejects_conflict(self):
        with self.assertRaisesRegex(ValueError, "require an enforcement policy"):
            WorkflowController(Governor(), "run", v2_contract())
        with self.assertRaisesRegex(ValueError, "conflicts with legacy"):
            WorkflowController(
                Governor(), "run", contract(),
                policy=EnforcementPolicy(mode="advisory"),
            )
        versioned_legacy = AgentContract.model_validate({
            **contract().model_dump(), "schema_version": 2,
        })
        with self.assertRaisesRegex(ValueError, "schema_version"):
            WorkflowController(Governor(), "run", versioned_legacy)

    def test_v2_policy_controls_gate_and_run_state(self):
        for mode, expected, executed in (
            ("no_contract", "allow", True),
            ("advisory", "allow_with_warning", True),
            ("guarded", "block", False),
            ("strict", "abort", False),
        ):
            with self.subTest(mode=mode):
                controller = WorkflowController(
                    Governor(), "run", v2_contract(),
                    policy=EnforcementPolicy(mode=mode),
                )
                self.assertEqual(controller.begin(context()).violations, [])
                effects = []
                outcome = controller.execute(
                    action(), context(), lambda _a: effects.append("sent"),
                )
                self.assertEqual(outcome.decision.decision, expected)
                self.assertEqual(outcome.executed, executed)
                self.assertEqual(effects, ["sent"] if executed else [])
                self.assertEqual(controller.state, "aborted" if mode == "strict" else "active")
                if mode != "strict":
                    self.assertEqual(controller.finish(context(), {"status": "ok"}).violations, [])
                    self.assertEqual(controller.state, "finished")

    def test_v2_strict_pre_and_post_violations_change_run_state(self):
        policy = EnforcementPolicy(mode="strict")
        pre = WorkflowController(Governor(), "pre", v2_contract(), policy=policy)
        self.assertEqual(
            [v.rule for v in pre.begin(context(agent_fp="other")).violations],
            ["agent.configuration_fingerprint_match"],
        )
        self.assertEqual(pre.state, "aborted")
        post = WorkflowController(Governor(), "post", v2_contract(), policy=policy)
        post.begin(context())
        self.assertEqual(
            [v.rule for v in post.finish(context(), {}).violations],
            ["response.schema_complete"],
        )
        self.assertEqual(post.state, "failed_post")

    def test_guarded_replan_and_post_check(self):
        controller = WorkflowController(Governor(), "run-1", contract())
        self.assertEqual(controller.state, "new")
        self.assertEqual(controller.begin(context()).violations, [])
        effects = []
        blocked = controller.execute(action(), context(), lambda _a: effects.append("sent"))
        self.assertEqual(blocked.decision.decision, "block")
        self.assertFalse(blocked.executed)
        self.assertEqual(controller.state, "active")
        allowed = controller.execute(
            action(), context(approval=True), lambda _a: effects.append("sent")
        )
        self.assertTrue(allowed.executed)
        self.assertEqual(effects, ["sent"])
        post = controller.finish(context(approval=True), {"status": "ok"})
        self.assertEqual(post.violations, [])
        self.assertEqual(controller.state, "finished")
        with self.assertRaises(RuntimeError):
            controller.execute(action(), context(), lambda _a: effects.append("again"))
        self.assertEqual(effects, ["sent"])

    def test_strict_pre_and_runtime_abort(self):
        pre_controller = WorkflowController(Governor(), "pre", contract("strict"))
        pre = pre_controller.begin(context(agent_fp="other"))
        self.assertEqual([v.rule for v in pre.violations], ["agent.configuration_fingerprint_match"])
        self.assertEqual(pre_controller.state, "aborted")
        with self.assertRaises(RuntimeError):
            pre_controller.execute(action(), context(), lambda _a: None)

        runtime_controller = WorkflowController(Governor(), "runtime", contract("strict"))
        runtime_controller.begin(context())
        calls = []
        runtime = runtime_controller.execute(action(), context(), lambda _a: calls.append("sent"))
        self.assertEqual(runtime.decision.decision, "abort")
        self.assertFalse(runtime.executed)
        self.assertEqual(runtime_controller.state, "aborted")
        self.assertEqual(calls, [])

    def test_strict_stops_after_external_evaluator_blocks_with_violation(self):
        class BlockingEvaluator:
            def evaluate(self, request):
                if request.phase == "runtime":
                    return GovernanceDecision(
                        phase="runtime", decision="block",
                        violations=[Violation(
                            rule="custom.block", phase="runtime",
                            action=request.action.tool_name,
                        )],
                    )
                return GovernanceDecision(phase=request.phase, violations=[])

        controller = WorkflowController(
            Governor(evaluator=BlockingEvaluator()), "run", contract("strict")
        )
        controller.begin(context())
        effects = []
        outcome = controller.execute(action(), context(), lambda _a: effects.append("sent"))
        self.assertEqual(outcome.decision.decision, "block")
        self.assertFalse(outcome.executed)
        self.assertEqual(controller.state, "aborted")
        with self.assertRaisesRegex(RuntimeError, "Run is not active"):
            controller.execute(action(), context(), lambda _a: effects.append("again"))
        self.assertEqual(effects, [])

    def test_contract_snapshot_and_post_failure_do_not_undo_effects(self):
        source = contract("strict")
        controller = WorkflowController(Governor(), "run", source)
        source.declared_tools.clear()
        controller.contract.declared_tools.clear()
        controller.begin(context())
        effects = []
        self.assertTrue(controller.execute(
            action(sensitive=False), context(), lambda _a: effects.append("sent")
        ).executed)
        post = controller.finish(context(), {})
        self.assertEqual([v.rule for v in post.violations], ["response.schema_complete"])
        self.assertEqual(controller.state, "failed_post")
        self.assertEqual(effects, ["sent"])

    def test_phase_order_and_evaluator_error_fail_closed(self):
        controller = WorkflowController(Governor(), "run", contract())
        with self.assertRaises(RuntimeError):
            controller.execute(action(), context(), lambda _a: None)
        with self.assertRaises(RuntimeError):
            controller.finish(context(), {"status": "ok"})

        class BrokenEvaluator:
            def evaluate(self, request):
                if request.phase == "runtime":
                    raise TimeoutError("cannot evaluate")
                return Governor().evaluate(request)

        controller = WorkflowController(Governor(evaluator=BrokenEvaluator()), "run", contract())
        controller.begin(context())
        effects = []
        with self.assertRaises(TimeoutError):
            controller.execute(action(), context(), lambda _a: effects.append("sent"))
        self.assertEqual(controller.state, "aborted")
        self.assertEqual(effects, [])


if __name__ == "__main__":
    unittest.main()
