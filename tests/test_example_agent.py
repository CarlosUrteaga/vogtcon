# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    JsonlDecisionLog,
    WorkflowController,
    load_contract,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "notification_agent.py"
SPEC = importlib.util.spec_from_file_location("notification_agent", EXAMPLE)
assert SPEC is not None and SPEC.loader is not None
notification_agent = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = notification_agent
SPEC.loader.exec_module(notification_agent)


def context(approved: bool, agent_fp: str = "notification-agent-v1") -> ExecutionContext:
    return ExecutionContext(
        state={"approval_granted": approved},
        available_tools=["send_notification"],
        observed_agent_fingerprint=agent_fp,
        observed_contract_fingerprint="notification-contract-v1",
    )


class NotificationExampleTests(unittest.TestCase):
    def _v2_trusted_context(self, contract, *, approved=False):
        return ExecutionContext(
            state={"approval_granted": approved},
            available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint=contract.contract_fingerprint,
        )

    def _v2_contract_requiring_ledger(self, contract):
        document = contract.model_dump()
        document["postconditions"] = [
            *document["postconditions"], "run_ledger.required",
        ]
        document.pop("contract_fingerprint")
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
        document["contract_fingerprint"] = "sha256:" + hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notification_contract_v2_ledger.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return load_contract(path).contract

    def test_v2_guarded_two_blocks_keep_same_run_and_zero_sends(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        begin_context = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        controllers = []
        outcomes = []
        events = []
        finish_contexts = []
        finish_calls = []
        tool_calls = []
        original_begin = WorkflowController.begin
        original_execute = WorkflowController.execute
        original_finish = WorkflowController.finish
        original_tool = notification_agent.InMemoryNotificationTool.__call__
        record_dir = tempfile.TemporaryDirectory()
        self.addCleanup(record_dir.cleanup)
        recorder = JsonlDecisionLog(Path(record_dir.name) / "events.jsonl")

        class ScriptedAgent:
            def __init__(self):
                self.decisions = []
                self.proposals = []

            def receive(self, decision):
                events.append("receive_feedback")
                self.decisions.append(decision)

            def propose(self, message, *, sensitive):
                if self.proposals:
                    self_test.assertEqual(
                        [v.rule for v in self.decisions[-1].violations],
                        ["sensitive_requires_approval"],
                    )
                    events.append("second_proposal")
                else:
                    events.append("first_proposal")
                proposal = ActionProposal(
                    tool_name="send_notification",
                    arguments={
                        "message": message,
                        "sensitive": sensitive,
                        "approval_granted": True,
                    },
                )
                self.proposals.append(proposal)
                return proposal

        self_test = self
        agent = ScriptedAgent()

        def begin(controller, ctx):
            controllers.append(controller)
            events.append("begin")
            return original_begin(controller, ctx)

        def execute(controller, proposal, ctx, send):
            context_snapshot = ctx.model_copy(deep=True).model_dump()
            outcome = original_execute(controller, proposal, ctx, send)
            events.append("execute")
            outcomes.append({
                "outcome": outcome,
                "state": controller.state,
                "context": ctx,
                "context_snapshot": context_snapshot,
                "contract": controller.contract.model_dump(),
                "run_id": controller.run_id,
                "controller": controller,
                "sink": list(tool.sent),
            })
            return outcome

        def finish(controller, ctx, response, run_ledger=None):
            events.append("finish")
            finish_contexts.append(ctx)
            finish_calls.append((controller.state, response, run_ledger))
            return original_finish(controller, ctx, response, run_ledger)

        def invoke(instance, proposal):
            tool_calls.append(proposal)
            events.append("tool")
            return original_tool(instance, proposal)

        def on_blocked(decision):
            events.append("feedback")
            agent.receive(decision)
            return agent.propose("secret", sensitive=True)

        def context_provider():
            events.append("host_context")
            return self._v2_trusted_context(contract)

        with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin), \
             patch.object(WorkflowController, "execute", autospec=True, side_effect=execute), \
             patch.object(WorkflowController, "finish", autospec=True, side_effect=finish), \
             patch.object(notification_agent, "NotificationAgent", return_value=agent), \
             patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=invoke):
            result = notification_agent.run_notification(
                run_id="v2-two-blocks", context=begin_context, message="secret", sensitive=True,
                tool=tool, contract=contract, policy=EnforcementPolicy(mode="guarded"),
                on_blocked=on_blocked, context_provider=context_provider,
                recorder=recorder,
            )

        self.assertEqual(len(controllers), 1)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual([x["outcome"].decision.decision for x in outcomes], ["block", "block"])
        self.assertEqual([x["outcome"].executed for x in outcomes], [False, False])
        self.assertEqual([x["state"] for x in outcomes], ["active", "active"])
        self.assertEqual([x["sink"] for x in outcomes], [[], []])
        self.assertIsNot(outcomes[0]["context"], outcomes[1]["context"])
        self.assertEqual([x["context_snapshot"]["state"] for x in outcomes], [
            {"approval_granted": False}, {"approval_granted": False},
        ])
        self.assertEqual(begin_context.state, {"approval_granted": False})
        self.assertEqual([x["contract"] for x in outcomes], [contract.model_dump()] * 2)
        self.assertTrue(all(x["controller"] is controllers[0] for x in outcomes))
        self.assertEqual([x["run_id"] for x in outcomes], ["v2-two-blocks"] * 2)
        self.assertIs(finish_contexts[0], outcomes[-1]["context"])
        self.assertEqual(len(finish_calls), 1)
        self.assertEqual(finish_calls, [("active", {"status": "blocked"}, None)])
        self.assertEqual(
            [v.rule for v in outcomes[0]["outcome"].decision.violations],
            ["sensitive_requires_approval"],
        )
        self.assertEqual(agent.decisions, [outcomes[0]["outcome"].decision])
        self.assertEqual(len(agent.proposals), 2)
        self.assertTrue(all(p.arguments["approval_granted"] for p in agent.proposals))
        self.assertEqual(events, [
            "begin", "first_proposal", "host_context", "execute", "feedback",
            "receive_feedback", "second_proposal", "host_context", "execute", "finish",
        ])
        self.assertEqual(len(tool_calls), 0)
        self.assertEqual(tool.sent, [])
        self.assertEqual(result.runtime, outcomes[-1]["outcome"])
        logged = recorder.read()
        self.assertEqual([event.event_type for event in logged], [
            "decision", "decision", "decision", "decision",
        ])
        self.assertEqual([event.phase for event in logged], [
            "pre_execution", "runtime", "runtime", "post_execution",
        ])
        self.assertEqual([event.decision for event in logged], [None, "block", "block", None])
        self.assertTrue(all(event.run_id == "v2-two-blocks" for event in logged))
        self.assertEqual([event.action_index for event in logged], [None, 1, 2, None])

    def test_v2_guarded_host_approval_allows_only_second_attempt(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        begin_context = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        controllers = []
        outcomes = []
        events = []
        finish_contexts = []
        finish_calls = []
        tool_calls = []
        original_begin = WorkflowController.begin
        original_execute = WorkflowController.execute
        original_finish = WorkflowController.finish
        original_tool = notification_agent.InMemoryNotificationTool.__call__
        host_state = {"approval_granted": False}
        record_dir = tempfile.TemporaryDirectory()
        self.addCleanup(record_dir.cleanup)
        recorder = JsonlDecisionLog(Path(record_dir.name) / "events.jsonl")

        class ScriptedAgent:
            def __init__(self):
                self.decisions = []
                self.proposals = []

            def receive(self, decision):
                events.append("receive_feedback")
                self.decisions.append(decision)

            def propose(self, message, *, sensitive):
                if self.proposals:
                    self_test.assertEqual(
                        [v.rule for v in self.decisions[-1].violations],
                        ["sensitive_requires_approval"],
                    )
                    events.append("second_proposal")
                else:
                    events.append("first_proposal")
                proposal = ActionProposal(
                    tool_name="send_notification",
                    arguments={
                        "message": message,
                        "sensitive": sensitive,
                        "approval_granted": True,
                    },
                )
                self.proposals.append(proposal)
                return proposal

        self_test = self
        agent = ScriptedAgent()

        def begin(controller, ctx):
            controllers.append(controller)
            events.append("begin")
            return original_begin(controller, ctx)

        def execute(controller, proposal, ctx, send):
            context_snapshot = ctx.model_copy(deep=True).model_dump()
            outcome = original_execute(controller, proposal, ctx, send)
            outcomes.append({
                "outcome": outcome, "state": controller.state, "context": ctx,
                "context_snapshot": context_snapshot,
                "contract": controller.contract.model_dump(), "run_id": controller.run_id,
                "controller": controller, "sink": list(tool.sent),
            })
            events.append("execute")
            return outcome

        def invoke(instance, proposal):
            tool_calls.append(proposal)
            events.append("tool")
            return original_tool(instance, proposal)

        def context_provider():
            events.append("host_context")
            return self._v2_trusted_context(contract, approved=host_state["approval_granted"])

        def on_blocked(decision):
            events.append("feedback")
            agent.receive(decision)
            host_state["approval_granted"] = True
            return agent.propose("secret", sensitive=True)

        def finish(controller, ctx, response, run_ledger=None):
            events.append("finish")
            finish_contexts.append(ctx)
            finish_calls.append((controller.state, response, run_ledger))
            return original_finish(controller, ctx, response, run_ledger)

        with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin), \
             patch.object(WorkflowController, "execute", autospec=True, side_effect=execute), \
             patch.object(WorkflowController, "finish", autospec=True, side_effect=finish), \
             patch.object(notification_agent, "NotificationAgent", return_value=agent), \
             patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=invoke):
            result = notification_agent.run_notification(
                run_id="v2-host-approval", context=begin_context, message="secret", sensitive=True,
                tool=tool, contract=contract, policy=EnforcementPolicy(mode="guarded"),
                on_blocked=on_blocked, context_provider=context_provider, recorder=recorder,
            )

        self.assertEqual(len(controllers), 1)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual([x["outcome"].decision.decision for x in outcomes], ["block", "allow"])
        self.assertEqual([x["outcome"].executed for x in outcomes], [False, True])
        self.assertEqual([x["state"] for x in outcomes], ["active", "active"])
        self.assertEqual([x["sink"] for x in outcomes], [[], ["secret"]])
        self.assertIsNot(outcomes[0]["context"], outcomes[1]["context"])
        self.assertEqual([x["context_snapshot"]["state"] for x in outcomes], [
            {"approval_granted": False}, {"approval_granted": True},
        ])
        self.assertEqual(host_state, {"approval_granted": True})
        self.assertEqual(begin_context.state, {"approval_granted": False})
        self.assertEqual([x["contract"] for x in outcomes], [contract.model_dump()] * 2)
        self.assertTrue(all(x["controller"] is controllers[0] for x in outcomes))
        self.assertEqual([x["run_id"] for x in outcomes], ["v2-host-approval"] * 2)
        self.assertIs(finish_contexts[0], outcomes[-1]["context"])
        self.assertEqual(len(finish_calls), 1)
        self.assertEqual(finish_calls, [("active", {"status": "sent"}, None)])
        self.assertEqual(
            [v.rule for v in outcomes[0]["outcome"].decision.violations],
            ["sensitive_requires_approval"],
        )
        self.assertEqual(agent.decisions, [outcomes[0]["outcome"].decision])
        self.assertEqual(len(agent.proposals), 2)
        self.assertTrue(all(p.arguments["approval_granted"] for p in agent.proposals))
        self.assertEqual(events, [
            "begin", "first_proposal", "host_context", "execute", "feedback",
            "receive_feedback", "second_proposal", "host_context", "tool", "execute",
            "finish",
        ])
        self.assertEqual(len(tool_calls), 1)
        self.assertEqual(tool.sent, ["secret"])
        self.assertEqual(result.runtime, outcomes[-1]["outcome"])
        logged = recorder.read()
        self.assertEqual([event.event_type for event in logged], [
            "decision", "decision", "decision", "tool_completed", "decision",
        ])
        self.assertEqual([event.phase for event in logged], [
            "pre_execution", "runtime", "runtime", "runtime", "post_execution",
        ])
        self.assertEqual([event.decision for event in logged], [
            None, "block", "allow", None, None,
        ])
        self.assertEqual([event.action_index for event in logged], [None, 1, 2, 2, None])
        self.assertTrue(all(event.run_id == "v2-host-approval" for event in logged))
        self.assertTrue(all(event.contract_id == contract.contract_id for event in logged))
        self.assertTrue(all(event.mode == "guarded" for event in logged))
        self.assertEqual(logged[1].violation_rules, ["sensitive_requires_approval"])
        self.assertEqual(logged[3].execution_status, "completed")
        self.assertEqual(sum(event.event_type == "tool_completed" for event in logged), 1)

    def test_v2_finish_without_ledger_closes_once_and_rejects_late_calls(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        trusted = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        controllers = []
        finish_calls = []
        original_begin = WorkflowController.begin
        original_finish = WorkflowController.finish

        def begin(controller, context):
            controllers.append(controller)
            return original_begin(controller, context)

        def finish(controller, context, response, run_ledger=None):
            finish_calls.append((response, run_ledger, controller.state))
            return original_finish(controller, context, response, run_ledger)

        with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin), \
             patch.object(WorkflowController, "finish", autospec=True, side_effect=finish):
            result = notification_agent.run_notification(
                run_id="v2-finish-once", context=trusted, message="notice",
                sensitive=False, tool=tool, contract=contract,
                policy=EnforcementPolicy(mode="guarded"),
            )

        self.assertEqual(result.state, "finished")
        self.assertEqual(result.post.violations, [])
        self.assertEqual(finish_calls, [({"status": "sent"}, None, "active")])
        self.assertEqual(tool.sent, ["notice"])
        self.assertEqual(len(controllers), 1)
        with self.assertRaisesRegex(RuntimeError, "Run is not active"):
            controllers[0].execute(
                ActionProposal(tool_name="send_notification", arguments={"message": "again"}),
                trusted,
                tool,
            )
        with self.assertRaisesRegex(RuntimeError, "Run is not active"):
            controllers[0].finish(trusted, {"status": "sent"})
        self.assertEqual(tool.sent, ["notice"])

    def test_v2_required_ledger_post_failure_keeps_effect_and_rejects_late_calls(self):
        loaded_contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        contract = self._v2_contract_requiring_ledger(loaded_contract)
        trusted = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        controllers = []
        original_begin = WorkflowController.begin

        def begin(controller, context):
            controllers.append(controller)
            return original_begin(controller, context)

        with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin):
            result = notification_agent.run_notification(
                run_id="v2-required-ledger", context=trusted, message="notice",
                sensitive=False, tool=tool, contract=contract,
                policy=EnforcementPolicy(mode="strict"),
            )

        self.assertEqual([violation.rule for violation in result.post.violations], [
            "run_ledger.required",
        ])
        self.assertEqual(result.state, "failed_post")
        self.assertEqual(tool.sent, ["notice"])
        self.assertTrue(result.runtime.executed)
        with self.assertRaisesRegex(RuntimeError, "Run is not active"):
            controllers[0].execute(
                ActionProposal(tool_name="send_notification", arguments={"message": "again"}),
                trusted,
                tool,
            )
        with self.assertRaisesRegex(RuntimeError, "Run is not active"):
            controllers[0].finish(trusted, {"status": "again"})
        self.assertEqual(tool.sent, ["notice"])

    def test_v2_host_ledger_is_forwarded_at_finish_and_recorded(self):
        loaded_contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        contract = self._v2_contract_requiring_ledger(loaded_contract)
        trusted = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        ledger = {"run_id": "v2-ledger-forwarded"}
        record_dir = tempfile.TemporaryDirectory()
        self.addCleanup(record_dir.cleanup)
        recorder = JsonlDecisionLog(Path(record_dir.name) / "events.jsonl")
        finish_arguments = []
        original_finish = WorkflowController.finish

        def finish(controller, context, response, run_ledger=None):
            finish_arguments.append(run_ledger)
            return original_finish(controller, context, response, run_ledger)

        with patch.object(WorkflowController, "finish", autospec=True, side_effect=finish):
            result = notification_agent.run_notification(
                run_id="v2-ledger-forwarded", context=trusted, message="notice",
                sensitive=False, tool=tool, contract=contract,
                policy=EnforcementPolicy(mode="guarded"),
                recorder=recorder, run_ledger=ledger,
            )

        self.assertEqual(finish_arguments, [ledger])
        self.assertEqual(result.post.violations, [])
        self.assertEqual(result.state, "finished")
        self.assertEqual(tool.sent, ["notice"])
        self.assertEqual([event.phase for event in recorder.read()], [
            "pre_execution", "runtime", "runtime", "post_execution",
        ])
        self.assertTrue(all(event.run_id == "v2-ledger-forwarded" for event in recorder.read()))

    def test_v2_guarded_callback_none_keeps_one_blocked_attempt(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        trusted = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        original_execute = WorkflowController.execute
        outcomes = []

        def execute(controller, *args):
            outcome = original_execute(controller, *args)
            outcomes.append((outcome, controller.state, list(tool.sent)))
            return outcome

        callback = unittest.mock.Mock(return_value=None)
        with patch.object(WorkflowController, "execute", autospec=True, side_effect=execute):
            result = notification_agent.run_notification(
                run_id="v2-no-retry", context=trusted, message="secret", sensitive=True,
                tool=tool, contract=contract, policy=EnforcementPolicy(mode="guarded"),
                on_blocked=callback,
            )
        callback.assert_called_once()
        self.assertEqual([(o.decision.decision, o.executed, state, sent) for o, state, sent in outcomes], [("block", False, "active", [])])
        self.assertEqual(result.runtime, outcomes[0][0])
        self.assertEqual(tool.sent, [])

    def test_v2_guarded_callback_only_runs_after_block(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        callback = unittest.mock.Mock(return_value=None)
        for mode, sensitive, approved, expected_state in (
            ("guarded", False, False, "finished"),
            ("strict", True, False, "aborted"),
        ):
            with self.subTest(mode=mode):
                trusted = self._v2_trusted_context(contract, approved=approved)
                tool = notification_agent.InMemoryNotificationTool()
                callback.reset_mock()
                result = notification_agent.run_notification(
                    run_id=f"v2-no-callback-{mode}", context=trusted, message="secret",
                    sensitive=sensitive, tool=tool, contract=contract,
                    policy=EnforcementPolicy(mode=mode), on_blocked=callback,
                )
                callback.assert_not_called()
                self.assertEqual(result.state, expected_state)
                self.assertEqual(tool.sent, ["secret"] if not sensitive else [])

    def test_v2_guarded_second_attempt_tool_error_propagates_after_effect(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        trusted = self._v2_trusted_context(contract)
        tool = notification_agent.InMemoryNotificationTool()
        original_tool = notification_agent.InMemoryNotificationTool.__call__
        failure = RuntimeError("second send response lost")
        attempts = []
        execute_count = 0
        original_execute = WorkflowController.execute

        def execute(controller, *args):
            nonlocal execute_count
            execute_count += 1
            return original_execute(controller, *args)

        def fail_after_send(instance, proposal):
            original_tool(instance, proposal)
            attempts.append(proposal.arguments["message"])
            raise failure

        def approve(decision):
            trusted.state["approval_granted"] = True
            return ActionProposal(
                tool_name="send_notification", arguments={"message": "secret", "sensitive": True},
            )

        callback = unittest.mock.Mock(side_effect=approve)
        with patch.object(WorkflowController, "execute", autospec=True, side_effect=execute), \
             patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=fail_after_send):
            with self.assertRaises(RuntimeError) as caught:
                notification_agent.run_notification(
                    run_id="v2-second-error", context=trusted, message="secret", sensitive=True,
                    tool=tool, contract=contract, policy=EnforcementPolicy(mode="guarded"),
                    on_blocked=callback, context_provider=lambda: trusted,
                )
        self.assertIs(caught.exception, failure)
        callback.assert_called_once()
        self.assertEqual(execute_count, 2)
        self.assertEqual(attempts, ["secret"])
        self.assertEqual(tool.sent, ["secret"])

    def test_v2_guarded_callback_and_second_context_provider_errors_propagate(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        for failure_point in ("callback", "context_provider"):
            with self.subTest(failure_point=failure_point):
                trusted = self._v2_trusted_context(contract)
                tool = notification_agent.InMemoryNotificationTool()
                failure = RuntimeError(f"{failure_point} failed")
                execute_count = 0
                original_execute = WorkflowController.execute

                def execute(controller, *args):
                    nonlocal execute_count
                    execute_count += 1
                    return original_execute(controller, *args)

                def callback(decision):
                    if failure_point == "callback":
                        raise failure
                    return ActionProposal(tool_name="send_notification", arguments={"message": "secret", "sensitive": True})

                provider_calls = 0
                def context_provider():
                    nonlocal provider_calls
                    provider_calls += 1
                    if failure_point == "context_provider" and provider_calls == 2:
                        raise failure
                    return trusted

                with patch.object(WorkflowController, "execute", autospec=True, side_effect=execute):
                    with self.assertRaises(RuntimeError) as caught:
                        notification_agent.run_notification(
                            run_id=f"v2-{failure_point}-error", context=trusted, message="secret",
                            sensitive=True, tool=tool, contract=contract,
                            policy=EnforcementPolicy(mode="guarded"), on_blocked=callback,
                            context_provider=context_provider,
                        )
                self.assertIs(caught.exception, failure)
                self.assertEqual(execute_count, 1)
                self.assertEqual(tool.sent, [])

    def test_begin_precedes_first_proposal(self):
        original_begin = WorkflowController.begin
        original_propose = notification_agent.NotificationAgent.propose
        original_tool = notification_agent.InMemoryNotificationTool.__call__
        events = []
        controllers = []
        counts = {"begin": 0, "propose": 0, "tool": 0}

        def begin(controller, trusted_context):
            counts["begin"] += 1
            events.append("begin_enter")
            controllers.append(controller)
            result = original_begin(controller, trusted_context)
            events.append(("begin_exit", controller.state))
            return result

        def propose(agent, message, *, sensitive):
            counts["propose"] += 1
            events.append("propose_enter")
            self.assertEqual(events[-2], ("begin_exit", "active"))
            return original_propose(agent, message, sensitive=sensitive)

        def invoke(tool, proposal):
            counts["tool"] += 1
            return original_tool(tool, proposal)

        tool = notification_agent.InMemoryNotificationTool()
        with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin), \
             patch.object(notification_agent.NotificationAgent, "propose", autospec=True, side_effect=propose), \
             patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=invoke):
            result = notification_agent.run_notification(
                run_id="ordered", context=context(True), message="hello",
                sensitive=False, tool=tool,
            )

        self.assertEqual(events, ["begin_enter", ("begin_exit", "active"), "propose_enter"])
        self.assertEqual(counts, {"begin": 1, "propose": 1, "tool": 1})
        self.assertEqual(result.state, "finished")
        self.assertEqual(tool.sent, ["hello"])

    def test_v2_valid_identity_begins_before_first_proposal(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        trusted = ExecutionContext(
            state={"approval_granted": False},
            available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint=contract.contract_fingerprint,
        )
        original_begin = WorkflowController.begin
        original_propose = notification_agent.NotificationAgent.propose
        events = []
        controller_seen = []

        def begin(controller, ctx):
            events.append("begin_enter")
            controller_seen.append(controller)
            result = original_begin(controller, ctx)
            events.append(("begin_exit", controller.state))
            return result

        def propose(agent, message, *, sensitive):
            events.append("propose_enter")
            self.assertEqual(events[-2], ("begin_exit", "active"))
            return original_propose(agent, message, sensitive=sensitive)

        tool = notification_agent.InMemoryNotificationTool()
        with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin), \
             patch.object(notification_agent.NotificationAgent, "propose", autospec=True, side_effect=propose):
            result = notification_agent.run_notification(
                run_id="v2-valid", context=trusted, message="hello",
                sensitive=False, tool=tool, contract=contract,
                policy=EnforcementPolicy(mode="strict"),
            )

        self.assertEqual(events, ["begin_enter", ("begin_exit", "active"), "propose_enter"])
        self.assertEqual(len(controller_seen), 1)
        self.assertEqual(controller_seen[0].run_id, "v2-valid")
        self.assertEqual(result.state, "finished")
        self.assertTrue(result.runtime.executed)
        self.assertEqual(tool.sent, ["hello"])

    def test_v2_strict_invalid_identity_stops_before_proposal(self):
        contract = load_contract(
            EXAMPLE.with_name("notification_contract_v2.yaml")
        ).contract
        original_begin = WorkflowController.begin
        original_execute = WorkflowController.execute
        original_finish = WorkflowController.finish
        original_propose = notification_agent.NotificationAgent.propose
        original_tool = notification_agent.InMemoryNotificationTool.__call__

        for invalid_identity, expected_rule in (
            ("agent", "agent.configuration_fingerprint_match"),
            ("contract", "contract.fingerprint_match"),
        ):
            with self.subTest(invalid_identity=invalid_identity):
                trusted = ExecutionContext(
                    state={"approval_granted": True},
                    available_tools=["send_notification"],
                    observed_agent_fingerprint=("unknown" if invalid_identity == "agent" else "notification-agent-v1"),
                    observed_contract_fingerprint=("unknown" if invalid_identity == "contract" else contract.contract_fingerprint),
                )
                calls = {"begin": 0, "execute": 0, "finish": 0, "propose": 0, "tool": 0}
                states = []
                controllers = []
                tool = notification_agent.InMemoryNotificationTool()

                def begin(controller, ctx):
                    calls["begin"] += 1
                    controllers.append(controller)
                    result = original_begin(controller, ctx)
                    states.append(controller.state)
                    return result

                def execute(controller, *args):
                    calls["execute"] += 1
                    return original_execute(controller, *args)

                def finish(controller, *args):
                    calls["finish"] += 1
                    return original_finish(controller, *args)

                def propose(agent, *args, **kwargs):
                    calls["propose"] += 1
                    return original_propose(agent, *args, **kwargs)

                def invoke(instance, proposal):
                    calls["tool"] += 1
                    return original_tool(instance, proposal)

                with patch.object(WorkflowController, "begin", autospec=True, side_effect=begin), \
                     patch.object(WorkflowController, "execute", autospec=True, side_effect=execute), \
                     patch.object(WorkflowController, "finish", autospec=True, side_effect=finish), \
                     patch.object(notification_agent.NotificationAgent, "propose", autospec=True, side_effect=propose), \
                     patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=invoke):
                    result = notification_agent.run_notification(
                        run_id=f"strict-{invalid_identity}", context=trusted,
                        message="hello", sensitive=False, tool=tool,
                        contract=contract, policy=EnforcementPolicy(mode="strict"),
                    )

                self.assertEqual([v.rule for v in result.pre.violations], [expected_rule])
                self.assertEqual(states, ["aborted"])
                self.assertEqual(result.state, "aborted")
                self.assertIsNone(result.runtime)
                self.assertIsNone(result.post)
                self.assertEqual(calls, {"begin": 1, "execute": 0, "finish": 0, "propose": 0, "tool": 0})
                self.assertEqual(tool.sent, [])
                with self.assertRaisesRegex(RuntimeError, "Run is not active"):
                    controllers[0].execute(
                        ActionProposal(
                            tool_name="send_notification", arguments={"message": "again"},
                        ),
                        trusted,
                        tool,
                    )
                with self.assertRaisesRegex(RuntimeError, "Run is not active"):
                    controllers[0].finish(trusted, {"status": "again"})
                self.assertEqual(tool.sent, [])

    def test_contract_loads_and_example_has_no_benchmark_import(self):
        document = load_contract(notification_agent.CONTRACT_PATH)
        self.assertEqual(document.contract.contract_id, "example.notification")
        self.assertNotIn("tools.enforcement", EXAMPLE.read_text(encoding="utf-8"))

    def test_sensitive_notification_blocked_then_allowed_by_trusted_approval(self):
        denied_tool = notification_agent.InMemoryNotificationTool()
        denied = notification_agent.run_notification(
            run_id="denied", context=context(False), message="secret",
            sensitive=True, tool=denied_tool,
        )
        self.assertEqual(denied.runtime.decision.decision, "block")
        self.assertFalse(denied.runtime.executed)
        self.assertEqual(denied_tool.sent, [])
        self.assertEqual(denied.state, "finished")

        allowed_tool = notification_agent.InMemoryNotificationTool()
        allowed = notification_agent.run_notification(
            run_id="allowed", context=context(True), message="secret",
            sensitive=True, tool=allowed_tool,
        )
        self.assertEqual(allowed.runtime.decision.decision, "allow")
        self.assertTrue(allowed.runtime.executed)
        self.assertEqual(allowed_tool.sent, ["secret"])
        self.assertEqual(allowed.state, "finished")

    def test_agent_claim_cannot_supply_approval(self):
        proposal = notification_agent.NotificationAgent().propose("notice", sensitive=True)
        proposal.arguments["approval_granted"] = True
        # Even if an agent adds that claim, only trusted context is consulted.
        from vogtcon import GovernorInput, Governor
        req = GovernorInput(
            run_id="spoof", contract=load_contract(notification_agent.CONTRACT_PATH).contract,
            phase="runtime", context=context(False), action=proposal,
        )
        self.assertEqual(Governor().evaluate(req).decision, "block")

    def test_v2_dispatch_matrix_ignores_agent_approval_claim(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        original_propose = notification_agent.NotificationAgent.propose
        original_execute = WorkflowController.execute
        original_tool = notification_agent.InMemoryNotificationTool.__call__

        for mode, decision, executed, state in (
            ("no_contract", "allow", True, "active"),
            ("advisory", "allow_with_warning", True, "active"),
            ("guarded", "block", False, "active"),
            ("strict", "abort", False, "aborted"),
        ):
            with self.subTest(mode=mode):
                trusted = ExecutionContext(
                    state={"approval_granted": False},
                    available_tools=["send_notification"],
                    observed_agent_fingerprint="notification-agent-v1",
                    observed_contract_fingerprint=contract.contract_fingerprint,
                )
                tool = notification_agent.InMemoryNotificationTool()
                calls = {"propose": 0, "execute": 0, "tool": 0}
                after_attempt = []

                def propose(agent, message, *, sensitive):
                    calls["propose"] += 1
                    proposal = original_propose(agent, message, sensitive=sensitive)
                    proposal.arguments["approval_granted"] = True
                    return proposal

                def execute(controller, proposal, ctx, send):
                    calls["execute"] += 1
                    self.assertEqual(controller.run_id, f"dispatch-{mode}")
                    self.assertIs(ctx, trusted)
                    self.assertIs(send, tool)
                    self.assertEqual(proposal.tool_name, "send_notification")
                    self.assertEqual(proposal.arguments, {
                        "message": "secret", "sensitive": True, "approval_granted": True,
                    })
                    outcome = original_execute(controller, proposal, ctx, send)
                    # Snapshot before returning to run_notification, which may finish.
                    after_attempt.append((outcome, controller.state, calls["tool"], list(tool.sent)))
                    return outcome

                def invoke(instance, proposal):
                    calls["tool"] += 1
                    return original_tool(instance, proposal)

                with patch.object(notification_agent.NotificationAgent, "propose", autospec=True, side_effect=propose), \
                     patch.object(WorkflowController, "execute", autospec=True, side_effect=execute), \
                     patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=invoke):
                    result = notification_agent.run_notification(
                        run_id=f"dispatch-{mode}", context=trusted, message="secret",
                        sensitive=True, tool=tool, contract=contract,
                        policy=EnforcementPolicy(mode=mode),
                    )

                self.assertEqual(result.pre.violations, [])
                self.assertEqual(result.runtime.decision.decision, decision)
                self.assertEqual(result.runtime.executed, executed)
                self.assertEqual(result.runtime.result, "sent" if executed else None)
                expected_sent = ["secret"] if executed else []
                self.assertEqual(after_attempt, [(result.runtime, state, int(executed), expected_sent)])
                self.assertEqual(calls, {"propose": 1, "execute": 1, "tool": int(executed)})
                self.assertEqual(tool.sent, expected_sent)
                self.assertEqual(trusted.state, {"approval_granted": False})

    def test_v2_tool_exception_propagates_after_possible_effect(self):
        contract = load_contract(EXAMPLE.with_name("notification_contract_v2.yaml")).contract
        trusted = ExecutionContext(
            state={"approval_granted": True},
            available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint=contract.contract_fingerprint,
        )
        tool = notification_agent.InMemoryNotificationTool()
        original_tool = notification_agent.InMemoryNotificationTool.__call__
        failure = RuntimeError("lost response after send")

        def fail_after_send(instance, proposal):
            original_tool(instance, proposal)
            raise failure

        with patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=fail_after_send) as send:
            with self.assertRaises(RuntimeError) as caught:
                notification_agent.run_notification(
                    run_id="dispatch-error", context=trusted, message="secret",
                    sensitive=True, tool=tool, contract=contract,
                    policy=EnforcementPolicy(mode="guarded"),
                )

        self.assertIs(caught.exception, failure)
        send.assert_called_once()
        # A failed return cannot establish that the external effect did not occur.
        self.assertEqual(tool.sent, ["secret"])

    def test_guarded_pre_fingerprint_failure_preserves_historical_continuation(self):
        tool = notification_agent.InMemoryNotificationTool()
        original_propose = notification_agent.NotificationAgent.propose
        original_tool = notification_agent.InMemoryNotificationTool.__call__
        calls = {"propose": 0, "tool": 0}

        def propose(agent, *args, **kwargs):
            calls["propose"] += 1
            return original_propose(agent, *args, **kwargs)

        def invoke(instance, proposal):
            calls["tool"] += 1
            return original_tool(instance, proposal)

        with patch.object(notification_agent.NotificationAgent, "propose", autospec=True, side_effect=propose), \
             patch.object(notification_agent.InMemoryNotificationTool, "__call__", autospec=True, side_effect=invoke):
            result = notification_agent.run_notification(
                run_id="bad-fingerprint", context=context(True, agent_fp="unknown"),
                message="hello", sensitive=False, tool=tool,
            )
        # The historic guarded mode records a pre violation but continues.
        self.assertEqual([v.rule for v in result.pre.violations], ["agent.configuration_fingerprint_match"])
        self.assertEqual(result.runtime.decision.decision, "allow")
        self.assertEqual(result.state, "finished")
        self.assertEqual(calls, {"propose": 1, "tool": 1})
        self.assertEqual(tool.sent, ["hello"])


if __name__ == "__main__":
    unittest.main()
