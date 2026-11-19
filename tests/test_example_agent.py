# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import unittest
from unittest.mock import patch
from pathlib import Path

from vogtcon import EnforcementPolicy, ExecutionContext, WorkflowController, load_contract

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
                tool = notification_agent.InMemoryNotificationTool()

                def begin(controller, ctx):
                    calls["begin"] += 1
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
