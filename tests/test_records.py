# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from vogtcon import (
    ActionProposal,
    AgentContract,
    ExecutionContext,
    Governor,
    JsonlDecisionLog,
    RunEvent,
    WorkflowController,
)


def contract() -> AgentContract:
    return AgentContract.model_validate({
        "contract_id": "records.test", "mode": "guarded",
        "approved_agent_configurations": ["agent-v1"],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["status"]},
        "memory_policy": "none",
        "validation_phases": ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": ["tool.declared_only", "sensitive_requires_approval"],
        "postconditions": ["response.schema_complete"],
        "agent_feedback": {
            "advisory_warning_visibility": False,
            "guarded_denial_style": "minimal",
            "strict_replanning_after_violation": False,
        },
        "contract_fingerprint": "contract-v1",
    })


def context(approved: bool = False) -> ExecutionContext:
    return ExecutionContext(
        state={"approval_granted": approved},
        available_tools=["send_notification"],
        observed_agent_fingerprint="agent-v1",
        observed_contract_fingerprint="contract-v1",
    )


def action() -> ActionProposal:
    return ActionProposal(
        tool_name="send_notification",
        arguments={"message": "SECRET-CONTENT", "sensitive": True},
    )


class RecordTests(unittest.TestCase):
    def test_decisions_written_before_effect_and_read_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            log = JsonlDecisionLog(path)
            controller = WorkflowController(Governor(), "run-1", contract(), log)
            controller.begin(context())
            calls = []
            blocked = controller.execute(action(), context(), lambda _a: calls.append("sent"))
            self.assertFalse(blocked.executed)
            self.assertEqual(calls, [])

            def send(_proposal):
                # The decision line must be durable before the effect.
                self.assertEqual([event.event_type for event in log.read()][-1], "decision")
                calls.append("sent")
                return "sent"

            allowed = controller.execute(action(), context(True), send)
            self.assertTrue(allowed.executed)
            controller.finish(context(True), {"status": "ok"})
            events = log.read()
            self.assertEqual([e.sequence for e in events], [1, 2, 3, 4, 5])
            self.assertEqual([e.event_type for e in events], [
                "decision", "decision", "decision", "tool_completed", "decision"
            ])
            self.assertEqual([e.action_index for e in events], [None, 1, 2, 2, None])
            self.assertEqual(events[1].violation_rules, ["sensitive_requires_approval"])
            self.assertEqual(events[2].decision, "allow")
            self.assertEqual(events[3].execution_status, "completed")
            self.assertEqual(calls, ["sent"])
            self.assertNotIn("SECRET-CONTENT", path.read_text(encoding="utf-8"))

    def test_record_failure_before_tool_aborts_without_effect(self):
        class BrokenLog:
            def __init__(self):
                self.count = 0

            def record(self, _event):
                self.count += 1
                if self.count == 2:
                    raise OSError("disk unavailable")

        log = BrokenLog()
        controller = WorkflowController(Governor(), "run", contract(), log)
        controller.begin(context(True))
        calls = []
        with self.assertRaisesRegex(OSError, "disk unavailable"):
            controller.execute(action(), context(True), lambda _a: calls.append("sent"))
        self.assertEqual(calls, [])
        self.assertEqual(controller.state, "aborted")

    def test_tool_error_is_recorded_as_uncertain_without_rollback_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = JsonlDecisionLog(Path(tmp) / "events.jsonl")
            controller = WorkflowController(Governor(), "run", contract(), log)
            controller.begin(context(True))
            calls = []

            def fail_after_effect(_proposal):
                calls.append("remote effect")
                raise RuntimeError("lost response")

            with self.assertRaisesRegex(RuntimeError, "lost response"):
                controller.execute(action(), context(True), fail_after_effect)
            self.assertEqual(calls, ["remote effect"])
            self.assertEqual(controller.state, "aborted")
            events = log.read()
            self.assertEqual(events[-1].event_type, "tool_error")
            self.assertEqual(events[-1].execution_status, "unknown")

    def test_completion_log_failure_does_not_claim_tool_failed_or_undo_effect(self):
        class FailingCompletionLog:
            def __init__(self):
                self.events = []

            def record(self, event):
                if event.event_type == "tool_completed":
                    raise OSError("completion log unavailable")
                self.events.append(event)

        log = FailingCompletionLog()
        controller = WorkflowController(Governor(), "run", contract(), log)
        controller.begin(context(True))
        effects = []
        with self.assertRaisesRegex(OSError, "completion log unavailable"):
            controller.execute(action(), context(True), lambda _a: effects.append("sent"))
        self.assertEqual(effects, ["sent"])
        self.assertEqual(controller.state, "aborted")
        self.assertEqual([e.event_type for e in log.events], ["decision", "decision"])

    def test_schema_rejects_unknown_fields_and_versions(self):
        valid = RunEvent(
            run_id="run", sequence=1, contract_id="c", mode="guarded",
            phase="runtime", event_type="decision", decision="allow",
            action_index=1, tool_name="send_notification",
        )
        with self.assertRaises(ValidationError):
            RunEvent.model_validate({**valid.model_dump(), "schema_version": 2})
        with self.assertRaises(ValidationError):
            RunEvent.model_validate({**valid.model_dump(), "secret": "not allowed"})
        with self.assertRaisesRegex(ValidationError, "matching status"):
            RunEvent.model_validate({
                **valid.model_dump(), "event_type": "tool_completed",
                "decision": None, "execution_status": "not_started",
            })


if __name__ == "__main__":
    unittest.main()
