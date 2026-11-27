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
from vogtcon.records import RunEventV2, parse_run_event


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


def _digest(ch: str = "a") -> str:
    return "sha256:" + (ch * 64)[:64]


class RunEventV2Tests(unittest.TestCase):
    def test_valid_v2_event_shapes_across_all_six_event_types(self) -> None:
        pre = RunEventV2(
            run_id="run-v2",
            sequence=1,
            contract_id="c-v3",
            mode="guarded",
            phase="pre_execution",
            event_type="decision",
            policy_scope="scope.1",
        )
        self.assertEqual(pre.schema_version, 2)

        rt_allow = RunEventV2(
            run_id="run-v2",
            sequence=2,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="decision",
            action_index=1,
            tool_name="transfer_funds",
            decision="allow",
            policy_scope="scope.1",
            effect_id="eff-000001",
            operation_digest=_digest("1"),
            effect_status="reserved",
        )
        self.assertEqual(rt_allow.effect_status, "reserved")

        rt_block = RunEventV2(
            run_id="run-v2",
            sequence=3,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="decision",
            action_index=2,
            tool_name="transfer_funds",
            decision="block",
            violation_rules=["limit-rule"],
            policy_scope="scope.1",
        )
        self.assertIsNone(rt_block.effect_id)
        self.assertEqual(rt_block.violation_rules, ("limit-rule",))
        with self.assertRaises(AttributeError):
            rt_block.violation_rules.append("hacked")  # type: ignore[attr-defined]
        self.assertIs(type(rt_block.model_dump()["violation_rules"]), list)
        with self.assertRaises(ValidationError):
            rt_block.model_copy(update={"effect_id": "eff-000009"})

        tool_done = RunEventV2(
            run_id="run-v2",
            sequence=4,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="tool_completed",
            action_index=1,
            tool_name="transfer_funds",
            execution_status="completed",
            policy_scope="scope.1",
            effect_id="eff-000001",
            operation_digest=_digest("1"),
        )
        self.assertEqual(tool_done.execution_status, "completed")

        tool_err = RunEventV2(
            run_id="run-v2",
            sequence=5,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="tool_error",
            action_index=1,
            tool_name="transfer_funds",
            execution_status="unknown",
            policy_scope="scope.1",
            effect_id="eff-000001",
            operation_digest=_digest("1"),
        )
        self.assertEqual(tool_err.execution_status, "unknown")

        observed_uncertain = RunEventV2(
            run_id="run-v2",
            sequence=6,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="effect_observed",
            action_index=1,
            tool_name="transfer_funds",
            execution_status="unknown",
            policy_scope="scope.1",
            effect_id="eff-000001",
            operation_digest=_digest("1"),
            effect_status="uncertain",
            evidence_ref="obs-timeout",
        )
        self.assertEqual(observed_uncertain.effect_status, "uncertain")

        reconciled = RunEventV2(
            run_id="run-v2",
            sequence=7,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="effect_reconciled",
            execution_status="completed",
            policy_scope="scope.1",
            effect_id="eff-000001",
            operation_digest=_digest("1"),
            effect_status="confirmed",
            evidence_ref="audit-confirmed-1",
        )
        self.assertEqual(reconciled.effect_status, "confirmed")

        compensated = RunEventV2(
            run_id="run-v2",
            sequence=8,
            contract_id="c-v3",
            mode="guarded",
            phase="runtime",
            event_type="effect_compensated",
            tool_name="refund_funds",
            execution_status="completed",
            policy_scope="scope.1",
            effect_id="eff-000002",
            operation_digest=_digest("2"),
            effect_status="confirmed",
            compensates_effect_id="eff-000001",
            evidence_ref="refund-confirmed-2",
        )
        self.assertEqual(compensated.compensates_effect_id, "eff-000001")

    def test_v2_rejects_extra_secret_fields_and_invalid_event_shapes(self) -> None:
        sentinel = "SECRET_ARG_OR_PROMPT_VALUE_888"
        base = {
            "schema_version": 2,
            "run_id": "run-v2",
            "sequence": 1,
            "contract_id": "c-v3",
            "mode": "guarded",
            "phase": "runtime",
            "event_type": "decision",
            "action_index": 1,
            "tool_name": "transfer_funds",
            "decision": "allow",
            "effect_id": "eff-000001",
            "operation_digest": _digest("1"),
            "effect_status": "reserved",
        }
        for forbidden_key in ("arguments", "prompt", "result", "params", "host_facts"):
            with self.subTest(forbidden_key=forbidden_key):
                with self.assertRaises(ValidationError) as ctx:
                    RunEventV2.model_validate({**base, forbidden_key: sentinel})
                self.assertNotIn(sentinel, str(ctx.exception))

        invalid_cases = [
            # blocked decision cannot carry effect_id
            {**base, "decision": "block"},
            # reserved decision missing operation_digest
            {**base, "operation_digest": None},
            # reserved decision with wrong effect_status
            {**base, "effect_status": "confirmed"},
            # pre_execution decision with effect_id
            {
                **base,
                "phase": "pre_execution",
                "action_index": None,
                "tool_name": None,
                "decision": None,
            },
            # effect_observed with status="reserved"
            {
                **base,
                "event_type": "effect_observed",
                "decision": None,
                "effect_status": "reserved",
                "execution_status": "completed",
            },
            # effect_observed uncertain with execution_status="completed"
            {
                **base,
                "event_type": "effect_observed",
                "decision": None,
                "effect_status": "uncertain",
                "execution_status": "completed",
            },
            # effect_reconciled missing evidence_ref
            {
                **base,
                "event_type": "effect_reconciled",
                "decision": None,
                "effect_status": "confirmed",
                "execution_status": "completed",
                "evidence_ref": None,
            },
            # effect_reconciled with uncertain status
            {
                **base,
                "event_type": "effect_reconciled",
                "decision": None,
                "effect_status": "uncertain",
                "execution_status": "completed",
                "evidence_ref": "ev-1",
            },
            # effect_compensated self-compensation
            {
                **base,
                "event_type": "effect_compensated",
                "decision": None,
                "effect_status": "confirmed",
                "execution_status": "completed",
                "compensates_effect_id": "eff-000001",
                "evidence_ref": "ev-comp",
            },
            # trace_id without span_id
            {**base, "trace_id": "trace-only"},
        ]
        for idx, payload in enumerate(invalid_cases):
            with self.subTest(case_index=idx):
                with self.assertRaises(ValidationError):
                    RunEventV2.model_validate(payload)

    def test_parse_run_event_and_jsonl_decision_log_multi_version_roundtrip(
        self,
    ) -> None:
        v1_event = RunEvent(
            run_id="run-v1",
            sequence=1,
            contract_id="c1",
            mode="guarded",
            phase="pre_execution",
            event_type="decision",
        )
        v2_event = RunEventV2(
            run_id="run-v2",
            sequence=1,
            contract_id="c3",
            mode="guarded",
            phase="runtime",
            event_type="effect_observed",
            action_index=1,
            tool_name="transfer_funds",
            execution_status="completed",
            effect_id="eff-000001",
            operation_digest=_digest("a"),
            effect_status="confirmed",
            evidence_ref="tx-100",
        )

        self.assertEqual(parse_run_event(v1_event.model_dump_json()), v1_event)
        self.assertEqual(parse_run_event(v2_event.model_dump_json()), v2_event)
        # Omitted schema_version in dict defaults to v1 RunEvent
        v1_no_ver = v1_event.model_dump()
        del v1_no_ver["schema_version"]
        self.assertEqual(parse_run_event(v1_no_ver), v1_event)

        for bad_ver in (0, 3, "1", "2", 2.0, True, False, None):
            with self.subTest(bad_ver=repr(bad_ver)):
                with self.assertRaises((ValidationError, ValueError)):
                    parse_run_event({**v2_event.model_dump(), "schema_version": bad_ver})

        with tempfile.TemporaryDirectory() as tmp:
            log = JsonlDecisionLog(Path(tmp) / "mixed.jsonl")
            log.record(v1_event)
            log.record(v2_event)
            events = log.read()
            self.assertEqual(len(events), 2)
            self.assertIsInstance(events[0], RunEvent)
            self.assertIsInstance(events[1], RunEventV2)
            self.assertEqual(events, [v1_event, v2_event])


if __name__ == "__main__":
    unittest.main()
