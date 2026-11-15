# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import models

from vogtcon import (
    ActionProposal, EnforcementPolicy, ExecutionContext, Governor, JsonlDecisionLog,
    TelemetryObserver, WorkflowController, load_contract,
)

models.ALLOW_MODEL_REQUESTS = False
os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "custom_agent.py"
SPEC = importlib.util.spec_from_file_location("custom_agent_telemetry", EXAMPLE)
assert SPEC is not None and SPEC.loader is not None
custom_agent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = custom_agent
SPEC.loader.exec_module(custom_agent)


def context(approved: bool) -> ExecutionContext:
    fingerprint = load_contract(
        custom_agent.CONTRACT_PATH, rule_catalog=custom_agent.RULES
    ).contract.contract_fingerprint
    return ExecutionContext(
        state={"approval_granted": approved},
        available_tools=["save_note"],
        observed_agent_fingerprint="pydantic-note-agent-v1",
        observed_contract_fingerprint=fingerprint,
    )


class TelemetryTests(unittest.TestCase):
    def test_v2_check_span_uses_external_policy_mode(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        telemetry = TelemetryObserver(provider)
        contract = load_contract(
            Path(__file__).resolve().parents[1] / "examples" / "notification_contract_v2.yaml"
        ).contract
        context = ExecutionContext(
            state={}, available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint=contract.contract_fingerprint,
        )
        with telemetry.run("v2-trace", contract.contract_id):
            controller = WorkflowController(
                Governor(), "v2-trace", contract, telemetry=telemetry,
                policy=EnforcementPolicy(mode="guarded"),
            )
            controller.begin(context)
            outcome = controller.execute(
                ActionProposal(
                    tool_name="send_notification", arguments={"sensitive": True},
                ),
                context, lambda _action: self.fail("blocked tool was invoked"),
            )
        self.assertEqual(outcome.decision.decision, "block")
        check_spans = [
            span for span in exporter.get_finished_spans()
            if span.name == "governor.check"
        ]
        self.assertEqual(len(check_spans), 2)
        self.assertTrue(all(span.attributes["mode"] == "guarded" for span in check_spans))

    def test_agent_model_check_tool_spans_share_trace_with_log(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        telemetry = TelemetryObserver(provider)
        with tempfile.TemporaryDirectory() as tmp:
            log = JsonlDecisionLog(Path(tmp) / "events.jsonl")
            sink = custom_agent.NoteTool()
            result = custom_agent.run_note(
                run_id="traced", context=context(True), tool=sink,
                model=custom_agent.scripted_model("DO-NOT-TRACE-CONTENT", True),
                recorder=log, telemetry=telemetry,
            )
            events = log.read()
        self.assertTrue(result.actions[0].executed)
        spans = exporter.get_finished_spans()
        names = [span.name for span in spans]
        self.assertIn("governor.run", names)
        self.assertEqual(names.count("governor.check"), 3)
        self.assertIn("governor.tool.execute", names)
        self.assertTrue(any(name.startswith("invoke_agent") for name in names))
        self.assertTrue(any(name.startswith("chat ") for name in names))
        self.assertTrue(any(name.startswith("execute_tool") for name in names))
        trace_ids = {span.context.trace_id for span in spans}
        self.assertEqual(len(trace_ids), 1)
        self.assertTrue(all(event.trace_id is not None and event.span_id is not None for event in events))
        self.assertEqual({event.trace_id for event in events}, {f"{next(iter(trace_ids)):032x}"})
        self.assertNotIn("DO-NOT-TRACE-CONTENT", str([span.attributes for span in spans]))

    def test_blocked_action_has_no_governor_tool_span(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        sink = custom_agent.NoteTool()
        result = custom_agent.run_note(
            run_id="blocked", context=context(False), tool=sink,
            model=custom_agent.scripted_model("private", True),
            telemetry=TelemetryObserver(provider),
        )
        self.assertEqual(result.actions[0].decision.decision, "block")
        self.assertEqual(sink.saved, [])
        self.assertNotIn("governor.tool.execute", [s.name for s in exporter.get_finished_spans()])

    def test_duplicate_actions_link_each_completion_to_its_tool_span(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        telemetry = TelemetryObserver(provider)
        contract = load_contract(
            custom_agent.CONTRACT_PATH, rule_catalog=custom_agent.RULES
        ).contract
        with tempfile.TemporaryDirectory() as tmp:
            log = JsonlDecisionLog(Path(tmp) / "events.jsonl")
            with telemetry.run("duplicates", contract.contract_id):
                controller = WorkflowController(
                    Governor(rule_catalog=custom_agent.RULES),
                    "duplicates", contract, log, telemetry,
                    policy=EnforcementPolicy(mode="guarded"),
                )
                controller.begin(context(True))
                for _ in range(2):
                    controller.execute(
                        ActionProposal(
                            tool_name="save_note",
                            arguments={"text": "same", "public": True},
                        ),
                        context(True), lambda _action: "saved",
                    )
                controller.finish(context(True), {"status": "saved"})
            completed = [event for event in log.read() if event.event_type == "tool_completed"]
        tool_spans = [
            span for span in exporter.get_finished_spans()
            if span.name == "governor.tool.execute"
        ]
        self.assertEqual([event.action_index for event in completed], [1, 2])
        self.assertEqual({span.attributes["action_index"] for span in tool_spans}, {1, 2})
        self.assertEqual(
            {event.action_index: event.span_id for event in completed},
            {span.attributes["action_index"]: f"{span.context.span_id:016x}" for span in tool_spans},
        )

    def test_tool_error_event_uses_the_execution_span(self):
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        telemetry = TelemetryObserver(provider)
        contract = load_contract(
            custom_agent.CONTRACT_PATH, rule_catalog=custom_agent.RULES
        ).contract
        with tempfile.TemporaryDirectory() as tmp:
            log = JsonlDecisionLog(Path(tmp) / "events.jsonl")
            with telemetry.run("tool-error", contract.contract_id):
                controller = WorkflowController(
                    Governor(rule_catalog=custom_agent.RULES),
                    "tool-error", contract, log, telemetry,
                    policy=EnforcementPolicy(mode="guarded"),
                )
                controller.begin(context(True))

                def fail(_action):
                    raise RuntimeError("tool failed")

                with self.assertRaisesRegex(RuntimeError, "tool failed"):
                    controller.execute(
                        ActionProposal(tool_name="save_note"),
                        context(True), fail,
                    )
            error = [event for event in log.read() if event.event_type == "tool_error"][0]
        tool_span = [
            span for span in exporter.get_finished_spans()
            if span.name == "governor.tool.execute"
        ][0]
        self.assertEqual(error.execution_status, "unknown")
        self.assertEqual(error.span_id, f"{tool_span.context.span_id:016x}")

    def test_exporter_failure_does_not_change_decision_or_effect(self):
        class BrokenExporter(SpanExporter):
            def export(self, _spans):
                raise RuntimeError("exporter unavailable")

            def shutdown(self):
                return None

        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(BrokenExporter()))
        sink = custom_agent.NoteTool()
        with self.assertLogs(level="ERROR"):
            result = custom_agent.run_note(
                run_id="exporter-failure", context=context(False), tool=sink,
                model=custom_agent.scripted_model("secret", True),
                telemetry=TelemetryObserver(provider),
            )
        self.assertEqual(result.actions[0].decision.decision, "block")
        self.assertEqual(sink.saved, [])

    def test_tracer_setup_failure_is_non_authoritative(self):
        class BrokenTracer:
            def start_as_current_span(self, *_args, **_kwargs):
                raise RuntimeError("tracer unavailable")

        sink = custom_agent.NoteTool()
        result = custom_agent.run_note(
            run_id="tracer-failure", context=context(False), tool=sink,
            model=custom_agent.scripted_model("secret", True),
            telemetry=TelemetryObserver(tracer=BrokenTracer()),
        )
        self.assertEqual(result.actions[0].decision.decision, "block")
        self.assertEqual(sink.saved, [])


if __name__ == "__main__":
    unittest.main()
