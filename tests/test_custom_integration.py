# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pydantic_ai import ModelResponse, TextPart, ToolCallPart, models
from pydantic_ai.models.function import FunctionModel

from vogtcon import ExecutionContext, JsonlDecisionLog, load_contract

models.ALLOW_MODEL_REQUESTS = False
os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "custom_agent.py"
SPEC = importlib.util.spec_from_file_location("custom_agent", EXAMPLE)
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


class PydanticAgentIntegrationTests(unittest.TestCase):
    def test_custom_yaml_and_rule_are_loaded_without_benchmark(self):
        contract = load_contract(custom_agent.CONTRACT_PATH, rule_catalog=custom_agent.RULES).contract
        self.assertEqual(contract.contract_id, "example.note_agent")
        self.assertEqual(contract.schema_version, 2)
        self.assertFalse(hasattr(contract, "mode"))
        self.assertNotIn("tools.enforcement", EXAMPLE.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
            load_contract(custom_agent.CONTRACT_PATH)

    def test_custom_v2_fingerprint_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = custom_agent.CONTRACT_PATH.read_text(encoding="utf-8")
            path = Path(tmp) / "tampered.yaml"
            path.write_text(source.replace("save_note", "other_tool", 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                load_contract(path, rule_catalog=custom_agent.RULES)

    def test_guarded_tool_blocks_without_trusted_approval(self):
        sink = custom_agent.NoteTool()
        run = custom_agent.run_note(
            run_id="blocked", context=context(False), tool=sink,
            model=custom_agent.scripted_model("secret", public=True),
        )
        self.assertEqual(run.actions[0].decision.decision, "block")
        self.assertFalse(run.actions[0].executed)
        self.assertEqual(sink.saved, [])
        self.assertEqual(run.state, "finished")
        self.assertEqual(run.verified_output, "Saved 0 note(s); blocked 1 request(s).")

    def test_false_model_success_is_not_the_verified_output(self):
        def respond(messages, _info):
            if len(messages) == 1:
                return ModelResponse(parts=[ToolCallPart(
                    "save_note", {"text": "note", "public": True}
                )])
            return ModelResponse(parts=[TextPart("The public note was saved successfully.")])

        sink = custom_agent.NoteTool()
        run = custom_agent.run_note(
            run_id="false-success", context=context(False), tool=sink,
            model=FunctionModel(respond),
        )
        self.assertEqual(run.untrusted_agent_output, "The public note was saved successfully.")
        self.assertEqual(run.verified_output, "Saved 0 note(s); blocked 1 request(s).")
        self.assertEqual(run.agent_output, run.verified_output)
        self.assertEqual(sink.saved, [])

    def test_guarded_tool_allows_with_trusted_approval(self):
        sink = custom_agent.NoteTool()
        run = custom_agent.run_note(
            run_id="allowed", context=context(True), tool=sink,
            model=custom_agent.scripted_model("secret", public=True),
        )
        self.assertEqual(run.actions[0].decision.decision, "allow")
        self.assertTrue(run.actions[0].executed)
        self.assertEqual(sink.saved, [{"text": "secret", "public": True}])
        self.assertEqual(run.post.violations, [])

    def test_host_dependencies_are_isolated_between_runs(self):
        model = custom_agent.scripted_model("shared model", public=True)
        first_tool = custom_agent.NoteTool()
        second_tool = custom_agent.NoteTool()
        first = custom_agent.run_note(
            run_id="first", context=context(True), tool=first_tool, model=model,
        )
        second = custom_agent.run_note(
            run_id="second", context=context(False), tool=second_tool, model=model,
        )
        self.assertEqual(first.actions[0].decision.decision, "allow")
        self.assertEqual(second.actions[0].decision.decision, "block")
        self.assertEqual(first_tool.saved, [{"text": "shared model", "public": True}])
        self.assertEqual(second_tool.saved, [])

    def test_private_note_needs_no_approval(self):
        sink = custom_agent.NoteTool()
        run = custom_agent.run_note(
            run_id="private", context=context(False), tool=sink,
            model=custom_agent.scripted_model("private", public=False),
        )
        self.assertTrue(run.actions[0].executed)
        self.assertEqual(sink.saved[0]["public"], False)

    def test_agent_can_replan_after_guarded_block(self):
        def respond(messages, _info):
            if len(messages) == 1:
                return ModelResponse(parts=[ToolCallPart("save_note", {"text": "note", "public": True})])
            if len(messages) == 3:
                self.assertIn("blocked by Governor", str(messages[-1].parts[0].content))
                return ModelResponse(parts=[ToolCallPart("save_note", {"text": "note", "public": False})])
            return ModelResponse(parts=[TextPart("completed")])

        sink = custom_agent.NoteTool()
        run = custom_agent.run_note(
            run_id="replan", context=context(False), tool=sink,
            model=FunctionModel(respond),
        )
        self.assertEqual([item.decision.decision for item in run.actions], ["block", "allow"])
        self.assertEqual(sink.saved, [{"text": "note", "public": False}])
        self.assertEqual(run.verified_output, "Saved 1 note(s); blocked 1 request(s).")

    def test_script_runs_without_benchmark_and_writes_inspectable_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            env = os.environ.copy()
            env.pop("GOVERNOR_BENCHMARK_ROOT", None)
            env["PYDANTIC_AI_NO_BANNER"] = "1"
            result = subprocess.run(
                [sys.executable, str(EXAMPLE), "--log", str(path)],
                cwd=EXAMPLE.parents[1], env=env,
                capture_output=True, text=True, check=True,
            )
            events = JsonlDecisionLog(path).read()
        self.assertIn("'decision': 'block'", result.stdout)
        self.assertIn("'decision': 'allow'", result.stdout)
        self.assertEqual({event.run_id for event in events}, {"note-False", "note-True"})
        self.assertTrue(any(event.violation_rules == ["note.public_requires_approval"] for event in events))


if __name__ == "__main__":
    unittest.main()
