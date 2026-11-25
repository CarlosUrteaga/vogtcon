# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pilots.notification_llm import evaluate, evaluate_run, run_case, schedule


def tool_message(name, arguments=None):
    return {
        "message": {
            "role": "assistant",
            "tool_calls": [{"function": {"name": name, "arguments": arguments or {}}}],
        },
    }


class NotificationLlmTests(unittest.TestCase):
    def run_script(self, case, actions):
        responses = iter(actions)

        def call(path, payload):
            self.assertEqual(path, "/api/chat")
            self.assertEqual(payload["model"], "mock")
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        with TemporaryDirectory() as directory:
            return run_case({"case": case, "replication": "smoke", "seed": 11}, "mock", call, Path(directory))

    def test_allowed_notification_observes_one_effect(self):
        run = self.run_script("C1", [
            tool_message("send_notification"), tool_message("finish", {"status": "completed"}),
        ])
        result = evaluate_run(run)
        self.assertEqual(result["effects"], 1)
        self.assertTrue(result["task_completed"])
        self.assertFalse(result["recovered_after_block"])

    def test_early_request_cannot_grant_approval(self):
        run = self.run_script("C3", [
            tool_message("request_approval"), tool_message("send_notification"),
            tool_message("finish", {"status": "completed"}),
        ])
        result = evaluate_run(run)
        self.assertEqual((result["host_grants"], result["effects"]), (0, 0))
        self.assertFalse(result["task_completed"])

    def test_denial_and_recovery_depend_on_host(self):
        actions = [tool_message("send_notification"), tool_message("request_approval")]
        denied = self.run_script("C2", [*actions, tool_message("finish", {"status": "declined"})])
        recovered = self.run_script("C3", [
            *actions, tool_message("send_notification"), tool_message("finish", {"status": "completed"}),
        ])
        self.assertTrue(evaluate_run(denied)["safe_decline"])
        evidence = {"format_version": 1, "smoke": True, "runs": [recovered]}
        self.assertTrue(evaluate(evidence)[0]["recovered_after_block"])

    def test_model_cannot_supply_an_approval_claim(self):
        run = self.run_script("C2", [tool_message("send_notification", {"approved": True})])
        result = evaluate_run(run)
        self.assertEqual(result["termination"], "invalid_tool_call")
        self.assertEqual((result["host_grants"], result["effects"]), (0, 0))

    def test_timeout_preserves_previous_observed_effect(self):
        run = self.run_script("C1", [tool_message("send_notification"), TimeoutError()])
        result = evaluate_run(run)
        self.assertEqual(result["failure"], "TimeoutError")
        self.assertEqual(result["effects"], 1)

    def test_replay_rejects_inconsistent_or_incomplete_evidence(self):
        run = self.run_script("C3", [tool_message("finish", {"status": "declined"})])
        evidence = {"format_version": 1, "smoke": True, "runs": [run]}
        for field, change in (
            ("destination", ["invented effect"]),
            ("decisions", run["decisions"][:-1]),
            ("termination", "turn_limit"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                tampered = deepcopy(run)
                tampered[field] = change
                evaluate({**evidence, "runs": [tampered]})
        with self.assertRaisesRegex(ValueError, "schedule"):
            evaluate({**evidence, "runs": []})

    def test_matrix_has_four_replicates_of_each_condition(self):
        matrix = schedule(False)
        self.assertEqual(len(matrix), 16)
        self.assertEqual(len({(entry["case"], entry["replication"]) for entry in matrix}), 16)
