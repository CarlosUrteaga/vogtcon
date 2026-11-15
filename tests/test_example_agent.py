# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from vogtcon import ExecutionContext, load_contract

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
        result = notification_agent.run_notification(
            run_id="bad-fingerprint", context=context(True, agent_fp="unknown"),
            message="hello", sensitive=False, tool=tool,
        )
        # The historic guarded mode records a pre violation but continues.
        self.assertEqual([v.rule for v in result.pre.violations], ["agent.configuration_fingerprint_match"])
        self.assertEqual(result.runtime.decision.decision, "allow")
        self.assertEqual(tool.sent, ["hello"])


if __name__ == "__main__":
    unittest.main()
