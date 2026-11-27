# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Tests for the host-classified v3 notification example."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from examples.notification_agent_v3 import (
    CONTRACT_PATH,
    InMemoryNotificationV3Tool,
    classify_notification_sensitivity,
    run_notification_v3,
)
from vogtcon import (
    ActionProposal,
    HostApproval,
    InMemoryEffectStore,
    JsonlDecisionLog,
    PlannedEffect,
)
from vogtcon.cli import EXIT_VALID, main


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        code = main(args)
    return code, out_buf.getvalue(), err_buf.getvalue()


class NotificationV3ExampleTests(unittest.TestCase):
    def _approval_for(
        self,
        *,
        recipient: str = "alerts@example.com",
        channel: str = "email",
        approval_id: str = "appr-notif-001",
        policy_scope: str = "scope.notifications",
        requester_id: str = "ops-user-1",
        approver_id: str = "approver-1",
        approver_authorities: list[str] | None = None,
        issued_at: str = "2026-06-01T10:00:00Z",
        expires_at: str = "2026-06-01T11:00:00Z",
    ) -> HostApproval:
        params: dict[str, str] = {"recipient": recipient}
        if channel != "email":
            params["channel"] = channel
        planned = PlannedEffect(
            tool_name="send_notification",
            parameters=params,
            defaults={"channel": "email"},
        )
        return HostApproval(
            approval_id=approval_id,
            operation_digest=planned.operation_digest(),
            policy_scope=policy_scope,
            requester_id=requester_id,
            approver_id=approver_id,
            approver_authorities=(
                approver_authorities
                if approver_authorities is not None
                else ["notification_approver"]
            ),
            issued_at=issued_at,
            expires_at=expires_at,
            status="active",
            single_use=True,
        )

    def test_v3_contract_passes_vogtcon_validate(self) -> None:
        code, out, err = _run_cli(["validate", str(CONTRACT_PATH), "--json"])
        self.assertEqual((code, err), (EXIT_VALID, ""))
        res = json.loads(out)
        self.assertEqual(res["status"], "valid")
        self.assertEqual(res["data"]["contract_version"], 3)
        self.assertTrue(res["data"]["fingerprint"]["verified"])
        self.assertEqual(res["data"]["contract_id"], "example.notification.v3")

    def test_non_sensitive_allowed_destination_completes_without_approval(self) -> None:
        self.assertFalse(classify_notification_sensitivity("ops@example.com", "email"))
        tool = InMemoryNotificationV3Tool()
        result = run_notification_v3(
            ActionProposal(
                tool_name="send_notification",
                arguments={"recipient": "ops@example.com", "message": "heartbeat"},
            ),
            run_id="run-nonsens",
            policy_scope="scope.notifications",
            requester_id="ops-user-1",
            evaluated_at="2026-06-01T10:15:00Z",
            tool=tool,
        )
        self.assertTrue(result.outcome.executed)
        assert result.outcome.effect is not None
        self.assertEqual(result.outcome.effect.status, "confirmed")
        self.assertEqual(result.state, "finished")
        self.assertEqual(len(tool.deliveries), 1)

    def test_host_classified_sensitive_blocked_even_when_agent_claims_not_sensitive(self) -> None:
        self.assertTrue(classify_notification_sensitivity("alerts@example.com", "email"))
        tool = InMemoryNotificationV3Tool()
        result = run_notification_v3(
            ActionProposal(
                tool_name="send_notification",
                arguments={
                    "recipient": "alerts@example.com",
                    "sensitive": False,
                    "message": "bypass attempt",
                },
            ),
            run_id="run-spoof",
            policy_scope="scope.notifications",
            requester_id="ops-user-1",
            evaluated_at="2026-06-01T10:15:00Z",
            tool=tool,
        )
        self.assertFalse(result.outcome.executed)
        self.assertEqual(result.outcome.decision.decision, "block")
        self.assertEqual(
            [v.rule for v in result.outcome.decision.violations],
            ["sensitive_approval"],
        )
        self.assertEqual(tool.deliveries, [])

    def test_disallowed_destination_and_invalid_approvals_blocked_zero_deliveries(self) -> None:
        cases = [
            (
                "disallowed_destination_even_with_approval",
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "external@evil.example", "message": "leak"},
                ),
                self._approval_for(recipient="external@evil.example"),
                "2026-06-01T10:15:00Z",
                "destination_policy",
            ),
            (
                "modified_channel_after_approval",
                ActionProposal(
                    tool_name="send_notification",
                    arguments={
                        "recipient": "alerts@example.com",
                        "channel": "pager",
                        "message": "escalate",
                    },
                ),
                self._approval_for(recipient="alerts@example.com", channel="email"),
                "2026-06-01T10:15:00Z",
                "sensitive_approval",
            ),
            (
                "unauthorized_approver",
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "alerts@example.com", "message": "alert"},
                ),
                self._approval_for(approver_authorities=["read_only"]),
                "2026-06-01T10:15:00Z",
                "sensitive_approval",
            ),
            (
                "disallowed_self_approval",
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "alerts@example.com", "message": "alert"},
                ),
                self._approval_for(approver_id="ops-user-1"),
                "2026-06-01T10:15:00Z",
                "sensitive_approval",
            ),
            (
                "expired_approval",
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "alerts@example.com", "message": "alert"},
                ),
                self._approval_for(),
                "2026-06-01T11:00:00Z",
                "sensitive_approval",
            ),
        ]

        for label, proposal, approval, eval_at, expected_rule in cases:
            with self.subTest(case=label):
                tool = InMemoryNotificationV3Tool()
                res = run_notification_v3(
                    proposal,
                    run_id=f"run-{label}",
                    policy_scope="scope.notifications",
                    requester_id="ops-user-1",
                    evaluated_at=eval_at,
                    approval=approval,
                    tool=tool,
                )
                self.assertFalse(res.outcome.executed)
                self.assertEqual(res.outcome.decision.decision, "block")
                self.assertIn(
                    expected_rule, [v.rule for v in res.outcome.decision.violations]
                )
                self.assertEqual(tool.deliveries, [])

    def test_legitimate_approved_flow_single_use_replay_and_explain_trace(self) -> None:
        secret_msg = "SECRET_NOTIFICATION_BODY_555"
        store = InMemoryEffectStore()
        tool = InMemoryNotificationV3Tool()
        approval = self._approval_for(approval_id="appr-once-99")

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "notif_v3.jsonl"
            recorder = JsonlDecisionLog(log_path)

            first = run_notification_v3(
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "alerts@example.com", "message": secret_msg},
                ),
                run_id="run-approved-1",
                policy_scope="scope.notifications",
                requester_id="ops-user-1",
                evaluated_at="2026-06-01T10:20:00Z",
                approval=approval,
                store=store,
                tool=tool,
                recorder=recorder,
            )
            self.assertTrue(first.outcome.executed)
            assert first.outcome.effect is not None
            self.assertEqual(first.outcome.effect.status, "confirmed")
            self.assertEqual(first.outcome.effect.approval_id, "appr-once-99")
            self.assertEqual(len(tool.deliveries), 1)

            # Single-use replay across a second run sharing the same store is blocked (INV-11)
            second = run_notification_v3(
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "alerts@example.com", "message": secret_msg},
                ),
                run_id="run-replay-2",
                policy_scope="scope.notifications",
                requester_id="ops-user-1",
                evaluated_at="2026-06-01T10:25:00Z",
                approval=approval,
                store=store,
                tool=tool,
                recorder=recorder,
            )
            self.assertFalse(second.outcome.executed)
            self.assertEqual(second.outcome.decision.decision, "block")
            self.assertEqual(
                [v.rule for v in second.outcome.decision.violations],
                ["sensitive_approval"],
            )
            self.assertEqual(len(tool.deliveries), 1)

            # vogtcon explain validates the RunEventV2 log cleanly and omits secret message (INV-08)
            code_j, out_j, err_j = _run_cli(["explain", str(log_path), "--json"])
            self.assertEqual((code_j, err_j), (0, ""))
            explained = json.loads(out_j)
            self.assertEqual(explained["status"], "ok")
            run1, run2 = explained["data"]["runs"]
            self.assertEqual(run1["trace_integrity"], "complete")
            self.assertEqual(run1["actions"][0]["approval_id"], "appr-once-99")
            self.assertEqual(
                run1["actions"][0]["effect_evidence"],
                "confirmed_by_host_observation",
            )
            self.assertEqual(run2["trace_integrity"], "complete")
            self.assertEqual(run2["actions"][0]["decision"], "block")
            self.assertNotIn(secret_msg, out_j)

            code_t, out_t, err_t = _run_cli(["explain", str(log_path)])
            self.assertEqual((code_t, err_t), (0, ""))
            self.assertIn("[approval: appr-once-99]", out_t)
            self.assertNotIn(secret_msg, out_t)


if __name__ == "__main__":
    unittest.main()
