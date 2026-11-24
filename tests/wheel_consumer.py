# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Run only from an isolated wheel install; see smoke_wheel_consumer.sh."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import vogtcon
from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    JsonlDecisionLog,
    WorkflowController,
)


def _make_context(controller: WorkflowController, approved: bool) -> ExecutionContext:
    return ExecutionContext(
        state={"approval_granted": approved},
        available_tools=["send_notification"],
        observed_agent_fingerprint="notification-agent-v1",
        observed_contract_fingerprint=controller.contract.contract_fingerprint,
    )


def main(contract_paths: list[Path]) -> None:
    installed_file = Path(vogtcon.__file__).resolve()
    assert Path(sys.prefix).resolve() in installed_file.parents, installed_file
    assert importlib.util.find_spec("pydantic_ai") is None

    v2_contract_path: Path | None = None
    for contract_path in contract_paths:
        is_v2 = contract_path.name == "notification_contract_v2.yaml"
        if is_v2:
            v2_contract_path = contract_path
        policy = EnforcementPolicy(mode="guarded") if is_v2 else None
        recorder = JsonlDecisionLog(Path(f"{contract_path.stem}-events.jsonl"))
        for approved in (False, True):
            controller = WorkflowController.from_contract_path(
                contract_path, f"wheel-{contract_path.stem}-{approved}",
                policy=policy, recorder=recorder,
            )
            context = _make_context(controller, approved)
            sent: list[str] = []

            def send_notification(proposal: ActionProposal) -> str:
                sent.append(str(proposal.arguments["message"]))
                return "sent"

            assert controller.begin(context).violations == []
            outcome = controller.execute(
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"message": "hello", "sensitive": True},
                ),
                context,
                send_notification,
            )
            assert outcome.executed is approved
            assert outcome.decision.decision == ("allow" if approved else "block")
            assert sent == (["hello"] if approved else [])
            assert controller.finish(
                context, {"status": "sent" if approved else "blocked"}
            ).violations == []
            assert controller.state == "finished"

        events = recorder.read()
        assert [event.event_type for event in events] == [
            "decision", "decision", "decision",
            "decision", "decision", "tool_completed", "decision",
        ]
        assert events[1].decision == "block"
        assert events[4].decision == "allow"
        assert all(event.mode == "guarded" for event in events)

    assert v2_contract_path is not None
    recovery_recorder = JsonlDecisionLog(Path("recovery-events.jsonl"))
    recovery_controller = WorkflowController.from_contract_path(
        v2_contract_path,
        "wheel-recovery",
        policy=EnforcementPolicy(mode="guarded"),
        recorder=recovery_recorder,
    )
    unapproved_context = _make_context(recovery_controller, False)
    approved_context = _make_context(recovery_controller, True)
    recovery_sent: list[str] = []

    def send_recovery_notification(proposal: ActionProposal) -> str:
        recovery_sent.append(str(proposal.arguments["message"]))
        return "sent"

    assert recovery_controller.begin(unapproved_context).violations == []
    blocked_outcome = recovery_controller.execute(
        ActionProposal(
            tool_name="send_notification",
            arguments={"message": "hello", "sensitive": True},
        ),
        unapproved_context,
        send_recovery_notification,
    )
    assert blocked_outcome.executed is False
    assert blocked_outcome.decision.decision == "block"
    assert recovery_sent == []

    allowed_outcome = recovery_controller.execute(
        ActionProposal(
            tool_name="send_notification",
            arguments={"message": "hello", "sensitive": True},
        ),
        approved_context,
        send_recovery_notification,
    )
    assert allowed_outcome.executed is True
    assert allowed_outcome.decision.decision == "allow"
    assert recovery_controller.finish(approved_context, {"status": "sent"}).violations == []
    assert recovery_controller.state == "finished"
    assert recovery_sent == ["hello"]

    recovery_events = recovery_recorder.read()
    assert [event.event_type for event in recovery_events] == [
        "decision", "decision", "decision", "tool_completed", "decision",
    ]
    assert recovery_events[1].decision == "block"
    assert recovery_events[2].decision == "allow"
    assert all(event.mode == "guarded" for event in recovery_events)

    print("Installed wheel consumer: v1, v2, and recovery paths passed")


if __name__ == "__main__":
    main([Path(value) for value in sys.argv[1:]])
