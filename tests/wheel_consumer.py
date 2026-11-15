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


def main(contract_paths: list[Path]) -> None:
    installed_file = Path(vogtcon.__file__).resolve()
    assert Path(sys.prefix).resolve() in installed_file.parents, installed_file
    assert importlib.util.find_spec("pydantic_ai") is None

    for contract_path in contract_paths:
        policy = (
            EnforcementPolicy(mode="guarded")
            if contract_path.name == "notification_contract_v2.yaml" else None
        )
        recorder = JsonlDecisionLog(Path(f"{contract_path.stem}-events.jsonl"))
        for approved in (False, True):
            controller = WorkflowController.from_contract_path(
                contract_path, f"wheel-{contract_path.stem}-{approved}",
                policy=policy, recorder=recorder,
            )
            context = ExecutionContext(
                state={"approval_granted": approved},
                available_tools=["send_notification"],
                observed_agent_fingerprint="notification-agent-v1",
                observed_contract_fingerprint=controller.contract.contract_fingerprint,
            )
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
    print("Installed wheel consumer: v1 and v2 blocked and allowed paths passed")


if __name__ == "__main__":
    main([Path(value) for value in sys.argv[1:]])
