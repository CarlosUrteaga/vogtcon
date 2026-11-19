# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Standalone in-memory agent integration; no benchmark imports or external effects.

The host supplies ExecutionContext from trusted runtime facts, including the
observed fingerprints and approval state. Agent arguments are never authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from vogtcon import (
    ActionProposal,
    AgentContract,
    ContractRulesV2,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    Governor,
    RunRecorder,
    ToolExecutionOutcome,
    WorkflowController,
    load_contract,
)

CONTRACT_PATH = Path(__file__).with_name("notification_contract.yaml")


class NotificationAgent:
    def propose(self, message: str, *, sensitive: bool) -> ActionProposal:
        return ActionProposal(
            tool_name="send_notification",
            arguments={"message": message, "sensitive": sensitive},
        )


@dataclass(slots=True)
class InMemoryNotificationTool:
    sent: list[str] = field(default_factory=list)

    def __call__(self, proposal: ActionProposal) -> str:
        message = proposal.arguments["message"]
        if not isinstance(message, str):
            raise ValueError("notification message must be a string")
        self.sent.append(message)
        return "sent"


@dataclass(frozen=True, slots=True)
class NotificationRun:
    pre: GovernanceDecision
    runtime: ToolExecutionOutcome[str] | None
    post: GovernanceDecision | None
    state: str


def run_notification(
    *,
    run_id: str,
    context: ExecutionContext,
    message: str,
    sensitive: bool,
    tool: InMemoryNotificationTool,
    contract: AgentContract | ContractRulesV2 | None = None,
    policy: EnforcementPolicy | None = None,
    on_blocked: Callable[[GovernanceDecision], ActionProposal | None] | None = None,
    context_provider: Callable[[], ExecutionContext] | None = None,
    recorder: RunRecorder | None = None,
    run_ledger: dict[str, object] | None = None,
) -> NotificationRun:
    """Run up to two proposals through synchronous checkpoints.

    ``context_provider`` is supplied by the trusted host and queried immediately
    before each dispatch; the original context is retained for ``begin`` and as
    the fallback when no provider is supplied. After an actual block decision,
    ``on_blocked`` receives that decision at most once and may return one retry.
    ``recorder`` observes run events, and ``run_ledger`` is forwarded to the
    post-execution check when the active run reaches ``finish``. ``runtime``
    reports the last performed attempt.
    """
    selected_contract = (
        load_contract(CONTRACT_PATH).contract if contract is None else contract
    )
    controller = WorkflowController(
        Governor(), run_id, selected_contract, recorder=recorder, policy=policy
    )
    pre = controller.begin(context)
    if controller.state != "active":
        return NotificationRun(pre, None, None, controller.state)

    proposal = NotificationAgent().propose(message, sensitive=sensitive)
    last_context = context

    def dispatch(action: ActionProposal) -> ToolExecutionOutcome[str]:
        nonlocal last_context
        trusted_context = context_provider() if context_provider is not None else context
        last_context = trusted_context
        return controller.execute(action, trusted_context, tool)

    runtime = dispatch(proposal)
    if (
        runtime.decision.decision == "block"
        and controller.state == "active"
        and on_blocked is not None
    ):
        retry = on_blocked(runtime.decision)
        if retry is not None:
            runtime = dispatch(retry)
    if controller.state != "active":
        return NotificationRun(pre, runtime, None, controller.state)
    response = {"status": "sent" if runtime.executed else "blocked"}
    post = controller.finish(last_context, response, run_ledger)
    return NotificationRun(pre, runtime, post, controller.state)


if __name__ == "__main__":
    for approved in (False, True):
        runtime_context = ExecutionContext(
            state={"approval_granted": approved},
            available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint="notification-contract-v1",
        )
        sink = InMemoryNotificationTool()
        run = run_notification(
            run_id=f"demo-{approved}", context=runtime_context,
            message="Example notice", sensitive=True, tool=sink,
        )
        print({"approved": approved, "decision": run.runtime.decision.decision if run.runtime else None, "sent": sink.sent})
