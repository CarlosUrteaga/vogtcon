# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Host-classified v3 notification example with bound single-use approvals.

Zero model-provider or agent-framework imports. The host classifies sensitivity
strictly from destination/channel policy, resolves PlannedEffect and HostFacts,
attaches any host-issued HostApproval, and observes external delivery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vogtcon import (
    ActionProposal,
    EffectGovernanceConfig,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    HostApproval,
    HostFacts,
    InMemoryEffectStore,
    ObservationInput,
    ObservedEffect,
    PlannedEffect,
    ResolvedAction,
    RunRecorder,
    ToolExecutionOutcome,
    WorkflowController,
)

CONTRACT_PATH = Path(__file__).resolve().parent / "notification_contract_v3.yaml"
AGENT_FINGERPRINT = "notification-agent-v3"
SENSITIVE_RECIPIENTS: frozenset[str] = frozenset({"alerts@example.com"})


def classify_notification_sensitivity(recipient: str, channel: str = "email") -> bool:
    """Classify notification sensitivity strictly from host policy, never agent claims."""
    normalized_recipient = recipient.strip().lower()
    normalized_channel = channel.strip().lower()
    return normalized_recipient in SENSITIVE_RECIPIENTS or normalized_channel == "pager"


@dataclass
class InMemoryNotificationV3Tool:
    """Local deterministic sink simulating an external notification gateway."""

    deliveries: list[dict[str, str]] = field(default_factory=list)

    def send(self, proposal: ActionProposal) -> dict[str, str]:
        recipient = str(proposal.arguments.get("recipient", "")).strip().lower()
        channel = str(proposal.arguments.get("channel", "email")).strip().lower()
        message = str(proposal.arguments.get("message", ""))
        receipt_id = f"notif-{len(self.deliveries) + 1:04d}"
        record = {
            "receipt_id": receipt_id,
            "recipient": recipient,
            "channel": channel,
            "message": message,
        }
        self.deliveries.append(record)
        return {"receipt_id": receipt_id, "delivered": "true"}


class NotificationResolver:
    """Host EffectResolver deriving PlannedEffect and host-classified HostFacts."""

    def __init__(
        self,
        *,
        policy_scope: str,
        requester_id: str,
        evaluated_at: str,
        approval: HostApproval | None = None,
    ) -> None:
        self._policy_scope = policy_scope
        self._requester_id = requester_id
        self._evaluated_at = evaluated_at
        self._approval = approval

    def resolve(
        self, action: ActionProposal, context: ExecutionContext
    ) -> ResolvedAction:
        raw_recipient = action.arguments.get("recipient")
        recipient = (
            raw_recipient.strip().lower()
            if isinstance(raw_recipient, str)
            else ""
        )
        raw_channel = action.arguments.get("channel")
        channel = (
            raw_channel.strip().lower()
            if isinstance(raw_channel, str) and raw_channel.strip()
            else "email"
        )
        # Sensitivity is strictly host-classified; action.arguments["sensitive"] is ignored.
        sensitive = classify_notification_sensitivity(recipient, channel)
        parameters: dict[str, Any] = {"recipient": recipient}
        if isinstance(raw_channel, str) and raw_channel.strip():
            parameters["channel"] = channel
        planned_effect = PlannedEffect(
            tool_name=action.tool_name,
            parameters=parameters,
            defaults={"channel": "email"},
        )
        facts: dict[str, Any] = {
            **dict(context.state),
            "sensitive": sensitive,
            "requester_id": self._requester_id,
        }
        if self._approval is not None:
            facts["approval_id"] = self._approval.approval_id
        return ResolvedAction(
            planned_effect=planned_effect,
            host_facts=HostFacts(facts=facts),
            policy_scope=self._policy_scope,
            requester_id=self._requester_id,
            evaluated_at=self._evaluated_at,
            approval=self._approval,
        )


class NotificationObserver:
    """Host EffectObserver classifying confirmed delivery from the tool receipt."""

    def observe(
        self, observation: ObservationInput, *, tool_result: Any = None
    ) -> ObservedEffect:
        if observation.invocation_outcome == "returned" and isinstance(
            tool_result, dict
        ) and isinstance(tool_result.get("receipt_id"), str):
            return ObservedEffect(
                status="confirmed",
                evidence_ref=f"gateway:{tool_result['receipt_id']}",
            )
        return ObservedEffect(status="uncertain", evidence_ref="gateway:unknown")


@dataclass(frozen=True, slots=True)
class NotificationV3RunResult:
    pre_decision: GovernanceDecision
    outcome: ToolExecutionOutcome[dict[str, str]]
    post_decision: GovernanceDecision
    state: str


def run_notification_v3(
    proposal: ActionProposal,
    *,
    run_id: str,
    policy_scope: str,
    requester_id: str,
    evaluated_at: str,
    approval: HostApproval | None = None,
    store: InMemoryEffectStore | None = None,
    tool: InMemoryNotificationV3Tool | None = None,
    recorder: RunRecorder | None = None,
    mode: str = "guarded",
) -> NotificationV3RunResult:
    """Execute one governed v3 notification proposal end-to-end."""
    effect_store = store if store is not None else InMemoryEffectStore()
    sink = tool if tool is not None else InMemoryNotificationV3Tool()
    cfg = EffectGovernanceConfig(
        store=effect_store,
        resolver=NotificationResolver(
            policy_scope=policy_scope,
            requester_id=requester_id,
            evaluated_at=evaluated_at,
            approval=approval,
        ),
        observer=NotificationObserver(),
        policy_scope=policy_scope,
    )
    controller = WorkflowController.from_contract_path(
        CONTRACT_PATH,
        run_id,
        policy=EnforcementPolicy(mode=mode),  # type: ignore[arg-type]
        recorder=recorder,
        effect_governance=cfg,
    )
    context = ExecutionContext(
        state={},
        available_tools=["send_notification"],
        observed_agent_fingerprint=AGENT_FINGERPRINT,
        observed_contract_fingerprint=controller.contract.contract_fingerprint,
    )
    pre_decision = controller.begin(context)
    outcome = controller.execute(proposal, context, sink.send)
    status = "sent" if outcome.executed else outcome.decision.decision or "blocked"
    post_decision = (
        controller.finish(context, {"status": status})
        if controller.state == "active"
        else GovernanceDecision(phase="post_execution", violations=[])
    )
    return NotificationV3RunResult(
        pre_decision=pre_decision,
        outcome=outcome,
        post_decision=post_decision,
        state=controller.state,
    )
