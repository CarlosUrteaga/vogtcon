# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Synchronous checkpoints and tool gating for one governed run.

The caller supplies trusted context and the tool implementation. This module
does not infer authorization from telemetry or undo effects after execution.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Self, TypeVar

from .contracts import load_contract
from .core import Governor
from .models import (
    ActionProposal,
    AgentContract,
    ContractRulesV2,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    GovernorInput,
    JsonObject,
)
from .records import RunEvent, RunRecorder
from .rules import RuleCatalog
from .telemetry import TelemetryObserver

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ToolExecutionOutcome(Generic[T]):
    decision: GovernanceDecision
    executed: bool
    result: T | None = None


class GovernedToolExecutor:
    """Evaluate one runtime proposal immediately before invoking its tool.

    Use ``execute(request, tool)`` for a host that already owns run state.
    For a complete pre/runtime/post run, prefer :class:`WorkflowController`.
    A blocked or aborted decision returns ``executed=False`` without calling
    ``tool``; tool exceptions propagate because their effects may be uncertain.
    """

    def __init__(self, governor: Governor, telemetry: TelemetryObserver | None = None) -> None:
        self._governor = governor
        self._telemetry = telemetry

    def execute(
        self,
        request: GovernorInput,
        tool: Callable[[ActionProposal], T],
        *,
        before_invoke: Callable[[GovernanceDecision], None] | None = None,
        after_invoke: Callable[[], None] | None = None,
        on_tool_error: Callable[[], None] | None = None,
        action_index: int | None = None,
    ) -> ToolExecutionOutcome[T]:
        if request.phase != "runtime" or request.action is None:
            raise ValueError("Tool execution requires a runtime action")
        # Keep the proposed action stable even if a custom evaluator mutates
        # nested Pydantic values or the caller changes its original request.
        snapshot = request.model_copy(deep=True)
        evaluation_request = snapshot.model_copy(deep=True)
        span_identity = {"action_index": action_index} if action_index is not None else {}
        check_span = self._telemetry.span(
            "governor.check", phase="runtime", mode=snapshot.effective_mode,
            run_id=snapshot.run_id, contract_id=snapshot.contract.contract_id,
            tool_name=snapshot.action.tool_name, **span_identity,
        ) if self._telemetry is not None else nullcontext(None)
        with check_span as span:
            decision = self._governor.evaluate(evaluation_request)
            if evaluation_request != snapshot:
                raise ValueError("Governor evaluator mutated the action or its context")
            if not isinstance(decision, GovernanceDecision) or decision.phase != "runtime":
                raise ValueError("Governor returned an invalid runtime decision")
            if (
                snapshot.effective_mode in ("guarded", "strict")
                and decision.violations
                and decision.decision in ("allow", "allow_with_warning")
            ):
                raise ValueError("Governor allowed a violating action in an enforcement mode")
            if self._telemetry is not None:
                self._telemetry.record_decision(span, decision)
            if before_invoke is not None:
                before_invoke(decision)
        if decision.decision not in ("allow", "allow_with_warning"):
            return ToolExecutionOutcome(decision=decision, executed=False)
        # A tool exception propagates: its external effects may be ambiguous.
        assert snapshot.action is not None
        tool_span = self._telemetry.span(
            "governor.tool.execute", phase="runtime", run_id=snapshot.run_id,
            contract_id=snapshot.contract.contract_id, tool_name=snapshot.action.tool_name,
            **span_identity,
        ) if self._telemetry is not None else nullcontext(None)
        with tool_span:
            try:
                result = tool(snapshot.action)
            except Exception:
                if on_tool_error is not None:
                    try:
                        on_tool_error()
                    except Exception:
                        # Preserve the tool failure when recording is also down.
                        pass
                raise
            if after_invoke is not None:
                after_invoke()
        return ToolExecutionOutcome(decision=decision, executed=True, result=result)


class WorkflowController:
    """Bind pre, runtime, and post checkpoints to one contract and run ID.

    Guarded blocks leave the run active so a caller may propose another action.
    Strict pre/runtime failures stop it. Post checks report violations after any
    tool effects; they cannot roll those effects back.

    Create one controller per run, call ``begin(context)``, route each proposed
    tool call through ``execute(action, context, tool)``, then call
    ``finish(context, response)`` while the state is active. The host supplies
    trusted ``ExecutionContext`` facts and the real tool callable. Pass
    ``policy=EnforcementPolicy(mode=...)`` when the contract uses v2 rules.
    """

    def __init__(
        self,
        governor: Governor,
        run_id: str,
        contract: AgentContract | ContractRulesV2,
        recorder: RunRecorder | None = None,
        telemetry: TelemetryObserver | None = None,
        *,
        policy: EnforcementPolicy | None = None,
    ) -> None:
        if not run_id:
            raise ValueError("run_id must be nonempty")
        if isinstance(contract, AgentContract) and "schema_version" in (contract.model_extra or {}):
            raise ValueError("Unsupported contract schema_version")
        if isinstance(contract, ContractRulesV2):
            if policy is None:
                raise ValueError("v2 contracts require an enforcement policy")
        elif policy is not None and policy.mode != contract.mode:
            raise ValueError("Enforcement policy conflicts with legacy contract mode")
        self._governor = governor
        self._executor = GovernedToolExecutor(governor, telemetry)
        self._run_id = run_id
        self._contract = contract.model_copy(deep=True)
        self._policy = policy
        self._mode = policy.mode if policy is not None else contract.mode
        self._state = "new"
        self._recorder = recorder
        self._telemetry = telemetry
        self._sequence = 0
        self._action_index = 0

    @classmethod
    def from_contract_path(
        cls,
        path: str | Path,
        run_id: str,
        *,
        policy: EnforcementPolicy | None = None,
        rule_catalog: RuleCatalog | None = None,
        recorder: RunRecorder | None = None,
        telemetry: TelemetryObserver | None = None,
    ) -> Self:
        """Load a contract and start one deterministic run.

        The same rule catalog validates the document and evaluates its rules.
        V2 still requires an explicit policy. Use the constructor directly to
        supply a custom Governor evaluator.
        """
        contract = load_contract(path, rule_catalog=rule_catalog).contract
        return cls(
            Governor(rule_catalog=rule_catalog), run_id, contract,
            recorder, telemetry, policy=policy,
        )

    def _record(
        self,
        *,
        phase: str,
        event_type: str,
        decision: GovernanceDecision | None = None,
        action_index: int | None = None,
        tool_name: str | None = None,
        execution_status: str = "not_started",
    ) -> None:
        if self._recorder is None:
            return
        self._sequence += 1
        trace_id, span_id = (
            self._telemetry.current_ids() if self._telemetry is not None else (None, None)
        )
        self._recorder.record(
            RunEvent.model_validate({
                "run_id": self._run_id,
                "sequence": self._sequence,
                "contract_id": self._contract.contract_id,
                "mode": self._mode,
                "phase": phase,
                "event_type": event_type,
                "action_index": action_index,
                "tool_name": tool_name,
                "decision": decision.decision if decision is not None else None,
                "violation_rules": [v.rule for v in decision.violations] if decision is not None else [],
                "execution_status": execution_status,
                "trace_id": trace_id,
                "span_id": span_id,
            })
        )

    @property
    def state(self) -> str:
        return self._state

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def contract(self) -> AgentContract | ContractRulesV2:
        return self._contract.model_copy(deep=True)

    def _request(
        self,
        phase: str,
        context: ExecutionContext,
        *,
        action: ActionProposal | None = None,
        response: JsonObject | None = None,
        run_ledger: JsonObject | None = None,
    ) -> GovernorInput:
        return GovernorInput.model_validate(
            {
                "run_id": self._run_id,
                "contract": self._contract.model_dump(),
                "phase": phase,
                "context": context.model_dump(),
                "action": action.model_dump() if action is not None else None,
                "response": response,
                "run_ledger": run_ledger,
                "policy": self._policy.model_dump() if self._policy is not None else None,
            }
        )

    def begin(self, context: ExecutionContext) -> GovernanceDecision:
        if self._state != "new":
            raise RuntimeError("Pre-execution check already completed")
        check_span = self._telemetry.span(
            "governor.check", phase="pre_execution", mode=self._mode,
            run_id=self._run_id, contract_id=self._contract.contract_id,
        ) if self._telemetry is not None else nullcontext(None)
        try:
            with check_span as span:
                decision = self._governor.evaluate(self._request("pre_execution", context))
                if not isinstance(decision, GovernanceDecision) or decision.phase != "pre_execution":
                    raise ValueError("Governor returned an invalid pre-execution decision")
                if self._telemetry is not None:
                    self._telemetry.record_decision(span, decision)
                self._record(phase="pre_execution", event_type="decision", decision=decision)
        except Exception:
            self._state = "aborted"
            raise
        self._state = "aborted" if self._mode == "strict" and decision.violations else "active"
        return decision

    def execute(
        self,
        action: ActionProposal,
        context: ExecutionContext,
        tool: Callable[[ActionProposal], T],
    ) -> ToolExecutionOutcome[T]:
        if self._state != "active":
            raise RuntimeError("Run is not active")
        self._action_index += 1
        action_index = self._action_index

        def record_before_tool(decision: GovernanceDecision) -> None:
            self._record(
                phase="runtime", event_type="decision", decision=decision,
                action_index=action_index, tool_name=action.tool_name,
            )

        def record_tool_completed() -> None:
            self._record(
                phase="runtime", event_type="tool_completed",
                action_index=action_index, tool_name=action.tool_name,
                execution_status="completed",
            )

        def record_tool_error() -> None:
            self._record(
                phase="runtime", event_type="tool_error",
                action_index=action_index, tool_name=action.tool_name,
                execution_status="unknown",
            )

        try:
            outcome = self._executor.execute(
                self._request("runtime", context, action=action), tool,
                before_invoke=record_before_tool,
                after_invoke=record_tool_completed,
                on_tool_error=record_tool_error,
                action_index=action_index,
            )
        except Exception:
            self._state = "aborted"
            raise
        if outcome.decision.decision == "abort" or (
            self._mode == "strict" and outcome.decision.violations
        ):
            self._state = "aborted"
        return outcome

    def finish(
        self,
        context: ExecutionContext,
        response: JsonObject,
        run_ledger: JsonObject | None = None,
    ) -> GovernanceDecision:
        if self._state != "active":
            raise RuntimeError("Run is not active")
        check_span = self._telemetry.span(
            "governor.check", phase="post_execution", mode=self._mode,
            run_id=self._run_id, contract_id=self._contract.contract_id,
        ) if self._telemetry is not None else nullcontext(None)
        try:
            with check_span as span:
                decision = self._governor.evaluate(
                    self._request(
                        "post_execution", context, response=response, run_ledger=run_ledger
                    )
                )
                if not isinstance(decision, GovernanceDecision) or decision.phase != "post_execution":
                    raise ValueError("Governor returned an invalid post-execution decision")
                if self._telemetry is not None:
                    self._telemetry.record_decision(span, decision)
                self._record(phase="post_execution", event_type="decision", decision=decision)
        except Exception:
            self._state = "aborted"
            raise
        self._state = "failed_post" if self._mode == "strict" and decision.violations else "finished"
        return decision
