# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Synchronous checkpoints and tool gating for one governed run.

The caller supplies trusted context and the tool implementation. This module
does not infer authorization from telemetry or undo effects after execution.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Generic, Self, TypeVar

from .contracts import load_contract
from .core import Governor
from .effects import (
    ApprovalReuseError,
    CompensationRecord,
    ConcurrencyError,
    EffectGovernanceConfig,
    EffectObservationError,
    EffectResolutionError,
    ObservationInput,
    ObservedEffect,
    ReconciliationError,
    ReconciliationRecord,
    ResolvedAction,
    ScopeSuspendedError,
)
from .models import (
    ActionProposal,
    AgentContract,
    ApprovalId,
    ContractRulesV2,
    ContractRulesV3,
    ContractSchema,
    EffectRecord,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    GovernorInput,
    HostApproval,
    HostFacts,
    JsonObject,
    PlannedEffect,
    PolicyScopeId,
    PrincipalId,
    RetrievedEvidence,
    TimestampStr,
    TrajectoryView,
    _thaw_json_value,
)
from .records import RunEvent, RunEventV2, RunRecorder
from .rules import BoundApprovalParams, RuleCatalog
from .telemetry import TelemetryObserver

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ToolExecutionOutcome(Generic[T]):
    decision: GovernanceDecision
    executed: bool
    result: T | None = None
    effect: EffectRecord | None = None


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
        if isinstance(request.contract, ContractRulesV3):
            raise ValueError(
                "v3 contracts cannot be executed directly via GovernedToolExecutor; "
                "use WorkflowController with explicit effect_governance configuration"
            )
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
        contract: ContractSchema,
        recorder: RunRecorder | None = None,
        telemetry: TelemetryObserver | None = None,
        *,
        policy: EnforcementPolicy | None = None,
        effect_governance: EffectGovernanceConfig | None = None,
    ) -> None:
        if not run_id:
            raise ValueError("run_id must be nonempty")
        if effect_governance is not None and not isinstance(
            effect_governance, EffectGovernanceConfig
        ):
            raise TypeError(
                "effect_governance must be an EffectGovernanceConfig or None"
            )
        if isinstance(contract, AgentContract) and "schema_version" in (contract.model_extra or {}):
            raise ValueError("Unsupported contract schema_version")
        if isinstance(contract, ContractRulesV3):
            if policy is None:
                raise ValueError("v3 contracts require an enforcement policy")
            if effect_governance is None:
                raise ValueError(
                    "v3 contracts require explicit effect_governance configuration"
                )
        elif isinstance(contract, ContractRulesV2):
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
        self._effect_governance = effect_governance
        self._op_lock = threading.Lock()

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
        effect_governance: EffectGovernanceConfig | None = None,
    ) -> Self:
        """Load a contract and start one deterministic run.

        The same rule catalog validates the document and evaluates its rules.
        V2 and v3 contracts require an explicit policy; v3 also requires
        explicit ``effect_governance``. Use the constructor directly to supply
        a custom Governor evaluator.
        """
        contract = load_contract(path, rule_catalog=rule_catalog).contract
        return cls(
            Governor(rule_catalog=rule_catalog), run_id, contract,
            recorder, telemetry, policy=policy,
            effect_governance=effect_governance,
        )

    @contextmanager
    def _acquire_op_lock(self) -> Iterator[None]:
        if self._effect_governance is None:
            yield
            return
        if not self._op_lock.acquire(blocking=False):
            raise ConcurrencyError(
                "Concurrent or re-entrant operation on WorkflowController is not supported"
            )
        try:
            yield
        finally:
            self._op_lock.release()

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

    def _record_v2(
        self,
        *,
        phase: str,
        event_type: str,
        decision: GovernanceDecision | None = None,
        action_index: int | None = None,
        tool_name: str | None = None,
        execution_status: str = "not_started",
        policy_scope: PolicyScopeId | None = None,
        effect_id: str | None = None,
        operation_digest: str | None = None,
        effect_status: str | None = None,
        approval_id: ApprovalId | None = None,
        compensates_effect_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> None:
        if self._recorder is None:
            return
        self._sequence += 1
        trace_id, span_id = (
            self._telemetry.current_ids() if self._telemetry is not None else (None, None)
        )
        event_payload: dict[str, object] = {
            "schema_version": 2,
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
            "policy_scope": policy_scope,
            "effect_id": effect_id,
            "operation_digest": operation_digest,
            "effect_status": effect_status,
            "compensates_effect_id": compensates_effect_id,
            "evidence_ref": evidence_ref,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        if approval_id is not None:
            event_payload["approval_id"] = approval_id
        self._recorder.record(RunEventV2.model_validate(event_payload))

    @property
    def state(self) -> str:
        return self._state

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def contract(self) -> ContractSchema:
        return self._contract.model_copy(deep=True)

    def _approval_binding_policy(
        self,
        tool_name: str,
        host_facts: HostFacts | None,
    ) -> tuple[bool, bool]:
        if not isinstance(self._contract, ContractRulesV3) or self._mode == "no_contract":
            return False, False
        matching_flags: list[bool] = []
        for binding in self._contract.rules:
            if (
                "runtime" not in binding.phases
                or binding.rule_type != "approval.bound_required"
            ):
                continue
            params = BoundApprovalParams.model_validate(_thaw_json_value(binding.params))
            if tool_name not in params.tools:
                continue
            if (
                params.sensitivity_fact_key is not None
                and host_facts is not None
                and host_facts.facts.get(params.sensitivity_fact_key) is False
            ):
                continue
            matching_flags.append(params.allow_retry_after_confirmed_absent)
        requires_approval = bool(matching_flags)
        return requires_approval, requires_approval and all(matching_flags)

    def _request(
        self,
        phase: str,
        context: ExecutionContext,
        *,
        action: ActionProposal | None = None,
        response: JsonObject | None = None,
        run_ledger: JsonObject | None = None,
        host_facts: HostFacts | None = None,
        planned_effect: PlannedEffect | None = None,
        policy_scope: PolicyScopeId | None = None,
        trajectory: TrajectoryView | None = None,
        requester_id: PrincipalId | None = None,
        evaluated_at: TimestampStr | None = None,
        approval: HostApproval | None = None,
        retrieved_evidence: tuple[RetrievedEvidence, ...] | None = None,
    ) -> GovernorInput:
        payload: dict[str, object] = {
            "run_id": self._run_id,
            "contract": self._contract.model_dump(),
            "phase": phase,
            "context": context.model_dump(),
            "action": action.model_dump() if action is not None else None,
            "response": response,
            "run_ledger": run_ledger,
            "policy": self._policy.model_dump() if self._policy is not None else None,
        }
        if host_facts is not None:
            payload["host_facts"] = host_facts
        if planned_effect is not None:
            payload["planned_effect"] = planned_effect
        if policy_scope is not None:
            payload["policy_scope"] = policy_scope
        if trajectory is not None:
            payload["trajectory"] = trajectory
        if requester_id is not None:
            payload["requester_id"] = requester_id
        if evaluated_at is not None:
            payload["evaluated_at"] = evaluated_at
        if approval is not None:
            payload["approval"] = approval
        if retrieved_evidence is not None:
            payload["retrieved_evidence"] = list(retrieved_evidence)
        return GovernorInput.model_validate(payload)

    def begin(self, context: ExecutionContext) -> GovernanceDecision:
        with self._acquire_op_lock():
            if self._state != "new":
                raise RuntimeError("Pre-execution check already completed")
            check_span = self._telemetry.span(
                "governor.check", phase="pre_execution", mode=self._mode,
                run_id=self._run_id, contract_id=self._contract.contract_id,
            ) if self._telemetry is not None else nullcontext(None)
            cfg = self._effect_governance
            if cfg is None:
                try:
                    with check_span as span:
                        decision = self._governor.evaluate(
                            self._request("pre_execution", context)
                        )
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

            trajectory = cfg.store.snapshot(cfg.policy_scope)
            try:
                with check_span as span:
                    decision = self._governor.evaluate(
                        self._request(
                            "pre_execution",
                            context,
                            policy_scope=cfg.policy_scope,
                            trajectory=trajectory,
                        )
                    )
                    if not isinstance(decision, GovernanceDecision) or decision.phase != "pre_execution":
                        raise ValueError("Governor returned an invalid pre-execution decision")
                    if self._telemetry is not None:
                        self._telemetry.record_decision(span, decision)
                    self._record_v2(
                        phase="pre_execution",
                        event_type="decision",
                        decision=decision,
                        policy_scope=cfg.policy_scope,
                    )
            except Exception:
                self._state = "aborted"
                raise
            self._state = "aborted" if self._mode == "strict" and decision.violations else "active"
            return decision

    def _execute_governed(
        self,
        action: ActionProposal,
        context: ExecutionContext,
        tool: Callable[[ActionProposal], T],
    ) -> ToolExecutionOutcome[T]:
        cfg = self._effect_governance
        assert cfg is not None
        with self._acquire_op_lock():
            if self._state == "suspended":
                raise ScopeSuspendedError(
                    policy_scope=None,
                    uncertain_effect_ids=cfg.store.uncertain_effects(None),
                )
            if self._state != "active":
                raise RuntimeError("Run is not active")

            action_snapshot = action.model_copy(deep=True)
            context_snapshot = context.model_copy(deep=True)

            # Stage 1: Resolution
            try:
                resolved = cfg.resolver.resolve(
                    action_snapshot.model_copy(deep=True),
                    context_snapshot.model_copy(deep=True),
                )
            except ConcurrencyError:
                raise
            except Exception:
                self._state = "aborted"
                raise EffectResolutionError("Effect resolver failed") from None
            if not isinstance(resolved, ResolvedAction):
                self._state = "aborted"
                raise EffectResolutionError("Effect resolver returned invalid output")
            if (
                cfg.policy_scope is not None
                and resolved.policy_scope is not None
                and resolved.policy_scope != cfg.policy_scope
            ):
                self._state = "aborted"
                raise ValueError(
                    "Resolved policy_scope conflicts with effect_governance.policy_scope"
                )
            effective_scope = (
                resolved.policy_scope
                if resolved.policy_scope is not None
                else cfg.policy_scope
            )

            # Pre-evaluation scope suspension check
            if cfg.store.is_scope_suspended(effective_scope):
                raise ScopeSuspendedError(
                    policy_scope=effective_scope,
                    uncertain_effect_ids=cfg.store.uncertain_effects(effective_scope),
                )

            # Stage 2: Evaluation
            trajectory = cfg.store.snapshot(effective_scope)
            expected_last_sequence = (
                trajectory.entries[-1].sequence if trajectory.entries else 0
            )
            try:
                request = self._request(
                    "runtime",
                    context_snapshot.model_copy(deep=True),
                    action=action_snapshot.model_copy(deep=True),
                    host_facts=resolved.host_facts,
                    planned_effect=resolved.planned_effect,
                    policy_scope=effective_scope,
                    trajectory=trajectory,
                    requester_id=resolved.requester_id,
                    evaluated_at=resolved.evaluated_at,
                    approval=resolved.approval,
                    retrieved_evidence=resolved.retrieved_evidence,
                )
                eval_req = request.model_copy(deep=True)
                check_span = self._telemetry.span(
                    "governor.check",
                    phase="runtime",
                    mode=self._mode,
                    run_id=self._run_id,
                    contract_id=self._contract.contract_id,
                    tool_name=resolved.planned_effect.tool_name,
                ) if self._telemetry is not None else nullcontext(None)
                with check_span as span:
                    decision = self._governor.evaluate(eval_req)
                    if eval_req != request:
                        raise ValueError("Governor evaluator mutated the action or its context")
                    if not isinstance(decision, GovernanceDecision) or decision.phase != "runtime":
                        raise ValueError("Governor returned an invalid runtime decision")
                    if (
                        self._mode in ("guarded", "strict")
                        and decision.violations
                        and decision.decision in ("allow", "allow_with_warning")
                    ):
                        raise ValueError(
                            "Governor allowed a violating action in an enforcement mode"
                        )
                    if self._telemetry is not None:
                        self._telemetry.record_decision(span, decision)
            except Exception:
                self._state = "aborted"
                raise

            operation_digest = resolved.planned_effect.operation_digest()
            tool_name = resolved.planned_effect.tool_name

            if decision.decision in ("block", "abort"):
                self._action_index += 1
                action_index = self._action_index
                try:
                    self._record_v2(
                        phase="runtime",
                        event_type="decision",
                        decision=decision,
                        action_index=action_index,
                        tool_name=tool_name,
                        policy_scope=effective_scope,
                        operation_digest=operation_digest,
                    )
                except Exception:
                    self._state = "aborted"
                    raise
                if decision.decision == "abort" or (
                    self._mode == "strict" and decision.violations
                ):
                    self._state = "aborted"
                return ToolExecutionOutcome(decision=decision, executed=False, effect=None)

            # Stage 3: Reservation
            next_action_index = self._action_index + 1
            requires_approval, allow_retry_after_absent = self._approval_binding_policy(
                tool_name, resolved.host_facts
            )
            has_approval_violation = any(
                v.rule_type == "approval.bound_required" for v in decision.violations
            )
            reserve_kwargs: dict[str, object] = {}
            if (
                requires_approval
                and resolved.approval is not None
                and not (decision.decision == "allow_with_warning" and has_approval_violation)
            ):
                reserve_kwargs = {
                    "approval_id": resolved.approval.approval_id,
                    "approval_single_use": resolved.approval.single_use,
                    "allow_retry_after_confirmed_absent": allow_retry_after_absent,
                }
            try:
                reserved = cfg.store.reserve(
                    run_id=self._run_id,
                    policy_scope=effective_scope,
                    action_index=next_action_index,
                    tool_name=tool_name,
                    operation_digest=operation_digest,
                    expected_last_sequence=expected_last_sequence,
                    **reserve_kwargs,  # type: ignore[arg-type]
                )
            except (ScopeSuspendedError, ConcurrencyError, ApprovalReuseError):
                raise
            except Exception:
                self._state = "aborted"
                raise
            self._action_index = next_action_index
            action_index = self._action_index

            # Stage 4: Pre-invocation Recording
            try:
                self._record_v2(
                    phase="runtime",
                    event_type="decision",
                    decision=decision,
                    action_index=action_index,
                    tool_name=tool_name,
                    policy_scope=effective_scope,
                    effect_id=reserved.effect_id,
                    operation_digest=reserved.operation_digest,
                    effect_status="reserved",
                    approval_id=reserved.approval_id,
                )
            except Exception:
                try:
                    cfg.store.record_observation(
                        effect_id=reserved.effect_id,
                        status="confirmed_absent",
                        evidence_ref="pre_invocation_record_failed",
                    )
                except Exception:
                    pass
                self._state = "aborted"
                raise

            # Stage 5: Invocation + Stage 6: Observation
            tool_span = self._telemetry.span(
                "governor.tool.execute",
                phase="runtime",
                run_id=self._run_id,
                contract_id=self._contract.contract_id,
                tool_name=tool_name,
                action_index=action_index,
            ) if self._telemetry is not None else nullcontext(None)
            with tool_span:
                try:
                    result = tool(action_snapshot.model_copy(deep=True))
                except Exception as tool_exc:
                    obs_in = ObservationInput(
                        effect_id=reserved.effect_id,
                        run_id=self._run_id,
                        policy_scope=effective_scope,
                        planned_effect=resolved.planned_effect,
                        invocation_outcome="raised",
                        error_type=type(tool_exc).__name__,
                    )
                    try:
                        observed = cfg.observer.observe(obs_in, tool_result=None)
                    except Exception:
                        observed = ObservedEffect(
                            status="uncertain", evidence_ref="observer_error"
                        )
                    if not isinstance(observed, ObservedEffect):
                        observed = ObservedEffect(
                            status="uncertain", evidence_ref="observer_error"
                        )
                    try:
                        final_record = cfg.store.record_observation(
                            effect_id=reserved.effect_id,
                            status=observed.status,
                            evidence_ref=observed.evidence_ref,
                            metadata=observed.metadata,
                        )
                    except Exception:
                        self._state = "aborted"
                        raise tool_exc
                    if final_record.status == "uncertain" and effective_scope is None:
                        self._state = "suspended"
                    try:
                        self._record_v2(
                            phase="runtime",
                            event_type="tool_error",
                            action_index=action_index,
                            tool_name=tool_name,
                            execution_status="unknown",
                            policy_scope=effective_scope,
                            effect_id=reserved.effect_id,
                            operation_digest=reserved.operation_digest,
                        )
                        self._record_v2(
                            phase="runtime",
                            event_type="effect_observed",
                            action_index=action_index,
                            tool_name=tool_name,
                            execution_status=(
                                "unknown"
                                if final_record.status == "uncertain"
                                else "completed"
                            ),
                            policy_scope=effective_scope,
                            effect_id=final_record.effect_id,
                            operation_digest=final_record.operation_digest,
                            effect_status=final_record.status,
                            approval_id=final_record.approval_id,
                            evidence_ref=final_record.evidence_ref,
                        )
                    except Exception:
                        pass
                    raise

            # Tool returned normally
            obs_in = ObservationInput(
                effect_id=reserved.effect_id,
                run_id=self._run_id,
                policy_scope=effective_scope,
                planned_effect=resolved.planned_effect,
                invocation_outcome="returned",
            )
            obs: ObservedEffect | None = None
            try:
                candidate = cfg.observer.observe(obs_in, tool_result=result)
                if isinstance(candidate, ObservedEffect):
                    obs = candidate
            except Exception:
                obs = None

            if obs is None:
                try:
                    uncertain_record = cfg.store.record_observation(
                        effect_id=reserved.effect_id,
                        status="uncertain",
                        evidence_ref="observer_error",
                    )
                except Exception:
                    self._state = "aborted"
                    raise EffectObservationError(
                        "Effect observer failed; effect marked uncertain"
                    ) from None
                if effective_scope is None:
                    self._state = "suspended"
                try:
                    self._record_v2(
                        phase="runtime",
                        event_type="tool_completed",
                        action_index=action_index,
                        tool_name=tool_name,
                        execution_status="completed",
                        policy_scope=effective_scope,
                        effect_id=reserved.effect_id,
                        operation_digest=reserved.operation_digest,
                    )
                    self._record_v2(
                        phase="runtime",
                        event_type="effect_observed",
                        action_index=action_index,
                        tool_name=tool_name,
                        execution_status="unknown",
                        policy_scope=effective_scope,
                        effect_id=uncertain_record.effect_id,
                        operation_digest=uncertain_record.operation_digest,
                        effect_status="uncertain",
                        approval_id=uncertain_record.approval_id,
                        evidence_ref=uncertain_record.evidence_ref,
                    )
                except Exception:
                    pass
                raise EffectObservationError(
                    "Effect observer failed; effect marked uncertain"
                ) from None

            try:
                final_record = cfg.store.record_observation(
                    effect_id=reserved.effect_id,
                    status=obs.status,
                    evidence_ref=obs.evidence_ref,
                    metadata=obs.metadata,
                )
            except Exception:
                self._state = "aborted"
                raise
            if final_record.status == "uncertain" and effective_scope is None:
                self._state = "suspended"
            try:
                self._record_v2(
                    phase="runtime",
                    event_type="tool_completed",
                    action_index=action_index,
                    tool_name=tool_name,
                    execution_status="completed",
                    policy_scope=effective_scope,
                    effect_id=reserved.effect_id,
                    operation_digest=reserved.operation_digest,
                )
                self._record_v2(
                    phase="runtime",
                    event_type="effect_observed",
                    action_index=action_index,
                    tool_name=tool_name,
                    execution_status=(
                        "unknown" if final_record.status == "uncertain" else "completed"
                    ),
                    policy_scope=effective_scope,
                    effect_id=final_record.effect_id,
                    operation_digest=final_record.operation_digest,
                    effect_status=final_record.status,
                    approval_id=final_record.approval_id,
                    evidence_ref=final_record.evidence_ref,
                )
            except Exception:
                self._state = "aborted"
                raise
            return ToolExecutionOutcome(
                decision=decision,
                executed=True,
                result=result,
                effect=final_record,
            )

    def execute(
        self,
        action: ActionProposal,
        context: ExecutionContext,
        tool: Callable[[ActionProposal], T],
    ) -> ToolExecutionOutcome[T]:
        if self._effect_governance is not None:
            return self._execute_governed(action, context, tool)
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

    def reconcile(self, record: ReconciliationRecord) -> EffectRecord:
        if self._effect_governance is None:
            raise RuntimeError("Effect governance is not configured")
        if not isinstance(record, ReconciliationRecord):
            raise TypeError("reconcile requires a ReconciliationRecord instance")
        cfg = self._effect_governance
        with self._acquire_op_lock():
            if self._state not in ("active", "suspended"):
                raise RuntimeError("Run is not active or suspended")
            effective_record = record
            if cfg.policy_scope is not None:
                if (
                    record.policy_scope is not None
                    and record.policy_scope != cfg.policy_scope
                ):
                    raise ReconciliationError(
                        "Reconciliation policy_scope conflicts with effect_governance.policy_scope"
                    )
                effective_record = record.model_copy(
                    update={"policy_scope": cfg.policy_scope}
                )
            reconciled = cfg.store.reconcile(effective_record)
            try:
                self._record_v2(
                    phase="runtime",
                    event_type="effect_reconciled",
                    action_index=(
                        reconciled.action_index
                        if reconciled.run_id == self._run_id
                        else None
                    ),
                    tool_name=reconciled.tool_name,
                    execution_status="completed",
                    policy_scope=reconciled.policy_scope,
                    effect_id=reconciled.effect_id,
                    operation_digest=reconciled.operation_digest,
                    effect_status=reconciled.status,
                    approval_id=reconciled.approval_id,
                    evidence_ref=reconciled.evidence_ref,
                )
            except Exception:
                self._state = "aborted"
                raise
            if (
                self._state == "suspended"
                and reconciled.policy_scope is None
                and not cfg.store.uncertain_effects(None)
            ):
                self._state = "active"
            return reconciled

    def record_compensation(self, compensation: CompensationRecord) -> EffectRecord:
        if self._effect_governance is None:
            raise RuntimeError("Effect governance is not configured")
        if not isinstance(compensation, CompensationRecord):
            raise TypeError(
                "record_compensation requires a CompensationRecord instance"
            )
        cfg = self._effect_governance
        with self._acquire_op_lock():
            if self._state not in ("active", "suspended"):
                raise RuntimeError("Run is not active or suspended")
            effective_comp = compensation
            if cfg.policy_scope is not None:
                if (
                    compensation.policy_scope is not None
                    and compensation.policy_scope != cfg.policy_scope
                ):
                    raise ReconciliationError(
                        "Compensation policy_scope conflicts with effect_governance.policy_scope"
                    )
                effective_comp = compensation.model_copy(
                    update={"policy_scope": cfg.policy_scope}
                )
            comp = cfg.store.record_compensation(
                run_id=self._run_id, compensation=effective_comp
            )
            try:
                self._record_v2(
                    phase="runtime",
                    event_type="effect_compensated",
                    action_index=None,
                    tool_name=comp.tool_name,
                    execution_status="completed",
                    policy_scope=comp.policy_scope,
                    effect_id=comp.effect_id,
                    operation_digest=comp.operation_digest,
                    effect_status="confirmed",
                    compensates_effect_id=comp.compensates_effect_id,
                    evidence_ref=comp.evidence_ref,
                )
            except Exception:
                self._state = "aborted"
                raise
            return comp

    def finish(
        self,
        context: ExecutionContext,
        response: JsonObject,
        run_ledger: JsonObject | None = None,
    ) -> GovernanceDecision:
        with self._acquire_op_lock():
            cfg = self._effect_governance
            if cfg is not None and self._state == "suspended":
                raise ScopeSuspendedError(
                    policy_scope=None,
                    uncertain_effect_ids=cfg.store.uncertain_effects(None),
                )
            if self._state != "active":
                raise RuntimeError("Run is not active")
            check_span = self._telemetry.span(
                "governor.check", phase="post_execution", mode=self._mode,
                run_id=self._run_id, contract_id=self._contract.contract_id,
            ) if self._telemetry is not None else nullcontext(None)
            if cfg is None:
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

            trajectory = cfg.store.snapshot(cfg.policy_scope)
            try:
                with check_span as span:
                    decision = self._governor.evaluate(
                        self._request(
                            "post_execution",
                            context,
                            response=response,
                            run_ledger=run_ledger,
                            policy_scope=cfg.policy_scope,
                            trajectory=trajectory,
                        )
                    )
                    if not isinstance(decision, GovernanceDecision) or decision.phase != "post_execution":
                        raise ValueError("Governor returned an invalid post-execution decision")
                    if self._telemetry is not None:
                        self._telemetry.record_decision(span, decision)
                    self._record_v2(
                        phase="post_execution",
                        event_type="decision",
                        decision=decision,
                        policy_scope=cfg.policy_scope,
                    )
            except Exception:
                self._state = "aborted"
                raise
            self._state = "failed_post" if self._mode == "strict" and decision.violations else "finished"
            return decision
