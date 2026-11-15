# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Pydantic AI agent whose only effectful tool crosses the Governor gate.

The host provides trusted context and the real tool implementation. FunctionModel
drives the runnable demonstration without a provider or model credentials.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, ModelResponse, RunContext, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.capabilities import Instrumentation
from pydantic_ai.models.instrumented import InstrumentationSettings

from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    GovernorInput,
    JsonlDecisionLog,
    RuleCatalog,
    RunRecorder,
    TelemetryObserver,
    ToolExecutionOutcome,
    WorkflowController,
    load_contract,
)

CONTRACT_PATH = Path(__file__).with_name("custom_contract.yaml")


def public_note_requires_approval(request: GovernorInput) -> bool:
    assert request.action is not None
    return (
        request.action.tool_name == "save_note"
        and request.action.arguments.get("public") is True
        and request.context.state.get("approval_granted") is not True
    )


RULES = RuleCatalog(
    runtime_rules={"note.public_requires_approval": public_note_requires_approval}
)


@dataclass(slots=True)
class NoteTool:
    """Replace this callable with the application's own tool implementation."""

    saved: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, proposal: ActionProposal) -> str:
        self.saved.append(dict(proposal.arguments))
        return "saved"


@dataclass(frozen=True, slots=True)
class NoteRun:
    pre: GovernanceDecision
    actions: tuple[ToolExecutionOutcome[str], ...]
    post: GovernanceDecision | None
    untrusted_agent_output: str | None
    verified_output: str | None
    state: str

    @property
    def agent_output(self) -> str | None:
        """Keep the old field name safe for callers that display it."""
        return self.verified_output


@dataclass(slots=True)
class _NoteDeps:
    """Host-owned facts and effectful tool for one agent run."""

    controller: WorkflowController
    context: ExecutionContext
    tool: Callable[[ActionProposal], str]
    actions: list[ToolExecutionOutcome[str]]


def scripted_model(text: str, public: bool) -> FunctionModel:
    """Supply a deterministic model call followed by a final response."""

    def respond(messages, _info) -> ModelResponse:
        if len(messages) == 1:
            return ModelResponse(
                parts=[ToolCallPart("save_note", {"text": text, "public": public})]
            )
        return ModelResponse(parts=[TextPart("done")])

    return FunctionModel(respond)


def run_note(
    *,
    run_id: str,
    context: ExecutionContext,
    tool: Callable[[ActionProposal], str],
    model: Any,
    recorder: RunRecorder | None = None,
    telemetry: TelemetryObserver | None = None,
) -> NoteRun:
    """Run one agent with host-owned dependencies and a v2 guarded contract.

    Each Pydantic AI tool call receives ``RunContext[_NoteDeps]``; its effect is
    invoked only through ``WorkflowController.execute``. The returned verified
    output is computed from executed actions, not the model's final claim.
    """
    controller = WorkflowController.from_contract_path(
        CONTRACT_PATH, run_id,
        policy=EnforcementPolicy(mode="guarded"), rule_catalog=RULES,
        recorder=recorder, telemetry=telemetry,
    )
    run_span = (
        telemetry.run(run_id, controller.contract.contract_id)
        if telemetry is not None else nullcontext()
    )
    with run_span:
        pre = controller.begin(context)
        if controller.state != "active":
            return NoteRun(pre, (), None, None, None, controller.state)

        actions: list[ToolExecutionOutcome[str]] = []
        capabilities = []
        if telemetry is not None:
            capabilities.append(Instrumentation(settings=InstrumentationSettings(
                tracer_provider=telemetry.tracer_provider,
                include_content=False,
                include_binary_content=False,
            )))
        agent = Agent(
            model,
            deps_type=_NoteDeps,
            instructions="Save the requested note with the supplied visibility.",
            capabilities=capabilities,
        )

        @agent.tool
        def save_note(ctx: RunContext[_NoteDeps], text: str, public: bool) -> str:
            """Save a note using the host's governed tool."""
            proposal = ActionProposal(
                tool_name="save_note", arguments={"text": text, "public": public}
            )
            outcome = ctx.deps.controller.execute(
                proposal, ctx.deps.context, ctx.deps.tool
            )
            ctx.deps.actions.append(outcome)
            if outcome.decision.decision == "abort":
                raise RuntimeError("Governor aborted this run")
            if not outcome.executed:
                rules = ", ".join(item.rule for item in outcome.decision.violations)
                return f"blocked by Governor: {rules}"
            return outcome.result or "completed"

        deps = _NoteDeps(controller, context, tool, actions)
        untrusted_agent_output = agent.run_sync("Save the note", deps=deps).output
        saved_count = sum(item.executed for item in actions)
        blocked_count = len(actions) - saved_count
        if blocked_count:
            verified_output = f"Saved {saved_count} note(s); blocked {blocked_count} request(s)."
        elif saved_count:
            verified_output = f"Saved {saved_count} note(s)."
        else:
            verified_output = "No note was saved."
        post = controller.finish(
            context,
            {"status": "saved" if saved_count else "blocked", "message": verified_output},
        )
        return NoteRun(
            pre, tuple(actions), post, untrusted_agent_output,
            verified_output, controller.state,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the governed Pydantic AI example offline")
    parser.add_argument("--log", type=Path, help="Append governance events to this JSONL file")
    parser.add_argument("--trace-console", action="store_true", help="Print OpenTelemetry spans; requires opentelemetry-sdk")
    args = parser.parse_args()
    telemetry = None
    if args.trace_console:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        telemetry = TelemetryObserver(provider)
    recorder = JsonlDecisionLog(args.log) if args.log else None
    contract_fingerprint = load_contract(CONTRACT_PATH, rule_catalog=RULES).contract.contract_fingerprint
    for approved in (False, True):
        trusted_context = ExecutionContext(
            state={"approval_granted": approved},
            available_tools=["save_note"],
            observed_agent_fingerprint="pydantic-note-agent-v1",
            observed_contract_fingerprint=contract_fingerprint,
        )
        sink = NoteTool()
        run = run_note(
            run_id=f"note-{approved}", context=trusted_context, tool=sink,
            model=scripted_model("Example note", public=True),
            recorder=recorder, telemetry=telemetry,
        )
        print({
            "approved": approved,
            "decision": run.actions[0].decision.decision,
            "rules": [v.rule for v in run.actions[0].decision.violations],
            "saved": sink.saved,
            "verified_output": run.verified_output,
        })
    if args.log:
        print(f"Governance events: {args.log}")
