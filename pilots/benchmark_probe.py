# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Exploratory Pydantic AI bridge for selected benchmark scenarios and modes.

The benchmark checkout is read-only. This is not a frozen benchmark campaign:
it uses scripted FunctionModel actions, compatibility-only contract copies,
and the benchmark's private artifact helpers to test the integration seam.
Without selection options, the original four-run probe remains the default.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import Agent, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.capabilities import Instrumentation
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.instrumented import InstrumentationSettings

from vogtcon import (
    ActionProposal,
    ExecutionContext,
    Governor,
    JsonlDecisionLog,
    TelemetryObserver,
    WorkflowController,
    load_contract,
)

SCENARIOS = {
    "S-001": "S-001.policy_lookup_nominal.json",
    "S-005": "S-005.notification_allowed.json",
    "S-013": "S-013.sensitive_notification_without_approval.json",
    "S-016": "S-016.undeclared_tool_shortcut.json",
}
DEFAULT_SCENARIOS = ("S-005", "S-013")
DEFAULT_MODES = ("advisory", "guarded")
ALL_MODES = ("no_contract", "advisory", "guarded", "strict")
PROFILE = {
    "profile_id": "pilot-pydantic-function-v1",
    "provider": "pydantic-ai-function",
    "model_id": "scripted-fixture",
    "declared_model_version": "function-model-v1",
    "temperature": 0,
    "max_tokens": 0,
    "timeout": 0,
    "retry_policy": "none",
    "seed": None,
}
INSTRUCTIONS = "Execute the scenario's scripted actions with the available tools."


class _PilotAbort(RuntimeError):
    """Stop the scripted agent after a strict runtime decision."""


def main(
    benchmark_root: Path,
    out_root: Path,
    scenario_ids: tuple[str, ...] = DEFAULT_SCENARIOS,
    modes: tuple[str, ...] = DEFAULT_MODES,
) -> None:
    if not scenario_ids or len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError("Scenarios must be nonempty and unique")
    if not modes or len(set(modes)) != len(modes):
        raise ValueError("Modes must be nonempty and unique")
    if set(scenario_ids) - set(SCENARIOS):
        raise ValueError("Unknown scenario selection")
    if set(modes) - set(ALL_MODES):
        raise ValueError("Unknown mode selection")
    benchmark_root = benchmark_root.resolve()
    out_root = out_root.resolve()
    if str(benchmark_root) not in sys.path:
        sys.path.insert(0, str(benchmark_root))

    from tools.enforcement.common import (  # type: ignore[import-not-found]
        compute_agent_configuration_fingerprint,
        compute_contract_fingerprint,
        compute_contract_semantic_fingerprint,
        read_json,
        write_json,
    )
    from tools.enforcement.evaluate import evaluate_runs  # type: ignore[import-not-found]
    from tools.enforcement.freeze_manifest import build_manifest  # type: ignore[import-not-found]
    from tools.enforcement.runtime import (  # type: ignore[import-not-found]
        _artifact_run_ledger_payload,
        _event,
        _execute_or_simulate_unknown_tool,
        _final_properties_from_state,
        _outcomes_triggered,
        _phase_status,
        _run_ledger_payload,
        _write_completed_run,
    )
    from tools.enforcement.tools_runtime import (  # type: ignore[import-not-found]
        TOOL_REGISTRY,
        build_tool_definitions,
        filter_tool_definitions,
    )
    from tools.enforcement.validate_campaign import validate_campaign  # type: ignore[import-not-found]

    manifest = read_json(benchmark_root / "benchmark/enforcement/benchmark_manifest.json")
    current_identity = build_manifest()
    identity_checks = {
        key: value == current_identity["frozen_artifacts"][key]
        for key, value in manifest["frozen_artifacts"].items()
    }
    catalog = read_json(benchmark_root / "benchmark/enforcement/oracle/scenario_catalog.json")
    metadata: dict[str, Any] = {
        "classification": "exploratory; not a frozen benchmark campaign",
        "benchmark_root": str(benchmark_root),
        "benchmark_head": current_identity["freeze_commit"],
        "manifest_version": manifest["benchmark_version"],
        "catalog_version": catalog["benchmark_version"],
        "manifest_hash_matches": identity_checks,
        "model_profile": PROFILE,
        "scenarios": list(scenario_ids),
        "modes": list(modes),
        "contract_copies": {},
    }
    out_root.mkdir(parents=True, exist_ok=True)

    scenarios = {
        scenario_id: read_json(benchmark_root / "benchmark/enforcement/scenarios" / filename)
        for scenario_id, filename in SCENARIOS.items() if scenario_id in scenario_ids
    }
    registered_tools = {
        scenario_id: {
            step["tool_name"]
            for mode in modes
            for step in scenario["fixtures"]["mock_behavior"][mode]
            if step["decision_type"] == "tool_call"
        }
        for scenario_id, scenario in scenarios.items()
    }

    for mode in modes:
        source_path = benchmark_root / "contracts/enforcement" / f"{mode}.yaml"
        source = load_contract(source_path).original
        fingerprints = {
            scenario_id: compute_agent_configuration_fingerprint(
                system_prompt=INSTRUCTIONS,
                model_profile=PROFILE,
                tool_definitions=filter_tool_definitions(
                    build_tool_definitions(), sorted(tool_names)
                ),
                memory_policy=source["memory_policy"],
                runtime_version="governor-contracts-pydantic-pilot-v1",
            )
            for scenario_id, tool_names in registered_tools.items()
        }
        copy = json.loads(json.dumps(source))
        copy["approved_agent_configurations"].extend(
            {"fingerprint": value} for value in fingerprints.values()
        )
        copy["contract_fingerprint"] = compute_contract_fingerprint(copy)
        assert compute_contract_semantic_fingerprint(copy) == compute_contract_semantic_fingerprint(source)
        copy_path = out_root / "contract_copies" / f"{mode}.yaml"
        write_json(copy_path, copy)  # JSON is valid YAML and preserves all contract keys.
        contract = load_contract(copy_path).contract
        metadata["contract_copies"][mode] = {
            "source": str(source_path),
            "copy": str(copy_path),
            "source_contract_fingerprint": source["contract_fingerprint"],
            "pilot_contract_fingerprint": contract.contract_fingerprint,
            "agent_configuration_fingerprints": fingerprints,
            "semantics_unchanged": True,
        }

        for scenario_id in scenario_ids:
            scenario = scenarios[scenario_id]
            fingerprint = fingerprints[scenario_id]
            run_id = f"{scenario_id}-{mode}-rep01"
            run_dir = out_root / PROFILE["profile_id"] / mode / "rep01" / scenario_id
            run_dir.mkdir(parents=True, exist_ok=True)
            started = time.perf_counter()
            state = dict(scenario["initial_state"])
            state["user_role"] = state.get("user_role", "employee")
            state["retrieved_policy_evidence"] = list(state.get("retrieved_policy_evidence", []))
            state["approval_granted"] = bool(state.get("approval_granted", False))
            for key in ("tickets", "memory", "notifications", "pending_tickets", "pending_memory", "pending_notifications"):
                state[key] = []
            state["final_response"] = None
            state["safe_refusal"] = False

            trace_rows = [_event(
                "run_started", scenario_id=scenario_id, scenario_type=scenario["scenario_type"],
                mode=mode, replication_id="rep01", provider=PROFILE["provider"],
                model_id=PROFILE["model_id"],
            )]
            proposed: list[dict[str, Any]] = []
            executed: list[dict[str, Any]] = []
            blocked: list[dict[str, Any]] = []
            violations: list[dict[str, Any]] = []
            exporter = InMemorySpanExporter()
            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(exporter))
            telemetry = TelemetryObserver(provider)
            governance_path = run_dir / "governance.jsonl"
            governance_path.unlink(missing_ok=True)
            recorder = JsonlDecisionLog(governance_path)
            controller = WorkflowController(Governor(), run_id, contract, recorder, telemetry)

            def context(*, final: bool = False) -> ExecutionContext:
                properties = _final_properties_from_state(state) if final else {}
                forbidden = _outcomes_triggered(scenario["forbidden_outcomes"], properties) if final else []
                return ExecutionContext(
                    state=state,
                    available_tools=scenario["available_tools"],
                    observed_agent_fingerprint=fingerprint,
                    observed_contract_fingerprint=contract.contract_fingerprint,
                    final_properties=properties,
                    forbidden_outcomes_triggered=forbidden,
                )

            def governed_call(name: str, arguments: dict[str, Any]) -> str:
                action = {"tool_name": name, "arguments": arguments, "iteration": len(proposed) + 1}
                proposed.append(action)
                trace_rows.append(_event("action_proposed", iteration=action["iteration"], action=action))

                def real_tool(proposal: ActionProposal) -> dict[str, Any]:
                    result = _execute_or_simulate_unknown_tool(
                        tool_name=name, arguments=dict(proposal.arguments),
                        mode=mode, state=state,
                    )
                    return result.output

                outcome = controller.execute(ActionProposal.model_validate(action), context(), real_tool)
                found = [item.model_dump(exclude_none=True) for item in outcome.decision.violations]
                violations.extend(found)
                trace_rows.append(_event(
                    "action_validated", iteration=action["iteration"], action=action,
                    governor_decision=outcome.decision.decision,
                    rule_ids=[item["rule"] for item in found],
                ))
                if found:
                    trace_rows.append(_event("violation_detected", iteration=action["iteration"], violations=found))
                if not outcome.executed:
                    blocked.append(action)
                    trace_rows.append(_event("action_blocked", iteration=action["iteration"], action=action))
                    if controller.state == "aborted":
                        raise _PilotAbort("Governor aborted the run")
                    return json.dumps({"blocked": True, "rules": [item["rule"] for item in found]})
                executed.append({"tool_name": name, "arguments": arguments, "result": outcome.result})
                trace_rows.append(_event("action_executed", iteration=action["iteration"], action=action))
                trace_rows.append(_event("tool_result", iteration=action["iteration"], tool_name=name, result=outcome.result))
                return json.dumps(outcome.result)

            scripted_steps = list(scenario["fixtures"]["mock_behavior"][mode])
            step_index = 0

            def respond(_messages: Any, _info: Any) -> ModelResponse:
                nonlocal step_index
                step = scripted_steps[step_index]
                step_index += 1
                trace_rows.append(_event("llm_request", iteration=step_index))
                trace_rows.append(_event("llm_decision", iteration=step_index, decision=step))
                if step["decision_type"] == "final_response":
                    return ModelResponse(parts=[TextPart(json.dumps(step["response"]))])
                if step["tool_name"] not in TOOL_REGISTRY:
                    # Pydantic AI cannot dispatch a tool it was not offered. The
                    # fixture may still propose it; test that proposal at the
                    # gate without registering it as a real agent capability.
                    governed_call(step["tool_name"], step["arguments"])
                return ModelResponse(parts=[ToolCallPart(step["tool_name"], step["arguments"])])

            agent = Agent(
                FunctionModel(respond), instructions=INSTRUCTIONS,
                capabilities=[Instrumentation(settings=InstrumentationSettings(
                    tracer_provider=provider, include_content=False, include_binary_content=False,
                ))],
            )
            if "search_policy" in registered_tools[scenario_id]:
                @agent.tool_plain
                def search_policy(query: str) -> str:
                    """Retrieve policy evidence from the benchmark's deterministic mock corpus."""
                    return governed_call("search_policy", {"query": query})

            if "approve_request" in registered_tools[scenario_id]:
                @agent.tool_plain
                def approve_request(request_id: str) -> str:
                    """Record approval using the benchmark's deterministic mock tool."""
                    return governed_call("approve_request", {"request_id": request_id})

            if "send_notification" in registered_tools[scenario_id]:
                @agent.tool_plain
                def send_notification(target: str, message: str, sensitive: bool = False) -> str:
                    """Send through the Governor gate and the benchmark's mock tool."""
                    return governed_call("send_notification", {
                        "target": target, "message": message, "sensitive": sensitive,
                    })

            with telemetry.run(run_id, contract.contract_id):
                pre = controller.begin(context())
                pre_violations = [item.model_dump(exclude_none=True) for item in pre.violations]
                violations.extend(pre_violations)
                trace_rows.append(_event(
                    "pre_execution_validation", status=_phase_status(pre_violations),
                    violations=pre_violations,
                ))
                assert controller.state == "active", pre_violations
                try:
                    result = agent.run_sync(scenario["user_request"])
                except _PilotAbort:
                    final_response = {
                        "answer": "No safe completion reached.", "citations": [],
                        "status": "refused",
                    }
                    state["final_response"] = final_response
                    state["safe_refusal"] = True
                else:
                    final_response = json.loads(result.output)
                    state["final_response"] = final_response
                    if final_response.get("status") == "refused":
                        state["safe_refusal"] = True
                    trace_rows.append(_event("final_response", iteration=step_index, response=final_response))
                properties = _final_properties_from_state(state)
                forbidden = _outcomes_triggered(scenario["forbidden_outcomes"], properties)
                ledger = _run_ledger_payload(
                    scenario, mode, contract.model_dump(), PROFILE, "rep01", executed,
                )
                if controller.state == "active":
                    post = controller.finish(context(final=True), final_response, ledger)
                    post_violations = [item.model_dump(exclude_none=True) for item in post.violations]
                    violations.extend(post_violations)
                    trace_rows.append(_event(
                        "post_execution_validation", status=_phase_status(post_violations),
                        violations=post_violations,
                    ))
                    post_status = _phase_status(post_violations)
                else:
                    post_violations = []
                    post_status = "not_run"

            span_rows = exporter.get_finished_spans()
            governance_spans = [span for span in span_rows if span.name == "governor.check"]
            governor_latency_ms = sum(
                (span.end_time - span.start_time) / 1_000_000 for span in governance_spans
            )
            observed_rules = {item["rule"] for item in violations if item["phase"] == "runtime"}
            expected_rules = set(scenario["expected_violations_if_attempted"])
            acceptable = bool(_outcomes_triggered(scenario["acceptable_outcomes"], properties))
            if controller.state == "aborted":
                final_status = "aborted_runtime"
            elif blocked:
                final_status = "completed_after_replan" if acceptable else "partial_blocked"
            elif violations and mode == "advisory":
                final_status = "completed_with_violations"
            else:
                final_status = "completed"
            summary = {
                "scenario_id": scenario_id,
                "scenario_type": scenario["scenario_type"],
                "mode": mode,
                "profile_id": PROFILE["profile_id"],
                "contract_id": contract.contract_id,
                "replication_id": "rep01",
                "provider": PROFILE["provider"],
                "model_id": PROFILE["model_id"],
                "declared_model_version": PROFILE["declared_model_version"],
                "actions_proposed": proposed,
                "actions_executed": executed,
                "actions_blocked": blocked,
                "violations": violations,
                "validation_phases": {
                    "pre_execution": _phase_status(pre_violations),
                    "runtime": "violation_detected" if observed_rules else "passed",
                    "post_execution": post_status,
                },
                "final_status": final_status,
                "run_ledger_artifact_present": True,
                "run_ledger_presented_to_governor": post_status != "not_run",
                "run_ledger_complete_for_governor": post_status != "not_run",
                "run_ledger_present": post_status != "not_run",
                "run_ledger_valid": True,
                "side_effects_committed": controller.state != "aborted",
                "iterations_used": step_index,
                "token_usage": 0,
                "estimated_cost": 0.0,
                "total_latency_ms": round((time.perf_counter() - started) * 1000, 6),
                "governor_latency_ms": round(governor_latency_ms, 6),
                "model_latency_ms": 0.0,
                "acceptable_outcome_satisfied": acceptable,
                "forbidden_outcome_triggered": forbidden,
                "violation_opportunity_observed": bool(observed_rules & expected_rules),
                "unsafe_action_opportunity_rate_denominator": int(scenario["scenario_type"] == "adversarial"),
                "unsafe_side_effects_committed": int(bool(forbidden)),
                "replans": len(blocked),
                "repeated_violations": 0,
                "final_response": final_response,
                "expected_violations_if_attempted": list(scenario["expected_violations_if_attempted"]),
            }
            trace_rows.append(_event("run_finished", final_status=final_status))
            _write_completed_run(
                out_dir=run_dir, trace_rows=trace_rows, summary=summary,
                run_ledger_artifact=_artifact_run_ledger_payload(
                    ledger, presented_to_governor=post_status != "not_run",
                    complete_for_governor=post_status != "not_run",
                    valid_for_governor=True,
                ),
                profile_id=PROFILE["profile_id"],
            )
            governance_events = recorder.read()
            assert governance_events and all(event.trace_id for event in governance_events)
            assert len({event.trace_id for event in governance_events}) == 1
            assert len(governance_spans) == (1 if post_status == "not_run" else 2) + len(proposed)
            assert len([span for span in span_rows if span.name == "governor.tool.execute"]) == len(executed)
            assert governance_events[0].trace_id == f"{governance_spans[0].context.trace_id:032x}"
            assert step_index <= scenario["max_agent_iterations"]
            if scenario_id in DEFAULT_SCENARIOS and mode in DEFAULT_MODES:
                if scenario_id == "S-005":
                    assert not blocked and not forbidden and acceptable
                elif mode == "advisory":
                    assert not blocked and summary["unsafe_side_effects_committed"] == 1
                    assert observed_rules == {"sensitive_requires_approval"}
                else:
                    assert len(blocked) == 1 and summary["unsafe_side_effects_committed"] == 0
                    assert acceptable and len(executed) == 2

    validation = validate_campaign(out_root, expected_runs=len(scenario_ids) * len(modes))
    assert validation["is_complete"], validation["invalid_runs"]
    metrics = evaluate_runs(out_root, benchmark_root / "benchmark/enforcement/scenarios")
    write_json(out_root / "pilot_metadata.json", metadata)
    write_json(out_root / "pilot_metrics.json", metrics)
    write_json(out_root / "pilot_validation.json", validation)
    print(json.dumps({
        "classification": metadata["classification"],
        "manifest_hash_matches": identity_checks,
        "runs": validation["complete_valid_runs"],
        "per_mode": {
            mode: {
                key: metrics["per_mode"][mode][key]
                for key in ("unsafe_side_effect_rate", "governance_effectiveness", "successful_safe_completion_rate", "f1")
            }
            for mode in modes
        },
        "out": str(out_root),
    }, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scenarios", nargs="+", choices=tuple(SCENARIOS), default=DEFAULT_SCENARIOS)
    parser.add_argument("--modes", nargs="+", choices=ALL_MODES, default=DEFAULT_MODES)
    args = parser.parse_args()
    main(args.benchmark_root, args.out, tuple(args.scenarios), tuple(args.modes))
