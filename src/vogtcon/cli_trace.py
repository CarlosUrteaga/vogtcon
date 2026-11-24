# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Trace parsing and correlation for ``vogtcon explain``."""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .records import RunEvent

EXIT_OK = 0
EXIT_INVALID_OR_INCONSISTENT = 1
EXIT_RUN_NOT_FOUND = 2
EXIT_IO_OR_USAGE = 3

TOOL_OUTCOMES = ("prevented", "completed", "error", "unfinalized", "unknown")


def _diag(
    code: str,
    message: str,
    *,
    line: int | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    return {"code": code, "message": message, "line": line, "run_id": run_id}


def _explain_result(
    path: str | Path,
    status: str,
    *,
    data: dict[str, Any] | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "output_version": 1,
        "command": "explain",
        "status": status,
        "path": str(path),
        "data": data,
        "diagnostics": diagnostics if diagnostics is not None else [],
    }


def _inconsistent_run(
    run_id: str,
    message: str,
    *,
    line: int | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[int, str]]:
    return (
        {
            "run_id": run_id,
            "contract_id": None,
            "mode": None,
            "trace_integrity": "inconsistent",
            "terminal": None,
            "pre_execution": None,
            "post_execution": None,
            "actions": None,
            "counts": None,
        },
        [_diag("inconsistent_log", message, line=line, run_id=run_id)],
        {},
    )


def _has_gap_between(seq_gaps: list[tuple[int, int]], lower_bound: int, upper_bound: int) -> bool:
    idx = bisect_left(seq_gaps, (lower_bound, 0))
    return idx < len(seq_gaps) and seq_gaps[idx][1] <= upper_bound


def _classify_outcome(
    decision: str | None,
    finalizer_type: str | None,
) -> tuple[str, str]:
    if decision in ("block", "abort"):
        return "prevented", "prevented_by_recorded_decision"
    if decision in ("allow", "allow_with_warning"):
        if finalizer_type == "tool_completed":
            return "completed", "not_verified"
        if finalizer_type == "tool_error":
            return "error", "indeterminate"
        return "unfinalized", "indeterminate"
    return "unknown", "indeterminate"


def _analyze_run(
    run_id: str,
    items: list[tuple[int, RunEvent]],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[int, str]]:
    first_event = items[0][1]
    contract_id = first_event.contract_id
    mode = first_event.mode

    prev_seq: int | None = None
    has_seq_gap = False
    seq_gaps: list[tuple[int, int]] = []
    terminal: str | None = None
    pre_execution: dict[str, Any] | None = None
    post_execution: dict[str, Any] | None = None

    actions_order: list[int] = []
    actions_map: dict[int, dict[str, Any]] = {}
    last_blocked_by_tool: dict[str, int] = {}
    prev_action_index: int | None = None
    has_action_gap = False

    for line_no, event in items:
        if event.contract_id != contract_id or event.mode != mode:
            return _inconsistent_run(
                run_id,
                f"Run '{run_id}' mixes contract_id or mode at line {line_no}",
                line=line_no,
            )

        if prev_seq is None:
            if event.sequence != 1:
                has_seq_gap = True
                seq_gaps.append((0, event.sequence))
        else:
            if event.sequence <= prev_seq:
                return _inconsistent_run(
                    run_id,
                    f"Non-increasing sequence {event.sequence} at line {line_no}",
                    line=line_no,
                )
            if event.sequence > prev_seq + 1:
                has_seq_gap = True
                seq_gaps.append((prev_seq, event.sequence))
        prev_seq = event.sequence

        if terminal is not None:
            return _inconsistent_run(
                run_id,
                f"Event after terminal {terminal} at line {line_no}",
                line=line_no,
            )

        if event.phase == "pre_execution":
            if pre_execution is not None or actions_order:
                return _inconsistent_run(
                    run_id,
                    f"Unexpected pre_execution event at line {line_no}",
                    line=line_no,
                )
            pre_execution = {
                "sequence": event.sequence,
                "decision": None,
                "violation_rules": list(event.violation_rules),
            }
            if mode == "strict" and event.violation_rules:
                terminal = "pre_abort"
            continue

        if event.phase == "post_execution":
            for act_idx in actions_order:
                entry = actions_map[act_idx]
                if (
                    entry["decision"] in ("allow", "allow_with_warning")
                    and entry["finalizer_type"] is None
                    and not _has_gap_between(seq_gaps, entry["decision_sequence"], event.sequence)
                ):
                    return _inconsistent_run(
                        run_id,
                        f"post_execution recorded while action {act_idx} lacks a finalizer without a sequence gap",
                        line=line_no,
                    )
            post_execution = {
                "sequence": event.sequence,
                "decision": None,
                "violation_rules": list(event.violation_rules),
            }
            terminal = "post_execution"
            continue

        # Runtime event
        assert event.action_index is not None and event.tool_name is not None
        act_idx = event.action_index
        if event.event_type == "decision":
            if act_idx in actions_map:
                return _inconsistent_run(
                    run_id,
                    f"Duplicate or out-of-order decision for action {act_idx} at line {line_no}",
                    line=line_no,
                )
            if prev_action_index is None:
                if act_idx != 1:
                    has_action_gap = True
            else:
                if act_idx <= prev_action_index:
                    return _inconsistent_run(
                        run_id,
                        f"Non-increasing action_index {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if act_idx > prev_action_index + 1:
                    has_action_gap = True
            if mode in ("guarded", "strict") and event.violation_rules and event.decision in ("allow", "allow_with_warning"):
                return _inconsistent_run(
                    run_id,
                    f"Decision '{event.decision}' with violations in {mode} mode at line {line_no}",
                    line=line_no,
                )
            prev_action_index = act_idx

            prior_block = last_blocked_by_tool.get(event.tool_name)
            if event.decision == "block":
                last_blocked_by_tool[event.tool_name] = act_idx

            actions_order.append(act_idx)
            actions_map[act_idx] = {
                "action_index": act_idx,
                "tool_name": event.tool_name,
                "decision": event.decision,
                "decision_sequence": event.sequence,
                "tool_event_sequence": None,
                "finalizer_type": None,
                "violation_rules": list(event.violation_rules),
                "prior_same_tool_block_action_index": prior_block,
            }
            if event.decision == "abort" or (mode == "strict" and event.violation_rules):
                terminal = "runtime_abort"
        else:
            # tool_completed or tool_error
            if act_idx in actions_map:
                entry = actions_map[act_idx]
                if entry["finalizer_type"] is not None:
                    return _inconsistent_run(
                        run_id,
                        f"Duplicate tool event for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if entry["tool_name"] != event.tool_name:
                    return _inconsistent_run(
                        run_id,
                        f"Tool name mismatch for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if entry["decision"] in ("block", "abort"):
                    return _inconsistent_run(
                        run_id,
                        f"Tool event recorded after {entry['decision']} at line {line_no}",
                        line=line_no,
                    )
                entry["tool_event_sequence"] = event.sequence
                entry["finalizer_type"] = event.event_type
                if event.event_type == "tool_error":
                    terminal = "tool_error"
            else:
                if prev_action_index is not None and act_idx <= prev_action_index:
                    return _inconsistent_run(
                        run_id,
                        f"Non-increasing action_index {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if actions_order:
                    prev_entry = actions_map[actions_order[-1]]
                    lower_bound = (
                        prev_entry["tool_event_sequence"]
                        if prev_entry["tool_event_sequence"] is not None
                        else prev_entry["decision_sequence"]
                    )
                elif pre_execution is not None:
                    lower_bound = pre_execution["sequence"]
                else:
                    lower_bound = 0
                if not _has_gap_between(seq_gaps, lower_bound, event.sequence):
                    return _inconsistent_run(
                        run_id,
                        f"Tool event without prior decision for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if (prev_action_index is None and act_idx != 1) or (
                    prev_action_index is not None and act_idx > prev_action_index + 1
                ):
                    has_action_gap = True
                prev_action_index = act_idx
                actions_order.append(act_idx)
                actions_map[act_idx] = {
                    "action_index": act_idx,
                    "tool_name": event.tool_name,
                    "decision": None,
                    "decision_sequence": None,
                    "tool_event_sequence": event.sequence,
                    "finalizer_type": event.event_type,
                    "violation_rules": None,
                    "prior_same_tool_block_action_index": None,
                }
                if event.event_type == "tool_error":
                    terminal = "tool_error"

    actions: list[dict[str, Any]] = []
    counts = {outcome: 0 for outcome in TOOL_OUTCOMES}
    tool_events_for_run: dict[int, str] = {}
    for act_idx in actions_order:
        raw = actions_map[act_idx]
        tool_outcome, effect_evidence = _classify_outcome(raw["decision"], raw["finalizer_type"])
        counts[tool_outcome] += 1
        if raw["finalizer_type"] is not None:
            tool_events_for_run[act_idx] = raw["finalizer_type"]
        actions.append({
            "action_index": raw["action_index"],
            "tool_name": raw["tool_name"],
            "decision": raw["decision"],
            "decision_sequence": raw["decision_sequence"],
            "tool_event_sequence": raw["tool_event_sequence"],
            "violation_rules": raw["violation_rules"],
            "prior_same_tool_block_action_index": raw["prior_same_tool_block_action_index"],
            "tool_outcome": tool_outcome,
            "effect_evidence": effect_evidence,
        })

    is_complete = (
        pre_execution is not None
        and not has_seq_gap
        and not has_action_gap
        and counts["unfinalized"] == 0
        and counts["unknown"] == 0
        and terminal is not None
    )
    trace_integrity = "complete" if is_complete else "partial"
    diagnostics: list[dict[str, Any]] = []
    if not is_complete:
        diagnostics.append(
            _diag(
                "partial_log",
                f"Run '{run_id}' has incomplete trace evidence",
                run_id=run_id,
            )
        )

    return (
        {
            "run_id": run_id,
            "contract_id": contract_id,
            "mode": mode,
            "trace_integrity": trace_integrity,
            "terminal": terminal,
            "pre_execution": pre_execution,
            "post_execution": post_execution,
            "actions": actions,
            "counts": counts,
        },
        diagnostics,
        tool_events_for_run,
    )


def analyze_log_file(
    log_path: str | Path,
    *,
    run_id: str | None = None,
) -> tuple[int, dict[str, Any], dict[tuple[str, int], str]]:
    path = Path(log_path)
    grouped: dict[str, list[tuple[int, RunEvent]]] = defaultdict(list)

    try:
        with path.open("r", encoding="utf-8") as source:
            for line_no, raw_line in enumerate(source, start=1):
                if not raw_line.strip():
                    continue
                try:
                    event = RunEvent.model_validate_json(raw_line)
                except (ValidationError, ValueError):
                    return (
                        EXIT_INVALID_OR_INCONSISTENT,
                        _explain_result(
                            log_path,
                            "invalid_log",
                            diagnostics=[
                                _diag("invalid_event", f"Invalid RunEvent at line {line_no}", line=line_no)
                            ],
                        ),
                        {},
                    )
                grouped[event.run_id].append((line_no, event))
    except OSError as error:
        message = "Log file not found" if isinstance(error, FileNotFoundError) else "Cannot read log file"
        return (
            EXIT_IO_OR_USAGE,
            _explain_result(
                log_path,
                "io_error",
                diagnostics=[_diag("io_error", message)],
            ),
            {},
        )
    except UnicodeError:
        return (
            EXIT_INVALID_OR_INCONSISTENT,
            _explain_result(
                log_path,
                "invalid_log",
                diagnostics=[_diag("invalid_event", "Log file is not valid UTF-8")],
            ),
            {},
        )

    if not grouped:
        return (
            EXIT_INVALID_OR_INCONSISTENT,
            _explain_result(
                log_path,
                "invalid_log",
                diagnostics=[_diag("empty_log", "Decision log contains no events")],
            ),
            {},
        )

    if run_id is not None:
        if run_id not in grouped:
            return (
                EXIT_RUN_NOT_FOUND,
                _explain_result(
                    log_path,
                    "run_not_found",
                    diagnostics=[
                        _diag("run_not_found", f"Run ID '{run_id}' not found in log", run_id=run_id)
                    ],
                ),
                {},
            )
        selected = [(run_id, grouped[run_id])]
    else:
        selected = list(grouped.items())

    runs: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    tool_events: dict[tuple[str, int], str] = {}
    has_inconsistent = False

    for selected_run_id, items in selected:
        run_summary, run_diags, run_tool_events = _analyze_run(selected_run_id, items)
        runs.append(run_summary)
        diagnostics.extend(run_diags)
        for act_idx, ev_type in run_tool_events.items():
            tool_events[(selected_run_id, act_idx)] = ev_type
        if run_summary["trace_integrity"] == "inconsistent":
            has_inconsistent = True

    if has_inconsistent:
        return (
            EXIT_INVALID_OR_INCONSISTENT,
            _explain_result(
                log_path,
                "inconsistent_log",
                data={"runs": runs},
                diagnostics=diagnostics,
            ),
            tool_events,
        )

    return (
        EXIT_OK,
        _explain_result(
            log_path,
            "ok",
            data={"runs": runs},
            diagnostics=diagnostics,
        ),
        tool_events,
    )


def explain_log_file(
    log_path: str | Path,
    *,
    run_id: str | None = None,
) -> tuple[int, dict[str, Any]]:
    code, result, _ = analyze_log_file(log_path, run_id=run_id)
    return code, result
