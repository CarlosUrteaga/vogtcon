# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Trace parsing and correlation for ``vogtcon explain``."""

from __future__ import annotations

import heapq
from bisect import bisect_left
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .records import RecordedEvent, RunEventV2, parse_run_event

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


def _can_allocate_distinct_slots(
    seq_gaps: list[tuple[int, int]],
    demands: list[tuple[int, int]],
) -> bool:
    if not demands:
        return True
    if any(lo > hi for lo, hi in demands):
        return False
    ordered = sorted(demands)
    active: list[int] = []
    d_idx = 0
    n_demands = len(ordered)
    for gap_start, gap_end_excl in seq_gaps:
        slot = gap_start + 1
        gap_end = gap_end_excl - 1
        while slot <= gap_end:
            while d_idx < n_demands and ordered[d_idx][0] <= slot:
                heapq.heappush(active, ordered[d_idx][1])
                d_idx += 1
            if not active:
                if d_idx >= n_demands:
                    return True
                next_start = ordered[d_idx][0]
                if next_start > gap_end:
                    break
                slot = next_start
                continue
            if active[0] < slot:
                return False
            heapq.heappop(active)
            slot += 1
    return d_idx == n_demands and not active


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
    items: list[tuple[int, RecordedEvent]],
    *,
    known_effects_across_runs: dict[str, dict[str, Any]] | None = None,
    file_reconciled_lines: dict[str, list[tuple[str, int]]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[int, str]]:
    has_v1 = any(not isinstance(ev, RunEventV2) for _, ev in items)
    has_v2 = any(isinstance(ev, RunEventV2) for _, ev in items)
    if has_v1 and has_v2:
        first_is_v2 = isinstance(items[0][1], RunEventV2)
        first_mix_line = next(
            line_no
            for line_no, ev in items
            if isinstance(ev, RunEventV2) != first_is_v2
        )
        return _inconsistent_run(
            run_id,
            f"Run '{run_id}' mixes schema_version 1 and 2 at line {first_mix_line}",
            line=first_mix_line,
        )
    if has_v2:
        return _analyze_run_v2(
            run_id,
            [(line_no, ev) for line_no, ev in items if isinstance(ev, RunEventV2)],
            known_effects_across_runs=known_effects_across_runs or {},
            file_reconciled_lines=file_reconciled_lines or {},
        )

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
    missing_decision_demands: list[tuple[int, int, int]] = []

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
            slot_demands = [(lo, hi) for lo, hi, _ in missing_decision_demands]
            for act_idx in actions_order:
                entry = actions_map[act_idx]
                if entry["decision"] in ("allow", "allow_with_warning") and entry["finalizer_type"] is None:
                    slot_demands.append((entry["decision_sequence"] + 1, event.sequence - 1))
            if slot_demands and not _can_allocate_distinct_slots(seq_gaps, slot_demands):
                return _inconsistent_run(
                    run_id,
                    "Insufficient distinct sequence slots for missing events before post_execution",
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
                missing_decision_demands.append((lower_bound + 1, event.sequence - 1, line_no))
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

    if (
        post_execution is None
        and len(missing_decision_demands) > 1
        and not _can_allocate_distinct_slots(seq_gaps, [(lo, hi) for lo, hi, _ in missing_decision_demands])
    ):
        return _inconsistent_run(
            run_id,
            "Insufficient distinct sequence slots for missing decisions",
            line=missing_decision_demands[-1][2],
        )

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


def _analyze_run_v2(
    run_id: str,
    items: list[tuple[int, RunEventV2]],
    *,
    known_effects_across_runs: dict[str, dict[str, Any]],
    file_reconciled_lines: dict[str, list[tuple[str, int]]],
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
    missing_decision_demands: list[tuple[int, int, int]] = []

    effects_by_id: dict[str, dict[str, Any]] = {}
    observed_effect_ids: set[str] = set()
    reconciled_in_run: set[str] = set()
    compensated_effect_ids: set[str] = set()
    reconciliations: list[dict[str, Any]] = []
    compensations: list[dict[str, Any]] = []

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
            if pre_execution is not None or actions_order or reconciliations or compensations:
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
            slot_demands = [(lo, hi) for lo, hi, _ in missing_decision_demands]
            for act_idx in actions_order:
                entry = actions_map[act_idx]
                if entry["decision"] in ("allow", "allow_with_warning"):
                    if entry["finalizer_type"] is None:
                        slot_demands.append((entry["decision_sequence"] + 1, event.sequence - 1))
                        if entry["observation_sequence"] is None:
                            slot_demands.append((entry["decision_sequence"] + 1, event.sequence - 1))
                    elif entry["observation_sequence"] is None:
                        slot_demands.append((entry["tool_event_sequence"] + 1, event.sequence - 1))
                elif entry["finalizer_type"] is not None and entry["observation_sequence"] is None:
                    slot_demands.append((entry["tool_event_sequence"] + 1, event.sequence - 1))
            if slot_demands and not _can_allocate_distinct_slots(seq_gaps, slot_demands):
                return _inconsistent_run(
                    run_id,
                    "Insufficient distinct sequence slots for missing events before post_execution",
                    line=line_no,
                )
            post_execution = {
                "sequence": event.sequence,
                "decision": None,
                "violation_rules": list(event.violation_rules),
            }
            terminal = "post_execution"
            continue

        # Pre-action_index dispatch for reconciliation and compensation events
        if event.event_type == "effect_reconciled":
            assert event.effect_id is not None and event.effect_status is not None
            eff_id = event.effect_id
            if eff_id in reconciled_in_run or any(
                prev_line < line_no
                for _, prev_line in file_reconciled_lines.get(eff_id, ())
            ):
                return _inconsistent_run(
                    run_id,
                    f"Duplicate effect_reconciled for effect '{eff_id}' at line {line_no}",
                    line=line_no,
                )
            if eff_id in effects_by_id:
                eff_info = effects_by_id[eff_id]
                if eff_info["observed_status"] != "uncertain":
                    return _inconsistent_run(
                        run_id,
                        f"Cannot reconcile non-uncertain effect '{eff_id}' at line {line_no}",
                        line=line_no,
                    )
                if (
                    eff_info.get("approval_id") is not None
                    and event.approval_id is not None
                    and eff_info["approval_id"] != event.approval_id
                ):
                    return _inconsistent_run(
                        run_id,
                        f"Approval ID mismatch on effect_reconciled for effect '{eff_id}' at line {line_no}",
                        line=line_no,
                    )
                eff_info["reconciled_status"] = event.effect_status
                eff_info["reconciliation_sequence"] = event.sequence
                eff_info["reconciliation_evidence_ref"] = event.evidence_ref
                act_entry = actions_map[eff_info["action_index"]]
                act_entry["effect_status"] = event.effect_status
                act_entry["reconciled"] = True
                act_entry["reconciliation_sequence"] = event.sequence
                act_entry["reconciliation_evidence_ref"] = event.evidence_ref
                if act_entry["approval_id"] is None and event.approval_id is not None:
                    act_entry["approval_id"] = event.approval_id
                    eff_info["approval_id"] = event.approval_id
                resolved_approval_id = (
                    event.approval_id
                    if event.approval_id is not None
                    else eff_info.get("approval_id")
                )
            else:
                cross_info = known_effects_across_runs.get(eff_id)
                if cross_info is not None:
                    if cross_info.get("observed_status") != "uncertain":
                        return _inconsistent_run(
                            run_id,
                            f"Cannot reconcile non-uncertain effect '{eff_id}' at line {line_no}",
                            line=line_no,
                        )
                    if (
                        cross_info.get("approval_id") is not None
                        and event.approval_id is not None
                        and cross_info["approval_id"] != event.approval_id
                    ):
                        return _inconsistent_run(
                            run_id,
                            f"Approval ID mismatch on effect_reconciled for effect '{eff_id}' at line {line_no}",
                            line=line_no,
                        )
                resolved_approval_id = (
                    event.approval_id
                    if event.approval_id is not None
                    else (
                        cross_info.get("approval_id")
                        if cross_info is not None
                        else None
                    )
                )
            reconciled_in_run.add(eff_id)
            rec_out: dict[str, Any] = {
                "effect_id": eff_id,
                "effect_status": event.effect_status,
                "sequence": event.sequence,
                "policy_scope": event.policy_scope,
                "evidence_ref": event.evidence_ref,
            }
            if resolved_approval_id is not None:
                rec_out["approval_id"] = resolved_approval_id
            reconciliations.append(rec_out)
            continue

        if event.event_type == "effect_compensated":
            assert (
                event.effect_id is not None
                and event.compensates_effect_id is not None
                and event.tool_name is not None
            )
            eff_id = event.effect_id
            if eff_id == event.compensates_effect_id:
                return _inconsistent_run(
                    run_id,
                    f"Effect '{eff_id}' cannot compensate itself at line {line_no}",
                    line=line_no,
                )
            if eff_id in compensated_effect_ids:
                return _inconsistent_run(
                    run_id,
                    f"Duplicate effect_compensated for effect '{eff_id}' at line {line_no}",
                    line=line_no,
                )
            compensated_effect_ids.add(eff_id)
            compensations.append({
                "effect_id": eff_id,
                "compensates_effect_id": event.compensates_effect_id,
                "tool_name": event.tool_name,
                "sequence": event.sequence,
                "policy_scope": event.policy_scope,
                "evidence_ref": event.evidence_ref,
            })
            continue

        # Runtime action-bound events (decision, tool_completed, tool_error, effect_observed)
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
            if (
                mode in ("guarded", "strict")
                and event.violation_rules
                and event.decision in ("allow", "allow_with_warning")
            ):
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
                "effect_id": event.effect_id,
                "policy_scope": event.policy_scope,
                "operation_digest": event.operation_digest,
                "effect_status": event.effect_status,
                "approval_id": event.approval_id,
                "observed_status": None,
                "observation_sequence": None,
                "observation_evidence_ref": None,
                "reconciled": False,
                "reconciliation_sequence": None,
                "reconciliation_evidence_ref": None,
            }
            if event.effect_id is not None:
                effects_by_id[event.effect_id] = {
                    "action_index": act_idx,
                    "policy_scope": event.policy_scope,
                    "operation_digest": event.operation_digest,
                    "approval_id": event.approval_id,
                    "observed_status": None,
                    "reconciled_status": None,
                }
            if event.decision == "abort" or (mode == "strict" and event.violation_rules):
                terminal = "runtime_abort"
        elif event.event_type in ("tool_completed", "tool_error"):
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
                if (
                    entry["effect_id"] is not None
                    and event.effect_id is not None
                    and entry["effect_id"] != event.effect_id
                ):
                    return _inconsistent_run(
                        run_id,
                        f"Effect ID mismatch for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if entry["effect_id"] is None and event.effect_id is not None:
                    entry["effect_id"] = event.effect_id
                if entry["policy_scope"] is None and event.policy_scope is not None:
                    entry["policy_scope"] = event.policy_scope
                entry["tool_event_sequence"] = event.sequence
                entry["finalizer_type"] = event.event_type
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
                        prev_entry["observation_sequence"]
                        or prev_entry["tool_event_sequence"]
                        or prev_entry["decision_sequence"]
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
                missing_decision_demands.append((lower_bound + 1, event.sequence - 1, line_no))
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
                    "effect_id": event.effect_id,
                    "policy_scope": event.policy_scope,
                    "operation_digest": event.operation_digest,
                    "effect_status": None,
                    "approval_id": None,
                    "observed_status": None,
                    "observation_sequence": None,
                    "observation_evidence_ref": None,
                    "reconciled": False,
                    "reconciliation_sequence": None,
                    "reconciliation_evidence_ref": None,
                }
        elif event.event_type == "effect_observed":
            assert event.effect_id is not None and event.effect_status is not None
            eff_id = event.effect_id
            if eff_id in observed_effect_ids:
                return _inconsistent_run(
                    run_id,
                    f"Duplicate effect_observed for effect '{eff_id}' at line {line_no}",
                    line=line_no,
                )
            if act_idx in actions_map:
                entry = actions_map[act_idx]
                if entry["observation_sequence"] is not None:
                    return _inconsistent_run(
                        run_id,
                        f"Duplicate effect_observed for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if entry["tool_name"] != event.tool_name:
                    return _inconsistent_run(
                        run_id,
                        f"Tool name mismatch on effect_observed for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if entry["decision"] in ("block", "abort"):
                    return _inconsistent_run(
                        run_id,
                        f"effect_observed recorded after {entry['decision']} at line {line_no}",
                        line=line_no,
                    )
                if entry["effect_id"] is not None and entry["effect_id"] != eff_id:
                    return _inconsistent_run(
                        run_id,
                        f"Effect ID mismatch on effect_observed for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if (
                    entry["approval_id"] is not None
                    and event.approval_id is not None
                    and entry["approval_id"] != event.approval_id
                ):
                    return _inconsistent_run(
                        run_id,
                        f"Approval ID mismatch on effect_observed for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                entry["effect_id"] = eff_id
                entry["policy_scope"] = event.policy_scope
                entry["operation_digest"] = event.operation_digest
                if entry["approval_id"] is None and event.approval_id is not None:
                    entry["approval_id"] = event.approval_id
                entry["observed_status"] = event.effect_status
                entry["effect_status"] = event.effect_status
                entry["observation_sequence"] = event.sequence
                entry["observation_evidence_ref"] = event.evidence_ref
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
                        prev_entry["observation_sequence"]
                        or prev_entry["tool_event_sequence"]
                        or prev_entry["decision_sequence"]
                    )
                elif pre_execution is not None:
                    lower_bound = pre_execution["sequence"]
                else:
                    lower_bound = 0
                if not _has_gap_between(seq_gaps, lower_bound, event.sequence):
                    return _inconsistent_run(
                        run_id,
                        f"effect_observed without prior decision for action {act_idx} at line {line_no}",
                        line=line_no,
                    )
                if (prev_action_index is None and act_idx != 1) or (
                    prev_action_index is not None and act_idx > prev_action_index + 1
                ):
                    has_action_gap = True
                missing_decision_demands.append((lower_bound + 1, event.sequence - 1, line_no))
                prev_action_index = act_idx
                actions_order.append(act_idx)
                actions_map[act_idx] = {
                    "action_index": act_idx,
                    "tool_name": event.tool_name,
                    "decision": None,
                    "decision_sequence": None,
                    "tool_event_sequence": None,
                    "finalizer_type": None,
                    "violation_rules": None,
                    "prior_same_tool_block_action_index": None,
                    "effect_id": eff_id,
                    "policy_scope": event.policy_scope,
                    "operation_digest": event.operation_digest,
                    "effect_status": event.effect_status,
                    "approval_id": event.approval_id,
                    "observed_status": event.effect_status,
                    "observation_sequence": event.sequence,
                    "observation_evidence_ref": event.evidence_ref,
                    "reconciled": False,
                    "reconciliation_sequence": None,
                    "reconciliation_evidence_ref": None,
                }
            observed_effect_ids.add(eff_id)
            effects_by_id[eff_id] = {
                "action_index": act_idx,
                "policy_scope": event.policy_scope,
                "operation_digest": event.operation_digest,
                "approval_id": actions_map[act_idx]["approval_id"],
                "observed_status": event.effect_status,
                "reconciled_status": None,
            }

    if (
        post_execution is None
        and len(missing_decision_demands) > 1
        and not _can_allocate_distinct_slots(
            seq_gaps, [(lo, hi) for lo, hi, _ in missing_decision_demands]
        )
    ):
        return _inconsistent_run(
            run_id,
            "Insufficient distinct sequence slots for missing decisions",
            line=missing_decision_demands[-1][2],
        )

    if terminal is None and items[-1][1].event_type == "tool_error":
        terminal = "tool_error"

    actions: list[dict[str, Any]] = []
    counts = {outcome: 0 for outcome in TOOL_OUTCOMES}
    tool_events_for_run: dict[int, str] = {}
    has_missing_v2_observation = False
    for act_idx in actions_order:
        raw = actions_map[act_idx]
        tool_outcome, effect_evidence = _classify_outcome(
            raw["decision"], raw["finalizer_type"]
        )
        if raw["reconciled"]:
            effect_evidence = (
                "confirmed_by_reconciliation"
                if raw["effect_status"] == "confirmed"
                else "confirmed_absent_by_reconciliation"
            )
        elif raw["observed_status"] is not None:
            if raw["observed_status"] == "confirmed":
                effect_evidence = "confirmed_by_host_observation"
            elif raw["observed_status"] == "confirmed_absent":
                effect_evidence = "confirmed_absent_by_host"
            else:
                effect_evidence = "indeterminate"
        elif raw["finalizer_type"] is not None:
            effect_evidence = "indeterminate"
            has_missing_v2_observation = True

        counts[tool_outcome] += 1
        if raw["finalizer_type"] is not None:
            tool_events_for_run[act_idx] = raw["finalizer_type"]

        action_out: dict[str, Any] = {
            "action_index": raw["action_index"],
            "tool_name": raw["tool_name"],
            "decision": raw["decision"],
            "decision_sequence": raw["decision_sequence"],
            "tool_event_sequence": raw["tool_event_sequence"],
            "violation_rules": raw["violation_rules"],
            "prior_same_tool_block_action_index": raw["prior_same_tool_block_action_index"],
            "tool_outcome": tool_outcome,
            "effect_evidence": effect_evidence,
            "effect_id": raw["effect_id"],
            "policy_scope": raw["policy_scope"],
            "effect_status": raw["effect_status"],
            "observation_sequence": raw["observation_sequence"],
        }
        if raw["approval_id"] is not None:
            action_out["approval_id"] = raw["approval_id"]
        if raw["reconciliation_sequence"] is not None:
            action_out["reconciliation_sequence"] = raw["reconciliation_sequence"]
            action_out["reconciliation_evidence_ref"] = raw["reconciliation_evidence_ref"]
        actions.append(action_out)

    is_complete = (
        pre_execution is not None
        and not has_seq_gap
        and not has_action_gap
        and not has_missing_v2_observation
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
            "reconciliations": reconciliations,
            "compensations": compensations,
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
    grouped: dict[str, list[tuple[int, RecordedEvent]]] = defaultdict(list)
    known_effects_across_runs: dict[str, dict[str, Any]] = {}
    file_reconciled_lines: dict[str, list[tuple[str, int]]] = defaultdict(list)

    try:
        with path.open("r", encoding="utf-8") as source:
            for line_no, raw_line in enumerate(source, start=1):
                if not raw_line.strip():
                    continue
                try:
                    event = parse_run_event(raw_line)
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
                if isinstance(event, RunEventV2):
                    if (
                        event.event_type in ("decision", "effect_observed")
                        and event.effect_id is not None
                    ):
                        info = known_effects_across_runs.setdefault(
                            event.effect_id,
                            {
                                "run_id": event.run_id,
                                "observed_status": None,
                                "policy_scope": event.policy_scope,
                                "approval_id": event.approval_id,
                            },
                        )
                        if event.event_type == "effect_observed":
                            info["observed_status"] = event.effect_status
                        if (
                            info.get("approval_id") is None
                            and event.approval_id is not None
                        ):
                            info["approval_id"] = event.approval_id
                    elif event.event_type == "effect_reconciled" and event.effect_id is not None:
                        file_reconciled_lines[event.effect_id].append((event.run_id, line_no))
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
        run_summary, run_diags, run_tool_events = _analyze_run(
            selected_run_id,
            items,
            known_effects_across_runs=known_effects_across_runs,
            file_reconciled_lines=file_reconciled_lines,
        )
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
