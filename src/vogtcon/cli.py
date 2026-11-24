# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""CLI local for contract validation and execution trace explanation."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from importlib import metadata
from pathlib import Path
from typing import Any, Sequence

import yaml

from .contracts import _validate_v2_fingerprint, load_contract, validate_contract_rules
from .models import AgentContract, ContractDocument, ContractRulesV2
from .records import RunEvent
from .rules import DEFAULT_RULE_CATALOG

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_UNSUPPORTED_RULES = 2
EXIT_USAGE_OR_IO = 3

EXIT_EXPLAIN_SUCCESS = 0
EXIT_EXPLAIN_INVALID_LOG = 1
EXIT_EXPLAIN_RUN_NOT_FOUND = 2
EXIT_EXPLAIN_USAGE_OR_IO = 3


def get_version() -> str:
    try:
        return metadata.version("vogtcon")
    except Exception:
        return "0.1.0"


# =============================================================================
# Subcommand: validate
# =============================================================================

def validate_contract_file(
    contract_path: str | Path,
) -> tuple[int, dict[str, Any]]:
    path = Path(contract_path)
    if not path.is_file():
        return EXIT_USAGE_OR_IO, {
            "status": "error",
            "path": str(path),
            "errors": [f"Contract file not found or inaccessible: {path}"],
        }

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return EXIT_USAGE_OR_IO, {
            "status": "error",
            "path": str(path),
            "errors": [f"Cannot read contract file: {exc}"],
        }

    try:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = yaml.safe_load(text)
    except Exception as exc:
        return EXIT_INVALID, {
            "status": "invalid",
            "path": str(path),
            "errors": [f"Failed to parse contract (invalid JSON/YAML): {exc}"],
        }

    if not isinstance(data, dict):
        return EXIT_INVALID, {
            "status": "invalid",
            "path": str(path),
            "errors": ["Contract document must contain an object"],
        }

    try:
        document = ContractDocument(data)
    except Exception as exc:
        return EXIT_INVALID, {
            "status": "invalid",
            "path": str(path),
            "errors": [f"Contract schema validation error: {exc}"],
        }

    contract = document.contract
    schema_version = 2 if isinstance(contract, ContractRulesV2) else 1
    contract_id = contract.contract_id
    mode = getattr(contract, "mode", None)
    phases = list(contract.validation_phases) if contract.validation_phases != "not_enforced" else []
    declared_tools = list(contract.declared_tools)
    fingerprint_val = contract.contract_fingerprint

    # Verify 3 validation phases
    if contract.validation_phases == "not_enforced" or set(contract.validation_phases) != {"pre_execution", "runtime", "post_execution"}:
        return EXIT_INVALID, {
            "status": "invalid",
            "path": str(path),
            "contract_id": contract_id,
            "schema_version": schema_version,
            "errors": ["Enforced contracts require all three validation phases (pre_execution, runtime, post_execution)"],
        }

    # Verify v2 fingerprint
    fingerprint_verified = False
    expected_fingerprint = fingerprint_val
    if isinstance(contract, ContractRulesV2):
        try:
            _validate_v2_fingerprint(document)
            fingerprint_verified = True
        except ValueError as exc:
            return EXIT_INVALID, {
                "status": "invalid",
                "path": str(path),
                "contract_id": contract_id,
                "schema_version": schema_version,
                "fingerprint": {
                    "value": fingerprint_val,
                    "verified": False,
                },
                "errors": [str(exc)],
            }
    else:
        # v1 fingerprint is not a sha256 hash digest of the document
        fingerprint_verified = True

    # Check rule catalog
    unsupported_runtime = sorted(set(contract.runtime_rules) - set(DEFAULT_RULE_CATALOG.runtime_rules))
    unsupported_post = sorted(set(contract.postconditions) - set(DEFAULT_RULE_CATALOG.postconditions))

    result_data: dict[str, Any] = {
        "status": "valid",
        "path": str(path),
        "contract_id": contract_id,
        "schema_version": schema_version,
        "mode": mode,
        "phases": phases,
        "fingerprint": {
            "value": fingerprint_val,
            "verified": fingerprint_verified,
            "expected": expected_fingerprint,
        },
        "declared_tools": declared_tools,
        "rules": {
            "runtime": list(contract.runtime_rules),
            "postconditions": list(contract.postconditions),
            "unsupported_runtime": unsupported_runtime,
            "unsupported_postconditions": unsupported_post,
        },
        "errors": [],
    }

    if unsupported_runtime or unsupported_post:
        result_data["status"] = "unsupported_rules"
        err_msg = []
        if unsupported_runtime:
            err_msg.append(f"Unsupported runtime_rules: {', '.join(unsupported_runtime)}")
        if unsupported_post:
            err_msg.append(f"Unsupported postconditions: {', '.join(unsupported_post)}")
        result_data["errors"] = err_msg
        return EXIT_UNSUPPORTED_RULES, result_data

    return EXIT_VALID, result_data


def render_validate_text(code: int, result: dict[str, Any]) -> str:
    path = result.get("path", "")
    if code == EXIT_VALID:
        lines = [
            "✓ Contract is valid",
            f"  Path:           {path}",
            f"  Contract ID:    {result.get('contract_id')}",
            f"  Schema Version: {result.get('schema_version')}",
            f"  Validation:     all 3 phases enforced ({', '.join(result.get('phases', []))})",
        ]
        fp = result.get("fingerprint", {})
        fp_str = fp.get("value", "none")
        if fp.get("verified"):
            fp_str += " (verified)"
        lines.append(f"  Fingerprint:    {fp_str}")
        rules = result.get("rules", {})
        lines.append(f"  Runtime Rules:  {', '.join(rules.get('runtime', []))}")
        lines.append(f"  Postconditions: {', '.join(rules.get('postconditions', []))}")
        lines.append(f"  Declared Tools: {', '.join(result.get('declared_tools', []))}")
        return "\n".join(lines)
    elif code == EXIT_UNSUPPORTED_RULES:
        rules = result.get("rules", {})
        unsupported = rules.get("unsupported_runtime", []) + rules.get("unsupported_postconditions", [])
        lines = [
            "! Contract contains rules outside default catalog",
            f"  Path:              {path}",
            f"  Contract ID:       {result.get('contract_id')}",
            f"  Schema Version:    {result.get('schema_version')}",
            f"  Unsupported Rules: {', '.join(unsupported)}",
            "  Note:              A custom RuleCatalog must be supplied by the host application.",
        ]
        return "\n".join(lines)
    else:
        errors = result.get("errors", ["Unknown validation error"])
        lines = [
            "✗ Contract validation failed",
            f"  Path:  {path}",
        ]
        for err in errors:
            lines.append(f"  Error: {err}")
        return "\n".join(lines)


# =============================================================================
# Subcommand: explain
# =============================================================================

def explain_log_file(
    log_path: str | Path,
    target_run_id: str | None = None,
) -> tuple[int, dict[str, Any]]:
    path = Path(log_path)
    if not path.is_file():
        return EXIT_EXPLAIN_USAGE_OR_IO, {
            "status": "error",
            "log_path": str(path),
            "errors": [f"Log file not found or inaccessible: {path}"],
        }

    events: list[RunEvent] = []
    try:
        with path.open("r", encoding="utf-8") as source:
            for line_idx, line in enumerate(source, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    event = RunEvent.model_validate_json(clean_line)
                    events.append(event)
                except Exception as exc:
                    return EXIT_EXPLAIN_INVALID_LOG, {
                        "status": "invalid_log_format",
                        "log_path": str(path),
                        "errors": [
                            f"Line {line_idx}: Invalid RunEvent schema: not a vogtcon decision log ({exc})"
                        ],
                    }
    except Exception as exc:
        return EXIT_EXPLAIN_USAGE_OR_IO, {
            "status": "error",
            "log_path": str(path),
            "errors": [f"Error reading log file: {exc}"],
        }

    # Group by run_id
    runs_by_id: dict[str, list[RunEvent]] = defaultdict(list)
    for event in events:
        runs_by_id[event.run_id].append(event)

    if target_run_id is not None:
        if target_run_id not in runs_by_id:
            return EXIT_EXPLAIN_RUN_NOT_FOUND, {
                "status": "run_not_found",
                "log_path": str(path),
                "errors": [f"Run ID '{target_run_id}' not found in log file"],
            }
        run_ids = [target_run_id]
    else:
        run_ids = list(runs_by_id.keys())

    analyzed_runs: list[dict[str, Any]] = []

    for r_id in run_ids:
        r_events = runs_by_id[r_id]
        r_events.sort(key=lambda e: e.sequence)

        # Check sequence continuity
        expected_seq = 1
        seq_broken = False
        for ev in r_events:
            if ev.sequence != expected_seq:
                seq_broken = True
                break
            expected_seq += 1

        contract_id = r_events[0].contract_id if r_events else "unknown"
        mode = r_events[0].mode if r_events else "unknown"

        # Separate phases
        pre_event = next((e for e in r_events if e.phase == "pre_execution"), None)
        post_event = next((e for e in r_events if e.phase == "post_execution"), None)

        runtime_events = [e for e in r_events if e.phase == "runtime"]

        # Group runtime events by action_index
        actions_by_index: dict[int, list[RunEvent]] = defaultdict(list)
        for e in runtime_events:
            if e.action_index is not None:
                actions_by_index[e.action_index].append(e)

        action_records: list[dict[str, Any]] = []
        blocked_tools: set[str] = set()

        blocked_count = 0
        allowed_count = 0
        retried_count = 0
        completed_invocations = 0
        error_invocations = 0
        unfinalized_invocations = 0
        all_violation_rules: list[str] = []

        for act_idx in sorted(actions_by_index.keys()):
            act_events = actions_by_index[act_idx]
            dec_event = next((e for e in act_events if e.event_type == "decision"), None)
            tool_event = next((e for e in act_events if e.event_type in ("tool_completed", "tool_error")), None)

            tool_name = dec_event.tool_name if dec_event else (tool_event.tool_name if tool_event else "unknown")
            decision = dec_event.decision if dec_event else None
            violations = list(dec_event.violation_rules) if dec_event else []
            all_violation_rules.extend(violations)

            # Detect retry
            is_retry = tool_name in blocked_tools

            # Tool outcome
            if decision in ("block", "abort"):
                tool_outcome = "prevented"
                blocked_count += 1
                blocked_tools.add(tool_name)
            elif decision in ("allow", "allow_with_warning"):
                allowed_count += 1
                if is_retry:
                    retried_count += 1
                if tool_event is not None:
                    if tool_event.event_type == "tool_completed":
                        tool_outcome = "completed"
                        completed_invocations += 1
                    else:
                        tool_outcome = "error"
                        error_invocations += 1
                else:
                    tool_outcome = "unfinalized"
                    unfinalized_invocations += 1
            else:
                # No prior decision or unknown
                tool_outcome = "unknown"

            trace_id = dec_event.trace_id if dec_event else (tool_event.trace_id if tool_event else None)
            span_id = dec_event.span_id if dec_event else (tool_event.span_id if tool_event else None)

            action_records.append({
                "action_index": act_idx,
                "tool_name": tool_name,
                "decision": decision,
                "violations": violations,
                "tool_outcome": tool_outcome,
                "is_retry": is_retry,
                "trace_id": trace_id,
                "span_id": span_id,
            })

        # Pre/post violations
        pre_violations = list(pre_event.violation_rules) if pre_event else []
        post_violations = list(post_event.violation_rules) if post_event else []
        all_violation_rules.extend(pre_violations)
        all_violation_rules.extend(post_violations)

        # Trace integrity
        if seq_broken:
            integrity = "inconsistent"
        elif pre_event is None or post_event is None or unfinalized_invocations > 0:
            integrity = "partial"
        else:
            integrity = "complete"

        analyzed_runs.append({
            "run_id": r_id,
            "contract_id": contract_id,
            "mode": mode,
            "trace_integrity": integrity,
            "events_count": len(r_events),
            "pre_execution": {
                "present": pre_event is not None,
                "decision": pre_event.decision if pre_event else ("allow" if not pre_violations else "block"),
                "violations": pre_violations,
            },
            "actions": action_records,
            "post_execution": {
                "present": post_event is not None,
                "decision": post_event.decision if post_event else ("allow" if not post_violations else "block"),
                "violations": post_violations,
            },
            "summary": {
                "total_actions": len(action_records),
                "blocked_actions": blocked_count,
                "allowed_actions": allowed_count,
                "retried_actions": retried_count,
                "completed_invocations": completed_invocations,
                "error_invocations": error_invocations,
                "unfinalized_invocations": unfinalized_invocations,
                "violation_rules": sorted(set(all_violation_rules)),
                "external_effect_status": "indeterminate_without_host_evidence",
            },
        })

    return EXIT_EXPLAIN_SUCCESS, {
        "status": "ok",
        "log_path": str(path),
        "runs": analyzed_runs,
        "errors": [],
    }


def render_explain_text(code: int, result: dict[str, Any]) -> str:
    if code != EXIT_EXPLAIN_SUCCESS:
        errors = result.get("errors", ["Unknown explain error"])
        lines = ["✗ Failed to explain log file", f"  Path: {result.get('log_path', '')}"]
        for err in errors:
            lines.append(f"  Error: {err}")
        return "\n".join(lines)

    runs = result.get("runs", [])
    if not runs:
        return f"Log file contains no runs: {result.get('log_path', '')}"

    blocks: list[str] = []
    divider = "=" * 80

    for run in runs:
        r_id = run.get("run_id")
        cid = run.get("contract_id")
        mode = run.get("mode")
        count = run.get("events_count")
        integrity = run.get("trace_integrity")

        lines = [
            divider,
            f"Run ID:    {r_id}",
            f"Contract:  {cid} | Mode: {mode} | Events: {count} | Integrity: {integrity}",
            divider,
            "",
            "Lifecycle:",
        ]

        pre = run.get("pre_execution", {})
        if pre.get("present"):
            v = pre.get("violations", [])
            v_str = f"({len(v)} violations)" if v else "(0 violations)"
            lines.append(f"  PRE-EXECUTION   Result: {pre.get('decision')} {v_str}")
        else:
            lines.append("  PRE-EXECUTION   [MISSING]")

        for act in run.get("actions", []):
            idx = act.get("action_index")
            tool = act.get("tool_name")
            dec = act.get("decision", "").upper()
            retry_tag = " [RETRY]" if act.get("is_retry") else ""
            lines.append(f"  RUNTIME (act {idx}) {tool}{retry_tag}")
            lines.append(f"          Decision: {dec}")
            if act.get("violations"):
                lines.append(f"          Violations: {', '.join(act.get('violations', []))}")
            outcome = act.get("tool_outcome")
            if outcome == "prevented":
                lines.append("          Tool:     prevented (execution not started)")
            elif outcome == "completed":
                lines.append("          Tool:     tool_completed (execution completed)")
            elif outcome == "error":
                lines.append("          Tool:     tool_error (execution failed with error)")
            elif outcome == "unfinalized":
                lines.append("          Tool:     UNFINALIZED (no tool_completed or tool_error recorded)")
            else:
                lines.append(f"          Tool:     {outcome}")

        post = run.get("post_execution", {})
        if post.get("present"):
            v = post.get("violations", [])
            v_str = f"({len(v)} violations)" if v else "(0 violations)"
            lines.append(f"  POST-EXECUTION  Result: {post.get('decision')} {v_str}")
        else:
            lines.append("  POST-EXECUTION  [MISSING]")

        lines.append("")
        s = run.get("summary", {})
        lines.append("Summary:")
        lines.append(f"  Proposed Actions:       {s.get('total_actions')}")
        lines.append(f"  Blocked Actions:        {s.get('blocked_actions')}")
        lines.append(f"  Allowed Actions:        {s.get('allowed_actions')}")
        lines.append(f"  Retried Actions:        {s.get('retried_actions')}")
        lines.append(f"  Tool Invocations:       {s.get('completed_invocations')} completed, {s.get('error_invocations')} errors, {s.get('unfinalized_invocations')} unfinalized")
        lines.append(f"  Trace Integrity:        {integrity}")

        if integrity == "partial":
            lines.append("  Host Effect Notice:     ! INDETERMINATE: Trace is partial or tool unfinalized. External effect cannot be verified.")
        else:
            lines.append("  Host Effect Notice:     tool callable finished; external delivery requires host-side evidence.")

        lines.append(divider)
        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


# =============================================================================
# Main Entrypoint
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vogtcon",
        description="Deterministic contracts and runtime governance CLI.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # validate
    validate_p = subparsers.add_parser(
        "validate",
        help="Validate a contract document (v1 or v2).",
    )
    validate_p.add_argument(
        "contract_path",
        help="Path to the contract YAML or JSON file.",
    )
    validate_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output structured JSON to stdout.",
    )

    # explain
    explain_p = subparsers.add_parser(
        "explain",
        help="Explain a vogtcon decision log (JSONL).",
    )
    explain_p.add_argument(
        "log_path",
        help="Path to the RunEvent JSONL file.",
    )
    explain_p.add_argument(
        "--run-id",
        dest="run_id",
        default=None,
        help="Filter and explain a specific run_id.",
    )
    explain_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output structured JSON to stdout.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE_OR_IO

    if args.command == "validate":
        code, result = validate_contract_file(args.contract_path)
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            out = render_validate_text(code, result)
            if code == EXIT_VALID:
                print(out)
            else:
                print(out, file=sys.stderr)
        return code

    elif args.command == "explain":
        code, result = explain_log_file(args.log_path, target_run_id=args.run_id)
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            out = render_explain_text(code, result)
            if code == EXIT_EXPLAIN_SUCCESS:
                print(out)
            else:
                print(out, file=sys.stderr)
        return code

    return EXIT_USAGE_OR_IO


if __name__ == "__main__":
    sys.exit(main())
