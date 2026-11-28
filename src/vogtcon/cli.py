# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Local CLI for contract validation and decision trace explanation."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from importlib import metadata
from pathlib import Path
from typing import Any, Sequence

import yaml
from pydantic import ValidationError

from .cli_trace import analyze_log_file
from .contracts import _UnsupportedContractRules, load_contract
from .models import ContractRulesV2, ContractRulesV3

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_UNSUPPORTED_RULES = 2
EXIT_USAGE_OR_IO = 3


def get_version() -> str:
    return metadata.version("vogtcon")


def _validation_result(
    path: str | Path,
    status: str,
    *,
    data: dict[str, Any] | None = None,
    diagnostic: tuple[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "output_version": 1,
        "command": "validate",
        "status": status,
        "path": str(path),
        "data": data,
        "diagnostics": [] if diagnostic is None else [{
            "code": diagnostic[0], "message": diagnostic[1], "line": None, "run_id": None,
        }],
    }


def validate_contract_file(contract_path: str | Path) -> tuple[int, dict[str, Any]]:
    try:
        contract = load_contract(contract_path).contract
    except _UnsupportedContractRules as error:
        return EXIT_UNSUPPORTED_RULES, _validation_result(
            contract_path, "unsupported_rules",
            data={"field": error.field, "unsupported_ids": error.ids},
            diagnostic=("unsupported_rule", str(error)),
        )
    except (OSError, UnicodeError) as error:
        message = "Contract file not found" if isinstance(error, FileNotFoundError) else "Cannot read contract file"
        return EXIT_USAGE_OR_IO, _validation_result(
            contract_path, "io_error", diagnostic=("io_error", message),
        )
    except (ValueError, TypeError, RecursionError, yaml.YAMLError) as error:
        if isinstance(error, ValidationError):
            message = "Contract does not match the expected schema"
        elif isinstance(error, yaml.YAMLError):
            message = "Contract is not valid JSON or YAML"
        elif isinstance(error, ValueError):
            message = str(error)
        else:
            message = "Contract contains values that cannot be represented as JSON"
        return EXIT_INVALID, _validation_result(
            contract_path, "invalid_contract", diagnostic=("invalid_contract", message),
        )

    if isinstance(contract, ContractRulesV3):
        return EXIT_VALID, _validation_result(contract_path, "valid", data={
            "contract_id": contract.contract_id,
            "contract_version": 3,
            "mode": None,
            "validation_phases": list(contract.validation_phases),
            "fingerprint": {"value": contract.contract_fingerprint, "verified": True},
            "declared_tools": list(contract.declared_tools),
            "runtime_rules": [
                binding.rule_type
                for binding in contract.rules
                if "runtime" in binding.phases
            ],
            "postconditions": [
                binding.rule_type
                for binding in contract.rules
                if "post_execution" in binding.phases
            ],
            "rules": [
                {
                    "instance_id": binding.instance_id,
                    "rule_type": binding.rule_type,
                    "phases": list(binding.phases),
                }
                for binding in contract.rules
            ],
        })

    is_v2 = isinstance(contract, ContractRulesV2)
    return EXIT_VALID, _validation_result(contract_path, "valid", data={
        "contract_id": contract.contract_id,
        "contract_version": 2 if is_v2 else 1,
        "mode": None if is_v2 else contract.mode,
        "validation_phases": contract.validation_phases,
        "fingerprint": {"value": contract.contract_fingerprint, "verified": is_v2},
        "declared_tools": contract.declared_tools,
        "runtime_rules": contract.runtime_rules,
        "postconditions": contract.postconditions,
    })


def render_validate_text(code: int, result: dict[str, Any]) -> str:
    path = result["path"]
    if code == EXIT_VALID:
        data = result["data"]
        phases = data["validation_phases"]
        phase_text = ", ".join(phases) if isinstance(phases, list) else phases
        fingerprint = data["fingerprint"]
        verification = "verified" if fingerprint["verified"] else "not verified"
        lines = [
            "✓ Contract is valid",
            f"  Path:           {path}",
            f"  Contract ID:    {data['contract_id']}",
            f"  Schema Version: {data['contract_version']}",
            f"  Validation:     {phase_text}",
            f"  Fingerprint:    {fingerprint['value']} ({verification})",
            f"  Runtime Rules:  {', '.join(data['runtime_rules'])}",
            f"  Postconditions: {', '.join(data['postconditions'])}",
            f"  Declared Tools: {', '.join(data['declared_tools'])}",
        ]
        if "rules" in data:
            bindings = ", ".join(
                f"{item['instance_id']} ({item['rule_type']})"
                for item in data["rules"]
            )
            lines.append(f"  Rule Bindings:  {bindings}")
        return "\n".join(lines)
    message = result["diagnostics"][0]["message"]
    if code == EXIT_UNSUPPORTED_RULES:
        return "\n".join([
            "! Contract contains rules outside default catalog",
            f"  Path: {path}",
            f"  {message}",
            "  A custom RuleCatalog must be supplied by the host application.",
        ])
    return "\n".join(["✗ Contract validation failed", f"  Path:  {path}", f"  Error: {message}"])


def _format_violations(violations: list[str] | None) -> str:
    if violations is None:
        return "violations unknown"
    if not violations:
        return "0 violations"
    return f"violations: {', '.join(violations)}"


def render_explain_text(
    code: int,
    result: dict[str, Any],
    *,
    tool_events: dict[tuple[str, int], str] | None = None,
) -> str:
    path = result["path"]
    data = result.get("data")
    diagnostics = result.get("diagnostics", [])

    if data is None or not data.get("runs"):
        message = diagnostics[0]["message"] if diagnostics else "Unknown log error"
        return "\n".join([
            "✗ Decision log explanation failed",
            f"  Path:  {path}",
            f"  Error: {message}",
        ])

    diags_by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for diag in diagnostics:
        diag_run_id = diag.get("run_id")
        if diag_run_id is not None:
            diags_by_run[diag_run_id].append(diag)

    sections: list[str] = []
    for run in data["runs"]:
        run_id = run["run_id"]
        if run["trace_integrity"] == "inconsistent":
            run_diags = diags_by_run.get(run_id, [])
            lines = [f"{run_id} · inconsistent"]
            for diag in run_diags:
                loc = f"line {diag['line']}: " if diag.get("line") is not None else ""
                lines.append(f"  ! {loc}{diag['message']}")
            sections.append("\n".join(lines))
            continue

        lines = [f"{run_id} · {run['mode']} · {run['contract_id']}"]
        pre = run["pre_execution"]
        if pre is not None:
            lines.append(f"  {pre['sequence']}  pre_execution     {_format_violations(pre['violation_rules'])}")
        else:
            lines.append("  -  pre_execution     missing")

        rendered_reconciled_ids: set[str] = set()
        for act in run["actions"]:
            idx = act["action_index"]
            tool = act["tool_name"]
            if act["decision"] is not None:
                v_str = ", ".join(act["violation_rules"]) if act["violation_rules"] else "0 violations"
                prior_idx = act["prior_same_tool_block_action_index"]
                prior_note = f" (prior same-tool block at action {prior_idx})" if prior_idx is not None else ""
                approval_note = (
                    f" [approval: {act['approval_id']}]"
                    if act.get("approval_id") is not None
                    else ""
                )
                lines.append(
                    f"  {act['decision_sequence']}  action {idx:<3}  {tool}  {act['decision']}  {v_str}{prior_note}{approval_note}"
                )
            else:
                lines.append(f"  -  action {idx:<3}  {tool}  decision missing")

            outcome = act["tool_outcome"]
            evidence = act["effect_evidence"]
            if act["tool_event_sequence"] is not None:
                has_v2_obs = act.get("observation_sequence") is not None
                if outcome == "completed":
                    ev_name = "tool_completed"
                    note = "callable returned; external delivery not verified"
                    tool_ev_evidence = "not_verified" if has_v2_obs else evidence
                elif outcome == "error":
                    ev_name = "tool_error"
                    note = "tool raised error; effect indeterminate"
                    tool_ev_evidence = "indeterminate" if has_v2_obs else evidence
                else:
                    recorded_ev = tool_events.get((run_id, idx)) if tool_events else None
                    if recorded_ev is None and run.get("terminal") == "tool_error" and act is run["actions"][-1]:
                        recorded_ev = "tool_error"
                    ev_name = recorded_ev or "tool_event"
                    if recorded_ev == "tool_completed":
                        note = "callable returned without recorded decision; effect indeterminate"
                    elif recorded_ev == "tool_error":
                        note = "tool raised error without recorded decision; effect indeterminate"
                    else:
                        note = "tool event recorded without decision; effect indeterminate"
                    tool_ev_evidence = evidence
                lines.append(
                    f"  {act['tool_event_sequence']}  action {idx:<3}  {ev_name}  {note} ({tool_ev_evidence})"
                )
            elif outcome == "prevented":
                lines.append(f"  -  action {idx:<3}  not executed ({evidence})")
            else:
                lines.append(f"  -  action {idx:<3}  tool outcome missing ({evidence})")

            if act.get("observation_sequence") is not None:
                eff_id = act.get("effect_id") or "-"
                obs_status = (
                    "uncertain"
                    if act.get("reconciliation_sequence") is not None
                    else (act.get("effect_status") or "unknown")
                )
                scope = act.get("policy_scope")
                scope_note = f" scope={scope}" if scope is not None else ""
                approval_note = (
                    f" [approval: {act['approval_id']}]"
                    if act.get("approval_id") is not None
                    else ""
                )
                obs_evidence = (
                    "indeterminate"
                    if act.get("reconciliation_sequence") is not None
                    else evidence
                )
                lines.append(
                    f"  {act['observation_sequence']}  action {idx:<3}  effect_observed  {eff_id} status={obs_status}{scope_note}{approval_note} ({obs_evidence})"
                )
            if act.get("reconciliation_sequence") is not None:
                eff_id = act.get("effect_id") or "-"
                rec_status = act.get("effect_status") or "unknown"
                ev_ref = act.get("reconciliation_evidence_ref")
                ref_note = f" ref={ev_ref}" if ev_ref is not None else ""
                rendered_reconciled_ids.add(eff_id)
                lines.append(
                    f"  {act['reconciliation_sequence']}  action {idx:<3}  effect_reconciled  {eff_id} status={rec_status}{ref_note} ({evidence})"
                )

        for rec in run.get("reconciliations") or ():
            if rec["effect_id"] not in rendered_reconciled_ids:
                scope_note = (
                    f" scope={rec['policy_scope']}"
                    if rec.get("policy_scope") is not None
                    else ""
                )
                approval_note = (
                    f" [approval: {rec['approval_id']}]"
                    if rec.get("approval_id") is not None
                    else ""
                )
                lines.append(
                    f"  {rec['sequence']}  reconcile  effect_reconciled  {rec['effect_id']} status={rec['effect_status']}{scope_note}{approval_note} ref={rec['evidence_ref']}"
                )

        for comp in run.get("compensations") or ():
            scope_note = (
                f" scope={comp['policy_scope']}"
                if comp.get("policy_scope") is not None
                else ""
            )
            lines.append(
                f"  {comp['sequence']}  compensate  effect_compensated  {comp['effect_id']} compensates={comp['compensates_effect_id']} tool={comp['tool_name']}{scope_note} ref={comp['evidence_ref']}"
            )

        post = run["post_execution"]
        if post is not None:
            lines.append(f"  {post['sequence']}  post_execution    {_format_violations(post['violation_rules'])}")

        counts = run["counts"]
        lines.append(
            f"  Integrity: {run['trace_integrity']} | Terminal: {run['terminal'] or 'none'} | "
            f"Counts: prevented={counts['prevented']}, completed={counts['completed']}, "
            f"error={counts['error']}, unfinalized={counts['unfinalized']}, unknown={counts['unknown']}"
        )
        sections.append("\n".join(lines))

    if code != 0 and diagnostics:
        diag_lines = [
            f"Error: {d['message']}"
            for d in diagnostics
            if d.get("code") == "inconsistent_log" and d.get("run_id") is None
        ]
        if diag_lines:
            sections.extend(diag_lines)

    return "\n\n".join(sections)


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

    validate_p = subparsers.add_parser(
        "validate",
        help="Validate a contract document (v1, v2, or v3).",
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

    explain_p = subparsers.add_parser(
        "explain",
        help="Explain a vogtcon decision log (JSONL).",
    )
    explain_p.add_argument(
        "log_path",
        help="Path to the RunEvent JSONL decision log.",
    )
    explain_p.add_argument(
        "--run-id",
        dest="run_id",
        default=None,
        help="Explain only the specified run_id.",
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
        return 0 if exc.code == 0 else EXIT_USAGE_OR_IO

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

    if args.command == "explain":
        code, result, tool_events = analyze_log_file(args.log_path, run_id=args.run_id)
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            out = render_explain_text(code, result, tool_events=tool_events)
            if code == 0:
                print(out)
            else:
                print(out, file=sys.stderr)
        return code

    return EXIT_USAGE_OR_IO


if __name__ == "__main__":
    sys.exit(main())
