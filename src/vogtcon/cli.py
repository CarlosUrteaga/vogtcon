# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Local CLI for contract validation."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, Sequence

import yaml
from pydantic import ValidationError

from .contracts import _UnsupportedContractRules, load_contract
from .models import ContractRulesV2

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
        return "\n".join([
            "✓ Contract is valid",
            f"  Path:           {path}",
            f"  Contract ID:    {data['contract_id']}",
            f"  Schema Version: {data['contract_version']}",
            f"  Validation:     {phase_text}",
            f"  Fingerprint:    {fingerprint['value']} ({verification})",
            f"  Runtime Rules:  {', '.join(data['runtime_rules'])}",
            f"  Postconditions: {', '.join(data['postconditions'])}",
            f"  Declared Tools: {', '.join(data['declared_tools'])}",
        ])
    message = result["diagnostics"][0]["message"]
    if code == EXIT_UNSUPPORTED_RULES:
        return "\n".join([
            "! Contract contains rules outside default catalog",
            f"  Path: {path}",
            f"  {message}",
            "  A custom RuleCatalog must be supplied by the host application.",
        ])
    return "\n".join(["✗ Contract validation failed", f"  Path:  {path}", f"  Error: {message}"])


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

    return EXIT_USAGE_OR_IO


if __name__ == "__main__":
    sys.exit(main())
