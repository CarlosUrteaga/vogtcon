# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Load contract data without changing its historical identity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from .models import (
    AgentContract,
    ContractDocument,
    ContractRulesV2,
    ContractRulesV3,
    ContractSchema,
    _canonical_sha256,
)
from .rules import DEFAULT_RULE_CATALOG, POSTCONDITIONS, RUNTIME_RULES, RuleCatalog

_PHASES = {"pre_execution", "runtime", "post_execution"}


class _UnsupportedContractRules(ValueError):
    def __init__(self, field: str, unknown: set[str]) -> None:
        self.field = field
        self.ids = sorted(unknown)
        super().__init__(f"Unsupported {field}: {', '.join(self.ids)}")


def validate_contract_rules(
    contract: ContractSchema,
    rule_catalog: RuleCatalog | None = None,
) -> None:
    """Resolve the supported vocabulary, including for direct evaluator calls.

    Enforced contracts must enable all checkpoints. This is a configuration
    requirement of this loader, not a change to the underlying data schema.
    """
    catalog = rule_catalog if rule_catalog is not None else DEFAULT_RULE_CATALOG
    if isinstance(contract, ContractRulesV3):
        unknown = {binding.rule_type for binding in contract.rules} - set(
            catalog.rule_types
        )
        if unknown:
            raise _UnsupportedContractRules("rules", unknown)
        for binding in contract.rules:
            spec = catalog.rule_types[binding.rule_type]
            if not set(binding.phases).issubset(spec.allowed_phases):
                raise ValueError(
                    f"Rule instance '{binding.instance_id}' declares unsupported "
                    f"phase(s) for rule_type '{binding.rule_type}'"
                )
        for binding in contract.rules:
            try:
                catalog.validate_rule_params(binding.rule_type, binding.params)
            except ValidationError:
                raise ValueError(
                    f"Invalid parameters for rule instance '{binding.instance_id}' "
                    f"(rule_type '{binding.rule_type}')"
                ) from None
        if set(contract.validation_phases) != _PHASES:
            raise ValueError("Enforced contracts require all three validation phases")
        return

    for name, supported in (
        ("runtime_rules", catalog.runtime_rules),
        ("postconditions", catalog.postconditions),
    ):
        unknown = set(getattr(contract, name)) - set(supported)
        if unknown:
            raise _UnsupportedContractRules(name, unknown)
    if (isinstance(contract, ContractRulesV2) or contract.mode != "no_contract") and (
        contract.validation_phases == "not_enforced"
        or set(contract.validation_phases) != _PHASES
    ):
        raise ValueError("Enforced contracts require all three validation phases")


def compute_v3_contract_fingerprint(
    contract: ContractRulesV3,
    rule_catalog: RuleCatalog | None = None,
) -> str:
    """Compute the canonical sha256 fingerprint over a v3 contract's effective form."""
    if not isinstance(contract, ContractRulesV3):
        raise TypeError("Expected a ContractRulesV3 instance")
    catalog = rule_catalog if rule_catalog is not None else DEFAULT_RULE_CATALOG
    validate_contract_rules(contract, rule_catalog=catalog)
    payload = contract.model_dump(mode="json")
    payload.pop("contract_fingerprint")
    payload["rules"] = [
        {
            "instance_id": binding.instance_id,
            "rule_type": binding.rule_type,
            "phases": list(binding.phases),
            "params": catalog.validate_rule_params(
                binding.rule_type, binding.params
            ).model_dump(mode="json"),
        }
        for binding in contract.rules
    ]
    return _canonical_sha256(payload)


def _validate_v2_fingerprint(document: ContractDocument) -> None:
    """Check parsed v2 values using the historical JSON digest convention."""
    contract = document.contract
    if not isinstance(contract, ContractRulesV2):
        return
    payload = document.original
    payload.pop("contract_fingerprint")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    if contract.contract_fingerprint != expected:
        raise ValueError("Contract fingerprint mismatch")


def _validate_v3_fingerprint(
    document: ContractDocument,
    rule_catalog: RuleCatalog | None = None,
) -> None:
    """Check a v3 contract fingerprint over its validated effective form."""
    if not isinstance(document.contract, ContractRulesV3):
        return
    expected = compute_v3_contract_fingerprint(
        document.contract, rule_catalog=rule_catalog
    )
    if document.contract.contract_fingerprint != expected:
        raise ValueError("Contract fingerprint mismatch")


def load_contract(
    path: str | Path,
    rule_catalog: RuleCatalog | None = None,
) -> ContractDocument:
    """Read a JSON or safe YAML contract and return its original and typed views.

    JSON is attempted first to retain JSON scalar semantics. YAML values must
    satisfy the same JSON-compatible Pydantic schema. V2 fingerprints are
    verified over parsed values; legacy fingerprints remain unchanged. File and
    parsing errors propagate; an invalid contract never becomes an allow decision.
    Pass the same ``rule_catalog`` to :class:`Governor` for custom rule IDs.

    Example::

        document = load_contract("agent_contract.yaml", rule_catalog=catalog)
        contract = document.contract
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Contract document must contain an object")
    document = ContractDocument(data)
    validate_contract_rules(document.contract, rule_catalog=rule_catalog)
    _validate_v2_fingerprint(document)
    _validate_v3_fingerprint(document, rule_catalog=rule_catalog)
    return document
