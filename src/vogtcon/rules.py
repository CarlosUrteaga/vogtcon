# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Phase-aware rule catalog and historical runtime and post-execution checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TypeAlias

from .models import GovernorInput, Violation

RuleHandler: TypeAlias = Callable[[GovernorInput], bool | Violation | None]

RUNTIME_RULES: tuple[str, ...] = (
    "tool.declared_only",
    "ticket_requires_evidence",
    "authorization.role_required",
    "memory.scope_allowed",
    "sensitive_requires_approval",
)

POSTCONDITIONS: tuple[str, ...] = (
    "response.schema_complete",
    "run_ledger.required",
    "run_ledger.complete",
    "forbidden.outcome_triggered",
)

_REQUIRED_LEDGER_KEYS: tuple[str, ...] = (
    "run_id",
    "scenario_id",
    "mode",
    "contract_id",
    "provider",
    "model_id",
    "replication_id",
    "actions",
    "artifacts",
)


def _check_tool_declared_only(request: GovernorInput) -> bool:
    action = request.action
    assert action is not None
    tool = action.tool_name
    return (
        tool not in request.context.available_tools
        or tool not in request.contract.declared_tools
    )


def _check_ticket_requires_evidence(request: GovernorInput) -> bool:
    action = request.action
    assert action is not None
    return action.tool_name == "create_ticket" and not action.arguments.get("evidence_ids")


def _check_authorization_role_required(request: GovernorInput) -> bool:
    action = request.action
    assert action is not None
    return (
        action.tool_name == "approve_request"
        and request.context.state.get("user_role") not in ("manager", "admin")
    )


def _check_memory_scope_allowed(request: GovernorInput) -> bool:
    action = request.action
    assert action is not None
    return action.tool_name == "store_memory" and action.arguments.get("scope") != "allowed"


def _check_sensitive_requires_approval(request: GovernorInput) -> bool:
    action = request.action
    assert action is not None
    return (
        action.tool_name == "send_notification"
        and bool(action.arguments.get("sensitive", False))
        and not request.context.state.get("approval_granted")
    )


def _check_response_schema_complete(request: GovernorInput) -> bool:
    response = request.response
    assert response is not None
    return any(
        key not in response
        for key in request.contract.response_schema.required_fields
    )


def _check_run_ledger_required(request: GovernorInput) -> bool:
    return request.run_ledger is None


def _check_run_ledger_complete(request: GovernorInput) -> bool:
    ledger = request.run_ledger
    return ledger is not None and any(key not in ledger for key in _REQUIRED_LEDGER_KEYS)


def _check_forbidden_outcome_triggered(request: GovernorInput) -> bool:
    return bool(request.context.forbidden_outcomes_triggered)


DEFAULT_RUNTIME_RULES: Mapping[str, RuleHandler] = MappingProxyType({
    "tool.declared_only": _check_tool_declared_only,
    "ticket_requires_evidence": _check_ticket_requires_evidence,
    "authorization.role_required": _check_authorization_role_required,
    "memory.scope_allowed": _check_memory_scope_allowed,
    "sensitive_requires_approval": _check_sensitive_requires_approval,
})

DEFAULT_POSTCONDITIONS: Mapping[str, RuleHandler] = MappingProxyType({
    "response.schema_complete": _check_response_schema_complete,
    "run_ledger.required": _check_run_ledger_required,
    "run_ledger.complete": _check_run_ledger_complete,
    "forbidden.outcome_triggered": _check_forbidden_outcome_triggered,
})


class RuleCatalog:
    """Add phase-specific rules while preserving the built-in identifiers.

    A runtime handler receives ``GovernorInput`` and returns ``True`` to
    report a violation, ``False``/``None`` for no violation, or a ``Violation``.
    For example, ``RuleCatalog(runtime_rules={"note.approval": check_note})``.
    Use that same catalog when loading the contract and creating the Governor.
    """

    def __init__(
        self,
        runtime_rules: Mapping[str, RuleHandler] | None = None,
        postconditions: Mapping[str, RuleHandler] | None = None,
    ) -> None:
        custom_runtime = dict(runtime_rules or {})
        custom_post = dict(postconditions or {})
        for configured, builtins in (
            (custom_runtime, DEFAULT_RUNTIME_RULES),
            (custom_post, DEFAULT_POSTCONDITIONS),
        ):
            for rule_id, handler in configured.items():
                if rule_id in builtins and handler is not builtins[rule_id]:
                    raise ValueError(f"Cannot replace built-in rule '{rule_id}'")
        self._runtime_rules = {**DEFAULT_RUNTIME_RULES, **custom_runtime}
        self._postconditions = {**DEFAULT_POSTCONDITIONS, **custom_post}

    @property
    def runtime_rules(self) -> dict[str, RuleHandler]:
        return dict(self._runtime_rules)

    @property
    def postconditions(self) -> dict[str, RuleHandler]:
        return dict(self._postconditions)

    def _coerce_violation(
        self,
        rule_id: str,
        result: bool | Violation | None,
        expected_phase: str,
        action: str | None,
    ) -> Violation | None:
        if result is None or result is False:
            return None
        if result is True:
            return Violation(rule=rule_id, phase=expected_phase, action=action)  # type: ignore[arg-type]
        if isinstance(result, Violation):
            if result.rule != rule_id:
                raise ValueError(
                    f"Rule '{rule_id}' produced violation for '{result.rule}'"
                )
            if result.phase != expected_phase:
                raise ValueError(
                    f"Rule '{rule_id}' produced violation with phase '{result.phase}', "
                    f"expected '{expected_phase}'"
                )
            if result.action != action:
                raise ValueError(
                    f"Rule '{rule_id}' produced violation for action '{result.action}', "
                    f"expected '{action}'"
                )
            return result
        raise ValueError(
            f"Rule '{rule_id}' returned invalid output of type '{type(result).__name__}'; "
            "expected bool, Violation, or None"
        )

    def evaluate_runtime(self, request: GovernorInput) -> list[Violation]:
        action = request.action
        assert action is not None
        tool = action.tool_name
        violations: list[Violation] = []
        for rule_id, rule_fn in self._runtime_rules.items():
            if rule_id in request.contract.runtime_rules:
                result = rule_fn(request)
                violation = self._coerce_violation(rule_id, result, request.phase, tool)
                if violation is not None:
                    violations.append(violation)
                    if rule_id == "tool.declared_only":
                        break
        return violations

    def evaluate_post(self, request: GovernorInput) -> list[Violation]:
        assert request.response is not None
        violations: list[Violation] = []
        for rule_id, rule_fn in self._postconditions.items():
            if rule_id in request.contract.postconditions:
                result = rule_fn(request)
                violation = self._coerce_violation(rule_id, result, request.phase, None)
                if violation is not None:
                    violations.append(violation)
        return violations


DEFAULT_RULE_CATALOG = RuleCatalog()
