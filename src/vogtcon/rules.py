# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Phase-aware rule catalog and historical runtime and post-execution checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict

from .models import GovernorInput, JsonObject, Phase, Violation

RuleHandler: TypeAlias = Callable[[GovernorInput], bool | Violation | None]

_VALID_PHASES: frozenset[Phase] = frozenset(
    {"pre_execution", "runtime", "post_execution"}
)


class EmptyRuleParams(BaseModel):
    """Parameter schema for v3 rule types that accept no parameters."""

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )


@dataclass(frozen=True, slots=True)
class RuleTypeSpec:
    """Typed specification for a v3 contract rule type."""

    allowed_phases: frozenset[Phase]
    params_model: type[BaseModel] = EmptyRuleParams

    def __post_init__(self) -> None:
        if (
            not isinstance(self.allowed_phases, frozenset)
            or not self.allowed_phases
            or not self.allowed_phases.issubset(_VALID_PHASES)
        ):
            raise ValueError(
                "RuleTypeSpec allowed_phases must be a non-empty frozenset of valid phases"
            )
        if not isinstance(self.params_model, type) or not issubclass(
            self.params_model, BaseModel
        ):
            raise TypeError(
                "RuleTypeSpec params_model must be a Pydantic BaseModel subclass"
            )
        cfg = self.params_model.model_config
        if (
            cfg.get("strict") is not True
            or cfg.get("extra") != "forbid"
            or cfg.get("frozen") is not True
            or cfg.get("allow_inf_nan") is not False
        ):
            raise ValueError(
                "RuleTypeSpec params_model must set strict=True, extra='forbid', "
                "frozen=True, allow_inf_nan=False"
            )

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

DEFAULT_RULE_TYPES: Mapping[str, RuleTypeSpec] = MappingProxyType({
    "tool.declared_only": RuleTypeSpec(
        allowed_phases=frozenset({"runtime"}),
        params_model=EmptyRuleParams,
    ),
    "response.schema_complete": RuleTypeSpec(
        allowed_phases=frozenset({"post_execution"}),
        params_model=EmptyRuleParams,
    ),
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
        rule_types: Mapping[str, RuleTypeSpec] | None = None,
    ) -> None:
        custom_runtime = dict(runtime_rules or {})
        custom_post = dict(postconditions or {})
        custom_rule_types = dict(rule_types or {})
        for configured, builtins in (
            (custom_runtime, DEFAULT_RUNTIME_RULES),
            (custom_post, DEFAULT_POSTCONDITIONS),
        ):
            for rule_id, handler in configured.items():
                if rule_id in builtins and handler is not builtins[rule_id]:
                    raise ValueError(f"Cannot replace built-in rule '{rule_id}'")
        historical_builtins = set(DEFAULT_RUNTIME_RULES) | set(DEFAULT_POSTCONDITIONS)
        for rule_type, spec in custom_rule_types.items():
            if not isinstance(rule_type, str) or not rule_type:
                raise ValueError("Rule type identifier must be a non-empty string")
            if not isinstance(spec, RuleTypeSpec):
                raise TypeError(
                    f"Rule type '{rule_type}' specification must be a RuleTypeSpec"
                )
            if (
                rule_type in DEFAULT_RULE_TYPES
                and spec != DEFAULT_RULE_TYPES[rule_type]
            ):
                raise ValueError(f"Cannot replace built-in rule type '{rule_type}'")
            if (
                rule_type in historical_builtins
                and rule_type not in DEFAULT_RULE_TYPES
            ):
                raise ValueError(
                    f"Cannot shadow historical built-in rule '{rule_type}' as a v3 rule type"
                )
        self._runtime_rules = {**DEFAULT_RUNTIME_RULES, **custom_runtime}
        self._postconditions = {**DEFAULT_POSTCONDITIONS, **custom_post}
        self._rule_types = {**DEFAULT_RULE_TYPES, **custom_rule_types}

    @property
    def runtime_rules(self) -> dict[str, RuleHandler]:
        return dict(self._runtime_rules)

    @property
    def postconditions(self) -> dict[str, RuleHandler]:
        return dict(self._postconditions)

    @property
    def rule_types(self) -> dict[str, RuleTypeSpec]:
        return dict(self._rule_types)

    def validate_rule_params(self, rule_type: str, params: JsonObject) -> BaseModel:
        spec = self._rule_types[rule_type]
        return spec.params_model.model_validate(params)

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
