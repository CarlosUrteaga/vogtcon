# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Phase-aware rule catalog and historical runtime and post-execution checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .models import (
    ContractRulesV3,
    FrozenJsonObject,
    GovernorInput,
    JsonObject,
    NonEmptyString,
    Phase,
    RuleBinding,
    Violation,
    _FrozenUniqueStrTupleField,
    _parse_utc_timestamp,
    _thaw_json_value,
)

RuleHandler: TypeAlias = Callable[[GovernorInput], bool | Violation | None]
V3RuleHandler: TypeAlias = Callable[
    [GovernorInput, BaseModel], bool | Violation | None
]

_VALID_PHASES: frozenset[Phase] = frozenset(
    {"pre_execution", "runtime", "post_execution"}
)


class EmptyRuleParams(BaseModel):
    """Parameter schema for v3 rule types that accept no parameters."""

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )


class BoundApprovalParams(BaseModel):
    """Parameter schema for the ``approval.bound_required`` v3 rule type."""

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )

    tools: _FrozenUniqueStrTupleField = Field(min_length=1)
    required_authorities: _FrozenUniqueStrTupleField = Field(min_length=1)
    authority_match: Literal["any", "all"] = "any"
    sensitivity_fact_key: NonEmptyString | None = None
    allow_self_approval: bool = False
    require_single_use: bool = True
    allow_retry_after_confirmed_absent: bool = False

    @model_validator(mode="after")
    def check_non_empty_tuples(self) -> Self:
        if not self.tools:
            raise ValueError("BoundApprovalParams tools must be non-empty")
        if not self.required_authorities:
            raise ValueError(
                "BoundApprovalParams required_authorities must be non-empty"
            )
        return self

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            merged = self.model_dump()
            merged.update(update)
            return type(self).model_validate(merged)
        return self.__copy__()


class DestinationAllowlistParams(BaseModel):
    """Parameter schema for the ``destination.allowlist`` v3 rule type."""

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )

    tools: _FrozenUniqueStrTupleField = Field(min_length=1)
    allowed_destinations: _FrozenUniqueStrTupleField = Field(min_length=1)
    destination_param: NonEmptyString = "destination"
    source: Literal["planned_effect", "host_facts"] = "planned_effect"

    @model_validator(mode="after")
    def check_non_empty_tuples(self) -> Self:
        if not self.tools:
            raise ValueError("DestinationAllowlistParams tools must be non-empty")
        if not self.allowed_destinations:
            raise ValueError(
                "DestinationAllowlistParams allowed_destinations must be non-empty"
            )
        return self

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            merged = self.model_dump()
            merged.update(update)
            return type(self).model_validate(merged)
        return self.__copy__()


class RetrievedEvidenceParams(BaseModel):
    """Parameter schema for the ``evidence.retrieved_required`` v3 rule type.

    Verifies only that host-verified retrieved evidence references satisfy
    count, source, digest, and optional claim-subset checks.
    Retrieval does NOT prove semantic relevance or accuracy.
    """

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )

    tools: _FrozenUniqueStrTupleField = Field(min_length=1)
    min_count: Annotated[int, Field(ge=1)] = 1
    allowed_sources: _FrozenUniqueStrTupleField | None = None
    require_content_digest: bool = False
    claim_param: NonEmptyString | None = None

    @model_validator(mode="after")
    def check_non_empty_tuples(self) -> Self:
        if not self.tools:
            raise ValueError("RetrievedEvidenceParams tools must be non-empty")
        if self.allowed_sources is not None and not self.allowed_sources:
            raise ValueError(
                "RetrievedEvidenceParams allowed_sources must be non-empty when specified"
            )
        return self

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            merged = self.model_dump()
            merged.update(update)
            return type(self).model_validate(merged)
        return self.__copy__()


@dataclass(frozen=True, slots=True)
class RuleTypeSpec:
    """Typed specification for a v3 contract rule type."""

    allowed_phases: frozenset[Phase]
    params_model: type[BaseModel] = EmptyRuleParams
    handler: V3RuleHandler | None = None

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
        if self.handler is not None and not callable(self.handler):
            raise TypeError("RuleTypeSpec handler must be callable or None")

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


def _check_v3_tool_declared_only(
    request: GovernorInput, _params: BaseModel
) -> bool:
    assert request.action is not None
    tool = (
        request.planned_effect.tool_name
        if request.planned_effect is not None
        else request.action.tool_name
    )
    return (
        tool not in request.context.available_tools
        or tool not in request.contract.declared_tools
    )


def _check_v3_response_schema_complete(
    request: GovernorInput, _params: BaseModel
) -> bool:
    assert request.response is not None
    return any(
        key not in request.response
        for key in request.contract.response_schema.required_fields
    )


def _check_v3_bound_approval(
    request: GovernorInput, params: BaseModel
) -> bool:
    assert isinstance(params, BoundApprovalParams)
    if request.planned_effect is None:
        return True
    if request.planned_effect.tool_name not in params.tools:
        return False
    if params.sensitivity_fact_key is not None:
        if (
            request.host_facts is None
            or params.sensitivity_fact_key not in request.host_facts.facts
        ):
            return True
        raw_sensitive = request.host_facts.facts[params.sensitivity_fact_key]
        if type(raw_sensitive) is not bool:
            return True
        if raw_sensitive is False:
            return False

    if (
        request.approval is None
        or request.requester_id is None
        or request.policy_scope is None
        or request.evaluated_at is None
    ):
        return True

    approval = request.approval
    if approval.status != "active":
        return True
    if approval.operation_digest != request.planned_effect.operation_digest():
        return True
    if approval.requester_id != request.requester_id:
        return True
    if approval.policy_scope != request.policy_scope:
        return True
    if (
        not params.allow_self_approval
        and approval.approver_id == request.requester_id
    ):
        return True

    held = set(approval.approver_authorities)
    required = set(params.required_authorities)
    if params.authority_match == "all":
        if not required.issubset(held):
            return True
    else:
        if not (held & required):
            return True

    eval_dt = _parse_utc_timestamp(request.evaluated_at)
    issued_dt = _parse_utc_timestamp(approval.issued_at)
    expires_dt = _parse_utc_timestamp(approval.expires_at)
    if not (issued_dt <= eval_dt < expires_dt):
        return True

    if params.require_single_use:
        if (
            not approval.single_use
            or request.trajectory is None
            or request.trajectory.policy_scope != request.policy_scope
        ):
            return True
        usage = request.trajectory.approval_by_id(approval.approval_id)
        if usage is not None:
            if (
                usage.operation_digest != approval.operation_digest
                or usage.policy_scope != approval.policy_scope
                or not usage.single_use
            ):
                return True
            if usage.status in ("reserved", "consumed", "locked_uncertain"):
                return True
            if (
                usage.status == "released_absent"
                and not params.allow_retry_after_confirmed_absent
            ):
                return True

    return False


def _check_v3_destination_allowlist(
    request: GovernorInput, params: BaseModel
) -> bool:
    assert isinstance(params, DestinationAllowlistParams)
    if request.planned_effect is None:
        return True
    if request.planned_effect.tool_name not in params.tools:
        return False
    if params.source == "planned_effect":
        dest = request.planned_effect.effective_parameters.get(
            params.destination_param
        )
    else:
        if request.host_facts is None:
            return True
        dest = request.host_facts.facts.get(params.destination_param)
    if (
        type(dest) is not str
        or not dest
        or dest not in params.allowed_destinations
    ):
        return True
    return False


def _check_v3_evidence_retrieved_required(
    request: GovernorInput, params: BaseModel
) -> bool:
    """Verify host-retrieved evidence provenance, count, digest, and claimed subset.

    Retrieval verification does NOT prove semantic relevance or accuracy.
    """
    assert isinstance(params, RetrievedEvidenceParams)
    if request.planned_effect is None:
        return True
    if request.planned_effect.tool_name not in params.tools:
        return False
    if request.retrieved_evidence is None:
        return True
    verified_ids = {
        item.evidence_id
        for item in request.retrieved_evidence
        if (
            params.allowed_sources is None
            or item.source in params.allowed_sources
        )
        and (
            not params.require_content_digest
            or item.content_digest is not None
        )
    }
    if len(verified_ids) < params.min_count:
        return True
    if params.claim_param is not None:
        claimed = request.planned_effect.effective_parameters.get(
            params.claim_param
        )
        if not isinstance(claimed, list) or any(
            type(item) is not str or not item for item in claimed
        ):
            return True
        claimed_set = set(claimed)
        if len(claimed_set) < params.min_count or not claimed_set.issubset(
            verified_ids
        ):
            return True
    return False


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
        handler=_check_v3_tool_declared_only,
    ),
    "response.schema_complete": RuleTypeSpec(
        allowed_phases=frozenset({"post_execution"}),
        params_model=EmptyRuleParams,
        handler=_check_v3_response_schema_complete,
    ),
    "approval.bound_required": RuleTypeSpec(
        allowed_phases=frozenset({"runtime"}),
        params_model=BoundApprovalParams,
        handler=_check_v3_bound_approval,
    ),
    "destination.allowlist": RuleTypeSpec(
        allowed_phases=frozenset({"runtime"}),
        params_model=DestinationAllowlistParams,
        handler=_check_v3_destination_allowlist,
    ),
    "evidence.retrieved_required": RuleTypeSpec(
        allowed_phases=frozenset({"runtime"}),
        params_model=RetrievedEvidenceParams,
        handler=_check_v3_evidence_retrieved_required,
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

    def validate_rule_params(
        self, rule_type: str, params: JsonObject | FrozenJsonObject
    ) -> BaseModel:
        spec = self._rule_types[rule_type]
        return spec.params_model.model_validate(_thaw_json_value(params))

    def validate_v3_handlers(self, contract: ContractRulesV3) -> None:
        if not isinstance(contract, ContractRulesV3):
            raise TypeError("Expected a ContractRulesV3 instance")
        for binding in contract.rules:
            spec = self._rule_types.get(binding.rule_type)
            if spec is None:
                raise ValueError(f"Unknown rule type '{binding.rule_type}'")
            if spec.handler is None:
                raise ValueError(
                    f"Rule type '{binding.rule_type}' has no evaluation handler configured"
                )

    def _coerce_v3_violation(
        self,
        binding: RuleBinding,
        result: bool | Violation | None,
        expected_phase: Phase,
        expected_action: str | None,
    ) -> Violation | None:
        if result is None or result is False:
            return None
        if result is True:
            return Violation(
                rule=binding.instance_id,
                rule_type=binding.rule_type,
                phase=expected_phase,
                action=expected_action,
            )
        if isinstance(result, Violation):
            if result.rule != binding.instance_id:
                raise ValueError(
                    f"Rule '{binding.instance_id}' produced violation for '{result.rule}'"
                )
            if result.phase != expected_phase:
                raise ValueError(
                    f"Rule '{binding.instance_id}' produced violation with phase '{result.phase}', "
                    f"expected '{expected_phase}'"
                )
            if result.action != expected_action:
                raise ValueError(
                    f"Rule '{binding.instance_id}' produced violation for action '{result.action}', "
                    f"expected '{expected_action}'"
                )
            if result.rule_type is None:
                return result.model_copy(update={"rule_type": binding.rule_type})
            if result.rule_type != binding.rule_type:
                raise ValueError(
                    f"Rule '{binding.instance_id}' produced violation with rule_type "
                    f"'{result.rule_type}', expected '{binding.rule_type}'"
                )
            return result
        raise ValueError(
            f"Rule '{binding.instance_id}' returned invalid output of type "
            f"'{type(result).__name__}'; expected bool, Violation, or None"
        )

    def evaluate_v3(self, request: GovernorInput) -> list[Violation]:
        if not isinstance(request.contract, ContractRulesV3):
            raise TypeError("evaluate_v3 requires a ContractRulesV3 contract")
        self.validate_v3_handlers(request.contract)
        expected_action: str | None = None
        if request.phase == "runtime":
            assert request.action is not None
            expected_action = (
                request.planned_effect.tool_name
                if request.planned_effect is not None
                else request.action.tool_name
            )
        elif request.phase == "post_execution":
            assert request.response is not None
        violations: list[Violation] = []
        for binding in request.contract.rules:
            if request.phase not in binding.phases:
                continue
            spec = self._rule_types[binding.rule_type]
            assert spec.handler is not None
            try:
                params = self.validate_rule_params(binding.rule_type, binding.params)
            except ValidationError:
                raise ValueError(
                    f"Invalid parameters for rule instance '{binding.instance_id}' "
                    f"(rule_type '{binding.rule_type}')"
                ) from None
            result = spec.handler(request, params)
            violation = self._coerce_v3_violation(
                binding, result, request.phase, expected_action
            )
            if violation is not None:
                violations.append(violation)
                if (
                    request.phase == "runtime"
                    and binding.rule_type == "tool.declared_only"
                ):
                    break
        return violations

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
