# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Data boundaries for governance, independent of the benchmark and providers.

These schemas validate structure, not policy compliance or the truth of agent
claims. Legacy models prevent field reassignment without deep immutability,
while HostFacts and PlannedEffect store deeply immutable snapshots.
ContractDocument keeps an independent original document for identity checks;
never compute a historical fingerprint from a model_dump().
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, Self, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    PlainSerializer,
    SerializerFunctionWrapHandler,
    WrapSerializer,
    field_validator,
    model_serializer,
    model_validator,
)

Mode = Literal["no_contract", "advisory", "guarded", "strict"]
Phase = Literal["pre_execution", "runtime", "post_execution"]
Decision = Literal["allow", "allow_with_warning", "block", "abort"]
NonEmptyString = Annotated[str, Field(min_length=1)]
InstanceId = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
JsonObject = dict[str, JsonValue]
FrozenJsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | Sequence["FrozenJsonValue"]
    | Mapping[str, "FrozenJsonValue"]
)
FrozenJsonObject: TypeAlias = Mapping[str, FrozenJsonValue]

OPERATION_IDENTITY_VERSION: Final[int] = 1
OPERATION_DIGEST_EXCLUDED_METADATA: Final[tuple[str, ...]] = (
    "run_id",
    "iteration",
    "policy_mode",
    "contract_fingerprint",
    "agent_fingerprint",
    "approval_id",
    "approver_id",
    "requester_id",
    "approval_issued_at",
    "approval_expires_at",
    "approval_scope",
    "trace_id",
    "span_id",
    "host_facts",
)


def _freeze_json_value(value: object) -> FrozenJsonValue:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze_json_value(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(item) for item in value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"Unsupported JSON value type: {type(value)!r}")


def _freeze_json_object(value: JsonObject) -> FrozenJsonObject:
    frozen = _freeze_json_value(value)
    assert isinstance(frozen, Mapping)
    return frozen


def _thaw_json_value(value: object) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw_json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json_value(item) for item in value]
    return value


def _thaw_json_object(value: FrozenJsonObject) -> JsonObject:
    thawed = _thaw_json_value(value)
    assert isinstance(thawed, dict)
    return thawed


if TYPE_CHECKING:
    _FrozenJsonObjectField: TypeAlias = FrozenJsonObject
    _FrozenPhaseTupleField: TypeAlias = tuple[Phase, ...]
    _FrozenRulePhasesField: TypeAlias = tuple[Phase, ...]
    _FrozenNonEmptyStrTupleField: TypeAlias = tuple[NonEmptyString, ...]
else:
    _FrozenJsonObjectField = Annotated[
        JsonObject,
        AfterValidator(_freeze_json_object),
        PlainSerializer(_thaw_json_object, return_type=JsonObject),
    ]
    _FrozenPhaseTupleField = Annotated[
        list[Phase],
        AfterValidator(tuple),
        PlainSerializer(list, return_type=list[Phase]),
    ]
    _FrozenNonEmptyStrTupleField = Annotated[
        list[NonEmptyString],
        AfterValidator(tuple),
        PlainSerializer(list, return_type=list[NonEmptyString]),
    ]


def _validate_and_freeze_rule_phases(value: list[Phase]) -> tuple[Phase, ...]:
    if not value:
        raise ValueError("RuleBinding phases must be non-empty")
    if len(set(value)) != len(value):
        raise ValueError("RuleBinding phases must not contain duplicates")
    return tuple(value)


if not TYPE_CHECKING:
    _FrozenRulePhasesField = Annotated[
        list[Phase],
        AfterValidator(_validate_and_freeze_rule_phases),
        PlainSerializer(list, return_type=list[Phase]),
    ]


def _canonical_json(value: object) -> str:
    return json.dumps(
        _thaw_json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _canonical_sha256(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value).encode('utf-8')).hexdigest()}"


class _Model(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )


class _ContractModel(_Model):
    """Preserve additional JSON metadata in historical contract documents."""

    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: dict[str, JsonValue] = Field(init=False)

    @model_serializer(mode="wrap")
    def _serialize_contract_model(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        extra = getattr(self, "__pydantic_extra__", None)
        if isinstance(extra, MappingProxyType):
            object.__setattr__(self, "__pydantic_extra__", _thaw_json_object(extra))
            try:
                dumped = handler(self)
            finally:
                object.__setattr__(self, "__pydantic_extra__", extra)
            thawed = _thaw_json_value(dumped)
            assert isinstance(thawed, dict)
            return thawed
        return handler(self)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        if isinstance(self.__pydantic_extra__, MappingProxyType):
            return self.__copy__()
        return super().__deepcopy__(memo)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if isinstance(self.__pydantic_extra__, MappingProxyType):
            extra = self.__pydantic_extra__
            copied = super().model_copy(
                update=dict(update) if update is not None else None,
                deep=False,
            )
            object.__setattr__(copied, "__pydantic_extra__", extra)
            return copied
        return super().model_copy(
            update=dict(update) if update is not None else None,
            deep=deep,
        )


class ApprovedAgentConfiguration(_ContractModel):
    fingerprint: NonEmptyString


class ResponseSchema(_ContractModel):
    required_fields: Annotated[
        list[NonEmptyString],
        PlainSerializer(list, return_type=list[NonEmptyString]),
    ]


def _freeze_response_schema(schema: ResponseSchema) -> ResponseSchema:
    frozen_extra = _freeze_json_object(dict(schema.__pydantic_extra__ or {}))
    copied = super(_ContractModel, schema).model_copy(deep=False)
    object.__setattr__(copied, "required_fields", tuple(schema.required_fields))
    object.__setattr__(copied, "__pydantic_extra__", frozen_extra)
    return copied


def _freeze_approved_config(
    item: NonEmptyString | ApprovedAgentConfiguration,
) -> NonEmptyString | ApprovedAgentConfiguration:
    if isinstance(item, ApprovedAgentConfiguration):
        frozen_extra = _freeze_json_object(dict(item.__pydantic_extra__ or {}))
        copied = super(_ContractModel, item).model_copy(deep=False)
        object.__setattr__(copied, "__pydantic_extra__", frozen_extra)
        return copied
    return item


class AgentFeedback(_ContractModel):
    advisory_warning_visibility: bool
    guarded_denial_style: NonEmptyString
    strict_replanning_after_violation: bool


class AgentContract(_ContractModel):
    """Typed view of an existing contract, without inventing a schema version.

Rule identifiers are strings here. Resolving supported rules and checking
fingerprints belong to the future loader/evaluator, not to these schemas.
"""

    contract_id: NonEmptyString
    mode: Mode
    approved_agent_configurations: list[
        NonEmptyString | ApprovedAgentConfiguration
    ]
    declared_tools: list[NonEmptyString]
    response_schema: ResponseSchema
    memory_policy: NonEmptyString
    validation_phases: list[Phase] | Literal["not_enforced"]
    runtime_rules: list[NonEmptyString]
    postconditions: list[NonEmptyString]
    agent_feedback: AgentFeedback
    contract_fingerprint: NonEmptyString


class ContractRulesV2(_Model):
    """Mode-independent rules with explicit metadata."""

    schema_version: Literal[2]
    contract_id: NonEmptyString
    approved_agent_configurations: list[
        NonEmptyString | ApprovedAgentConfiguration
    ]
    declared_tools: list[NonEmptyString]
    response_schema: ResponseSchema
    memory_policy: NonEmptyString
    validation_phases: list[Phase]
    runtime_rules: list[NonEmptyString]
    postconditions: list[NonEmptyString]
    contract_fingerprint: NonEmptyString
    metadata: JsonObject = Field(default_factory=dict)


class EnforcementPolicy(_Model):
    """Run-level enforcement mode, kept outside a v2 rules document."""

    mode: Mode


class RuleBinding(_Model):
    """Parameterized rule instance bound to one or more validation phases."""

    instance_id: InstanceId
    rule_type: NonEmptyString
    phases: _FrozenRulePhasesField
    params: _FrozenJsonObjectField = Field(
        default_factory=dict, validate_default=True
    )

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            frozen_update = dict(update)
            if "phases" in frozen_update:
                frozen_update["phases"] = _validate_and_freeze_rule_phases(
                    list(frozen_update["phases"])
                )
            if "params" in frozen_update:
                frozen_update["params"] = _freeze_json_object(
                    dict(frozen_update["params"])
                )
            return super().model_copy(update=frozen_update, deep=False)
        return self.__copy__()


if TYPE_CHECKING:
    _FrozenApprovedConfigsField: TypeAlias = tuple[
        NonEmptyString | ApprovedAgentConfiguration, ...
    ]
    _FrozenRulesTupleField: TypeAlias = tuple[RuleBinding, ...]
else:
    _FrozenApprovedConfigsField = Annotated[
        list[NonEmptyString | ApprovedAgentConfiguration],
        AfterValidator(
            lambda value: tuple(_freeze_approved_config(item) for item in value)
        ),
        WrapSerializer(lambda value, handler: handler(list(value))),
    ]
    _FrozenRulesTupleField = Annotated[
        list[RuleBinding],
        AfterValidator(tuple),
        WrapSerializer(lambda value, handler: handler(list(value))),
    ]


class ContractRulesV3(_Model):
    """Mode-independent v3 contract with deeply immutable parameterized rule bindings."""

    schema_version: Literal[3]
    contract_id: NonEmptyString
    approved_agent_configurations: _FrozenApprovedConfigsField
    declared_tools: _FrozenNonEmptyStrTupleField
    response_schema: Annotated[
        ResponseSchema,
        AfterValidator(_freeze_response_schema),
    ]
    memory_policy: NonEmptyString
    validation_phases: _FrozenPhaseTupleField
    rules: _FrozenRulesTupleField
    contract_fingerprint: NonEmptyString
    metadata: _FrozenJsonObjectField = Field(
        default_factory=dict, validate_default=True
    )

    @field_validator("schema_version", mode="before")
    @classmethod
    def check_strict_int_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be integer 3")
        return value

    @model_validator(mode="after")
    def check_unique_instance_ids(self) -> Self:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for binding in self.rules:
            if binding.instance_id in seen:
                duplicates.add(binding.instance_id)
            else:
                seen.add(binding.instance_id)
        if duplicates:
            raise ValueError(
                f"Duplicate rule instance_id(s): {', '.join(sorted(duplicates))}"
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
            frozen_update = dict(update)
            if "approved_agent_configurations" in frozen_update:
                frozen_update["approved_agent_configurations"] = tuple(
                    _freeze_approved_config(item)
                    for item in frozen_update["approved_agent_configurations"]
                )
            if "declared_tools" in frozen_update:
                frozen_update["declared_tools"] = tuple(
                    frozen_update["declared_tools"]
                )
            if "response_schema" in frozen_update:
                schema_val = frozen_update["response_schema"]
                if not isinstance(schema_val, ResponseSchema):
                    schema_val = ResponseSchema.model_validate(schema_val)
                frozen_update["response_schema"] = _freeze_response_schema(
                    schema_val
                )
            if "validation_phases" in frozen_update:
                frozen_update["validation_phases"] = tuple(
                    frozen_update["validation_phases"]
                )
            if "rules" in frozen_update:
                frozen_update["rules"] = tuple(
                    item
                    if isinstance(item, RuleBinding)
                    else RuleBinding.model_validate(item)
                    for item in frozen_update["rules"]
                )
            if "metadata" in frozen_update:
                frozen_update["metadata"] = _freeze_json_object(
                    dict(frozen_update["metadata"])
                )
            copied = super().model_copy(update=frozen_update, deep=False)
            copied.check_unique_instance_ids()
            return copied
        return self.__copy__()


ContractSchema: TypeAlias = AgentContract | ContractRulesV2 | ContractRulesV3


@dataclass(frozen=True, slots=True, init=False)
class ContractDocument:
    """Keep original JSON data separate from the typed contract.

    This accepts an already parsed mapping; file loading is deliberately out of
    scope. Whitespace from a source file is not preserved. The original values,
    ordering, duplicates, and omitted keys are preserved independently of the model.
    """

    contract: ContractSchema
    _original_json: str = field(repr=False)

    def __init__(self, document: JsonObject) -> None:
        snapshot = deepcopy(document)
        if "schema_version" not in snapshot:
            contract: ContractSchema = AgentContract.model_validate(snapshot)
        elif type(snapshot["schema_version"]) is int and snapshot["schema_version"] == 2:
            contract = ContractRulesV2.model_validate(snapshot)
        elif type(snapshot["schema_version"]) is int and snapshot["schema_version"] == 3:
            contract = ContractRulesV3.model_validate(snapshot)
        else:
            raise ValueError("Unsupported contract schema_version")
        original_json = json.dumps(snapshot, ensure_ascii=False, allow_nan=False)
        object.__setattr__(self, "contract", contract)
        object.__setattr__(self, "_original_json", original_json)

    @property
    def original(self) -> JsonObject:
        """Return a fresh copy of the original values, never a model dump."""
        return json.loads(self._original_json)


class ActionProposal(_Model):
    tool_name: NonEmptyString
    arguments: JsonObject = Field(default_factory=dict)
    iteration: Annotated[int, Field(ge=1)] | None = None


class HostFacts(_Model):
    """Host-supplied facts, separate from untrusted agent action proposals.

    Validated values are stored as deeply immutable snapshots. Schema validation
    checks structure only and does not prove provenance; the host remains
    responsible for sourcing trustworthy facts.
    """

    facts: _FrozenJsonObjectField = Field(default_factory=dict, validate_default=True)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            frozen_update = dict(update)
            if "facts" in frozen_update:
                frozen_update["facts"] = _freeze_json_value(frozen_update["facts"])
            return super().model_copy(update=frozen_update, deep=False)
        return self.__copy__()


class PlannedEffect(_Model):
    """Host-resolved planned effect, separate from ActionProposal.

    Validated ``parameters`` and ``defaults`` are stored as deeply immutable
    snapshots. Canonical operation identity derives solely from ``tool_name`` and
    ``effective_parameters`` (a top-level overlay where explicit ``parameters``,
    including explicit ``None``, replace ``defaults`` keys as whole values).
    """

    tool_name: NonEmptyString
    parameters: _FrozenJsonObjectField = Field(default_factory=dict, validate_default=True)
    defaults: _FrozenJsonObjectField = Field(default_factory=dict, validate_default=True)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            frozen_update = dict(update)
            for key in ("parameters", "defaults"):
                if key in frozen_update:
                    frozen_update[key] = _freeze_json_value(frozen_update[key])
            return super().model_copy(update=frozen_update, deep=False)
        return self.__copy__()

    @property
    def effective_parameters(self) -> JsonObject:
        return {**_thaw_json_object(self.defaults), **_thaw_json_object(self.parameters)}

    def canonical_operation(self) -> JsonObject:
        return {
            "identity": "vogtcon.operation",
            "version": OPERATION_IDENTITY_VERSION,
            "tool_name": self.tool_name,
            "parameters": self.effective_parameters,
        }

    def operation_digest(self) -> str:
        return _canonical_sha256(self.canonical_operation())


class ExecutionContext(_Model):
    """Facts supplied by the runtime, distinct from agent action arguments.

The caller is responsible for sourcing trustworthy state. A schema cannot prove
that a role or approval is genuine. Keep state flexible for tool-specific facts.
"""

    state: Annotated[
        JsonObject,
        PlainSerializer(_thaw_json_object, return_type=JsonObject),
    ]
    available_tools: list[NonEmptyString]
    observed_agent_fingerprint: NonEmptyString | None = None
    observed_contract_fingerprint: NonEmptyString | None = None
    final_properties: JsonObject = Field(default_factory=dict)
    forbidden_outcomes_triggered: list[NonEmptyString] = Field(default_factory=list)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        if isinstance(self.state, MappingProxyType):
            return super().model_copy(
                update={
                    "available_tools": deepcopy(self.available_tools, memo),
                    "final_properties": deepcopy(self.final_properties, memo),
                    "forbidden_outcomes_triggered": deepcopy(
                        self.forbidden_outcomes_triggered, memo
                    ),
                },
                deep=False,
            )
        return super().__deepcopy__(memo)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if deep and isinstance(self.state, MappingProxyType):
            copied_update: dict[str, Any] = {
                "available_tools": deepcopy(self.available_tools),
                "final_properties": deepcopy(self.final_properties),
                "forbidden_outcomes_triggered": deepcopy(
                    self.forbidden_outcomes_triggered
                ),
            }
            if update is not None:
                for key, val in update.items():
                    copied_update[key] = (
                        val if isinstance(val, MappingProxyType) else deepcopy(val)
                    )
            return super().model_copy(update=copied_update, deep=False)
        return super().model_copy(
            update=dict(update) if update is not None else None,
            deep=deep,
        )


class GovernorInput(_Model):
    """Phase-specific evaluation request; incomplete post-evidence is valid input.

The integration computes final properties/outcomes; this model does not read an
oracle. V2 rules require a separate ``policy``; a legacy contract retains its
embedded mode. IDs are supplied by the runtime and are not proof of authorization.
"""

    model_config = ConfigDict(hide_input_in_errors=True)

    run_id: NonEmptyString
    contract: AgentContract | ContractRulesV2
    phase: Phase
    context: ExecutionContext
    action: ActionProposal | None = None
    response: JsonObject | None = None
    run_ledger: JsonObject | None = None
    policy: EnforcementPolicy | None = Field(default=None, exclude_if=lambda value: value is None)
    host_facts: HostFacts | None = Field(default=None, exclude_if=lambda value: value is None)
    planned_effect: PlannedEffect | None = Field(default=None, exclude_if=lambda value: value is None)

    @field_validator("contract", mode="before")
    @classmethod
    def dispatch_contract(cls, value: object) -> AgentContract | ContractRulesV2:
        if isinstance(value, AgentContract):
            if "schema_version" in (value.model_extra or {}):
                raise ValueError("Unsupported contract schema_version")
            return value
        if isinstance(value, ContractRulesV2):
            return value
        if isinstance(value, ContractRulesV3):
            raise ValueError(
                "v3 contracts are not yet executable; runtime evaluation is introduced in Stage 2"
            )
        if isinstance(value, dict):
            if "schema_version" not in value:
                return AgentContract.model_validate(value)
            if type(value["schema_version"]) is int and value["schema_version"] == 2:
                return ContractRulesV2.model_validate(value)
            if type(value["schema_version"]) is int and value["schema_version"] == 3:
                raise ValueError(
                    "v3 contracts are not yet executable; runtime evaluation is introduced in Stage 2"
                )
            raise ValueError("Unsupported contract schema_version")
        raise ValueError("contract must be a v1 or v2 contract")

    @property
    def effective_mode(self) -> Mode:
        """Resolve the mode once from the policy or the historical contract."""
        if self.policy is not None:
            return self.policy.mode
        assert isinstance(self.contract, AgentContract)
        return self.contract.mode

    def validate_source_agreement(self) -> None:
        """Verify phase and value agreement across legacy and host-supplied inputs."""
        if self.phase == "runtime":
            if self.planned_effect is not None:
                if self.action is None:
                    raise ValueError("runtime evaluation requires an action")
                if self.planned_effect.tool_name != self.action.tool_name:
                    raise ValueError(
                        "planned_effect.tool_name conflicts with action.tool_name"
                    )
        elif self.planned_effect is not None:
            raise ValueError("planned_effect is only accepted for runtime evaluation")
        if self.host_facts is not None:
            conflicts = [
                key
                for key in sorted(set(self.context.state) & set(self.host_facts.facts))
                if _canonical_json(self.context.state[key])
                != _canonical_json(self.host_facts.facts[key])
            ]
            if conflicts:
                raise ValueError(
                    f"host_facts conflicts with context.state for key(s): {', '.join(conflicts)}"
                )

    @model_validator(mode="after")
    def check_phase_inputs(self) -> Self:
        if isinstance(self.contract, ContractRulesV2):
            if self.policy is None:
                raise ValueError("v2 contracts require an enforcement policy")
        elif self.policy is not None and self.policy.mode != self.contract.mode:
            raise ValueError("Enforcement policy conflicts with legacy contract mode")
        if self.phase == "runtime":
            if self.action is None:
                raise ValueError("runtime evaluation requires an action")
        elif self.action is not None:
            raise ValueError("action is only accepted for runtime evaluation")
        self.validate_source_agreement()
        if self.phase == "pre_execution":
            if (
                self.context.observed_agent_fingerprint is None
                or self.context.observed_contract_fingerprint is None
            ):
                raise ValueError("pre-execution evaluation requires observed fingerprints")
        if self.phase == "post_execution":
            if self.response is None:
                raise ValueError("post-execution evaluation requires a response mapping")
        elif self.response is not None or self.run_ledger is not None:
            raise ValueError("response and run_ledger are only accepted after execution")
        if self.host_facts is not None:
            frozen_context = self.context.model_copy(
                update={"state": _freeze_json_object(self.context.state)}
            )
            object.__setattr__(self, "context", frozen_context)
        return self

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        copied = super().model_copy(
            update=dict(update) if update is not None else None,
            deep=deep,
        )
        copied.validate_source_agreement()
        if copied.host_facts is not None and not isinstance(
            copied.context.state, MappingProxyType
        ):
            frozen_context = copied.context.model_copy(
                update={"state": _freeze_json_object(copied.context.state)}
            )
            object.__setattr__(copied, "context", frozen_context)
        return copied


class Violation(_Model):
    rule: NonEmptyString
    phase: Phase
    severity: NonEmptyString = "high"
    action: NonEmptyString | None = None


class GovernanceDecision(_Model):
    """Evaluation output; tool decisions are only meaningful at runtime.

Pre/post evaluations carry violations but no tool decision. Their run-level
effects (strict pre-abort or post-failure) remain the harness's responsibility.
No default 'allow' is inferred from a missing decision.
"""

    phase: Phase
    violations: list[Violation]
    decision: Decision | None = None
    explanation: str = ""

    @model_validator(mode="after")
    def check_phase_result(self) -> Self:
        if self.phase == "runtime" and self.decision is None:
            raise ValueError("runtime evaluation requires an explicit decision")
        if self.phase != "runtime" and self.decision is not None:
            raise ValueError("tool decisions are only accepted for the runtime phase")
        if any(item.phase != self.phase for item in self.violations):
            raise ValueError("violation phases must match the evaluation phase")
        return self
