# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Data boundaries for governance, independent of the benchmark and providers.

These schemas validate structure, not policy compliance or the truth of agent
claims. Models prevent field reassignment, but nested lists/dicts are not deeply
immutable. ContractDocument keeps an independent original document for identity
checks; never compute a historical fingerprint from a model_dump().
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

Mode = Literal["no_contract", "advisory", "guarded", "strict"]
Phase = Literal["pre_execution", "runtime", "post_execution"]
Decision = Literal["allow", "allow_with_warning", "block", "abort"]
NonEmptyString = Annotated[str, Field(min_length=1)]
JsonObject = dict[str, JsonValue]


class _Model(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False
    )


class _ContractModel(_Model):
    """Preserve additional JSON metadata in historical contract documents."""

    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: dict[str, JsonValue] = Field(init=False)


class ApprovedAgentConfiguration(_ContractModel):
    fingerprint: NonEmptyString


class ResponseSchema(_ContractModel):
    required_fields: list[NonEmptyString]


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


@dataclass(frozen=True, slots=True, init=False)
class ContractDocument:
    """Keep original JSON data separate from the typed contract.

    This accepts an already parsed mapping; file loading is deliberately out of
    scope. Whitespace from a source file is not preserved. The original values,
    ordering, duplicates, and omitted keys are preserved independently of the model.
    """

    contract: AgentContract | ContractRulesV2
    _original_json: str = field(repr=False)

    def __init__(self, document: JsonObject) -> None:
        snapshot = deepcopy(document)
        if "schema_version" not in snapshot:
            contract = AgentContract.model_validate(snapshot)
        elif type(snapshot["schema_version"]) is int and snapshot["schema_version"] == 2:
            contract = ContractRulesV2.model_validate(snapshot)
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


class ExecutionContext(_Model):
    """Facts supplied by the runtime, distinct from agent action arguments.

The caller is responsible for sourcing trustworthy state. A schema cannot prove
that a role or approval is genuine. Keep state flexible for tool-specific facts.
"""

    state: JsonObject
    available_tools: list[NonEmptyString]
    observed_agent_fingerprint: NonEmptyString | None = None
    observed_contract_fingerprint: NonEmptyString | None = None
    final_properties: JsonObject = Field(default_factory=dict)
    forbidden_outcomes_triggered: list[NonEmptyString] = Field(default_factory=list)


class GovernorInput(_Model):
    """Phase-specific evaluation request; incomplete post-evidence is valid input.

The integration computes final properties/outcomes; this model does not read an
oracle. V2 rules require a separate ``policy``; a legacy contract retains its
embedded mode. IDs are supplied by the runtime and are not proof of authorization.
"""

    run_id: NonEmptyString
    contract: AgentContract | ContractRulesV2
    phase: Phase
    context: ExecutionContext
    action: ActionProposal | None = None
    response: JsonObject | None = None
    run_ledger: JsonObject | None = None
    policy: EnforcementPolicy | None = Field(default=None, exclude_if=lambda value: value is None)

    @field_validator("contract", mode="before")
    @classmethod
    def dispatch_contract(cls, value: object) -> AgentContract | ContractRulesV2:
        if isinstance(value, AgentContract):
            if "schema_version" in (value.model_extra or {}):
                raise ValueError("Unsupported contract schema_version")
            return value
        if isinstance(value, ContractRulesV2):
            return value
        if isinstance(value, dict):
            if "schema_version" not in value:
                return AgentContract.model_validate(value)
            if type(value["schema_version"]) is int and value["schema_version"] == 2:
                return ContractRulesV2.model_validate(value)
            raise ValueError("Unsupported contract schema_version")
        raise ValueError("contract must be a v1 or v2 contract")

    @property
    def effective_mode(self) -> Mode:
        """Resolve the mode once from the policy or the historical contract."""
        if self.policy is not None:
            return self.policy.mode
        assert isinstance(self.contract, AgentContract)
        return self.contract.mode

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
        return self


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
