# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Small, content-free JSONL record of governance decisions and tool attempts."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, Protocol, Self, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
    model_validator,
)

from .models import (
    ApprovalId,
    Decision,
    EffectId,
    EffectStatus,
    Mode,
    NonEmptyString,
    Phase,
    PolicyScopeId,
    Sha256Digest,
    _tuple_to_list_if_tuple,
)

if TYPE_CHECKING:
    _FrozenStrTupleField: TypeAlias = tuple[str, ...]
else:
    _FrozenStrTupleField = Annotated[
        list[str],
        BeforeValidator(_tuple_to_list_if_tuple),
        AfterValidator(tuple),
        PlainSerializer(list, return_type=list[str]),
    ]

EventType = Literal["decision", "tool_completed", "tool_error"]
EventTypeV2 = Literal[
    "decision",
    "tool_completed",
    "tool_error",
    "effect_observed",
    "effect_reconciled",
    "effect_compensated",
]
ExecutionStatus = Literal["not_started", "completed", "unknown"]


class RunEvent(BaseModel):
    """Versioned local evidence; never includes prompts, arguments or results."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    run_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    contract_id: str = Field(min_length=1)
    mode: Mode
    phase: Phase
    event_type: EventType
    action_index: int | None = Field(default=None, ge=1)
    tool_name: str | None = None
    decision: Decision | None = None
    violation_rules: list[str] = Field(default_factory=list)
    execution_status: ExecutionStatus = "not_started"
    trace_id: str | None = None
    span_id: str | None = None

    @model_validator(mode="after")
    def check_event_shape(self) -> "RunEvent":
        if (self.trace_id is None) != (self.span_id is None):
            raise ValueError("trace_id and span_id must be supplied together")
        if self.event_type == "decision":
            if self.execution_status != "not_started":
                raise ValueError("decision events must precede tool execution")
            if self.phase == "runtime":
                if self.decision is None or self.action_index is None or not self.tool_name:
                    raise ValueError("runtime decisions require decision and action identity")
            elif self.decision is not None or self.action_index is not None or self.tool_name is not None:
                raise ValueError("pre/post decisions cannot describe a tool action")
        elif (
            self.phase != "runtime"
            or self.action_index is None
            or not self.tool_name
            or self.decision is not None
            or self.violation_rules
            or self.execution_status != ("completed" if self.event_type == "tool_completed" else "unknown")
        ):
            raise ValueError("tool events require a runtime action and matching status")
        return self


class RunEventV2(BaseModel):
    """Versioned v2 local evidence including governed-effect transitions without payload content."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )

    schema_version: Literal[2] = 2
    run_id: NonEmptyString
    sequence: int = Field(ge=1)
    contract_id: NonEmptyString
    mode: Mode
    phase: Phase
    event_type: EventTypeV2
    action_index: int | None = Field(default=None, ge=1)
    tool_name: NonEmptyString | None = None
    decision: Decision | None = None
    violation_rules: _FrozenStrTupleField = Field(
        default_factory=tuple, validate_default=True
    )
    execution_status: ExecutionStatus = "not_started"
    policy_scope: PolicyScopeId | None = None
    effect_id: EffectId | None = None
    operation_digest: Sha256Digest | None = None
    effect_status: EffectStatus | None = None
    approval_id: ApprovalId | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    compensates_effect_id: EffectId | None = None
    evidence_ref: NonEmptyString | None = None
    trace_id: str | None = None
    span_id: str | None = None

    @field_validator("schema_version", mode="before")
    @classmethod
    def check_strict_int_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be integer 2")
        return value

    @model_validator(mode="after")
    def check_event_shape(self) -> "RunEventV2":
        if (self.trace_id is None) != (self.span_id is None):
            raise ValueError("trace_id and span_id must be supplied together")
        if self.event_type == "decision":
            if self.execution_status != "not_started":
                raise ValueError("decision events must precede tool execution")
            if self.evidence_ref is not None or self.compensates_effect_id is not None:
                raise ValueError(
                    "decision events cannot carry evidence_ref or compensates_effect_id"
                )
            if self.phase == "runtime":
                if (
                    self.decision is None
                    or self.action_index is None
                    or not self.tool_name
                ):
                    raise ValueError(
                        "runtime decisions require decision and action identity"
                    )
                if self.decision in ("block", "abort"):
                    if (
                        self.effect_id is not None
                        or self.effect_status is not None
                        or self.approval_id is not None
                    ):
                        raise ValueError(
                            "blocked or aborted decisions cannot reserve an effect or approval"
                        )
                elif self.effect_id is not None:
                    if (
                        self.effect_status != "reserved"
                        or self.operation_digest is None
                    ):
                        raise ValueError(
                            "reserved decision effect requires effect_status='reserved' and operation_digest"
                        )
                elif self.effect_status is not None:
                    raise ValueError("effect_status on decision requires effect_id")
                elif self.approval_id is not None:
                    raise ValueError("approval_id on decision requires effect_id")
            elif any(
                v is not None
                for v in (
                    self.decision,
                    self.action_index,
                    self.tool_name,
                    self.effect_id,
                    self.effect_status,
                    self.operation_digest,
                    self.approval_id,
                )
            ):
                raise ValueError(
                    "pre/post decisions cannot describe a tool action or effect"
                )
        elif self.event_type in ("tool_completed", "tool_error"):
            expected_exec = (
                "completed" if self.event_type == "tool_completed" else "unknown"
            )
            if (
                self.phase != "runtime"
                or self.action_index is None
                or not self.tool_name
                or self.decision is not None
                or self.violation_rules
                or self.compensates_effect_id is not None
                or self.effect_status is not None
                or self.evidence_ref is not None
                or self.approval_id is not None
                or self.execution_status != expected_exec
            ):
                raise ValueError(
                    "tool events require a runtime action and matching status"
                )
        elif self.event_type == "effect_observed":
            if (
                self.phase != "runtime"
                or self.action_index is None
                or not self.tool_name
                or self.effect_id is None
                or self.operation_digest is None
                or self.effect_status
                not in ("confirmed", "confirmed_absent", "uncertain")
                or self.decision is not None
                or self.violation_rules
                or self.compensates_effect_id is not None
            ):
                raise ValueError(
                    "effect_observed events require runtime action, effect_id, operation_digest, and observed effect_status"
                )
            expected_exec = (
                "unknown" if self.effect_status == "uncertain" else "completed"
            )
            if self.execution_status != expected_exec:
                raise ValueError(
                    "effect_observed execution_status must match effect_status"
                )
        elif self.event_type == "effect_reconciled":
            if (
                self.phase != "runtime"
                or self.effect_id is None
                or self.operation_digest is None
                or self.effect_status not in ("confirmed", "confirmed_absent")
                or self.evidence_ref is None
                or self.execution_status != "completed"
                or self.decision is not None
                or self.violation_rules
                or self.compensates_effect_id is not None
            ):
                raise ValueError(
                    "effect_reconciled events require runtime phase, effect_id, operation_digest, resolved effect_status, evidence_ref, and execution_status='completed'"
                )
        elif self.event_type == "effect_compensated":
            if (
                self.phase != "runtime"
                or self.effect_id is None
                or not self.tool_name
                or self.operation_digest is None
                or self.effect_status != "confirmed"
                or self.compensates_effect_id is None
                or self.evidence_ref is None
                or self.execution_status != "completed"
                or self.decision is not None
                or self.violation_rules
                or self.approval_id is not None
            ):
                raise ValueError(
                    "effect_compensated events require runtime phase, effect_id, tool_name, operation_digest, effect_status='confirmed', compensates_effect_id, evidence_ref, and execution_status='completed'"
                )
            if self.compensates_effect_id == self.effect_id:
                raise ValueError("Effect cannot compensate itself")
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


RecordedEvent: TypeAlias = RunEvent | RunEventV2


def parse_run_event(raw: str | Mapping[str, Any]) -> RecordedEvent:
    """Parse a v1 RunEvent or v2 RunEventV2 from a JSON line or mapping."""
    if isinstance(raw, str):
        data = json.loads(raw)
    elif isinstance(raw, Mapping):
        data = dict(raw)
    else:
        raise ValueError("RunEvent input must be a JSON string or mapping")
    if not isinstance(data, dict):
        raise ValueError("RunEvent JSON must decode to an object")
    if "schema_version" not in data:
        return RunEvent.model_validate(data)
    version = data["schema_version"]
    if type(version) is int and version == 1:
        return RunEvent.model_validate(data)
    if type(version) is int and version == 2:
        return RunEventV2.model_validate(data)
    raise ValueError("Unsupported RunEvent schema_version")


class RunRecorder(Protocol):
    """Sink for versioned ``RunEvent`` or ``RunEventV2`` evidence from one controller.

    Implement ``record(event)`` to use another durable store, or pass
    ``JsonlDecisionLog(path)`` for a local sequential JSONL file. A failed
    write before a tool invocation prevents that invocation.
    """

    def record(self, event: RecordedEvent) -> None: ...


class JsonlDecisionLog:
    """Append a complete line and sync it before the caller starts a tool.

    This is for a single-process local run. Concurrent writers and remote
    transaction guarantees are outside this small integration boundary.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, event: RecordedEvent) -> None:
        line = event.model_dump_json() + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as output:
            output.write(line)
            output.flush()
            os.fsync(output.fileno())

    def read(self) -> list[RecordedEvent]:
        with self.path.open("r", encoding="utf-8") as source:
            return [parse_run_event(line) for line in source if line.strip()]
