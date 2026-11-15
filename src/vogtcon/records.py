# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Small, content-free JSONL record of governance decisions and tool attempts."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import Decision, Mode, Phase

EventType = Literal["decision", "tool_completed", "tool_error"]
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


class RunRecorder(Protocol):
    """Sink for versioned ``RunEvent`` evidence from one controller.

    Implement ``record(event)`` to use another durable store, or pass
    ``JsonlDecisionLog(path)`` for a local sequential JSONL file. A failed
    write before a tool invocation prevents that invocation.
    """

    def record(self, event: RunEvent) -> None: ...


class JsonlDecisionLog:
    """Append a complete line and sync it before the caller starts a tool.

    This is for a single-process local run. Concurrent writers and remote
    transaction guarantees are outside this small integration boundary.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, event: RunEvent) -> None:
        line = event.model_dump_json() + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as output:
            output.write(line)
            output.flush()
            os.fsync(output.fileno())

    def read(self) -> list[RunEvent]:
        with self.path.open("r", encoding="utf-8") as source:
            return [RunEvent.model_validate_json(line) for line in source if line.strip()]
