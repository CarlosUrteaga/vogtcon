# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Host effect-resolution and observation interfaces and sequential effect store."""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal, Protocol, Self

from pydantic import ConfigDict, Field, model_validator

from .models import (
    ActionProposal,
    ApprovalId,
    ApprovalStateRecord,
    ApprovalUsageStatus,
    EffectId,
    EffectRecord,
    ExecutionContext,
    FrozenJsonObject,
    HostApproval,
    HostFacts,
    JsonObject,
    NonEmptyString,
    PlannedEffect,
    PolicyScopeId,
    PrincipalId,
    ReconciliationStatus,
    RetrievedEvidence,
    Sha256Digest,
    TimestampStr,
    TrajectoryEntry,
    TrajectoryView,
    _FrozenEvidenceTupleField,
    _FrozenJsonObjectField,
    _Model,
    _thaw_json_object,
    _thaw_json_value,
)

_POLICY_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")

_REQUIRED_STORE_METHODS: tuple[str, ...] = (
    "snapshot",
    "is_scope_suspended",
    "uncertain_effects",
    "reserve",
    "record_observation",
    "reconcile",
    "record_compensation",
)


def _validate_policy_scope_id(policy_scope: PolicyScopeId | None) -> None:
    if policy_scope is None:
        return
    if (
        not isinstance(policy_scope, str)
        or not (1 <= len(policy_scope) <= 128)
        or _POLICY_SCOPE_RE.match(policy_scope) is None
    ):
        raise ValueError("Invalid policy_scope identifier")


class EffectGovernanceError(RuntimeError):
    """Base operational error for governed-effect lifecycle failures."""


class ScopeSuspendedError(EffectGovernanceError):
    """Raised when an operation targets a scope suspended by uncertain effects."""

    def __init__(
        self,
        *,
        policy_scope: PolicyScopeId | None,
        uncertain_effect_ids: Sequence[EffectId] = (),
    ) -> None:
        _validate_policy_scope_id(policy_scope)
        self.policy_scope: PolicyScopeId | None = policy_scope
        self.uncertain_effect_ids: tuple[EffectId, ...] = tuple(uncertain_effect_ids)
        scope_label = (
            f"policy_scope '{policy_scope}'"
            if policy_scope is not None
            else "undelimited scope"
        )
        ids_label = (
            f" (uncertain effect_id(s): {', '.join(self.uncertain_effect_ids)})"
            if self.uncertain_effect_ids
            else ""
        )
        super().__init__(
            f"Execution is suspended for {scope_label} due to unresolved uncertain effect(s){ids_label}"
        )


class ConcurrencyError(EffectGovernanceError):
    """Raised when concurrent or re-entrant operation is detected."""


class ReconciliationError(ValueError):
    """Raised on invalid, unknown, repeated, contradictory, or mismatched reconciliation/compensation."""


class EffectResolutionError(EffectGovernanceError):
    """Raised when the host EffectResolver fails or returns an invalid output."""


class EffectObservationError(EffectGovernanceError):
    """Raised when the host EffectObserver fails or returns an invalid output."""


class ApprovalReuseError(EffectGovernanceError):
    """Raised when an approval cannot be reserved due to replay, lock, or binding mismatch."""


class ResolvedAction(_Model):
    """Host-resolved planned effect, trusted host facts, and optional authorization context."""

    model_config = ConfigDict(hide_input_in_errors=True)

    planned_effect: PlannedEffect
    host_facts: HostFacts = Field(default_factory=HostFacts)
    policy_scope: PolicyScopeId | None = None
    requester_id: PrincipalId | None = None
    evaluated_at: TimestampStr | None = None
    approval: HostApproval | None = None
    retrieved_evidence: _FrozenEvidenceTupleField | None = None

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self.__copy__()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        if update is not None:
            merged: dict[str, Any] = {
                "planned_effect": self.planned_effect,
                "host_facts": self.host_facts,
                "policy_scope": self.policy_scope,
                "requester_id": self.requester_id,
                "evaluated_at": self.evaluated_at,
                "approval": self.approval,
                "retrieved_evidence": (
                    list(self.retrieved_evidence)
                    if self.retrieved_evidence is not None
                    else None
                ),
            }
            merged.update(update)
            return type(self).model_validate(merged)
        return self.__copy__()


class ObservationInput(_Model):
    """Content-safe input context passed to the host EffectObserver."""

    model_config = ConfigDict(hide_input_in_errors=True)

    effect_id: EffectId
    run_id: NonEmptyString
    policy_scope: PolicyScopeId | None = None
    planned_effect: PlannedEffect
    invocation_outcome: Literal["returned", "raised"]
    error_type: NonEmptyString | None = None

    @model_validator(mode="after")
    def check_outcome_error_type(self) -> Self:
        if self.invocation_outcome == "returned" and self.error_type is not None:
            raise ValueError(
                "error_type is not accepted when invocation_outcome is 'returned'"
            )
        if self.invocation_outcome == "raised" and self.error_type is None:
            raise ValueError(
                "error_type is required when invocation_outcome is 'raised'"
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
            merged: dict[str, Any] = {
                "effect_id": self.effect_id,
                "run_id": self.run_id,
                "policy_scope": self.policy_scope,
                "planned_effect": self.planned_effect,
                "invocation_outcome": self.invocation_outcome,
                "error_type": self.error_type,
            }
            merged.update(update)
            return type(self).model_validate(merged)
        return self.__copy__()


class ObservedEffect(_Model):
    """Host-classified post-invocation observation result."""

    model_config = ConfigDict(hide_input_in_errors=True)

    status: Literal["confirmed", "confirmed_absent", "uncertain"]
    evidence_ref: NonEmptyString | None = None
    metadata: _FrozenJsonObjectField = Field(
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
            merged = self.model_dump()
            for key, val in update.items():
                merged[key] = _thaw_json_value(val) if key == "metadata" else val
            return type(self).model_validate(merged)
        return self.__copy__()


class ReconciliationRecord(_Model):
    """Host-supplied evidence resolving an uncertain effect."""

    model_config = ConfigDict(hide_input_in_errors=True)

    effect_id: EffectId
    resolved_status: ReconciliationStatus
    evidence_ref: NonEmptyString
    policy_scope: PolicyScopeId | None = None
    metadata: _FrozenJsonObjectField = Field(
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
            merged = self.model_dump()
            for key, val in update.items():
                merged[key] = _thaw_json_value(val) if key == "metadata" else val
            return type(self).model_validate(merged)
        return self.__copy__()


class CompensationRecord(_Model):
    """Host-supplied evidence recording a new compensating effect linked to a prior confirmed effect."""

    model_config = ConfigDict(hide_input_in_errors=True)

    compensates_effect_id: EffectId
    tool_name: NonEmptyString
    operation_digest: Sha256Digest
    evidence_ref: NonEmptyString
    policy_scope: PolicyScopeId | None = None
    metadata: _FrozenJsonObjectField = Field(
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
            merged = self.model_dump()
            for key, val in update.items():
                merged[key] = _thaw_json_value(val) if key == "metadata" else val
            return type(self).model_validate(merged)
        return self.__copy__()


class EffectResolver(Protocol):
    """Trusted host callback that resolves an agent proposal into a PlannedEffect and HostFacts."""

    def resolve(
        self, action: ActionProposal, context: ExecutionContext
    ) -> ResolvedAction: ...


class EffectObserver(Protocol):
    """Trusted host callback that classifies external effect outcome after tool invocation."""

    def observe(
        self, observation: ObservationInput, *, tool_result: Any = None
    ) -> ObservedEffect: ...


class EffectStore(Protocol):
    """Authoritative sequential store for effect reservations, observations, and trajectories."""

    def snapshot(
        self, policy_scope: PolicyScopeId | None = None
    ) -> TrajectoryView: ...

    def is_scope_suspended(
        self, policy_scope: PolicyScopeId | None = None
    ) -> bool: ...

    def uncertain_effects(
        self, policy_scope: PolicyScopeId | None = None
    ) -> tuple[EffectId, ...]: ...

    def reserve(
        self,
        *,
        run_id: str,
        policy_scope: PolicyScopeId | None,
        action_index: int,
        tool_name: str,
        operation_digest: str,
        metadata: JsonObject | FrozenJsonObject | None = None,
        expected_last_sequence: int | None = None,
        approval_id: ApprovalId | None = None,
        approval_single_use: bool = True,
        allow_retry_after_confirmed_absent: bool = False,
    ) -> EffectRecord: ...

    def record_observation(
        self,
        *,
        effect_id: EffectId,
        status: Literal["confirmed", "confirmed_absent", "uncertain"],
        evidence_ref: str | None = None,
        metadata: JsonObject | FrozenJsonObject | None = None,
    ) -> EffectRecord: ...

    def reconcile(self, record: ReconciliationRecord) -> EffectRecord: ...

    def record_compensation(
        self, *, run_id: str, compensation: CompensationRecord
    ) -> EffectRecord: ...


@dataclass(frozen=True, slots=True)
class EffectGovernanceConfig:
    """Explicit opt-in configuration wiring host resolution, observation, and effect storage."""

    store: EffectStore
    resolver: EffectResolver
    observer: EffectObserver
    policy_scope: PolicyScopeId | None = None

    def __post_init__(self) -> None:
        _validate_policy_scope_id(self.policy_scope)
        if not callable(getattr(self.resolver, "resolve", None)):
            raise TypeError(
                "EffectGovernanceConfig resolver must define a callable resolve method"
            )
        if not callable(getattr(self.observer, "observe", None)):
            raise TypeError(
                "EffectGovernanceConfig observer must define a callable observe method"
            )
        for method_name in _REQUIRED_STORE_METHODS:
            if not callable(getattr(self.store, method_name, None)):
                raise TypeError(
                    f"EffectGovernanceConfig store must implement callable '{method_name}'"
                )


class InMemoryEffectStore:
    """Authoritative single-process, sequential, in-memory effect and trajectory store.

    Crash/restart boundary:
        This reference store lives entirely in process memory. Reservations,
        trajectory entries, and scope suspensions do NOT survive process crash
        or restart. Crash-recoverable persistent stores are outside initial
        Stage 2 support and must implement :class:`EffectStore` externally.

    No scope reset:
        This store intentionally exposes NO ``reset_scope()``, ``clear()``, or
        delete methods. Append-only trajectory entries and scope suspensions
        cannot be bypassed by starting a new run or resetting a scope.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._in_flight_by_scope: dict[PolicyScopeId | None, EffectId] = {}
        self._entries: list[TrajectoryEntry] = []
        self._effects: dict[EffectId, EffectRecord] = {}
        self._approvals: dict[ApprovalId, ApprovalStateRecord] = {}
        self._next_effect_num: int = 0

    @contextmanager
    def _acquire_lock(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise ConcurrencyError(
                "Concurrent access to InMemoryEffectStore is not supported"
            )
        try:
            yield
        finally:
            self._lock.release()

    def _uncertain_effects_unlocked(
        self, policy_scope: PolicyScopeId | None
    ) -> tuple[EffectId, ...]:
        return tuple(
            record.effect_id
            for record in self._effects.values()
            if record.policy_scope == policy_scope and record.status == "uncertain"
        )

    def snapshot(
        self, policy_scope: PolicyScopeId | None = None
    ) -> TrajectoryView:
        _validate_policy_scope_id(policy_scope)
        with self._acquire_lock():
            entries = [
                entry
                for entry in self._entries
                if entry.policy_scope == policy_scope
            ]
            effects = [
                record
                for record in self._effects.values()
                if record.policy_scope == policy_scope
            ]
            uncertain_ids = [
                record.effect_id
                for record in effects
                if record.status == "uncertain"
            ]
            approvals = (
                [
                    rec
                    for rec in self._approvals.values()
                    if rec.policy_scope == policy_scope
                ]
                if policy_scope is not None
                else []
            )
            return TrajectoryView(
                policy_scope=policy_scope,
                entries=entries,
                effects=effects,
                suspended=bool(uncertain_ids),
                uncertain_effect_ids=uncertain_ids,
                approvals=approvals,
            )

    def uncertain_effects(
        self, policy_scope: PolicyScopeId | None = None
    ) -> tuple[EffectId, ...]:
        _validate_policy_scope_id(policy_scope)
        with self._acquire_lock():
            return self._uncertain_effects_unlocked(policy_scope)

    def is_scope_suspended(
        self, policy_scope: PolicyScopeId | None = None
    ) -> bool:
        _validate_policy_scope_id(policy_scope)
        with self._acquire_lock():
            return bool(self._uncertain_effects_unlocked(policy_scope))

    def reserve(
        self,
        *,
        run_id: str,
        policy_scope: PolicyScopeId | None,
        action_index: int,
        tool_name: str,
        operation_digest: str,
        metadata: JsonObject | FrozenJsonObject | None = None,
        expected_last_sequence: int | None = None,
        approval_id: ApprovalId | None = None,
        approval_single_use: bool = True,
        allow_retry_after_confirmed_absent: bool = False,
    ) -> EffectRecord:
        _validate_policy_scope_id(policy_scope)
        if expected_last_sequence is not None and (
            type(expected_last_sequence) is not int
            or expected_last_sequence < 0
        ):
            raise ValueError(
                "expected_last_sequence must be a non-negative integer"
            )
        if type(approval_single_use) is not bool:
            raise TypeError("approval_single_use must be a bool")
        if type(allow_retry_after_confirmed_absent) is not bool:
            raise TypeError("allow_retry_after_confirmed_absent must be a bool")
        if approval_id is not None and policy_scope is None:
            raise ValueError(
                "Bound approval reservation requires a non-null policy_scope"
            )
        with self._acquire_lock():
            uncertain_ids = self._uncertain_effects_unlocked(policy_scope)
            if uncertain_ids:
                raise ScopeSuspendedError(
                    policy_scope=policy_scope,
                    uncertain_effect_ids=uncertain_ids,
                )
            if policy_scope in self._in_flight_by_scope:
                active_id = self._in_flight_by_scope[policy_scope]
                raise ConcurrencyError(
                    f"Policy scope {policy_scope!r} already has an active reserved effect '{active_id}'"
                )
            if expected_last_sequence is not None:
                current_last_sequence = max(
                    (
                        entry.sequence
                        for entry in self._entries
                        if entry.policy_scope == policy_scope
                    ),
                    default=0,
                )
                if current_last_sequence != expected_last_sequence:
                    raise ConcurrencyError(
                        "Policy scope trajectory changed between evaluation and reservation"
                    )
            candidate_id = f"eff-{self._next_effect_num + 1:06d}"
            candidate_seq = len(self._entries) + 1
            candidate_approval: ApprovalStateRecord | None = None
            if approval_id is not None:
                assert policy_scope is not None
                existing_approval = self._approvals.get(approval_id)
                if existing_approval is not None:
                    if existing_approval.operation_digest != operation_digest:
                        raise ApprovalReuseError(
                            f"Approval '{approval_id}' cannot be reused with a different operation_digest"
                        )
                    if existing_approval.policy_scope != policy_scope:
                        raise ApprovalReuseError(
                            f"Approval '{approval_id}' is bound to a different policy_scope"
                        )
                    if existing_approval.single_use != approval_single_use:
                        raise ApprovalReuseError(
                            f"Approval '{approval_id}' cannot change single_use mode once bound"
                        )
                    if existing_approval.status == "reserved":
                        raise ConcurrencyError(
                            f"Approval '{approval_id}' is currently reserved by an active effect"
                        )
                    if existing_approval.status == "locked_uncertain":
                        raise ApprovalReuseError(
                            f"Approval '{approval_id}' is locked by an unresolved uncertain effect"
                        )
                    if existing_approval.status == "consumed" and (
                        existing_approval.single_use or approval_single_use
                    ):
                        raise ApprovalReuseError(
                            f"Single-use approval '{approval_id}' has already been consumed"
                        )
                    if (
                        existing_approval.status == "released_absent"
                        and existing_approval.single_use
                        and not allow_retry_after_confirmed_absent
                    ):
                        raise ApprovalReuseError(
                            f"Retry of single-use approval '{approval_id}' after confirmed absence is not permitted by policy"
                        )
                candidate_approval = ApprovalStateRecord(
                    approval_id=approval_id,
                    operation_digest=operation_digest,
                    policy_scope=policy_scope,
                    status="reserved",
                    effect_id=candidate_id,
                    single_use=approval_single_use,
                    retry_count=(
                        existing_approval.retry_count + 1
                        if existing_approval is not None
                        and existing_approval.status == "released_absent"
                        else 0
                    ),
                )
            thawed_meta = (
                _thaw_json_value(metadata) if metadata is not None else {}
            )
            entry = TrajectoryEntry(
                sequence=candidate_seq,
                kind="reserved",
                effect_id=candidate_id,
                run_id=run_id,
                policy_scope=policy_scope,
                action_index=action_index,
                tool_name=tool_name,
                operation_digest=operation_digest,
                status="reserved",
                approval_id=approval_id,
                metadata=thawed_meta,
            )
            record = EffectRecord(
                effect_id=candidate_id,
                run_id=run_id,
                policy_scope=policy_scope,
                action_index=action_index,
                tool_name=tool_name,
                operation_digest=operation_digest,
                status="reserved",
                approval_id=approval_id,
                metadata=thawed_meta,
            )
            self._next_effect_num += 1
            self._entries.append(entry)
            self._effects[candidate_id] = record
            self._in_flight_by_scope[policy_scope] = candidate_id
            if candidate_approval is not None:
                assert approval_id is not None
                self._approvals[approval_id] = candidate_approval
            return record

    def record_observation(
        self,
        *,
        effect_id: EffectId,
        status: Literal["confirmed", "confirmed_absent", "uncertain"],
        evidence_ref: str | None = None,
        metadata: JsonObject | FrozenJsonObject | None = None,
    ) -> EffectRecord:
        with self._acquire_lock():
            if not isinstance(effect_id, str) or effect_id not in self._effects:
                raise ReconciliationError("Unknown effect_id for observation")
            existing = self._effects[effect_id]
            if existing.status != "reserved":
                raise ReconciliationError(
                    "Only reserved effects can record an observation"
                )
            if status not in ("confirmed", "confirmed_absent", "uncertain"):
                raise ValueError(
                    "Observed status must be 'confirmed', 'confirmed_absent', or 'uncertain'"
                )
            if metadata is not None:
                thawed_update = _thaw_json_value(metadata)
                if not isinstance(thawed_update, dict):
                    raise ValueError("metadata must be a JSON object")
                entry_meta: dict[str, Any] = thawed_update
                merged_meta: dict[str, Any] = {
                    **_thaw_json_object(existing.metadata),
                    **thawed_update,
                }
            else:
                entry_meta = {}
                merged_meta = _thaw_json_object(existing.metadata)

            entry = TrajectoryEntry(
                sequence=len(self._entries) + 1,
                kind="observed",
                effect_id=existing.effect_id,
                run_id=existing.run_id,
                policy_scope=existing.policy_scope,
                action_index=existing.action_index,
                tool_name=existing.tool_name,
                operation_digest=existing.operation_digest,
                status=status,
                approval_id=existing.approval_id,
                evidence_ref=evidence_ref,
                metadata=entry_meta,
            )
            updated = EffectRecord(
                effect_id=existing.effect_id,
                run_id=existing.run_id,
                policy_scope=existing.policy_scope,
                action_index=existing.action_index,
                tool_name=existing.tool_name,
                operation_digest=existing.operation_digest,
                status=status,
                approval_id=existing.approval_id,
                evidence_ref=evidence_ref,
                metadata=merged_meta,
            )
            updated_approval: ApprovalStateRecord | None = None
            if (
                existing.approval_id is not None
                and existing.approval_id in self._approvals
            ):
                prev_approval = self._approvals[existing.approval_id]
                mapped_status: ApprovalUsageStatus = {
                    "confirmed": "consumed",
                    "uncertain": "locked_uncertain",
                    "confirmed_absent": "released_absent",
                }[status]
                updated_approval = prev_approval.model_copy(
                    update={
                        "status": mapped_status,
                        "effect_id": existing.effect_id,
                    }
                )
            self._entries.append(entry)
            self._effects[effect_id] = updated
            if updated_approval is not None:
                assert existing.approval_id is not None
                self._approvals[existing.approval_id] = updated_approval
            if self._in_flight_by_scope.get(existing.policy_scope) == effect_id:
                del self._in_flight_by_scope[existing.policy_scope]
            return updated

    def reconcile(self, record: ReconciliationRecord) -> EffectRecord:
        if not isinstance(record, ReconciliationRecord):
            raise TypeError("reconcile requires a ReconciliationRecord instance")
        with self._acquire_lock():
            if record.effect_id not in self._effects:
                raise ReconciliationError("Unknown effect_id for reconciliation")
            existing = self._effects[record.effect_id]
            if existing.status != "uncertain":
                raise ReconciliationError(
                    "Only uncertain effects can be reconciled"
                )
            if (
                record.policy_scope is not None
                and record.policy_scope != existing.policy_scope
            ):
                raise ReconciliationError(
                    "Reconciliation policy_scope does not match target effect"
                )
            entry_meta = _thaw_json_object(record.metadata)
            merged_meta = (
                {**_thaw_json_object(existing.metadata), **entry_meta}
                if entry_meta
                else _thaw_json_object(existing.metadata)
            )
            entry = TrajectoryEntry(
                sequence=len(self._entries) + 1,
                kind="reconciled",
                effect_id=existing.effect_id,
                run_id=existing.run_id,
                policy_scope=existing.policy_scope,
                action_index=existing.action_index,
                tool_name=existing.tool_name,
                operation_digest=existing.operation_digest,
                status=record.resolved_status,
                approval_id=existing.approval_id,
                evidence_ref=record.evidence_ref,
                metadata=entry_meta,
            )
            updated = EffectRecord(
                effect_id=existing.effect_id,
                run_id=existing.run_id,
                policy_scope=existing.policy_scope,
                action_index=existing.action_index,
                tool_name=existing.tool_name,
                operation_digest=existing.operation_digest,
                status=record.resolved_status,
                approval_id=existing.approval_id,
                evidence_ref=record.evidence_ref,
                metadata=merged_meta,
            )
            updated_approval: ApprovalStateRecord | None = None
            if (
                existing.approval_id is not None
                and existing.approval_id in self._approvals
            ):
                prev_approval = self._approvals[existing.approval_id]
                reconciled_status: ApprovalUsageStatus = (
                    "consumed"
                    if record.resolved_status == "confirmed"
                    else "released_absent"
                )
                updated_approval = prev_approval.model_copy(
                    update={
                        "status": reconciled_status,
                        "effect_id": existing.effect_id,
                    }
                )
            self._entries.append(entry)
            self._effects[existing.effect_id] = updated
            if updated_approval is not None:
                assert existing.approval_id is not None
                self._approvals[existing.approval_id] = updated_approval
            return updated

    def record_compensation(
        self, *, run_id: str, compensation: CompensationRecord
    ) -> EffectRecord:
        if not isinstance(compensation, CompensationRecord):
            raise TypeError(
                "record_compensation requires a CompensationRecord instance"
            )
        with self._acquire_lock():
            if compensation.compensates_effect_id not in self._effects:
                raise ReconciliationError(
                    "Unknown target effect_id for compensation"
                )
            target = self._effects[compensation.compensates_effect_id]
            if target.status != "confirmed":
                raise ReconciliationError(
                    "Only confirmed effects can be compensated"
                )
            if (
                compensation.policy_scope is not None
                and compensation.policy_scope != target.policy_scope
            ):
                raise ReconciliationError(
                    "Compensation policy_scope does not match target effect"
                )
            effective_scope = target.policy_scope
            if effective_scope in self._in_flight_by_scope:
                active_id = self._in_flight_by_scope[effective_scope]
                raise ConcurrencyError(
                    f"Policy scope {effective_scope!r} already has an active reserved effect '{active_id}'"
                )
            candidate_id = f"eff-{self._next_effect_num + 1:06d}"
            candidate_seq = len(self._entries) + 1
            comp_meta = _thaw_json_object(compensation.metadata)
            entry = TrajectoryEntry(
                sequence=candidate_seq,
                kind="compensated",
                effect_id=candidate_id,
                run_id=run_id,
                policy_scope=effective_scope,
                action_index=None,
                tool_name=compensation.tool_name,
                operation_digest=compensation.operation_digest,
                status="confirmed",
                compensates_effect_id=target.effect_id,
                evidence_ref=compensation.evidence_ref,
                metadata=comp_meta,
            )
            record = EffectRecord(
                effect_id=candidate_id,
                run_id=run_id,
                policy_scope=effective_scope,
                action_index=None,
                tool_name=compensation.tool_name,
                operation_digest=compensation.operation_digest,
                status="confirmed",
                compensates_effect_id=target.effect_id,
                evidence_ref=compensation.evidence_ref,
                metadata=comp_meta,
            )
            self._next_effect_num += 1
            self._entries.append(entry)
            self._effects[candidate_id] = record
            return record
